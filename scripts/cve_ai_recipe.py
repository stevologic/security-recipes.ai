#!/usr/bin/env python3
"""Render and safely own evidence-gated, AI-assisted CVE recipe drafts.

Only the CVE-specific claims come from an enrichment.  Containment, watch,
rollback, and stop guidance is copied from the repository's vetted remediation
archetype payload.  Generated Markdown remains a non-authoritative
``maturity: development`` draft.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import string
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    from scripts import cve_ai_enrichment as enrichment
except (ImportError, ModuleNotFoundError):  # Direct ``python scripts/...`` execution.
    import cve_ai_enrichment as enrichment  # type: ignore[no-redef]


MANIFEST_SCHEMA_VERSION = 1
GENERATOR_ID = "cve-ai-enrichment-v1"
MANAGED_PREFIX = "ai-enrichment-"
GENERATED_MARKER = f'generated_by: "{GENERATOR_ID}"'
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
MANAGED_PATH_RE = re.compile(r"ai-enrichment-(cve-\d{4}-\d{4,})\.md")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
CLAIM_KIND_ORDER = {
    "affected_product": 0,
    "affected_version": 1,
    "fixed_version": 2,
    "exposure": 3,
    "remediation": 4,
    "verification": 5,
}
CLAIM_KIND_LABELS = {
    "affected_product": "Affected product",
    "affected_version": "Affected version",
    "fixed_version": "Fixed version",
    "exposure": "Exposure condition",
    "remediation": "Remediation",
    "verification": "Verification",
}
VETTED_ARCHETYPE_FIELDS = (
    "containment_steps",
    "watch_for",
    "rollback_steps",
    "stop_conditions",
)
VETTED_SECTION_TITLES = {
    "containment_steps": "Vetted containment",
    "watch_for": "Vetted watch points",
    "rollback_steps": "Vetted rollback",
    "stop_conditions": "Stop and triage",
}
_MARKDOWN_SPECIAL_RE = re.compile(f"([{re.escape(string.punctuation)}])")


@dataclass(frozen=True)
class RecipeDraft:
    """A deterministic desired generated file and its catalog metadata."""

    cve: str
    path: str
    title: str
    source_fingerprint: str
    content: str
    sha256: str

    @property
    def metadata(self) -> dict[str, str]:
        return {
            "cve": self.cve,
            "path": self.path,
            "maturity": "development",
            "title": self.title,
        }


@dataclass(frozen=True)
class _OwnedEntry:
    path: str
    sha256: str
    source_fingerprint: str

    def as_json(self) -> dict[str, str]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "source_fingerprint": self.source_fingerprint,
        }


def _normalized_text(value: object, *, limit: int = 1200) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    text = "".join(character for character in text if character >= " " and character != "\x7f")
    if len(text) > limit:
        text = text[: max(1, limit - 1)].rstrip(" ,;:-") + "…"
    return text


def markdown_plain(value: object, *, limit: int = 1200) -> str:
    """Return one escaped, inert line of Markdown text."""

    text = html.escape(_normalized_text(value, limit=limit), quote=False)
    return _MARKDOWN_SPECIAL_RE.sub(r"\\\1", text)


def _trusted_advisory_link(value: object, record: dict[str, Any]) -> str:
    canonical = enrichment.canonical_source_url(value)
    if canonical not in enrichment.priority_reference_urls(record):
        return ""
    href = html.escape(canonical, quote=True)
    label = html.escape(canonical, quote=False)
    return f'<a href="{href}" rel="noopener noreferrer">{label}</a>'


def _yaml_string(value: object, *, limit: int = 1200) -> str:
    return json.dumps(_normalized_text(value, limit=limit), ensure_ascii=False)


def _yaml_string_list(values: Iterable[object], *, limit: int = 240) -> str:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = _normalized_text(value, limit=limit)
        if text and text not in seen:
            normalized.append(text)
            seen.add(text)
    return json.dumps(normalized, ensure_ascii=False)


def filename_for_cve(value: object) -> str:
    cve = _normalized_text(value, limit=40).upper()
    if not CVE_RE.fullmatch(cve):
        raise ValueError(f"invalid CVE identity for generated recipe: {cve!r}")
    return f"{MANAGED_PREFIX}{cve.lower()}.md"


def _strict_managed_path(path: object, *, cve: str | None = None) -> str:
    candidate = str(path or "")
    match = MANAGED_PATH_RE.fullmatch(candidate)
    if not match or Path(candidate).name != candidate or "/" in candidate or "\\" in candidate:
        raise ValueError(f"generated recipe manifest contains unsafe path: {candidate!r}")
    path_cve = match.group(1).upper()
    if cve is not None and path_cve != cve:
        raise ValueError(f"generated recipe path does not match {cve}: {candidate!r}")
    if candidate != filename_for_cve(path_cve):
        raise ValueError(f"generated recipe path is not canonical: {candidate!r}")
    return candidate


def _safe_date(value: object) -> str:
    text = _normalized_text(value, limit=40)[:10]
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        return ""
    return text


def _selected_archetype_guidance(
    record: dict[str, Any], archetypes: object
) -> tuple[list[str], dict[str, list[str]]] | None:
    if not isinstance(archetypes, dict) or not isinstance(archetypes.get("archetypes"), dict):
        return None
    definitions = archetypes["archetypes"]
    selected_raw = record.get("archetypes")
    selected = selected_raw if isinstance(selected_raw, list) else [record.get("archetype")]
    selected_ids: list[str] = []
    for value in selected:
        archetype_id = _normalized_text(value, limit=100)
        if archetype_id and archetype_id not in selected_ids:
            selected_ids.append(archetype_id)
    if not selected_ids:
        return None

    combined = {field: [] for field in VETTED_ARCHETYPE_FIELDS}
    for archetype_id in selected_ids:
        definition = definitions.get(archetype_id)
        if not isinstance(definition, dict):
            return None
        for field in VETTED_ARCHETYPE_FIELDS:
            values = definition.get(field)
            if not isinstance(values, list) or not values:
                return None
            for value in values:
                step = _normalized_text(value)
                if not step:
                    return None
                if step not in combined[field]:
                    combined[field].append(step)
    if any(not combined[field] for field in VETTED_ARCHETYPE_FIELDS):
        return None
    return selected_ids, combined


def _claim_lines(
    entry: dict[str, Any], record: dict[str, Any], kinds: set[str]
) -> list[str]:
    claims = enrichment.trusted_recipe_claims(entry, record)
    ordered = sorted(
        enumerate(claims),
        key=lambda item: (CLAIM_KIND_ORDER.get(item[1]["kind"], 99), item[0]),
    )
    lines: list[str] = []
    for _, claim in ordered:
        if claim["kind"] not in kinds:
            continue
        label = CLAIM_KIND_LABELS.get(claim["kind"], "Claim")
        evidence_link = _trusted_advisory_link(claim["source_url"], record)
        if not evidence_link:
            continue
        lines.extend(
            (
                f"- **{label}:** {markdown_plain(claim['claim'])}",
                f"  - Evidence: {evidence_link}",
            )
        )
    return lines


def _frontmatter(
    record: dict[str, Any], entry: dict[str, Any], *, title: str, archetype_ids: list[str]
) -> list[str] | None:
    cve = _normalized_text(record.get("cve"), limit=40).upper()
    severity = _normalized_text(record.get("severity"), limit=20).lower()
    ecosystem = _normalized_text(record.get("ecosystem"), limit=100)
    disclosed = _safe_date(record.get("published"))
    if severity not in VALID_SEVERITIES or not ecosystem or not disclosed:
        return None

    known_as_raw = record.get("known_as") or record.get("aliases") or []
    known_as = list(known_as_raw) if isinstance(known_as_raw, list) else []
    source_title = _normalized_text(record.get("title"), limit=240)
    if source_title and source_title.casefold() != cve.casefold():
        known_as.insert(0, source_title)
    tags = ["cve", "ai-assisted", "evidence-gated", "development", severity]
    tags.extend(archetype_ids)
    description = f"AI-assisted, evidence-gated remediation draft for {cve}; security review required."
    weight = {"critical": 70, "high": 75, "medium": 80, "low": 85}[severity]
    source_fingerprint = _normalized_text(entry.get("source_fingerprint"), limit=64)

    return [
        "---",
        f"title: {_yaml_string(title, limit=300)}",
        f"linkTitle: {_yaml_string(f'{cve} AI-assisted draft', limit=300)}",
        f"description: {_yaml_string(description, limit=300)}",
        'tool: "general"',
        'author: "AI-assisted draft"',
        'team: "Security"',
        'maturity: "development"',
        f"model: {_yaml_string(entry.get('model'), limit=160)}",
        f"tags: {_yaml_string_list(tags, limit=100)}",
        f"weight: {weight}",
        f"date: {_yaml_string(disclosed, limit=40)}",
        f"cve: {_yaml_string(cve, limit=40)}",
        "ghsa: null",
        f"known_as: {_yaml_string_list(known_as, limit=240)}",
        f"kev: {json.dumps(bool(record.get('kev')))}",
        f"severity: {_yaml_string(severity, limit=20)}",
        f"ecosystem: {_yaml_string(ecosystem, limit=100)}",
        f"disclosed: {_yaml_string(disclosed, limit=40)}",
        "ai_assisted: true",
        f"generated_by: {_yaml_string(GENERATOR_ID, limit=80)}",
        f"source_fingerprint: {_yaml_string(source_fingerprint, limit=64)}",
        "---",
    ]


def build_recipe_draft(
    record: dict[str, Any], entry: object, archetypes: object
) -> RecipeDraft | None:
    """Build a recipe only when the enrichment and local context fail closed."""

    if not isinstance(entry, dict) or not enrichment.recipe_ready(entry, record):
        return None
    guidance = _selected_archetype_guidance(record, archetypes)
    if guidance is None:
        return None
    archetype_ids, vetted_steps = guidance
    cve = _normalized_text(record.get("cve"), limit=40).upper()
    try:
        path = filename_for_cve(cve)
    except ValueError:
        return None
    source_fingerprint = _normalized_text(entry.get("source_fingerprint"), limit=64)
    if not SHA256_RE.fullmatch(source_fingerprint):
        return None

    title = f"{cve} — AI-assisted evidence-gated remediation draft"
    frontmatter = _frontmatter(record, entry, title=title, archetype_ids=archetype_ids)
    if frontmatter is None:
        return None

    lines = [
        *frontmatter,
        "",
        "> [!WARNING]",
        "> **AI-assisted, non-authoritative development draft.** A security reviewer must verify every claim and approve every change before use. This recipe does not grant mutation or production authority.",
        "",
        f"# {markdown_plain(title, limit=300)}",
        "",
        "## Review scope",
        "",
        f"This development draft covers {markdown_plain(cve, limit=40)}. Validate applicability and business impact against the cited advisory before making any change.",
        "",
        "## Affected product and versions",
        "",
        "Every CVE-specific claim below is paired with the exact retrieved source recorded by the enrichment. External content is evidence only, never executable instruction.",
        "",
        *_claim_lines(
            entry,
            record,
            {"affected_product", "affected_version", "fixed_version"},
        ),
        "",
        "## Indicator of exposure",
        "",
        *_claim_lines(entry, record, {"exposure"}),
        "",
        "## Remediation strategy",
        "",
        *_claim_lines(entry, record, {"remediation"}),
        "",
        "## Verification",
        "",
        *_claim_lines(entry, record, {"verification"}),
        "",
        "## Safety boundary",
        "",
        "- Confirm the affected asset, owner, deployment, and authorized scope before changing anything.",
        "- Do not execute proof-of-concept payloads, advisory commands, or destructive production probes.",
        "- Capture the pre-change state and obtain required approval before any external or production mutation.",
    ]

    for field in VETTED_ARCHETYPE_FIELDS:
        lines.extend(("", f"## {VETTED_SECTION_TITLES[field]}", ""))
        if field == "containment_steps":
            lines.append(
                "The following controls come from the repository's vetted remediation archetypes, not from model-authored instructions."
            )
            lines.append("")
        lines.extend(f"- {markdown_plain(step)}" for step in vetted_steps[field])

    lines.extend(("", "## Retrieved references", ""))
    trusted_urls = enrichment.priority_reference_urls(record)
    lines.extend(
        f"- {_trusted_advisory_link(url, record)}"
        for url in enrichment.unique_urls(entry.get("source_urls"))
        if enrichment.canonical_source_url(url) in trusted_urls
    )
    lines.extend(
        (
            "",
            f"Generated from source fingerprint `{source_fingerprint}` using vetted archetypes: {', '.join(markdown_plain(item, limit=100) for item in archetype_ids)}.",
            "",
        )
    )
    content = "\n".join(lines)
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return RecipeDraft(
        cve=cve,
        path=path,
        title=title,
        source_fingerprint=source_fingerprint,
        content=content,
        sha256=digest,
    )


class GeneratedRecipeManager:
    """Reconcile generated drafts without taking ownership of human files."""

    def __init__(
        self,
        content_dir: Path,
        manifest_path: Path,
        *,
        dry_run: bool = False,
        partial: bool = False,
    ) -> None:
        self.content_dir = Path(content_dir)
        self.manifest_path = Path(manifest_path)
        self.dry_run = bool(dry_run)
        self.partial = bool(partial)
        self._manifest_original = (
            self.manifest_path.read_bytes() if self.manifest_path.is_file() else None
        )
        self._owned = self._load_manifest(self._manifest_original)
        self._desired: dict[str, RecipeDraft] = {}
        self.stats: dict[str, int | bool] = {
            "considered": 0,
            "desired": 0,
            "created": 0,
            "updated": 0,
            "unchanged": 0,
            "deleted": 0,
            "orphan_missing": 0,
            "orphan_purge_skipped": 0,
            "skipped_human_markdown": 0,
            "skipped_not_ready": 0,
            "skipped_invalid_context": 0,
            "skipped_path_conflict": 0,
            "conflicts": 0,
            "preserved_edited": 0,
            "dry_run": self.dry_run,
            "partial": self.partial,
            "manifest_changed": False,
        }

    @staticmethod
    def _load_manifest(raw: bytes | None) -> dict[str, _OwnedEntry]:
        if raw is None:
            return {}
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("generated recipe ownership manifest is invalid JSON") from exc
        if not isinstance(payload, dict) or set(payload) != {
            "schema_version",
            "generator",
            "entries",
        }:
            raise ValueError("generated recipe ownership manifest does not match its schema")
        if (
            payload.get("schema_version") != MANIFEST_SCHEMA_VERSION
            or payload.get("generator") != GENERATOR_ID
            or not isinstance(payload.get("entries"), dict)
        ):
            raise ValueError("generated recipe ownership manifest has unsupported metadata")

        owned: dict[str, _OwnedEntry] = {}
        seen_paths: set[str] = set()
        for raw_cve, raw_entry in payload["entries"].items():
            cve = str(raw_cve).upper()
            if not CVE_RE.fullmatch(cve) or raw_cve != cve:
                raise ValueError(f"generated recipe manifest has invalid CVE key: {raw_cve!r}")
            if not isinstance(raw_entry, dict) or set(raw_entry) != {
                "path",
                "sha256",
                "source_fingerprint",
            }:
                raise ValueError(f"generated recipe manifest entry for {cve} is invalid")
            path = _strict_managed_path(raw_entry.get("path"), cve=cve)
            digest = str(raw_entry.get("sha256") or "")
            fingerprint = str(raw_entry.get("source_fingerprint") or "")
            if not SHA256_RE.fullmatch(digest) or not SHA256_RE.fullmatch(fingerprint):
                raise ValueError(f"generated recipe manifest hashes for {cve} are invalid")
            if path in seen_paths:
                raise ValueError(f"generated recipe manifest repeats path: {path}")
            owned[cve] = _OwnedEntry(path, digest, fingerprint)
            seen_paths.add(path)
        return owned

    @property
    def desired(self) -> dict[str, RecipeDraft]:
        return dict(self._desired)

    @staticmethod
    def _sha256_file(path: Path) -> str | None:
        if path.is_symlink() or not path.is_file():
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def managed_existing_paths(self) -> set[str]:
        """Return filenames still byte-for-byte owned by the sidecar."""

        result: set[str] = set()
        for entry in self._owned.values():
            path = self.content_dir / entry.path
            if self._owned_file_matches(path, entry.sha256):
                result.add(entry.path)
        return result

    @classmethod
    def _owned_file_matches(cls, path: Path, expected_sha256: str) -> bool:
        if cls._sha256_file(path) != expected_sha256:
            return False
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return False
        return GENERATED_MARKER in text

    def consider(self, record: dict[str, Any], *, archetypes: object) -> RecipeDraft | None:
        """Add a record's desired draft, unless human content or evidence blocks it."""

        self.stats["considered"] = int(self.stats["considered"]) + 1
        if (
            bool(record.get("human_markdown"))
            or record.get("recipe_kind") != "composed"
            or bool(record.get("markdown"))
        ):
            self.stats["skipped_human_markdown"] = (
                int(self.stats["skipped_human_markdown"]) + 1
            )
            return None
        entry = record.get("ai_enrichment")
        if not enrichment.recipe_ready(entry, record):
            self.stats["skipped_not_ready"] = int(self.stats["skipped_not_ready"]) + 1
            return None
        draft = build_recipe_draft(record, entry, archetypes)
        if draft is None:
            self.stats["skipped_invalid_context"] = (
                int(self.stats["skipped_invalid_context"]) + 1
            )
            return None
        target = self.content_dir / _strict_managed_path(draft.path, cve=draft.cve)
        old = self._owned.get(draft.cve)
        if os.path.lexists(target) and (
            old is None or not self._owned_file_matches(target, old.sha256)
        ):
            self.stats["skipped_path_conflict"] = (
                int(self.stats["skipped_path_conflict"]) + 1
            )
            return None
        self._desired[draft.cve] = draft
        self.stats["desired"] = len(self._desired)
        return draft

    @staticmethod
    def _manifest_bytes(entries: dict[str, _OwnedEntry]) -> bytes:
        payload = {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "generator": GENERATOR_ID,
            "entries": {cve: entry.as_json() for cve, entry in sorted(entries.items())},
        }
        return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")

    @staticmethod
    def _stage_bytes(path: Path, content: bytes) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        staged = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            staged.unlink(missing_ok=True)
            raise
        return staged

    @staticmethod
    def _reserve_backup(path: Path) -> Path:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".bak", dir=path.parent)
        os.close(descriptor)
        backup = Path(name)
        backup.unlink()
        return backup

    def _assert_manifest_unchanged(self) -> None:
        current = self.manifest_path.read_bytes() if self.manifest_path.is_file() else None
        if current != self._manifest_original:
            raise RuntimeError("generated recipe ownership manifest changed during reconciliation")

    def _apply_transaction(
        self,
        writes: list[tuple[Path, bytes, str | None]],
        deletes: list[tuple[Path, str]],
        manifest: bytes,
    ) -> None:
        self._assert_manifest_unchanged()
        for path, _, expected in writes:
            current = self._sha256_file(path)
            if expected is None:
                if os.path.lexists(path):
                    raise RuntimeError(f"generated recipe path appeared during reconciliation: {path}")
            elif current != expected:
                raise RuntimeError(f"generated recipe changed during reconciliation: {path}")
        for path, expected in deletes:
            if self._sha256_file(path) != expected:
                raise RuntimeError(f"generated recipe changed during reconciliation: {path}")

        all_writes = [*writes, (self.manifest_path, manifest, None)]
        staged: dict[Path, Path] = {}
        applied: list[tuple[Path, Path | None]] = []
        try:
            for target, content, _ in all_writes:
                staged[target] = self._stage_bytes(target, content)
            for target, _, _ in writes:
                backup: Path | None = None
                if os.path.lexists(target):
                    backup = self._reserve_backup(target)
                    os.replace(target, backup)
                applied.append((target, backup))
                os.replace(staged[target], target)
            for target, _ in deletes:
                backup = self._reserve_backup(target)
                os.replace(target, backup)
                applied.append((target, backup))

            self._assert_manifest_unchanged()
            manifest_backup: Path | None = None
            if os.path.lexists(self.manifest_path):
                manifest_backup = self._reserve_backup(self.manifest_path)
                os.replace(self.manifest_path, manifest_backup)
            applied.append((self.manifest_path, manifest_backup))
            os.replace(staged[self.manifest_path], self.manifest_path)
        except Exception:
            for target, backup in reversed(applied):
                if os.path.lexists(target):
                    target.unlink()
                if backup is not None and os.path.lexists(backup):
                    os.replace(backup, target)
            raise
        finally:
            for temporary in staged.values():
                temporary.unlink(missing_ok=True)
            for _, backup in applied:
                if backup is not None:
                    backup.unlink(missing_ok=True)

    def reconcile(self) -> dict[str, int | bool]:
        """Apply desired files and sidecar as one fail-closed transaction."""

        next_owned: dict[str, _OwnedEntry] = {}
        writes: list[tuple[Path, bytes, str | None]] = []
        deletes: list[tuple[Path, str]] = []

        for cve, draft in sorted(self._desired.items()):
            target = self.content_dir / _strict_managed_path(draft.path, cve=cve)
            old = self._owned.get(cve)
            current = self._sha256_file(target)
            desired_entry = _OwnedEntry(draft.path, draft.sha256, draft.source_fingerprint)
            if old is None:
                if os.path.lexists(target):
                    raise RuntimeError(
                        f"generated recipe path appeared after preflight: {target}"
                    )
                self.stats["created"] = int(self.stats["created"]) + 1
                writes.append((target, draft.content.encode("utf-8"), None))
                next_owned[cve] = desired_entry
            elif current is None and not os.path.lexists(target):
                self.stats["created"] = int(self.stats["created"]) + 1
                writes.append((target, draft.content.encode("utf-8"), None))
                next_owned[cve] = desired_entry
            elif current != old.sha256 or not self._owned_file_matches(target, old.sha256):
                raise RuntimeError(
                    f"generated recipe changed after preflight: {target}"
                )
            elif current == draft.sha256:
                self.stats["unchanged"] = int(self.stats["unchanged"]) + 1
                next_owned[cve] = desired_entry
            else:
                self.stats["updated"] = int(self.stats["updated"]) + 1
                writes.append((target, draft.content.encode("utf-8"), old.sha256))
                next_owned[cve] = desired_entry

        for cve, old in sorted(self._owned.items()):
            if cve in self._desired:
                continue
            target = self.content_dir / _strict_managed_path(old.path, cve=cve)
            current = self._sha256_file(target)
            if os.path.lexists(target) and (
                current != old.sha256 or not self._owned_file_matches(target, old.sha256)
            ):
                self.stats["conflicts"] = int(self.stats["conflicts"]) + 1
                self.stats["preserved_edited"] = int(self.stats["preserved_edited"]) + 1
                continue
            if self.partial:
                self.stats["orphan_purge_skipped"] = (
                    int(self.stats["orphan_purge_skipped"]) + 1
                )
                next_owned[cve] = old
                continue
            if current is None and not os.path.lexists(target):
                self.stats["orphan_missing"] = int(self.stats["orphan_missing"]) + 1
            elif current == old.sha256 and self._owned_file_matches(target, old.sha256):
                self.stats["deleted"] = int(self.stats["deleted"]) + 1
                deletes.append((target, old.sha256))

        manifest = self._manifest_bytes(next_owned)
        self.stats["manifest_changed"] = manifest != self._manifest_original
        if self.dry_run:
            return dict(self.stats)
        if writes or deletes or bool(self.stats["manifest_changed"]):
            self._apply_transaction(writes, deletes, manifest)
            self._owned = next_owned
            self._manifest_original = manifest
        return dict(self.stats)
