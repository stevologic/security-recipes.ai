#!/usr/bin/env python3
"""Validate the generated CVE catalog, its shards, and recipe invariants."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
from collections import Counter
from datetime import date, datetime
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from scripts.cve_ai_enrichment import enrichment_errors
except ModuleNotFoundError:  # Direct ``python scripts/validate_cve_catalog.py`` execution.
    from cve_ai_enrichment import enrichment_errors  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = ROOT / "static" / "api" / "cve-catalog"
DEFAULT_CONTENT = ROOT / "content" / "recipes" / "cve"
CVE_RE = re.compile(r"CVE-(\d{4})-(\d+)")
GHSA_RE = re.compile(r"GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}", re.IGNORECASE)
FRONTMATTER_RE = re.compile(r"\A---\s*\n(?P<body>.*?)\n---\s*\n", re.DOTALL)
SHA256_RE = re.compile(r"[0-9a-f]{64}", re.IGNORECASE)
SHARD_PATH_RE = re.compile(r"shards/\d{4}/\d{4,}\.jsonl\.gz")
INDEX_PARTITION_PATH_RE = re.compile(r"indexes/(\d{4})\.json\.gz")
NVD_FEED_ROOT = "https://nvd.nist.gov/feeds/json/cve/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FORBIDDEN_GENERIC_TITLE = "affected product security vulnerability"
NVD_METADATA_FIELDS = ("lastModifiedDate", "size", "zipSize", "gzSize", "sha256")
BROWSER_INDEX_FIELDS = [
    "cve",
    "title",
    "severity",
    "score",
    "published",
    "ecosystem_index",
    "kev",
    "archetype_indexes",
    "has_markdown",
]
BROWSER_SEVERITY_CODES = {"medium": 0, "high": 1, "critical": 2}
BROWSER_SEVERITY_NAMES = {str(code): severity for severity, code in BROWSER_SEVERITY_CODES.items()}
MAX_STABLE_MARKDOWN_BYTES = 256 * 1024
ARCHETYPE_LIST_FIELDS = (
    "exposure_checks",
    "remediation_steps",
    "containment_steps",
    "verification_steps",
    "rollback_steps",
    "stop_conditions",
    "watch_for",
)
AGENTIC_ACTION_ORDER = (
    "discover",
    "assess",
    "mitigate",
    "remediate",
    "verify",
    "rollback",
    "triage",
)
AGENTIC_OPERATION_VALUES = ("inspect", "assess", "edit", "test", "restore", "report")
AGENTIC_TARGET_KIND_VALUES = (
    "source_code",
    "dependency_manifest",
    "lockfile",
    "configuration",
    "build_definition",
    "deployment_manifest",
    "infrastructure_as_code",
    "runtime_policy",
    "inventory",
    "firmware_image",
    "binary_artifact",
    "test",
    "documentation",
    "triage_report",
)
AGENTIC_PHASE_CONTRACTS = {
    "discover": ("exposure_checks", "inspect", False, False, "none", "triage"),
    "assess": ("watch_for", "assess", False, False, "none", "triage"),
    "mitigate": (
        "containment_steps",
        "edit",
        True,
        True,
        "before_external_or_production_change",
        "rollback_then_triage",
    ),
    "remediate": (
        "remediation_steps",
        "edit",
        True,
        True,
        "before_external_or_production_change",
        "rollback_then_triage",
    ),
    "verify": ("verification_steps", "test", False, False, "none", "triage"),
    "rollback": (
        "rollback_steps",
        "restore",
        True,
        False,
        "before_external_or_production_change",
        "stop_and_triage",
    ),
    "triage": ("stop_conditions", "report", True, False, "none", "stop"),
}
AGENTIC_CONTRACT_KEYS = {
    "schema_version",
    "action_order",
    "operation_values",
    "target_kind_values",
    "phase_contracts",
    "required_outputs",
    "fixed_version_policy",
    "safety_boundaries",
}
AGENTIC_PHASE_KEYS = {
    "source_field",
    "operation",
    "mutates_files",
    "requires_rollback_plan",
    "approval_gate",
    "on_failure",
    "required_evidence",
}
AGENTIC_ACTION_KEYS = {"id", "phase", "source_field", "operation", "target_kinds"}
ECOSYSTEM_HINT_KEYS = {"file_globs", "target_kinds", "safe_edit_intent"}
REQUIRED_ECOSYSTEM_HINTS = {
    "javascript/npm",
    "python/pypi",
    "java/maven",
    "php/wordpress",
    "linux/kernel",
    "windows/system",
    "apple/platform",
    "browser",
    "operating-system",
    "hardware/firmware",
    "software/application",
}
VENDOR_CONTROLLED_ECOSYSTEMS = {
    "linux/kernel",
    "windows/system",
    "apple/platform",
    "browser",
    "operating-system",
    "hardware/firmware",
}
ARCHETYPE_RISK_PRECEDENCE = (
    "command_code_injection",
    "unsafe_deserialization",
    "memory_corruption",
    "use_after_free",
    "privilege_escalation",
    "authentication_bypass",
    "authorization_idor",
    "sql_query_injection",
    "ssrf",
    "xxe",
    "path_traversal_file_handling",
    "supply_chain_update_integrity",
    "http_request_smuggling",
    "crypto_certificate_validation",
    "information_disclosure",
    "cross_site_scripting",
    "race_lifetime",
    "resource_exhaustion_dos",
)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def expected_shard(cve: str) -> str:
    match = CVE_RE.fullmatch(cve)
    if not match:
        return ""
    year, sequence = match.groups()
    return f"shards/{year}/{int(sequence) // 1000:04d}.jsonl.gz"


def ten_year_cutoff(end_date: date) -> date:
    try:
        return end_date.replace(year=end_date.year - 10)
    except ValueError:  # February 29.
        return end_date.replace(year=end_date.year - 10, day=28)


def valid_shard_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts and SHARD_PATH_RE.fullmatch(value) is not None


def _is_link_or_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or bool(is_junction and is_junction())


def _safe_catalog_output_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) == ".":
        return None
    return path.as_posix()


def declared_catalog_output_paths(manifest: dict[str, Any]) -> set[str]:
    """Return every physical file owned by one catalog generation."""
    declared = {"manifest.json", "index.json", "archetypes.json"}

    def add(value: object) -> None:
        relative = _safe_catalog_output_path(value)
        if relative:
            declared.add(relative)

    for key in ("browser_index", "runtime_summary", "archetypes_asset", "complete_index"):
        entry = manifest.get(key)
        if isinstance(entry, dict):
            add(entry.get("path"))

    complete_index = manifest.get("complete_index")
    if isinstance(complete_index, dict):
        for entry in complete_index.get("partitions") or []:
            if isinstance(entry, dict):
                add(entry.get("path"))

    for entry in manifest.get("shard_manifest") or []:
        if isinstance(entry, dict):
            add(entry.get("path"))
    return declared


def _expected_catalog_dirs(declared: set[str]) -> set[str]:
    directories: set[str] = set()
    for relative in declared:
        for parent in PurePosixPath(relative).parents:
            if str(parent) != ".":
                directories.add(parent.as_posix())
    return directories


def validate_physical_catalog_tree(
    catalog_dir: Path,
    manifest: dict[str, Any],
    failures: list[str],
) -> bool:
    """Reject physical nodes that are not owned by the active manifest.

    The traversal never follows links or junctions. The boolean result is
    false only for filesystem node types that would be unsafe to read later;
    ordinary missing/orphan files remain normal validation failures.
    """
    declared = declared_catalog_output_paths(manifest)
    expected_dirs = _expected_catalog_dirs(declared)
    physical_files: set[str] = set()
    physical_dirs: set[str] = set()
    links: set[str] = set()
    special: set[str] = set()

    def visit(directory: Path) -> None:
        with os.scandir(directory) as scanned:
            children = sorted(scanned, key=lambda entry: entry.name)
        for child in children:
            path = Path(child.path)
            relative = path.relative_to(catalog_dir).as_posix()
            if child.is_symlink() or _is_link_or_junction(path):
                links.add(relative)
            elif child.is_dir(follow_symlinks=False):
                physical_dirs.add(relative)
                visit(path)
            elif child.is_file(follow_symlinks=False):
                physical_files.add(relative)
            else:
                special.add(relative)

    visit(catalog_dir)
    if physical_files != declared:
        missing = sorted(declared - physical_files)
        orphaned = sorted(physical_files - declared)
        fail(
            failures,
            f"physical catalog file set does not match declared outputs: missing={missing[:10]}, orphaned={orphaned[:10]}",
        )
    orphaned_dirs = sorted(physical_dirs - expected_dirs)
    if orphaned_dirs:
        fail(
            failures,
            f"physical catalog directory set contains undeclared directories: orphaned={orphaned_dirs[:10]}",
        )
    if links:
        fail(failures, f"physical catalog contains links or junctions: {sorted(links)[:10]}")
    if special:
        fail(failures, f"physical catalog contains special filesystem entries: {sorted(special)[:10]}")
    return not links and not special


def parse_nonnegative_integer(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def valid_datetime(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def fail(failures: list[str], message: str, *, cap: int = 200) -> None:
    if len(failures) < cap:
        failures.append(message)


def nonempty_unique_strings(value: object) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and bool(item.strip()) for item in value)
        and len(value) == len(set(value))
    )


def validate_agentic_contract(archetypes: dict[str, Any], failures: list[str]) -> bool:
    errors_before = len(failures)
    contract = archetypes.get("agentic_contract")
    if not isinstance(contract, dict) or set(contract) != AGENTIC_CONTRACT_KEYS:
        fail(failures, "agentic_contract does not match the required top-level schema")
        return False
    if contract.get("schema_version") != 1:
        fail(failures, "agentic_contract schema_version must be 1")
    if contract.get("action_order") != list(AGENTIC_ACTION_ORDER):
        fail(failures, "agentic_contract action_order is not the deterministic seven-phase workflow")
    if contract.get("operation_values") != list(AGENTIC_OPERATION_VALUES):
        fail(failures, "agentic_contract operation_values do not match the supported operations")
    if contract.get("target_kind_values") != list(AGENTIC_TARGET_KIND_VALUES):
        fail(failures, "agentic_contract target_kind_values do not match the supported target kinds")

    phases = contract.get("phase_contracts")
    if not isinstance(phases, dict) or set(phases) != set(AGENTIC_ACTION_ORDER):
        fail(failures, "agentic_contract phase_contracts must contain every phase in action_order")
    else:
        expected_fields = (
            "source_field",
            "operation",
            "mutates_files",
            "requires_rollback_plan",
            "approval_gate",
            "on_failure",
        )
        for phase, expected_values in AGENTIC_PHASE_CONTRACTS.items():
            policy = phases.get(phase)
            prefix = f"agentic phase {phase!r}"
            if not isinstance(policy, dict) or set(policy) != AGENTIC_PHASE_KEYS:
                fail(failures, f"{prefix} does not match the required schema")
                continue
            actual_values = tuple(policy.get(field) for field in expected_fields)
            if actual_values != expected_values:
                fail(failures, f"{prefix} policy does not match the deterministic safety contract")
            if not nonempty_unique_strings(policy.get("required_evidence")):
                fail(failures, f"{prefix} required_evidence must be a nonempty unique string list")

    required_outputs = contract.get("required_outputs")
    if not isinstance(required_outputs, dict) or set(required_outputs) != set(AGENTIC_ACTION_ORDER):
        fail(failures, "agentic_contract required_outputs must map every phase in action_order")
    elif (
        any(not isinstance(value, str) or not value.strip() for value in required_outputs.values())
        or len(required_outputs) != len(set(required_outputs.values()))
    ):
        fail(failures, "agentic_contract required_outputs must be unique nonempty strings")

    version_policy = contract.get("fixed_version_policy")
    if not isinstance(version_policy, dict) or set(version_policy) != {
        "allowed_sources",
        "require_source_record",
        "when_unknown",
    }:
        fail(failures, "agentic_contract fixed_version_policy does not match the required schema")
    else:
        if not nonempty_unique_strings(version_policy.get("allowed_sources")):
            fail(failures, "fixed_version_policy allowed_sources must be a nonempty unique string list")
        if version_policy.get("require_source_record") is not True:
            fail(failures, "fixed_version_policy must require an authoritative source record")
        unknown = version_policy.get("when_unknown")
        if (
            not isinstance(unknown, str)
            or not unknown.strip()
            or "do not" not in unknown.lower()
            or not all(term in unknown.lower() for term in ("invent", "infer", "guess"))
            or "triage.md" not in unknown.lower()
        ):
            fail(failures, "fixed_version_policy must forbid invented versions and require TRIAGE.md")

    boundaries = contract.get("safety_boundaries")
    if not nonempty_unique_strings(boundaries):
        fail(failures, "agentic_contract safety_boundaries must be a nonempty unique string list")
    else:
        boundary_text = " ".join(boundaries).lower()
        for concept in (
            "scope", "exploit", "invent", "rollback", "secrets", "incident response",
            "untrusted evidence", "embedded commands",
        ):
            if concept not in boundary_text:
                fail(failures, f"agentic_contract safety_boundaries do not cover {concept!r}")

    hints = archetypes.get("ecosystem_target_hints")
    if not isinstance(hints, dict) or set(hints) != REQUIRED_ECOSYSTEM_HINTS:
        fail(failures, "ecosystem_target_hints must cover every inferred ecosystem exactly")
    else:
        allowed_targets = set(AGENTIC_TARGET_KIND_VALUES)
        for ecosystem, hint in hints.items():
            prefix = f"ecosystem target hint {ecosystem!r}"
            if not isinstance(hint, dict) or set(hint) != ECOSYSTEM_HINT_KEYS:
                fail(failures, f"{prefix} does not match the required schema")
                continue
            globs = hint.get("file_globs")
            if not nonempty_unique_strings(globs):
                fail(failures, f"{prefix} file_globs must be a nonempty unique string list")
            elif any("\\" in glob or ":" in glob or ".." in PurePosixPath(glob).parts for glob in globs):
                fail(failures, f"{prefix} contains an unsafe file glob")
            targets = hint.get("target_kinds")
            if not nonempty_unique_strings(targets) or any(target not in allowed_targets for target in targets or []):
                fail(failures, f"{prefix} target_kinds are invalid")
            if ecosystem in VENDOR_CONTROLLED_ECOSYSTEMS and isinstance(targets, list) and "source_code" in targets:
                fail(failures, f"{prefix} must not direct agents to edit vendor-controlled source")
            intent = hint.get("safe_edit_intent")
            if not isinstance(intent, str) or not intent.strip():
                fail(failures, f"{prefix} has no safe_edit_intent")

    return len(failures) == errors_before


def valid_archetype_contracts(archetypes: dict[str, Any], failures: list[str]) -> set[str]:
    contract_valid = validate_agentic_contract(archetypes, failures)
    definitions = archetypes.get("archetypes")
    if not isinstance(definitions, dict) or not definitions:
        fail(failures, "archetypes must be a nonempty object")
        return set()
    valid: set[str] = set()
    global_action_ids: set[str] = set()
    allowed_targets = set(AGENTIC_TARGET_KIND_VALUES)
    for archetype_id, archetype in definitions.items():
        prefix = f"archetype {archetype_id!r}"
        errors_before = len(failures)
        if not isinstance(archetype_id, str) or not archetype_id.strip():
            fail(failures, "archetype IDs must be nonempty strings")
            continue
        if not isinstance(archetype, dict):
            fail(failures, f"{prefix} must be an object")
            continue
        for field in ("title", "description"):
            if not isinstance(archetype.get(field), str) or not archetype[field].strip():
                fail(failures, f"{prefix} has invalid {field}")
        for field in ARCHETYPE_LIST_FIELDS:
            values = archetype.get(field)
            if not nonempty_unique_strings(values):
                fail(failures, f"{prefix} has invalid {field}: expected a nonempty unique string list")

        actions = archetype.get("agentic_actions")
        if not isinstance(actions, list) or len(actions) != len(AGENTIC_ACTION_ORDER):
            fail(failures, f"{prefix} must define exactly one agentic action for every phase")
            actions = []
        elif [action.get("phase") if isinstance(action, dict) else None for action in actions] != list(
            AGENTIC_ACTION_ORDER
        ):
            fail(failures, f"{prefix} agentic actions are not in deterministic phase order")
        for position, action in enumerate(actions):
            phase = AGENTIC_ACTION_ORDER[position]
            action_prefix = f"{prefix} action {phase!r}"
            if not isinstance(action, dict) or set(action) != AGENTIC_ACTION_KEYS:
                fail(failures, f"{action_prefix} does not match the required schema")
                continue
            action_id = action.get("id")
            if action_id != f"{archetype_id}.{phase}":
                fail(failures, f"{action_prefix} has a nondeterministic ID {action_id!r}")
            elif action_id in global_action_ids:
                fail(failures, f"duplicate agentic action ID {action_id!r}")
            else:
                global_action_ids.add(action_id)
            source_field, operation, *_ = AGENTIC_PHASE_CONTRACTS[phase]
            if action.get("phase") != phase:
                fail(failures, f"{action_prefix} has the wrong phase")
            if action.get("source_field") != source_field:
                fail(failures, f"{action_prefix} does not reference {source_field!r}")
            if action.get("operation") != operation:
                fail(failures, f"{action_prefix} does not use operation {operation!r}")
            targets = action.get("target_kinds")
            if not nonempty_unique_strings(targets) or any(target not in allowed_targets for target in targets or []):
                fail(failures, f"{action_prefix} target_kinds are invalid")
            if phase == "triage" and isinstance(targets, list) and "triage_report" not in targets:
                fail(failures, f"{action_prefix} must target triage_report")
            if phase in {"mitigate", "remediate"} and isinstance(targets, list) and not (
                set(targets) - {"test", "documentation", "triage_report"}
            ):
                fail(failures, f"{action_prefix} has no mutable implementation target")
        if contract_valid and len(failures) == errors_before:
            valid.add(archetype_id)
    hints = archetypes.get("ecosystem_target_hints")
    incompatible: set[str] = set()
    if isinstance(hints, dict):
        for archetype_id, archetype in definitions.items():
            if not isinstance(archetype_id, str) or not isinstance(archetype, dict):
                continue
            for action in archetype.get("agentic_actions") or []:
                if not isinstance(action, dict):
                    continue
                phase = str(action.get("phase") or "")
                raw_targets = set(action.get("target_kinds") or [])
                for ecosystem, hint in hints.items():
                    if not isinstance(hint, dict):
                        continue
                    effective = raw_targets & set(hint.get("target_kinds") or [])
                    if phase == "triage" and "triage_report" in raw_targets:
                        effective.add("triage_report")
                    if not effective:
                        fail(
                            failures,
                            f"agentic action {action.get('id')!r} has no effective target for ecosystem {ecosystem!r}",
                        )
                        incompatible.add(archetype_id)
    valid.difference_update(incompatible)
    return valid


def is_safe_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value.strip() or "\\" in value or ":" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and path.suffix == ".md"
        and path.parts[:3] == ("content", "recipes", "cve")
    )


def ordered_archetypes(families: list[str]) -> list[str]:
    precedence = {archetype_id: position for position, archetype_id in enumerate(ARCHETYPE_RISK_PRECEDENCE)}
    return sorted(families, key=lambda archetype_id: (precedence.get(archetype_id, len(precedence)), archetype_id))


def frontmatter_value(frontmatter: str, key: str) -> str:
    match = re.search(rf'^{re.escape(key)}:\s*["\']?([^"\'\r\n]+)', frontmatter, re.MULTILINE | re.I)
    return match.group(1).strip() if match else ""


def frontmatter_line_value(frontmatter: str, key: str) -> str:
    match = re.search(rf"^{re.escape(key)}:\s*(.*?)\s*$", frontmatter, re.MULTILINE | re.I)
    if not match:
        return ""
    value = match.group(1).strip()
    if value.startswith('"') and value.endswith('"'):
        try:
            value = str(json.loads(value))
        except json.JSONDecodeError:
            value = value.strip('"')
    else:
        value = value.strip("\"'")
    return re.sub(r"\s+", " ", value).strip()


def validate_markdown_recipes(
    content_dir: Path,
    failures: list[str],
) -> tuple[dict[str, int], dict[str, dict[str, str]]]:
    identities: dict[str, list[str]] = {}
    counts = {"files": 0, "cve": 0, "ghsa": 0}
    inventory: dict[str, dict[str, str]] = {}
    for path in sorted(content_dir.glob("*.md")):
        if path.name == "_index.md":
            continue
        counts["files"] += 1
        text = path.read_text(encoding="utf-8", errors="replace")
        match = FRONTMATTER_RE.match(text)
        if not match:
            fail(failures, f"Markdown recipe has no valid frontmatter: {path}")
            continue
        frontmatter = match.group("body")
        cve_value = frontmatter_value(frontmatter, "cve").upper()
        ghsa_value = frontmatter_value(frontmatter, "ghsa").upper()
        cve = CVE_RE.fullmatch(cve_value)
        ghsa = GHSA_RE.fullmatch(ghsa_value)
        if cve:
            identity = cve.group(0)
            counts["cve"] += 1
        elif ghsa:
            identity = ghsa.group(0)
            counts["ghsa"] += 1
        else:
            fail(failures, f"Markdown recipe has no canonical CVE/GHSA identity: {path}")
            continue
        relative_path = path.relative_to(ROOT).as_posix()
        identities.setdefault(identity, []).append(relative_path)

        for key in ("title", "severity", "ecosystem", "kev", "disclosed", "maturity"):
            if not frontmatter_value(frontmatter, key):
                fail(failures, f"{identity} is missing required frontmatter {key}: {path}")
        severity = frontmatter_value(frontmatter, "severity").lower()
        if severity not in {"critical", "high", "medium", "low"}:
            fail(failures, f"{identity} has invalid severity {severity!r}: {path}")
        maturity = frontmatter_value(frontmatter, "maturity").lower()
        if maturity not in {"development", "stable"}:
            fail(failures, f"{identity} has invalid maturity {maturity!r}: {path}")
        disclosed = frontmatter_value(frontmatter, "disclosed")
        try:
            date.fromisoformat(disclosed[:10])
        except ValueError:
            fail(failures, f"{identity} has invalid disclosed date {disclosed!r}: {path}")
        if not re.search(r"^(?:known_as|aliases):", frontmatter, re.MULTILINE | re.I):
            fail(failures, f"{identity} has neither known_as nor aliases: {path}")
        content_markdown = text[match.end() :].strip() if maturity == "stable" else ""
        if len(content_markdown.encode("utf-8")) > MAX_STABLE_MARKDOWN_BYTES:
            fail(failures, f"{identity} stable Markdown exceeds the {MAX_STABLE_MARKDOWN_BYTES}-byte limit")
        inventory[relative_path] = {
            "identity": identity,
            "title": frontmatter_line_value(frontmatter, "title"),
            "maturity": maturity,
            "content_markdown": content_markdown,
        }

    for identity, paths in identities.items():
        if len(paths) > 1:
            fail(failures, f"duplicate Markdown identity {identity}: {paths}")
    return counts, inventory


def validate_complete_index(
    catalog_dir: Path,
    index: dict[str, Any],
    manifest: dict[str, Any],
    failures: list[str],
) -> list[dict[str, Any]]:
    """Validate and combine the published-year compact index partitions."""
    expected_index_keys = {
        "schema_version",
        "catalog_updated_at",
        "total",
        "scope",
        "partition_key",
        "partitions",
    }
    if set(index) != expected_index_keys:
        fail(failures, "index does not match the required partition-manifest schema")
    if index.get("schema_version") != 2:
        fail(failures, "index schema_version must be 2")
    if index.get("scope") != manifest.get("scope"):
        fail(failures, "index scope does not match manifest scope")
    if index.get("catalog_updated_at") != manifest.get("catalog_updated_at"):
        fail(failures, "index catalog_updated_at does not match manifest")
    if index.get("partition_key") != "published_year":
        fail(failures, "index partition_key must be published_year")
    if "records" in index:
        fail(failures, "index must not embed the complete records array")

    raw_partitions = index.get("partitions")
    if not isinstance(raw_partitions, list):
        fail(failures, "index partitions must be an array")
        raw_partitions = []
    complete_index = manifest.get("complete_index")
    if not isinstance(complete_index, dict):
        fail(failures, "manifest complete_index is missing")
        complete_index = {}
    if complete_index.get("path") != "index.json":
        fail(failures, "manifest complete_index path must be index.json")
    if complete_index.get("format") != "published-year-partitions":
        fail(failures, "manifest complete_index format is invalid")
    if complete_index.get("partitions") != raw_partitions:
        fail(failures, "manifest complete_index partitions do not match index.json")

    declared_paths: set[str] = set()
    declared_years: set[str] = set()
    expected_years = set((manifest.get("by_publication_year") or {}).keys())
    records: list[dict[str, Any]] = []
    for position, entry in enumerate(raw_partitions):
        if not isinstance(entry, dict):
            fail(failures, f"index partition {position} must be an object")
            continue
        expected_entry_keys = {"year", "path", "records", "sha256", "bytes", "uncompressed_bytes"}
        if set(entry) != expected_entry_keys:
            fail(failures, f"index partition {position} metadata schema is invalid")
        year = str(entry.get("year") or "")
        relative = str(entry.get("path") or "")
        path_match = INDEX_PARTITION_PATH_RE.fullmatch(relative)
        if not re.fullmatch(r"\d{4}", year) or path_match is None or path_match.group(1) != year:
            fail(failures, f"index partition {position} has invalid year/path")
            continue
        if year in declared_years:
            fail(failures, f"duplicate complete-index publication year {year}")
        if relative in declared_paths:
            fail(failures, f"duplicate complete-index partition path {relative}")
        declared_years.add(year)
        declared_paths.add(relative)

        path = catalog_dir / relative
        if not path.is_file():
            fail(failures, f"missing complete-index partition: {relative}")
            continue
        payload = path.read_bytes()
        if len(payload) != entry.get("bytes"):
            fail(failures, f"complete-index compressed size mismatch: {relative}")
        if hashlib.sha256(payload).hexdigest() != entry.get("sha256"):
            fail(failures, f"complete-index hash mismatch: {relative}")
        if (
            len(payload) < 10
            or int.from_bytes(payload[4:8], "little") != 0
            or payload[9] != 3
        ):
            fail(failures, f"complete-index gzip header is not deterministic: {relative}")
        try:
            uncompressed = gzip.decompress(payload)
        except (OSError, EOFError) as exc:
            fail(failures, f"invalid complete-index gzip {relative}: {exc}")
            continue
        if len(uncompressed) != entry.get("uncompressed_bytes"):
            fail(failures, f"complete-index uncompressed size mismatch: {relative}")
        try:
            partition = json.loads(uncompressed)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            fail(failures, f"invalid complete-index JSON {relative}: {exc}")
            continue
        expected_keys = {"schema_version", "catalog_updated_at", "year", "total", "records"}
        if not isinstance(partition, dict) or set(partition) != expected_keys:
            fail(failures, f"complete-index partition schema is invalid: {relative}")
            continue
        if partition.get("schema_version") != 2:
            fail(failures, f"complete-index partition schema_version must be 2: {relative}")
        if partition.get("catalog_updated_at") != manifest.get("catalog_updated_at"):
            fail(failures, f"complete-index timestamp mismatch: {relative}")
        if str(partition.get("year") or "") != year:
            fail(failures, f"complete-index publication year mismatch: {relative}")
        partition_records = partition.get("records")
        if not isinstance(partition_records, list):
            fail(failures, f"complete-index records must be an array: {relative}")
            continue
        if partition.get("total") != len(partition_records) or entry.get("records") != len(partition_records):
            fail(failures, f"complete-index record count mismatch: {relative}")
        if not partition_records:
            fail(failures, f"complete-index partition must not be empty: {relative}")
        year_summary = (manifest.get("by_publication_year") or {}).get(year)
        if not isinstance(year_summary, dict) or year_summary.get("total") != len(partition_records):
            fail(failures, f"complete-index count does not match publication-year summary: {relative}")
        cve_ids: list[str] = []
        for record_number, record in enumerate(partition_records):
            if not isinstance(record, dict):
                fail(failures, f"complete-index record {record_number} is not an object: {relative}")
                continue
            if str(record.get("published") or "")[:4] != year:
                fail(failures, f"complete-index record is in the wrong publication-year partition: {relative}")
            cve_ids.append(str(record.get("cve") or ""))
            records.append(record)
        if cve_ids != sorted(cve_ids):
            fail(failures, f"complete-index partition records are not sorted by CVE ID: {relative}")

    indexes_dir = catalog_dir / "indexes"
    physical_paths = (
        {
            path.relative_to(catalog_dir).as_posix()
            for path in indexes_dir.rglob("*.json.gz")
            if path.is_file()
        }
        if indexes_dir.is_dir()
        else set()
    )
    if physical_paths != declared_paths:
        missing = sorted(declared_paths - physical_paths)
        orphaned = sorted(physical_paths - declared_paths)
        fail(
            failures,
            f"physical complete-index partition set does not match index: missing={missing[:10]}, orphaned={orphaned[:10]}",
        )
    if declared_years != expected_years:
        fail(failures, "complete-index years do not match manifest publication-year coverage")

    expected_total = len(records)
    if index.get("total") != expected_total:
        fail(failures, f"index total {index.get('total')} does not match {expected_total} partition records")
    if complete_index.get("records") != expected_total:
        fail(failures, "manifest complete_index record total does not match partitions")
    declared_total = sum(
        entry.get("records", 0)
        for entry in raw_partitions
        if isinstance(entry, dict) and type(entry.get("records")) is int
    )
    if declared_total != expected_total:
        fail(failures, "complete-index partition metadata totals do not match records")
    return sorted(records, key=lambda record: str(record.get("cve") or ""))


def validate_browser_index(
    catalog_dir: Path,
    manifest: dict[str, Any],
    index_records: list[dict[str, Any]],
    failures: list[str],
) -> int:
    entry = manifest.get("browser_index")
    if not isinstance(entry, dict):
        fail(failures, "manifest browser_index is missing")
        return 0
    relative = entry.get("path")
    if relative != "browser-index.json.gz":
        fail(failures, f"manifest browser_index has unexpected path {relative!r}")
        return 0
    path = catalog_dir / relative
    if not path.is_file():
        fail(failures, f"missing browser index: {relative}")
        return 0
    payload = path.read_bytes()
    if len(payload) != entry.get("bytes"):
        fail(failures, "browser index compressed size mismatch")
    if hashlib.sha256(payload).hexdigest() != entry.get("sha256"):
        fail(failures, "browser index hash mismatch")
    if (
        len(payload) < 10
        or int.from_bytes(payload[4:8], "little") != 0
        or payload[9] != 3
    ):
        fail(failures, "browser index gzip header is not deterministic")
    try:
        uncompressed = gzip.decompress(payload)
    except (OSError, EOFError) as exc:
        fail(failures, f"invalid browser index gzip: {exc}")
        return 0
    if len(uncompressed) != entry.get("uncompressed_bytes"):
        fail(failures, "browser index uncompressed size mismatch")
    try:
        browser = json.loads(uncompressed)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(failures, f"invalid browser index JSON: {exc}")
        return 0
    expected_keys = {
        "schema_version",
        "severity_codes",
        "fields",
        "ecosystems",
        "archetypes",
        "records",
    }
    if not isinstance(browser, dict) or set(browser) != expected_keys:
        fail(failures, "browser index does not match the required top-level schema")
        return 0
    if browser.get("schema_version") != 2:
        fail(failures, "browser index schema_version must be 2")
    if browser.get("severity_codes") != BROWSER_SEVERITY_NAMES:
        fail(failures, "browser index severity_codes are invalid")
    if browser.get("fields") != BROWSER_INDEX_FIELDS:
        fail(failures, "browser index fields do not match the required order")
    ecosystems = browser.get("ecosystems")
    archetypes = browser.get("archetypes")
    browser_records = browser.get("records")
    for label, dictionary in (("ecosystems", ecosystems), ("archetypes", archetypes)):
        if (
            not isinstance(dictionary, list)
            or any(not isinstance(value, str) or not value for value in dictionary)
            or dictionary != sorted(set(dictionary))
        ):
            fail(failures, f"browser index {label} dictionary is not sorted and unique")
    if not isinstance(ecosystems, list) or not isinstance(archetypes, list):
        return 0
    expected_ecosystems = sorted({str(record.get("ecosystem") or "") for record in index_records})
    expected_archetypes = sorted(
        {family for record in index_records for family in (record.get("archetypes") or [])}
    )
    if ecosystems != expected_ecosystems:
        fail(failures, "browser index ecosystem dictionary does not match index.json")
    if archetypes != expected_archetypes:
        fail(failures, "browser index archetype dictionary does not match index.json")
    if not isinstance(browser_records, list):
        fail(failures, "browser index records must be an array")
        return 0
    if len(browser_records) != len(index_records) or entry.get("records") != len(index_records):
        fail(failures, "browser index record count does not match index.json")
    for position, compact in enumerate(index_records):
        if position >= len(browser_records):
            break
        row = browser_records[position]
        if not isinstance(row, list) or len(row) != len(BROWSER_INDEX_FIELDS):
            fail(failures, f"browser index record {position} has invalid width")
            continue
        ecosystem_index = row[5]
        family_indexes = row[7]
        if type(row[2]) is not int or row[2] not in set(BROWSER_SEVERITY_CODES.values()):
            fail(failures, f"browser index record {position} has invalid numeric severity")
            continue
        if type(ecosystem_index) is not int or not 0 <= ecosystem_index < len(ecosystems):
            fail(failures, f"browser index record {position} has invalid ecosystem index")
            continue
        if (
            not isinstance(family_indexes, list)
            or any(type(value) is not int or not 0 <= value < len(archetypes) for value in family_indexes)
        ):
            fail(failures, f"browser index record {position} has invalid archetype indexes")
            continue
        if not isinstance(row[6], bool) or not isinstance(row[8], bool):
            fail(failures, f"browser index record {position} has non-boolean flags")
            continue
        compact_families = compact.get("archetypes") or []
        if compact.get("ecosystem") not in ecosystems or any(
            family not in archetypes for family in compact_families
        ):
            fail(failures, f"browser index dictionaries cannot decode index record {position}")
            continue
        expected = [
            compact.get("cve"),
            compact.get("title"),
            BROWSER_SEVERITY_CODES.get(str(compact.get("severity") or ""), -1),
            compact.get("score"),
            compact.get("published"),
            ecosystems.index(compact.get("ecosystem")),
            compact.get("kev"),
            [archetypes.index(family) for family in compact_families],
            compact.get("has_markdown"),
        ]
        if row != expected:
            fail(failures, f"browser index record {position} is not equivalent to index.json")
    return len(browser_records)


def validate_runtime_summary(
    catalog_dir: Path,
    manifest: dict[str, Any],
    failures: list[str],
) -> None:
    entry = manifest.get("runtime_summary")
    if not isinstance(entry, dict):
        fail(failures, "manifest runtime_summary is missing")
        return
    relative = entry.get("path")
    if relative != "runtime-summary.json":
        fail(failures, f"manifest runtime_summary has unexpected path {relative!r}")
        return
    path = catalog_dir / relative
    if not path.is_file():
        fail(failures, f"missing runtime summary: {relative}")
        return
    payload = path.read_bytes()
    if len(payload) != entry.get("bytes"):
        fail(failures, "runtime summary size mismatch")
    if hashlib.sha256(payload).hexdigest() != entry.get("sha256"):
        fail(failures, "runtime summary hash mismatch")
    try:
        summary = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(failures, f"invalid runtime summary JSON: {exc}")
        return

    scope = manifest.get("scope") or {}
    expected = {
        "schema_version": 2,
        "catalog_updated_at": manifest.get("catalog_updated_at"),
        "scope": {
            "published_start": scope.get("published_start"),
            "published_end": scope.get("published_end"),
        },
        "totals": manifest.get("totals"),
        "by_severity": manifest.get("by_severity"),
        "by_publication_year": manifest.get("by_publication_year"),
        "browser_index": manifest.get("browser_index"),
        "archetypes": manifest.get("archetypes_asset"),
        "shard_set_sha256": manifest.get("shard_set_sha256"),
    }
    if summary != expected:
        fail(failures, "runtime summary does not exactly match manifest runtime fields")


def validate_runtime_asset_versions(
    catalog_dir: Path,
    manifest: dict[str, Any],
    archetypes: dict[str, Any],
    shard_entries: list[dict[str, Any]],
    failures: list[str],
) -> None:
    archetypes_entry = manifest.get("archetypes_asset")
    if not isinstance(archetypes_entry, dict) or archetypes_entry.get("path") != "archetypes.json":
        fail(failures, "manifest archetypes_asset is missing or has an unexpected path")
    else:
        archetypes_path = catalog_dir / "archetypes.json"
        payload = archetypes_path.read_bytes() if archetypes_path.is_file() else b""
        if archetypes_entry.get("bytes") != len(payload):
            fail(failures, "archetypes asset size mismatch")
        if archetypes_entry.get("sha256") != hashlib.sha256(payload).hexdigest():
            fail(failures, "archetypes asset hash mismatch")

        definitions = archetypes.get("archetypes")
        definitions = definitions if isinstance(definitions, dict) else {}
        recipes = {
            str(archetype_id): {
                "agentic_actions": archetype.get("agentic_actions"),
                "instruction_sources": {
                    field: archetype.get(field) for field in ARCHETYPE_LIST_FIELDS
                },
            }
            for archetype_id, archetype in sorted(definitions.items())
            if isinstance(archetype, dict)
        }
        contract_payload = (
            json.dumps(
                {
                    "agentic_contract": archetypes.get("agentic_contract"),
                    "ecosystem_target_hints": archetypes.get("ecosystem_target_hints"),
                    "archetypes": recipes,
                },
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        metadata = archetypes_entry.get("agentic_contract")
        target_hints = archetypes.get("ecosystem_target_hints")
        expected_metadata = {
            "schema_version": 1,
            "sha256": hashlib.sha256(contract_payload).hexdigest(),
            "bytes": len(contract_payload),
            "archetypes": len(definitions),
            "actions": sum(
                len(archetype.get("agentic_actions") or [])
                for archetype in definitions.values()
                if isinstance(archetype, dict)
            ),
            "phases": len(AGENTIC_ACTION_ORDER),
            "ecosystems": len(target_hints) if isinstance(target_hints, dict) else 0,
            "target_hints": sum(
                1 for hint in (target_hints or {}).values() if isinstance(hint, dict)
            ) if isinstance(target_hints, dict) else 0,
        }
        if metadata != expected_metadata:
            fail(failures, "manifest agentic contract metadata does not match the shared contract")

    canonical_inventory = [
        {"path": str(entry.get("path") or ""), "sha256": str(entry.get("sha256") or "")}
        for entry in sorted(shard_entries, key=lambda value: str(value.get("path") or ""))
    ]
    inventory_payload = (
        json.dumps(canonical_inventory, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")
    expected_digest = hashlib.sha256(inventory_payload).hexdigest()
    actual_digest = manifest.get("shard_set_sha256")
    if not isinstance(actual_digest, str) or SHA256_RE.fullmatch(actual_digest) is None:
        fail(failures, "manifest shard_set_sha256 is invalid")
    elif actual_digest != expected_digest:
        fail(failures, "manifest shard_set_sha256 does not match the shard inventory")


def validate_source_completeness(
    manifest: dict[str, Any],
    end_date: date | None,
    catalog_records: int,
    failures: list[str],
) -> None:
    sources = manifest.get("sources")
    if not isinstance(sources, dict):
        fail(failures, "manifest sources must be an object")
        return

    nvd = sources.get("nvd")
    if not isinstance(nvd, dict):
        fail(failures, "manifest NVD source metadata is missing")
        feeds: list[Any] = []
    else:
        if nvd.get("feed_root") != NVD_FEED_ROOT:
            fail(failures, "manifest NVD feed_root is invalid")
        raw_feeds = nvd.get("feeds")
        if not isinstance(raw_feeds, list):
            fail(failures, "manifest NVD feeds must be an array")
            feeds = []
        else:
            feeds = raw_feeds

    years: list[int] = []
    accepted_total = 0
    for position, feed in enumerate(feeds):
        prefix = f"manifest NVD feed {position}"
        if not isinstance(feed, dict):
            fail(failures, f"{prefix} must be an object")
            continue
        year = feed.get("year")
        if type(year) is not int:
            fail(failures, f"{prefix} has invalid year")
        else:
            years.append(year)
            expected_url = f"{NVD_FEED_ROOT}/nvdcve-2.0-{year}.json.gz"
            if feed.get("url") != expected_url:
                fail(failures, f"{prefix} has invalid URL")

        accepted = feed.get("accepted_records")
        if type(accepted) is not int or accepted < 0:
            fail(failures, f"{prefix} has invalid accepted_records")
        else:
            accepted_total += accepted

        metadata = feed.get("metadata")
        if not isinstance(metadata, dict):
            fail(failures, f"{prefix} metadata must be an object")
            continue
        missing = [field for field in NVD_METADATA_FIELDS if field not in metadata]
        if missing:
            fail(failures, f"{prefix} metadata is missing required fields {missing}")
        if not valid_datetime(metadata.get("lastModifiedDate")):
            fail(failures, f"{prefix} metadata has invalid lastModifiedDate")
        for field in ("size", "zipSize", "gzSize"):
            if parse_nonnegative_integer(metadata.get(field)) is None:
                fail(failures, f"{prefix} metadata has invalid {field}")
        sha256 = metadata.get("sha256")
        if not isinstance(sha256, str) or SHA256_RE.fullmatch(sha256) is None:
            fail(failures, f"{prefix} metadata has invalid sha256")

    if len(years) != len(set(years)):
        fail(failures, "manifest NVD feed years are not unique")
    if end_date is not None:
        expected_years = list(range(2002, end_date.year + 1))
        if sorted(years) != expected_years:
            fail(failures, f"manifest NVD feed years must be exactly 2002..{end_date.year}")
    if accepted_total != catalog_records:
        fail(
            failures,
            f"manifest NVD accepted_records sum {accepted_total} does not match catalog_records {catalog_records}",
        )

    kev = sources.get("cisa_kev")
    if not isinstance(kev, dict):
        fail(failures, "manifest CISA KEV source metadata is missing")
        return
    if kev.get("url") != CISA_KEV_URL:
        fail(failures, "manifest CISA KEV URL is invalid")
    if not isinstance(kev.get("catalog_version"), str) or not kev["catalog_version"].strip():
        fail(failures, "manifest CISA KEV catalog_version is missing")
    if not valid_datetime(kev.get("date_released")):
        fail(failures, "manifest CISA KEV date_released is invalid")
    sha256 = kev.get("sha256")
    if not isinstance(sha256, str) or SHA256_RE.fullmatch(sha256) is None:
        fail(failures, "manifest CISA KEV sha256 is invalid")
    if type(kev.get("catalog_records")) is not int or kev["catalog_records"] < 0:
        fail(failures, "manifest CISA KEV catalog_records is invalid")


def validate(catalog_dir: Path, content_dir: Path = DEFAULT_CONTENT) -> dict[str, Any]:
    failures: list[str] = []
    warnings: list[str] = []
    if _is_link_or_junction(catalog_dir):
        fail(failures, f"catalog root must not be a link or junction: {catalog_dir}")
        return {"ok": False, "failures": failures, "warnings": warnings}
    index_path = catalog_dir / "index.json"
    manifest_path = catalog_dir / "manifest.json"
    archetype_path = catalog_dir / "archetypes.json"
    for path in (index_path, manifest_path, archetype_path):
        if _is_link_or_junction(path):
            fail(failures, f"required catalog file must not be a link or junction: {path}")
        elif not path.is_file():
            fail(failures, f"missing required catalog file: {path}")
    if failures:
        return {"ok": False, "failures": failures, "warnings": warnings}

    manifest = load_json(manifest_path)
    if not validate_physical_catalog_tree(catalog_dir, manifest, failures):
        return {"ok": False, "failures": failures, "warnings": warnings}
    index = load_json(index_path)
    archetypes = load_json(archetype_path)
    markdown_counts, markdown_inventory = validate_markdown_recipes(content_dir, failures)
    if manifest.get("schema_version") != 2:
        fail(failures, "manifest schema_version must be 2")
    if archetypes.get("schema_version") != 1:
        fail(failures, "archetype schema_version must be 1")

    archetype_ids = set((archetypes.get("archetypes") or {}).keys())
    valid_archetype_ids = valid_archetype_contracts(archetypes, failures)
    if archetypes.get("default_archetype") not in archetype_ids:
        fail(failures, "default_archetype is missing from archetypes")
    default_archetype = str(archetypes.get("default_archetype") or "")

    scope = manifest.get("scope") or {}
    scope_valid = True
    try:
        start_date = date.fromisoformat(scope["published_start"])
        end_date = date.fromisoformat(scope["published_end"])
    except (KeyError, TypeError, ValueError):
        fail(failures, "manifest has invalid publication scope")
        scope_valid = False
        start_date = date.min
        end_date = date.max
    if scope_valid and start_date != ten_year_cutoff(end_date):
        fail(failures, "manifest publication scope must span exactly 10 calendar years")
    if scope.get("statuses_excluded") != ["Reject", "Rejected"]:
        fail(failures, "manifest rejected-status policy is invalid")
    metric_policy = scope.get("metric_policy")
    if not isinstance(metric_policy, str) or "baseScore >= 4.0" not in metric_policy:
        fail(failures, "manifest metric policy must declare the CVSS 4.0 inclusion threshold")
    records = validate_complete_index(catalog_dir, index, manifest, failures)

    index_by_cve: dict[str, dict[str, Any]] = {}
    valid_composed_cves: set[str] = set()
    for position, record in enumerate(records):
        if not isinstance(record, dict):
            fail(failures, f"index record {position} is not an object")
            continue
        cve = str(record.get("cve") or "")
        if not CVE_RE.fullmatch(cve):
            fail(failures, f"index record {position} has invalid CVE ID: {cve!r}")
            continue
        if cve in index_by_cve:
            fail(failures, f"duplicate catalog identity: {cve}")
        index_by_cve[cve] = record
        title = str(record.get("title") or "").strip()
        if not title:
            fail(failures, f"{cve} has an empty title")
        elif title.casefold() == FORBIDDEN_GENERIC_TITLE:
            fail(failures, f"{cve} uses the forbidden generic affected-product title")
        if record.get("severity") not in {"medium", "high", "critical"}:
            fail(failures, f"{cve} has out-of-scope severity {record.get('severity')!r}")
        try:
            if float(record.get("score")) < 4.0:
                fail(failures, f"{cve} has score below 4.0")
        except (TypeError, ValueError):
            fail(failures, f"{cve} has invalid score")
        try:
            published = date.fromisoformat(str(record.get("published")))
            if not start_date <= published <= end_date:
                fail(failures, f"{cve} is outside the publication window")
        except ValueError:
            fail(failures, f"{cve} has invalid publication date")
        if record.get("shard") != expected_shard(cve):
            fail(failures, f"{cve} points to the wrong shard: {record.get('shard')!r}")
        if record.get("archetype") not in archetype_ids:
            fail(failures, f"{cve} references unknown archetype {record.get('archetype')!r}")
        families = record.get("archetypes")
        composition_valid = True
        if (
            not isinstance(families, list)
            or not families
            or any(not isinstance(family, str) or not family for family in families)
        ):
            fail(failures, f"{cve} has invalid archetypes list")
            composition_valid = False
            families = []
        elif len(families) != len(set(families)):
            fail(failures, f"{cve} has duplicate archetype families")
            composition_valid = False
        if families:
            if record.get("archetype") != families[0]:
                fail(failures, f"{cve} primary archetype is not the first composed family")
                composition_valid = False
            if families != ordered_archetypes(families):
                fail(failures, f"{cve} archetypes are not in deterministic risk order")
                composition_valid = False
            if default_archetype in families and families != [default_archetype]:
                fail(failures, f"{cve} mixes the generic archetype with specific families")
                composition_valid = False
            unknown = [family for family in families if family not in archetype_ids]
            invalid = [family for family in families if family not in valid_archetype_ids]
            if unknown:
                fail(failures, f"{cve} references unknown composed archetypes {unknown}")
                composition_valid = False
            if invalid:
                fail(failures, f"{cve} references archetypes with invalid contracts {invalid}")
                composition_valid = False
        if not isinstance(record.get("has_markdown"), bool):
            fail(failures, f"{cve} has non-boolean has_markdown")
        if composition_valid:
            valid_composed_cves.add(cve)

    if list(index_by_cve) != sorted(index_by_cve):
        fail(failures, "index records are not sorted by CVE ID")

    raw_shard_entries = manifest.get("shard_manifest")
    if not isinstance(raw_shard_entries, list):
        fail(failures, "manifest shard_manifest must be an array")
        shard_entries: list[dict[str, Any]] = []
    else:
        shard_entries = []
        for position, entry in enumerate(raw_shard_entries):
            if not isinstance(entry, dict):
                fail(failures, f"manifest shard entry {position} must be an object")
                continue
            shard_entries.append(entry)

    manifest_shard_paths: list[str] = []
    for position, entry in enumerate(shard_entries):
        relative = entry.get("path")
        if not valid_shard_path(relative):
            fail(failures, f"manifest shard entry {position} has invalid path {relative!r}")
            continue
        manifest_shard_paths.append(relative)
    if len(manifest_shard_paths) != len(set(manifest_shard_paths)):
        fail(failures, "manifest shard paths are not unique")
    manifest_shard_path_set = set(manifest_shard_paths)
    validate_runtime_asset_versions(catalog_dir, manifest, archetypes, shard_entries, failures)
    shards_dir = catalog_dir / "shards"
    physical_shard_paths = (
        {
            path.relative_to(catalog_dir).as_posix()
            for path in shards_dir.rglob("*.jsonl.gz")
            if path.is_file()
        }
        if shards_dir.is_dir()
        else set()
    )
    if physical_shard_paths != manifest_shard_path_set:
        missing = sorted(manifest_shard_path_set - physical_shard_paths)
        orphaned = sorted(physical_shard_paths - manifest_shard_path_set)
        fail(
            failures,
            f"physical shard set does not match manifest: missing={missing[:10]}, orphaned={orphaned[:10]}",
        )

    shard_ids: set[str] = set()
    shard_count = 0
    authoritative_markdown = 0
    markdown_drafts = 0
    markdown_pages = 0
    ai_enriched = 0
    ai_enrichment_complete = 0
    ai_enrichment_insufficient = 0
    catalog_markdown_paths: set[str] = set()
    for entry in shard_entries:
        relative = entry.get("path")
        if not valid_shard_path(relative):
            continue
        path = catalog_dir / relative
        if not path.is_file():
            fail(failures, f"missing shard: {relative}")
            continue
        payload = path.read_bytes()
        if len(payload) != entry.get("bytes"):
            fail(failures, f"shard compressed size mismatch: {relative}")
        digest = hashlib.sha256(payload).hexdigest()
        if digest != entry.get("sha256"):
            fail(failures, f"shard hash mismatch: {relative}")
        if (
            len(payload) < 10
            or int.from_bytes(payload[4:8], "little") != 0
            or payload[9] != 3
        ):
            fail(failures, f"shard gzip header is not deterministic: {relative}")
        try:
            uncompressed = gzip.decompress(payload)
        except (OSError, EOFError) as exc:
            fail(failures, f"invalid gzip shard {relative}: {exc}")
            continue
        if len(uncompressed) != entry.get("uncompressed_bytes"):
            fail(failures, f"shard uncompressed size mismatch: {relative}")
        lines = uncompressed.splitlines()
        if len(lines) != entry.get("records"):
            fail(failures, f"shard count mismatch: {relative}")
        shard_count += len(lines)
        for line_number, line in enumerate(lines, 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                fail(failures, f"invalid JSON in {relative}:{line_number}: {exc}")
                continue
            cve = str(record.get("cve") or "")
            if cve in shard_ids:
                fail(failures, f"duplicate CVE across shards: {cve}")
            shard_ids.add(cve)
            compact = index_by_cve.get(cve)
            if compact is None:
                fail(failures, f"shard contains CVE absent from index: {cve}")
                continue
            if compact.get("shard") != relative:
                fail(failures, f"index/shard path mismatch for {cve}")
            for field in (
                "title",
                "severity",
                "score",
                "published",
                "ecosystem",
                "kev",
                "archetype",
                "archetypes",
            ):
                if record.get(field) != compact.get(field):
                    fail(failures, f"index/shard {field} mismatch for {cve}")
            recipe_kind = record.get("recipe_kind")
            if recipe_kind not in {"composed", "markdown-draft", "markdown-override"}:
                fail(failures, f"{cve} has invalid recipe_kind")
            markdown = record.get("markdown")
            if not isinstance(markdown, list):
                fail(failures, f"{cve} markdown metadata is not an array")
                markdown = []
            markdown_pages += len(markdown)
            stable_entries = 0
            markdown_paths: set[str] = set()
            for override in markdown:
                if not isinstance(override, dict):
                    fail(failures, f"{cve} has a non-object Markdown entry")
                    continue
                override_path = str(override.get("path") or "")
                source_markdown: dict[str, str] | None = None
                if not is_safe_relative_path(override.get("path")):
                    fail(failures, f"{cve} has an unsafe Markdown path {override.get('path')!r}")
                elif override_path in markdown_paths:
                    fail(failures, f"{cve} repeats Markdown path {override_path!r}")
                else:
                    markdown_paths.add(override_path)
                    catalog_markdown_paths.add(override_path)
                    source_markdown = markdown_inventory.get(override_path)
                    if source_markdown is None:
                        fail(failures, f"{cve} catalog Markdown path is missing from current content: {override_path}")
                if override.get("cve") != cve:
                    fail(failures, f"{cve} Markdown metadata has mismatched identity {override.get('cve')!r}")
                if not isinstance(override.get("title"), str) or not override["title"].strip():
                    fail(failures, f"{cve} has a Markdown entry without a title")
                maturity = override.get("maturity")
                if not isinstance(maturity, str) or not maturity.strip():
                    fail(failures, f"{cve} has a Markdown entry without maturity")
                elif maturity not in {"development", "stable"}:
                    fail(failures, f"{cve} has a Markdown entry with invalid maturity {maturity!r}")
                if source_markdown is not None:
                    if source_markdown.get("identity") != cve:
                        fail(failures, f"{cve} catalog Markdown identity is stale for {override_path}")
                    if source_markdown.get("title") != override.get("title"):
                        fail(failures, f"{cve} catalog Markdown title is stale for {override_path}")
                    if source_markdown.get("maturity") != maturity:
                        fail(failures, f"{cve} catalog Markdown maturity is stale for {override_path}")
                if maturity == "stable":
                    stable_entries += 1
                    content = override.get("content_markdown")
                    if not isinstance(content, str) or not content.strip():
                        fail(failures, f"{cve} stable override has empty content_markdown")
                    elif content.lstrip().startswith("---"):
                        fail(failures, f"{cve} stable override content_markdown still contains frontmatter")
                    elif len(content.encode("utf-8")) > MAX_STABLE_MARKDOWN_BYTES:
                        fail(failures, f"{cve} stable override exceeds the Markdown size limit")
                    elif source_markdown is not None and source_markdown.get("content_markdown") != content:
                        fail(failures, f"{cve} stable override content_markdown is stale for {override_path}")
                elif "content_markdown" in override:
                    fail(failures, f"{cve} non-stable Markdown unexpectedly embeds content_markdown")
            expected_has_markdown = recipe_kind == "markdown-override"
            if compact.get("has_markdown") is not expected_has_markdown:
                fail(failures, f"{cve} has_markdown does not match authoritative stable override state")
            if recipe_kind == "composed" and markdown:
                fail(failures, f"{cve} composed record unexpectedly declares Markdown pages")
            elif recipe_kind == "markdown-draft":
                markdown_drafts += 1
                if not markdown or stable_entries:
                    fail(failures, f"{cve} markdown-draft state is inconsistent")
            elif recipe_kind == "markdown-override":
                authoritative_markdown += 1
                if stable_entries == 0:
                    fail(failures, f"{cve} declares an override without stable embedded content")
            if not record.get("summary"):
                fail(failures, f"{cve} has no source summary")
            if record.get("nvd_url") != f"https://nvd.nist.gov/vuln/detail/{cve}":
                fail(failures, f"{cve} has invalid NVD URL")
            products = record.get("products")
            if not isinstance(products, list):
                fail(failures, f"{cve} products must be an array")
                products = []
            products_stored = record.get("products_stored")
            product_match_count = record.get("product_match_count")
            products_truncated = record.get("products_truncated")
            if type(products_stored) is not int or products_stored != len(products):
                fail(failures, f"{cve} products_stored does not match the stored products array")
            elif products_stored > 12:
                fail(failures, f"{cve} stores more than the 12-product cap")
            if type(product_match_count) is not int or product_match_count < len(products):
                fail(failures, f"{cve} has invalid product_match_count")
            if not isinstance(products_truncated, bool):
                fail(failures, f"{cve} has non-boolean products_truncated")
            elif type(product_match_count) is int and type(products_stored) is int:
                if products_truncated is not (product_match_count > products_stored):
                    fail(failures, f"{cve} products_truncated is inconsistent with product counts")
            metric_scores = []
            for metric in record.get("metrics") or []:
                try:
                    metric_scores.append(float(metric.get("score")))
                except (TypeError, ValueError):
                    pass
            if not any(score >= 4.0 for score in metric_scores):
                fail(failures, f"{cve} lacks a stored Medium/High/Critical metric observation")
            if record.get("kev") and not record.get("kev_details"):
                fail(failures, f"{cve} is marked KEV without KEV provenance")
            enrichment = record.get("ai_enrichment")
            if enrichment is not None:
                ai_enriched += 1
                for error in enrichment_errors(enrichment, record):
                    fail(failures, f"{cve} {error}")
                if isinstance(enrichment, dict):
                    ai_enrichment_complete += int(enrichment.get("status") == "complete")
                    ai_enrichment_insufficient += int(enrichment.get("status") == "insufficient_evidence")

    if shard_ids != set(index_by_cve):
        missing = sorted(set(index_by_cve) - shard_ids)
        extra = sorted(shard_ids - set(index_by_cve))
        fail(failures, f"index/shard identity mismatch: missing={missing[:10]}, extra={extra[:10]}")

    expected_markdown_paths = {
        path
        for path, metadata in markdown_inventory.items()
        if metadata.get("identity") in index_by_cve
    }
    if catalog_markdown_paths != expected_markdown_paths:
        missing = sorted(expected_markdown_paths - catalog_markdown_paths)
        stale = sorted(catalog_markdown_paths - expected_markdown_paths)
        fail(
            failures,
            f"catalog Markdown inventory is stale: missing={missing[:10]}, stale={stale[:10]}",
        )

    browser_records = validate_browser_index(
        catalog_dir,
        manifest,
        [record for record in records if isinstance(record, dict)],
        failures,
    )
    validate_runtime_summary(catalog_dir, manifest, failures)

    totals = manifest.get("totals") or {}
    expected_total = len(index_by_cve)
    if type(totals.get("catalog_records")) is not int or totals.get("catalog_records") != expected_total:
        fail(failures, "manifest catalog_records does not match index")
    validate_source_completeness(
        manifest,
        end_date if scope_valid else None,
        expected_total,
        failures,
    )
    valid_composed_total = len(valid_composed_cves)
    expected_coverage_percent = round(valid_composed_total * 100.0 / expected_total, 6) if expected_total else 0.0
    if totals.get("composed_recipe_coverage") != valid_composed_total:
        fail(failures, "manifest composed_recipe_coverage does not match valid archetype compositions")
    if totals.get("coverage_percent") != expected_coverage_percent:
        fail(failures, "manifest coverage_percent is not exact")
    if totals.get("agentic_recipe_coverage") != valid_composed_total:
        fail(failures, "manifest agentic_recipe_coverage does not match valid agentic compositions")
    if totals.get("agentic_coverage_percent") != expected_coverage_percent:
        fail(failures, "manifest agentic_coverage_percent is not exact")
    if totals.get("shards") != len(shard_entries):
        fail(failures, "manifest shard total does not match shard_manifest")
    if shard_count != expected_total:
        fail(failures, "physical shard record count does not match index")
    if totals.get("markdown_overrides") != authoritative_markdown:
        fail(failures, "manifest authoritative Markdown override count does not match shards")
    if totals.get("stable_markdown_overrides") != authoritative_markdown:
        fail(failures, "manifest stable Markdown override count does not match shards")
    if totals.get("markdown_drafts") != markdown_drafts:
        fail(failures, "manifest Markdown draft count does not match shards")
    if totals.get("markdown_pages") != markdown_pages:
        fail(failures, "manifest Markdown page count does not match shards")
    if totals.get("ai_enriched_records") != ai_enriched:
        fail(failures, "manifest AI-enriched record count does not match shards")
    if totals.get("ai_enrichment_complete") != ai_enrichment_complete:
        fail(failures, "manifest complete AI-enrichment count does not match shards")
    if totals.get("ai_enrichment_insufficient_evidence") != ai_enrichment_insufficient:
        fail(failures, "manifest insufficient AI-enrichment count does not match shards")

    calculated_severity = Counter(record.get("severity") for record in records)
    if dict(sorted(calculated_severity.items())) != manifest.get("by_severity"):
        fail(failures, "manifest severity counts do not match index")

    duplicate_markdown = manifest.get("markdown_duplicate_ids") or {}
    if duplicate_markdown:
        fail(failures, f"{len(duplicate_markdown)} canonical CVE IDs have duplicate Markdown overrides")

    return {
        "ok": not failures,
        "catalog_records": expected_total,
        "shards": len(shard_entries),
        "browser_records": browser_records,
        "archetypes": len(archetype_ids),
        "agentic": {
            "records": valid_composed_total,
            "coverage_percent": expected_coverage_percent,
            "actions": sum(
                len(archetype.get("agentic_actions") or [])
                for archetype in (archetypes.get("archetypes") or {}).values()
                if isinstance(archetype, dict)
            ),
            "phases": len(AGENTIC_ACTION_ORDER),
            "ecosystems": len(archetypes.get("ecosystem_target_hints") or {}),
        },
        "markdown": markdown_counts,
        "ai_enrichment": {
            "records": ai_enriched,
            "complete": ai_enrichment_complete,
            "insufficient_evidence": ai_enrichment_insufficient,
        },
        "failures": failures,
        "warnings": warnings,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog-dir", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--content-dir", type=Path, default=DEFAULT_CONTENT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    catalog_dir = args.catalog_dir if args.catalog_dir.is_absolute() else ROOT / args.catalog_dir
    content_dir = args.content_dir if args.content_dir.is_absolute() else ROOT / args.content_dir
    result = validate(catalog_dir, content_dir)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
