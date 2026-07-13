"""Executable, bounded lifecycle support for remediation playbooks.

This module deliberately does not mutate a target workspace.  It inventories
files selected by a playbook, creates an explicit run packet, records hashes of
operator-provided evidence, and verifies that evidence later.  File contents
are never copied into a run packet.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import tempfile
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PLAYBOOK_REGISTRY = REPO_ROOT / "data" / "remediation_suite" / "playbooks.json"
RUN_SCHEMA_VERSION = "1.0"
RUN_KIND = "security-recipes.playbook-run"
EVIDENCE_KIND = "security-recipes.playbook-evidence"
INSPECTION_KIND = "security-recipes.workspace-inspection"
DEFAULT_MAX_FILES = 500
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_ENTRIES = 50_000
MAX_SKIPPED_DETAILS = 200
RUN_CONTROL_ARTIFACTS = frozenset({"run.json", "PLAN.md", "AGENT_TASK.md", "evidence.json"})
IGNORED_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "dist",
        "build",
        ".next",
        "coverage",
        "tmp",
        "__pycache__",
    }
)
CONDITIONALLY_IGNORED_DIRECTORY_NAMES = frozenset({".security-recipes", "public"})
ALLOWED_EVIDENCE_KINDS = frozenset(
    {
        "approval",
        "artifact",
        "attestation",
        "finding",
        "log",
        "policy",
        "report",
        "review",
        "scanner",
        "test",
        "other",
    }
)
PLAYBOOK_ID_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class PlaybookError(ValueError):
    """Raised when registry data, paths, or run artifacts are invalid."""


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _stable_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def profile_sha256(playbook: dict[str, Any]) -> str:
    """Return a deterministic hash for one registry profile."""

    return _sha256_bytes(_canonical_json(playbook))


def _require_string(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise PlaybookError(f"{label} must be a non-empty string")
    return text


def _require_string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise PlaybookError(f"{label} must be a non-empty list")
    result = [_require_string(item, f"{label} item") for item in value]
    if len(set(result)) != len(result):
        raise PlaybookError(f"{label} must not contain duplicates")
    return result


def _require_nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PlaybookError(f"{label} must be a non-negative integer")
    return value


def _require_uuid(value: Any, label: str) -> str:
    text = _require_string(value, label)
    try:
        parsed = uuid.UUID(text)
    except ValueError as exc:
        raise PlaybookError(f"{label} must be a UUID") from exc
    if str(parsed) != text.lower():
        raise PlaybookError(f"{label} must be a canonical UUID")
    return text


def _require_timestamp(value: Any, label: str) -> str:
    text = _require_string(value, label)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PlaybookError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise PlaybookError(f"{label} must include a timezone")
    return text


def _validate_pattern(pattern: str, label: str) -> None:
    normalized = pattern.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[a-zA-Z]:/", normalized):
        raise PlaybookError(f"{label} must be relative: {pattern}")
    if ".." in PurePosixPath(normalized).parts:
        raise PlaybookError(f"{label} must not traverse parent directories: {pattern}")


def validate_playbook_registry(registry: dict[str, Any]) -> dict[str, Any]:
    """Validate and return a playbook registry."""

    if not isinstance(registry, dict):
        raise PlaybookError("playbook registry root must be an object")
    _require_string(registry.get("schema_version"), "registry.schema_version")
    _require_string(registry.get("suite_version"), "registry.suite_version")
    playbooks = registry.get("playbooks")
    if not isinstance(playbooks, list) or not playbooks:
        raise PlaybookError("registry.playbooks must be a non-empty list")

    seen: set[str] = set()
    for index, playbook in enumerate(playbooks):
        prefix = f"registry.playbooks[{index}]"
        if not isinstance(playbook, dict):
            raise PlaybookError(f"{prefix} must be an object")
        playbook_id = _require_string(playbook.get("id"), f"{prefix}.id")
        if not PLAYBOOK_ID_PATTERN.fullmatch(playbook_id):
            raise PlaybookError(f"{prefix}.id is not a canonical slug: {playbook_id}")
        if playbook_id in seen:
            raise PlaybookError(f"duplicate playbook id: {playbook_id}")
        seen.add(playbook_id)
        for field in ("title", "page", "category", "summary"):
            _require_string(playbook.get(field), f"{prefix}.{field}")
        if not str(playbook["page"]).startswith("/security-remediation/"):
            raise PlaybookError(f"{prefix}.page must be a remediation page")

        phases = playbook.get("phases")
        if not isinstance(phases, list) or len(phases) < 3:
            raise PlaybookError(f"{prefix}.phases must contain at least three phases")
        for phase_index, phase in enumerate(phases):
            if not isinstance(phase, dict):
                raise PlaybookError(f"{prefix}.phases[{phase_index}] must be an object")
            for field in ("label", "title", "detail"):
                _require_string(phase.get(field), f"{prefix}.phases[{phase_index}].{field}")

        gate = playbook.get("gate")
        if not isinstance(gate, dict):
            raise PlaybookError(f"{prefix}.gate must be an object")
        for field in ("question", "pass", "stop"):
            _require_string(gate.get(field), f"{prefix}.gate.{field}")

        for field in ("evidence", "outputs", "file_patterns", "recipe_queries"):
            values = _require_string_list(playbook.get(field), f"{prefix}.{field}")
            if field == "file_patterns":
                for pattern in values:
                    _validate_pattern(pattern, f"{prefix}.file_patterns")

        python = playbook.get("python")
        if not isinstance(python, dict):
            raise PlaybookError(f"{prefix}.python must be an object")
        _require_string(python.get("scenario"), f"{prefix}.python.scenario")
        command = _require_string(python.get("command"), f"{prefix}.python.command")
        required_fragments = (
            " playbook start ",
            f"--playbook {playbook_id}",
            "--workspace",
            "--finding",
            "--run-dir",
        )
        if any(fragment not in f" {command} " for fragment in required_fragments):
            raise PlaybookError(f"{prefix}.python.command does not use the canonical start interface")
    return registry


def load_playbook_registry(path: str | Path | None = None) -> dict[str, Any]:
    registry_path = Path(path) if path else DEFAULT_PLAYBOOK_REGISTRY
    try:
        payload = json.loads(registry_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PlaybookError(f"playbook registry does not exist: {registry_path}") from exc
    except json.JSONDecodeError as exc:
        raise PlaybookError(f"playbook registry is invalid JSON: {exc}") from exc
    return validate_playbook_registry(payload)


def playbook_by_id(registry: dict[str, Any], playbook_id: str) -> dict[str, Any]:
    wanted = _require_string(playbook_id, "playbook id").lower()
    for playbook in registry.get("playbooks", []):
        if str(playbook.get("id", "")).lower() == wanted:
            return playbook
    available = ", ".join(sorted(str(item["id"]) for item in registry.get("playbooks", [])))
    raise PlaybookError(f"unknown playbook '{playbook_id}'. Available: {available}")


def _expand_braces(pattern: str) -> list[str]:
    """Expand simple comma-separated brace alternatives recursively."""

    start = pattern.find("{")
    if start < 0:
        return [pattern]
    end = pattern.find("}", start + 1)
    if end < 0:
        raise PlaybookError(f"unclosed brace expression in file pattern: {pattern}")
    choices = pattern[start + 1 : end].split(",")
    if not choices or any(not choice for choice in choices):
        raise PlaybookError(f"empty brace alternative in file pattern: {pattern}")
    expanded: list[str] = []
    for choice in choices:
        expanded.extend(_expand_braces(pattern[:start] + choice + pattern[end + 1 :]))
    return expanded


def expand_file_patterns(patterns: Iterable[str]) -> list[str]:
    expanded: list[str] = []
    for pattern in patterns:
        _validate_pattern(pattern, "file pattern")
        expanded.extend(_expand_braces(pattern.replace("\\", "/")))
    return list(dict.fromkeys(expanded))


def _matches_pattern(path: str, pattern: str) -> bool:
    # Python's fnmatch treats ``**/*`` as requiring another slash.  Globstar
    # semantics allow zero directories, so include its collapsed equivalent.
    candidates = {pattern}
    pending = [pattern]
    while pending:
        candidate = pending.pop()
        if "/**/*" in candidate:
            collapsed = candidate.replace("/**/*", "/**", 1)
            if collapsed not in candidates:
                candidates.add(collapsed)
                pending.append(collapsed)
    for candidate in candidates:
        if fnmatch.fnmatchcase(path, candidate):
            return True
        if candidate.startswith("**/") and fnmatch.fnmatchcase(path, candidate[3:]):
            return True
        if candidate.endswith("/**"):
            prefix = candidate[:-3].rstrip("/")
            if path == prefix or path.startswith(prefix + "/"):
                return True
    return False


def _explicit_pattern_enters_directory(relative: str, patterns: Iterable[str]) -> bool:
    """Allow an otherwise ignored root only when a profile names it directly."""

    prefix = relative.rstrip("/") + "/"
    for pattern in patterns:
        if pattern.startswith("**/"):
            continue
        wildcard_positions = [position for marker in "*?[" if (position := pattern.find(marker)) >= 0]
        literal_prefix = pattern[: min(wildcard_positions)] if wildcard_positions else pattern
        if pattern == relative or pattern.startswith(prefix) or (literal_prefix and prefix.startswith(literal_prefix)):
            return True
    return False


def _is_link(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction and is_junction())


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _workspace_root(workspace: str | Path) -> Path:
    supplied = Path(workspace)
    if _is_link(supplied):
        raise PlaybookError(f"workspace root must not be a symlink or junction: {workspace}")
    try:
        root = supplied.resolve(strict=True)
    except FileNotFoundError as exc:
        raise PlaybookError(f"workspace does not exist: {workspace}") from exc
    if not root.is_dir():
        raise PlaybookError(f"workspace is not a directory: {workspace}")
    return root


def _assert_no_link_components(path: Path, root: Path) -> None:
    if not _inside(path, root):
        raise PlaybookError(f"path is outside workspace: {path}")
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        if current.exists() and _is_link(current):
            raise PlaybookError(f"symlink and junction paths are not allowed: {current}")


def _existing_file_inside(workspace: Path, value: str | Path) -> tuple[Path, str]:
    supplied = Path(value)
    candidate = supplied if supplied.is_absolute() else workspace / supplied
    lexical = Path(os.path.abspath(candidate))
    _assert_no_link_components(lexical, workspace)
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise PlaybookError(f"file does not exist: {value}") from exc
    if not _inside(resolved, workspace):
        raise PlaybookError(f"file is outside workspace: {value}")
    if not resolved.is_file() or _is_link(candidate):
        raise PlaybookError(f"path is not a regular non-link file: {value}")
    return resolved, resolved.relative_to(workspace).as_posix()


def _hash_file(path: Path, *, max_bytes: int) -> dict[str, Any]:
    before = path.stat()
    if before.st_size > max_bytes:
        raise PlaybookError(f"file exceeds {max_bytes} byte limit: {path}")
    digest = hashlib.sha256()
    read_bytes = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(min(1024 * 1024, max_bytes + 1 - read_bytes))
            if not chunk:
                break
            read_bytes += len(chunk)
            if read_bytes > max_bytes:
                raise PlaybookError(f"file exceeds {max_bytes} byte limit: {path}")
            digest.update(chunk)
    after = path.stat()
    if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
        raise PlaybookError(f"file changed while it was being hashed: {path}")
    return {
        "size": after.st_size,
        "modified_ns": after.st_mtime_ns,
        "sha256": digest.hexdigest(),
    }


def inspect_workspace(
    *,
    playbook: dict[str, Any],
    workspace: str | Path,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_entries: int = DEFAULT_MAX_ENTRIES,
) -> dict[str, Any]:
    """Return a bounded, hash-only inventory selected by a playbook."""

    limits = {
        "max_files": int(max_files),
        "max_file_bytes": int(max_file_bytes),
        "max_total_bytes": int(max_total_bytes),
        "max_entries": int(max_entries),
    }
    if any(value <= 0 for value in limits.values()):
        raise PlaybookError("inspection limits must be positive integers")

    root = _workspace_root(workspace)
    patterns = expand_file_patterns(_require_string_list(playbook.get("file_patterns"), "playbook.file_patterns"))
    has_unanchored_patterns = any(pattern.startswith("**/") for pattern in patterns)
    files: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    skipped_counts: dict[str, int] = {}
    visited_entries = 0
    visited_files = 0
    total_bytes = 0
    truncated = False

    def note_skip(relative: str, reason: str) -> None:
        skipped_counts[reason] = skipped_counts.get(reason, 0) + 1
        if len(skipped) < MAX_SKIPPED_DETAILS:
            skipped.append({"path": relative, "reason": reason})

    stop = False
    for current_root, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_root)
        retained_dirs: list[str] = []
        for dirname in sorted(dirnames):
            visited_entries += 1
            if visited_entries > limits["max_entries"]:
                truncated = True
                stop = True
                break
            directory = current / dirname
            relative = directory.relative_to(root).as_posix()
            inside_conditional_root = any(
                part in CONDITIONALLY_IGNORED_DIRECTORY_NAMES for part in PurePosixPath(relative).parts[:-1]
            )
            if dirname in IGNORED_DIRECTORY_NAMES or (
                dirname in CONDITIONALLY_IGNORED_DIRECTORY_NAMES
                and not _explicit_pattern_enters_directory(relative, patterns)
            ):
                note_skip(relative, "ignored_directory")
            elif inside_conditional_root and not _explicit_pattern_enters_directory(relative, patterns):
                note_skip(relative, "unselected_directory")
            elif not has_unanchored_patterns and not _explicit_pattern_enters_directory(relative, patterns):
                note_skip(relative, "unselected_directory")
            elif _is_link(directory):
                note_skip(relative, "link_directory")
            else:
                retained_dirs.append(dirname)
        dirnames[:] = retained_dirs
        if stop:
            break

        for filename in sorted(filenames):
            visited_entries += 1
            if visited_entries > limits["max_entries"]:
                truncated = True
                stop = True
                break
            visited_files += 1
            path = current / filename
            relative = path.relative_to(root).as_posix()
            if _is_link(path):
                note_skip(relative, "link_file")
                continue
            if not any(_matches_pattern(relative, pattern) for pattern in patterns):
                continue
            if len(files) >= limits["max_files"]:
                truncated = True
                stop = True
                break
            try:
                stat = path.stat()
            except OSError:
                note_skip(relative, "unreadable")
                continue
            if stat.st_size > limits["max_file_bytes"]:
                note_skip(relative, "file_size_limit")
                continue
            if total_bytes + stat.st_size > limits["max_total_bytes"]:
                note_skip(relative, "total_size_limit")
                truncated = True
                stop = True
                break
            try:
                metadata = _hash_file(path, max_bytes=limits["max_file_bytes"])
            except (OSError, PlaybookError):
                note_skip(relative, "unreadable_or_changed")
                continue
            files.append({"path": relative, **metadata})
            total_bytes += int(metadata["size"])
        if stop:
            break

    return {
        "schema_version": RUN_SCHEMA_VERSION,
        "kind": INSPECTION_KIND,
        "playbook_id": playbook["id"],
        "workspace": str(root),
        "patterns": patterns,
        "limits": limits,
        "summary": {
            "visited_entry_count": min(visited_entries, limits["max_entries"]),
            "visited_file_count": visited_files,
            "matched_file_count": len(files),
            "matched_total_bytes": total_bytes,
            "skipped_counts": dict(sorted(skipped_counts.items())),
            "truncated": truncated,
        },
        "files": files,
        "skipped": skipped,
    }


def _new_run_path(workspace: Path, run_dir: str | Path) -> Path:
    supplied = Path(run_dir)
    candidate = supplied if supplied.is_absolute() else workspace / supplied
    candidate = Path(os.path.abspath(candidate))
    if not _inside(candidate, workspace) or candidate == workspace:
        raise PlaybookError(f"run directory must be a child of the workspace: {run_dir}")
    _assert_no_link_components(candidate.parent, workspace)
    if candidate.exists():
        raise PlaybookError(f"run directory already exists: {candidate}")
    candidate.parent.mkdir(parents=True, exist_ok=True)
    _assert_no_link_components(candidate.parent, workspace)
    if not _inside(candidate.parent.resolve(strict=True), workspace):
        raise PlaybookError(f"run directory parent resolves outside workspace: {run_dir}")
    return candidate


def _render_plan(playbook: dict[str, Any], finding: dict[str, Any], inspection: dict[str, Any]) -> str:
    lines = [
        f"# {playbook['title']} plan",
        "",
        f"Finding: `{finding['path']}` (`{finding['sha256']}`)",
        f"Matched workspace files: **{inspection['summary']['matched_file_count']}**",
        "",
        "## Workflow",
        "",
    ]
    for index, phase in enumerate(playbook["phases"], 1):
        lines.extend([f"{index}. **{phase['label']} - {phase['title']}**: {phase['detail']}"])
    lines.extend(
        [
            "",
            "## Decision gate",
            "",
            f"- Question: {playbook['gate']['question']}",
            f"- Continue: {playbook['gate']['pass']}",
            f"- Stop: {playbook['gate']['stop']}",
            "",
            "## Required evidence",
            "",
            *[f"- [ ] {item}" for item in playbook["evidence"]],
            "",
            "## Expected outputs",
            "",
            *[f"- {item}" for item in playbook["outputs"]],
            "",
        ]
    )
    return "\n".join(lines)


def _render_agent_task(playbook: dict[str, Any], finding: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"# Agent task: {playbook['title']}",
            "",
            playbook["summary"],
            "",
            "## Bounded input",
            "",
            f"- Finding metadata file: `{finding['path']}`",
            f"- Finding SHA-256: `{finding['sha256']}`",
            f"- Playbook: `{playbook['id']}`",
            "",
            "## Operating contract",
            "",
            "- Treat the inspected file patterns as discovery hints, not blanket write authorization.",
            "- Work on one finding and keep production, credentials, external writes, and destructive actions out of scope.",
            "- Stop when the decision gate fails; produce a triage note instead of broadening scope.",
            "- Record tests, scans, approvals, and other proof with `playbook record`.",
            "- Do not claim completion until `playbook verify` returns a complete result.",
            "",
            "## Stop condition",
            "",
            playbook["gate"]["stop"],
            "",
        ]
    )


def _write_text(path: Path, text: str) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())


def start_run(
    *,
    registry: dict[str, Any],
    playbook_id: str,
    workspace: str | Path,
    finding: str | Path,
    run_dir: str | Path,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_entries: int = DEFAULT_MAX_ENTRIES,
) -> dict[str, Any]:
    """Atomically create a new playbook run directory."""

    validate_playbook_registry(registry)
    playbook = playbook_by_id(registry, playbook_id)
    root = _workspace_root(workspace)
    finding_path, finding_relative = _existing_file_inside(root, finding)
    finding_metadata = {"path": finding_relative, **_hash_file(finding_path, max_bytes=max_file_bytes)}
    inspection = inspect_workspace(
        playbook=playbook,
        workspace=root,
        max_files=max_files,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
        max_entries=max_entries,
    )
    destination = _new_run_path(root, run_dir)
    run_id = str(uuid.uuid4())
    run = {
        "schema_version": RUN_SCHEMA_VERSION,
        "kind": RUN_KIND,
        "run_id": run_id,
        "created_at": _utc_now(),
        "status": "planned",
        "registry": {
            "schema_version": registry["schema_version"],
            "suite_version": registry["suite_version"],
        },
        "playbook": {
            "id": playbook["id"],
            "title": playbook["title"],
            "page": playbook["page"],
            "category": playbook["category"],
            "profile_sha256": profile_sha256(playbook),
        },
        "workspace": {"root": str(root), "inspection": inspection},
        "finding": finding_metadata,
        "required_evidence": list(playbook["evidence"]),
        "allowed_evidence_kinds": sorted(ALLOWED_EVIDENCE_KINDS),
        "expected_outputs": list(playbook["outputs"]),
    }
    evidence = {
        "schema_version": RUN_SCHEMA_VERSION,
        "kind": EVIDENCE_KIND,
        "run_id": run_id,
        "items": [],
    }

    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent))
    try:
        _write_text(temporary / "run.json", _stable_json(run))
        _write_text(temporary / "PLAN.md", _render_plan(playbook, finding_metadata, inspection))
        _write_text(temporary / "AGENT_TASK.md", _render_agent_task(playbook, finding_metadata))
        _write_text(temporary / "evidence.json", _stable_json(evidence))
        os.replace(temporary, destination)
    except Exception:
        if temporary.exists():
            for child in temporary.iterdir():
                if child.is_file():
                    child.unlink()
            temporary.rmdir()
        raise

    return {
        "run_dir": str(destination),
        "run_id": run_id,
        "playbook_id": playbook["id"],
        "artifacts": ["run.json", "PLAN.md", "AGENT_TASK.md", "evidence.json"],
        "inspection": inspection["summary"],
    }


def _load_json_object(path: Path, label: str, *, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> dict[str, Any]:
    if not path.exists() or not path.is_file() or _is_link(path):
        raise PlaybookError(f"{label} is missing or not a regular file: {path}")
    if path.stat().st_size > max_bytes:
        raise PlaybookError(f"{label} exceeds {max_bytes} bytes: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PlaybookError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise PlaybookError(f"{label} root must be an object")
    return payload


def _load_run(run_dir: str | Path) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    supplied = Path(run_dir)
    if _is_link(supplied):
        raise PlaybookError(f"run directory must not be a symlink or junction: {run_dir}")
    try:
        root = supplied.resolve(strict=True)
    except FileNotFoundError as exc:
        raise PlaybookError(f"run directory does not exist: {run_dir}") from exc
    if not root.is_dir():
        raise PlaybookError(f"run directory is not a directory: {run_dir}")
    run = _load_json_object(root / "run.json", "run manifest")
    evidence = _load_json_object(root / "evidence.json", "evidence index")
    return root, run, evidence


def _validate_run_location(run_root: Path, supplied_run_dir: str | Path, workspace: Path) -> None:
    lexical = Path(os.path.abspath(Path(supplied_run_dir)))
    _assert_no_link_components(lexical, workspace)
    try:
        resolved = lexical.resolve(strict=True)
    except FileNotFoundError as exc:
        raise PlaybookError(f"run directory does not exist: {supplied_run_dir}") from exc
    if resolved != run_root:
        raise PlaybookError("run directory resolves through an unexpected path")
    for name in RUN_CONTROL_ARTIFACTS:
        artifact = run_root / name
        if not artifact.exists() or not artifact.is_file() or _is_link(artifact):
            raise PlaybookError(f"required run artifact is missing or not a regular file: {name}")


def _validate_inspection_schema(inspection: Any, *, playbook_id: str, workspace_root: str) -> None:
    if not isinstance(inspection, dict):
        raise PlaybookError("run.workspace.inspection must be an object")
    if inspection.get("schema_version") != RUN_SCHEMA_VERSION or inspection.get("kind") != INSPECTION_KIND:
        raise PlaybookError("workspace inspection schema or kind is invalid")
    if inspection.get("playbook_id") != playbook_id:
        raise PlaybookError("workspace inspection playbook_id does not match run.playbook.id")
    if inspection.get("workspace") != workspace_root:
        raise PlaybookError("workspace inspection root does not match run.workspace.root")
    _require_string_list(inspection.get("patterns"), "run.workspace.inspection.patterns")

    limits = inspection.get("limits")
    if not isinstance(limits, dict):
        raise PlaybookError("run.workspace.inspection.limits must be an object")
    for name in ("max_files", "max_file_bytes", "max_total_bytes", "max_entries"):
        if _require_nonnegative_int(limits.get(name), f"run.workspace.inspection.limits.{name}") <= 0:
            raise PlaybookError(f"run.workspace.inspection.limits.{name} must be positive")

    summary = inspection.get("summary")
    if not isinstance(summary, dict):
        raise PlaybookError("run.workspace.inspection.summary must be an object")
    for name in ("visited_entry_count", "visited_file_count", "matched_file_count", "matched_total_bytes"):
        _require_nonnegative_int(summary.get(name), f"run.workspace.inspection.summary.{name}")
    if not isinstance(summary.get("truncated"), bool):
        raise PlaybookError("run.workspace.inspection.summary.truncated must be a boolean")
    skipped_counts = summary.get("skipped_counts")
    if not isinstance(skipped_counts, dict) or not all(
        isinstance(key, str) and key and isinstance(value, int) and not isinstance(value, bool) and value >= 0
        for key, value in skipped_counts.items()
    ):
        raise PlaybookError("run.workspace.inspection.summary.skipped_counts is invalid")

    files = inspection.get("files")
    if not isinstance(files, list):
        raise PlaybookError("run.workspace.inspection.files must be a list")
    seen_paths: set[str] = set()
    for index, item in enumerate(files):
        prefix = f"run.workspace.inspection.files[{index}]"
        if not isinstance(item, dict) or not _valid_relative_path(item.get("path")):
            raise PlaybookError(f"{prefix}.path is invalid")
        relative = str(item["path"])
        if relative in seen_paths:
            raise PlaybookError(f"{prefix}.path is duplicated")
        seen_paths.add(relative)
        if not SHA256_PATTERN.fullmatch(str(item.get("sha256") or "")):
            raise PlaybookError(f"{prefix}.sha256 is invalid")
        _require_nonnegative_int(item.get("size"), f"{prefix}.size")
        _require_nonnegative_int(item.get("modified_ns"), f"{prefix}.modified_ns")
    if summary["matched_file_count"] != len(files):
        raise PlaybookError("workspace inspection matched_file_count does not match files")
    if summary["matched_total_bytes"] != sum(int(item["size"]) for item in files):
        raise PlaybookError("workspace inspection matched_total_bytes does not match files")
    if len(files) > limits["max_files"] or summary["matched_total_bytes"] > limits["max_total_bytes"]:
        raise PlaybookError("workspace inspection exceeds its recorded limits")
    if summary["visited_entry_count"] > limits["max_entries"]:
        raise PlaybookError("workspace inspection visited_entry_count exceeds its recorded limit")

    skipped = inspection.get("skipped")
    if not isinstance(skipped, list):
        raise PlaybookError("run.workspace.inspection.skipped must be a list")
    for index, item in enumerate(skipped):
        prefix = f"run.workspace.inspection.skipped[{index}]"
        if not isinstance(item, dict) or not _valid_relative_path(item.get("path")):
            raise PlaybookError(f"{prefix}.path is invalid")
        _require_string(item.get("reason"), f"{prefix}.reason")


def _validate_evidence_item_schema(item: Any, *, index: int) -> str:
    prefix = f"evidence.items[{index}]"
    if not isinstance(item, dict):
        raise PlaybookError(f"{prefix} must be an object")
    evidence_id = _require_uuid(item.get("evidence_id"), f"{prefix}.evidence_id")
    if str(item.get("kind") or "") not in ALLOWED_EVIDENCE_KINDS:
        raise PlaybookError(f"{prefix}.kind is unsupported")
    _require_string(item.get("label"), f"{prefix}.label")
    if not _valid_relative_path(item.get("path")):
        raise PlaybookError(f"{prefix}.path is invalid")
    requirements = item.get("requirements")
    if not isinstance(requirements, list) or not all(isinstance(value, str) and value.strip() for value in requirements):
        raise PlaybookError(f"{prefix}.requirements must be a string list")
    if len(requirements) != len(set(requirements)):
        raise PlaybookError(f"{prefix}.requirements must not contain duplicates")
    _require_timestamp(item.get("recorded_at"), f"{prefix}.recorded_at")
    if not SHA256_PATTERN.fullmatch(str(item.get("sha256") or "")):
        raise PlaybookError(f"{prefix}.sha256 is invalid")
    _require_nonnegative_int(item.get("size"), f"{prefix}.size")
    _require_nonnegative_int(item.get("modified_ns"), f"{prefix}.modified_ns")
    return evidence_id


def _validate_run_headers(run: dict[str, Any], evidence: dict[str, Any]) -> None:
    if run.get("schema_version") != RUN_SCHEMA_VERSION or run.get("kind") != RUN_KIND:
        raise PlaybookError("run manifest schema or kind is invalid")
    run_id = _require_uuid(run.get("run_id"), "run.run_id")
    _require_timestamp(run.get("created_at"), "run.created_at")
    if run.get("status") != "planned":
        raise PlaybookError("run.status must be 'planned'")

    registry = run.get("registry")
    if not isinstance(registry, dict):
        raise PlaybookError("run.registry must be an object")
    _require_string(registry.get("schema_version"), "run.registry.schema_version")
    _require_string(registry.get("suite_version"), "run.registry.suite_version")

    playbook = run.get("playbook")
    if not isinstance(playbook, dict):
        raise PlaybookError("run.playbook must be an object")
    for name in ("id", "title", "page", "category"):
        _require_string(playbook.get(name), f"run.playbook.{name}")
    if not SHA256_PATTERN.fullmatch(str(playbook.get("profile_sha256") or "")):
        raise PlaybookError("run.playbook.profile_sha256 is invalid")

    workspace = run.get("workspace")
    if not isinstance(workspace, dict):
        raise PlaybookError("run.workspace must be an object")
    workspace_root = _require_string(workspace.get("root"), "run.workspace.root")
    _validate_inspection_schema(
        workspace.get("inspection"),
        playbook_id=str(playbook["id"]),
        workspace_root=workspace_root,
    )

    finding = run.get("finding")
    if not isinstance(finding, dict) or not _valid_relative_path(finding.get("path")):
        raise PlaybookError("run.finding.path is invalid")
    if not SHA256_PATTERN.fullmatch(str(finding.get("sha256") or "")):
        raise PlaybookError("run.finding.sha256 is invalid")
    _require_nonnegative_int(finding.get("size"), "run.finding.size")
    _require_nonnegative_int(finding.get("modified_ns"), "run.finding.modified_ns")
    _require_string_list(run.get("required_evidence"), "run.required_evidence")
    _require_string_list(run.get("expected_outputs"), "run.expected_outputs")
    if run.get("allowed_evidence_kinds") != sorted(ALLOWED_EVIDENCE_KINDS):
        raise PlaybookError("run.allowed_evidence_kinds does not match the supported evidence kinds")

    if evidence.get("schema_version") != RUN_SCHEMA_VERSION or evidence.get("kind") != EVIDENCE_KIND:
        raise PlaybookError("evidence index schema or kind is invalid")
    if evidence.get("run_id") != run_id:
        raise PlaybookError("evidence index run_id does not match run manifest")
    items = evidence.get("items")
    if not isinstance(items, list):
        raise PlaybookError("evidence.items must be a list")
    evidence_ids = [_validate_evidence_item_schema(item, index=index) for index, item in enumerate(items)]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise PlaybookError("evidence.items contains duplicate evidence_id values")


def _atomic_replace_json(path: Path, payload: dict[str, Any]) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(_stable_json(payload))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def record_evidence(
    *,
    run_dir: str | Path,
    evidence_file: str | Path,
    kind: str,
    requirements: Iterable[str] | None = None,
    label: str | None = None,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> dict[str, Any]:
    """Record relative metadata and a hash for evidence without copying it."""

    run_root, run, evidence = _load_run(run_dir)
    _validate_run_headers(run, evidence)
    evidence_kind = _require_string(kind, "evidence kind").lower()
    if evidence_kind not in ALLOWED_EVIDENCE_KINDS:
        allowed = ", ".join(sorted(ALLOWED_EVIDENCE_KINDS))
        raise PlaybookError(f"unsupported evidence kind '{kind}'. Allowed: {allowed}")

    workspace = _workspace_root(str(run["workspace"]["root"]))
    if not _inside(run_root, workspace):
        raise PlaybookError("run directory is outside the workspace recorded by the run")
    _validate_run_location(run_root, run_dir, workspace)
    path, relative = _existing_file_inside(workspace, evidence_file)
    if path in {run_root / name for name in RUN_CONTROL_ARTIFACTS}:
        raise PlaybookError("run control artifacts cannot be recorded as evidence")

    required = _require_string_list(run.get("required_evidence"), "run.required_evidence")
    selected_requirements = [str(item).strip() for item in (requirements or []) if str(item).strip()]
    unknown = sorted(set(selected_requirements) - set(required))
    if unknown:
        raise PlaybookError(f"evidence references unknown requirements: {', '.join(unknown)}")
    metadata = _hash_file(path, max_bytes=max_file_bytes)
    item = {
        "evidence_id": str(uuid.uuid4()),
        "kind": evidence_kind,
        "label": str(label or path.name).strip() or path.name,
        "path": relative,
        "requirements": list(dict.fromkeys(selected_requirements)),
        "recorded_at": _utc_now(),
        **metadata,
    }
    evidence["items"].append(item)
    _atomic_replace_json(run_root / "evidence.json", evidence)
    return item


def _valid_relative_path(value: Any) -> bool:
    text = str(value or "").replace("\\", "/")
    if not text or text.startswith("/") or re.match(r"^[a-zA-Z]:/", text):
        return False
    return ".." not in PurePosixPath(text).parts


def verify_run(
    *,
    run_dir: str | Path,
    registry: dict[str, Any],
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> dict[str, Any]:
    """Verify run schemas, profile identity, evidence kinds, and hashes."""

    issues: list[str] = []
    missing_requirements: list[str] = []
    try:
        validate_playbook_registry(registry)
        run_root, run, evidence = _load_run(run_dir)
        _validate_run_headers(run, evidence)
    except PlaybookError as exc:
        return {"valid": False, "complete": False, "issues": [str(exc)], "missing_requirements": []}

    playbook_summary = run.get("playbook")
    if not isinstance(playbook_summary, dict):
        issues.append("run.playbook must be an object")
        playbook_summary = {}
    try:
        playbook = playbook_by_id(registry, str(playbook_summary.get("id") or ""))
        expected_profile_hash = profile_sha256(playbook)
        if playbook_summary.get("profile_sha256") != expected_profile_hash:
            issues.append("playbook profile hash does not match the current registry")
        for name in ("id", "title", "page", "category"):
            if playbook_summary.get(name) != playbook.get(name):
                issues.append(f"run.playbook.{name} does not match the current registry")
        run_registry = run["registry"]
        for name in ("schema_version", "suite_version"):
            if run_registry.get(name) != registry.get(name):
                issues.append(f"run.registry.{name} does not match the current registry")
        inspection_patterns = run["workspace"]["inspection"]["patterns"]
        if inspection_patterns != expand_file_patterns(playbook["file_patterns"]):
            issues.append("workspace inspection patterns do not match the current playbook profile")
        if run.get("expected_outputs") != playbook.get("outputs"):
            issues.append("run expected outputs do not match the current playbook profile")
    except PlaybookError as exc:
        issues.append(str(exc))
        playbook = None

    workspace_value = str(run["workspace"]["root"])
    try:
        workspace = _workspace_root(workspace_value)
        if not _inside(run_root, workspace):
            issues.append("run directory is outside the recorded workspace")
        else:
            _validate_run_location(run_root, run_dir, workspace)
    except PlaybookError as exc:
        issues.append(str(exc))
        workspace = None

    if workspace is not None:
        finding = run.get("finding")
        if not isinstance(finding, dict) or not _valid_relative_path(finding.get("path")):
            issues.append("finding metadata path is invalid")
        else:
            try:
                finding_path, _ = _existing_file_inside(workspace, str(finding["path"]))
                actual = _hash_file(finding_path, max_bytes=max_file_bytes)
                if finding.get("sha256") != actual["sha256"] or finding.get("size") != actual["size"]:
                    issues.append("finding file hash or size no longer matches the run manifest")
            except PlaybookError as exc:
                issues.append(f"finding verification failed: {exc}")

    required = run.get("required_evidence")
    if not isinstance(required, list) or not all(isinstance(item, str) and item.strip() for item in required):
        issues.append("run.required_evidence must be a list of non-empty strings")
        required = []
    satisfied: set[str] = set()
    verified_count = 0
    for index, item in enumerate(evidence.get("items", [])):
        prefix = f"evidence.items[{index}]"
        if not isinstance(item, dict):
            issues.append(f"{prefix} must be an object")
            continue
        kind = str(item.get("kind") or "")
        if kind not in ALLOWED_EVIDENCE_KINDS:
            issues.append(f"{prefix}.kind is unsupported: {kind}")
        relative = item.get("path")
        if not _valid_relative_path(relative):
            issues.append(f"{prefix}.path is invalid")
            continue
        digest = str(item.get("sha256") or "")
        if not SHA256_PATTERN.fullmatch(digest):
            issues.append(f"{prefix}.sha256 is invalid")
            continue
        requirements = item.get("requirements")
        if not isinstance(requirements, list) or not all(isinstance(value, str) for value in requirements):
            issues.append(f"{prefix}.requirements must be a string list")
            requirements = []
        unknown = sorted(set(requirements) - set(required))
        if unknown:
            issues.append(f"{prefix} references unknown requirements: {', '.join(unknown)}")
        if workspace is None:
            continue
        try:
            evidence_path, _ = _existing_file_inside(workspace, str(relative))
            if evidence_path in {run_root / name for name in RUN_CONTROL_ARTIFACTS}:
                issues.append(f"{prefix} references a run control artifact")
                continue
            actual = _hash_file(evidence_path, max_bytes=max_file_bytes)
            if item.get("sha256") != actual["sha256"] or item.get("size") != actual["size"]:
                issues.append(f"{prefix} hash or size does not match {relative}")
                continue
        except PlaybookError as exc:
            issues.append(f"{prefix} verification failed: {exc}")
            continue
        verified_count += 1
        satisfied.update(requirements)

    if playbook is not None and list(required) != list(playbook.get("evidence", [])):
        issues.append("run evidence requirements do not match the current playbook profile")
    missing_requirements = [item for item in required if item not in satisfied]
    valid = not issues
    return {
        "valid": valid,
        "complete": valid and not missing_requirements,
        "run_id": run.get("run_id"),
        "playbook_id": playbook_summary.get("id"),
        "verified_evidence_count": verified_count,
        "required_evidence_count": len(required),
        "missing_requirements": missing_requirements,
        "issues": issues,
    }


__all__ = [
    "ALLOWED_EVIDENCE_KINDS",
    "DEFAULT_MAX_ENTRIES",
    "DEFAULT_MAX_FILES",
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_TOTAL_BYTES",
    "DEFAULT_PLAYBOOK_REGISTRY",
    "PlaybookError",
    "expand_file_patterns",
    "inspect_workspace",
    "load_playbook_registry",
    "playbook_by_id",
    "profile_sha256",
    "record_evidence",
    "start_run",
    "validate_playbook_registry",
    "verify_run",
]
