#!/usr/bin/env python3
"""Regenerate or verify every deterministic evidence generator in dependency order.

The dependency graph comes from the checked-in artifacts themselves: a generator
depends on another generator only when its output contains a ``path``/``sha256``
record for the other generator's output.  Human-readable links therefore remain
useful documentation without accidentally becoming content-hash dependencies.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_GLOB = "generate_*.py"
ADDITIONAL_GENERATOR_SCRIPTS = ("validate_workflow_control_plane.py",)
OWNERSHIP_MANIFEST = Path("scripts/generated-output-ownership.json")
OWNERSHIP_SCHEMA_VERSION = 1
EXCLUSIVE_GENERATED_ROOTS = (Path("data/evidence"),)


class PipelineError(RuntimeError):
    """Raised when the generator inventory or dependency graph is invalid."""


@dataclass(frozen=True, order=True)
class Generator:
    """One deterministic generator and its checked-in output artifact."""

    name: str
    script: Path
    output: Path


def _path_call_value(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "Path":
        return None
    if len(node.args) != 1 or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
        return None
    return node.args[0].value


def _generator_metadata(script: Path, repo_root: Path) -> Generator | None:
    source = script.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(script))
    supports_check = any(isinstance(node, ast.Constant) and node.value == "--check" for node in ast.walk(tree))
    if not supports_check:
        return None

    output_value: str | None = None
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == "DEFAULT_OUTPUT" for target in targets):
            continue
        output_value = _path_call_value(node.value)
        break
    if not output_value:
        raise PipelineError(f"{script.relative_to(repo_root)} supports --check but has no literal DEFAULT_OUTPUT")

    return Generator(
        name=script.stem.removeprefix("generate_"),
        script=script.relative_to(repo_root),
        output=Path(output_value),
    )


def discover_generators(repo_root: Path = REPO_ROOT) -> list[Generator]:
    """Return the complete, deterministic ``--check`` generator inventory."""

    scripts = set((repo_root / "scripts").glob(GENERATOR_GLOB))
    scripts.update(
        path
        for name in ADDITIONAL_GENERATOR_SCRIPTS
        if (path := repo_root / "scripts" / name).is_file()
    )
    generators = [
        generator
        for script in sorted(scripts)
        if (generator := _generator_metadata(script, repo_root)) is not None
    ]
    if not generators:
        raise PipelineError("no --check-capable generators were discovered")

    outputs: dict[str, str] = {}
    for generator in generators:
        output = generator.output.as_posix()
        _safe_repo_path(output, repo_root)
        if output in outputs:
            raise PipelineError(f"duplicate generator output {output}: {outputs[output]} and {generator.name}")
        outputs[output] = generator.name
    return generators


def _safe_repo_path(value: str | Path, repo_root: Path) -> Path:
    """Resolve one repository-relative path without allowing link escapes."""

    relative = Path(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise PipelineError(f"generated path must stay repository-relative: {relative.as_posix()}")
    root = repo_root.resolve()
    candidate = root / relative
    try:
        candidate.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise PipelineError(f"generated path resolves outside the repository: {relative.as_posix()}") from exc
    return candidate


def ownership_payload(generators: list[Generator]) -> dict[str, Any]:
    """Return the deterministic producer ledger for all checked-in outputs."""

    return {
        "schema_version": OWNERSHIP_SCHEMA_VERSION,
        "owner": "scripts/run_generator_pipeline.py",
        "exclusive_generated_roots": [path.as_posix() for path in EXCLUSIVE_GENERATED_ROOTS],
        "artifacts": [
            {
                "generator": generator.name,
                "script": generator.script.as_posix(),
                "path": generator.output.as_posix(),
            }
            for generator in sorted(generators)
        ],
    }


def _load_ownership_manifest(repo_root: Path, *, required: bool) -> tuple[dict[str, Any] | None, set[str]]:
    path = repo_root / OWNERSHIP_MANIFEST
    if not path.is_file():
        if required:
            raise PipelineError(
                f"missing generated-output ownership manifest: {OWNERSHIP_MANIFEST.as_posix()}; run --write"
            )
        return None, set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PipelineError(f"invalid ownership manifest {OWNERSHIP_MANIFEST.as_posix()}: {exc}") from exc
    if not isinstance(payload, dict):
        raise PipelineError("generated-output ownership manifest root must be an object")
    if payload.get("schema_version") != OWNERSHIP_SCHEMA_VERSION:
        raise PipelineError("generated-output ownership manifest schema_version is unsupported")
    if payload.get("owner") != "scripts/run_generator_pipeline.py":
        raise PipelineError("generated-output ownership manifest owner is invalid")
    roots = payload.get("exclusive_generated_roots")
    if not isinstance(roots, list) or not all(isinstance(root, str) and root for root in roots):
        raise PipelineError("generated-output ownership manifest roots are invalid")
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        raise PipelineError("generated-output ownership manifest artifacts must be an array")
    owned: set[str] = set()
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict) or set(artifact) != {"generator", "script", "path"}:
            raise PipelineError(f"ownership artifact {index} has an invalid schema")
        if not all(isinstance(artifact.get(field), str) and artifact[field] for field in artifact):
            raise PipelineError(f"ownership artifact {index} has an empty field")
        normalized = Path(artifact["path"]).as_posix()
        _safe_repo_path(normalized, repo_root)
        if normalized in owned:
            raise PipelineError(f"ownership manifest repeats artifact path: {normalized}")
        owned.add(normalized)
    return payload, owned


def _files_under(relative_root: Path, repo_root: Path) -> set[str]:
    root = _safe_repo_path(relative_root, repo_root)
    if not root.exists():
        return set()
    return {
        path.relative_to(repo_root).as_posix()
        for path in root.rglob("*")
        if path.is_file() or path.is_symlink()
    }


def validate_ownership(generators: list[Generator], repo_root: Path = REPO_ROOT) -> int:
    """Require the producer ledger and exclusive roots to match the live inventory exactly."""

    payload, owned = _load_ownership_manifest(repo_root, required=True)
    expected = ownership_payload(generators)
    if payload != expected:
        expected_paths = {generator.output.as_posix() for generator in generators}
        raise PipelineError(
            "generated-output ownership manifest is stale: "
            f"missing={sorted(expected_paths - owned)[:10]}, retired={sorted(owned - expected_paths)[:10]}; run --write"
        )
    expected_paths = {generator.output.as_posix() for generator in generators}
    for root in EXCLUSIVE_GENERATED_ROOTS:
        physical = _files_under(root, repo_root)
        declared = {path for path in expected_paths if Path(path).is_relative_to(root)}
        if physical != declared:
            raise PipelineError(
                f"exclusive generated root {root.as_posix()} is not reconciled: "
                f"missing={sorted(declared - physical)[:10]}, orphaned={sorted(physical - declared)[:10]}"
            )
    return len(expected_paths)


def _write_ownership_manifest(generators: list[Generator], repo_root: Path) -> None:
    path = repo_root / OWNERSHIP_MANIFEST
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(ownership_payload(generators), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(rendered, encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def _remove_owned_outputs(paths: set[str], repo_root: Path) -> list[str]:
    removed: list[str] = []
    for relative in sorted(paths):
        path = _safe_repo_path(relative, repo_root)
        if path.is_symlink() or path.is_file():
            path.unlink()
            removed.append(relative)
            parent = path.parent
            while parent != repo_root and parent != repo_root.resolve():
                try:
                    parent.rmdir()
                except OSError:
                    break
                parent = parent.parent
    return removed


def _hash_paths(value: Any) -> Iterable[str]:
    """Yield paths backed by explicit content hashes in a generated artifact."""

    if isinstance(value, dict):
        path = value.get("path")
        digest = value.get("sha256")
        if isinstance(path, str) and isinstance(digest, str) and len(digest) == 64:
            yield Path(path).as_posix()
        for child in value.values():
            yield from _hash_paths(child)
    elif isinstance(value, list):
        for child in value:
            yield from _hash_paths(child)


def _hash_references(value: Any, *, location: str = "$") -> Iterable[tuple[str, str, str]]:
    if isinstance(value, dict):
        path = value.get("path")
        digest = value.get("sha256")
        if isinstance(path, str) and isinstance(digest, str) and len(digest) == 64:
            yield Path(path).as_posix(), digest.lower(), location
        for key, child in value.items():
            yield from _hash_references(child, location=f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _hash_references(child, location=f"{location}[{index}]")


def validate_hashed_references(
    generators: list[Generator],
    repo_root: Path = REPO_ROOT,
    *,
    forbidden_paths: set[str] | None = None,
    allow_missing_outputs: bool = False,
) -> int:
    """Validate every explicit path/SHA-256 reference, not only DAG edges."""

    forbidden = {Path(path).as_posix() for path in (forbidden_paths or set())}
    digest_cache: dict[str, str] = {}
    failures: list[str] = []
    count = 0
    for generator in generators:
        output_path = repo_root / generator.output
        if allow_missing_outputs and not output_path.exists():
            continue
        try:
            payload = json.loads(output_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise PipelineError(f"missing generated artifact: {generator.output.as_posix()}") from exc
        except json.JSONDecodeError as exc:
            raise PipelineError(f"invalid JSON generated artifact {generator.output.as_posix()}: {exc}") from exc
        for relative, expected_digest, location in _hash_references(payload):
            count += 1
            label = f"{generator.output.as_posix()}:{location}"
            try:
                referenced = _safe_repo_path(relative, repo_root)
            except PipelineError as exc:
                failures.append(f"{label}: {exc}")
                continue
            if relative in forbidden:
                failures.append(f"{label}: references retired or unowned artifact {relative}")
                continue
            if referenced.is_symlink() or not referenced.is_file():
                failures.append(f"{label}: referenced file is missing or not a regular file: {relative}")
                continue
            actual_digest = digest_cache.get(relative)
            if actual_digest is None:
                canonical = referenced.read_bytes().replace(b"\r\n", b"\n")
                actual_digest = hashlib.sha256(canonical).hexdigest()
                digest_cache[relative] = actual_digest
            if actual_digest != expected_digest:
                failures.append(
                    f"{label}: SHA-256 mismatch for {relative}: expected {expected_digest}, got {actual_digest}"
                )
    if failures:
        raise PipelineError("invalid generated path/hash references:\n- " + "\n- ".join(failures[:50]))
    return count


def _is_mcp_tool_decorator(node: ast.expr) -> bool:
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return False
    return isinstance(node.func.value, ast.Name) and node.func.value.id == "mcp" and node.func.attr == "tool"


def registered_mcp_tools(repo_root: Path = REPO_ROOT) -> set[str]:
    """Return the tool names actually registered by ``mcp_server.py``."""

    server_path = repo_root / "mcp_server.py"
    tree = ast.parse(server_path.read_text(encoding="utf-8"), filename=str(server_path))
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("recipes_")
        and any(_is_mcp_tool_decorator(decorator) for decorator in node.decorator_list)
    }


def configured_mcp_data_paths(repo_root: Path = REPO_ROOT) -> set[str]:
    """Return repository data files named by ``ServerConfig`` defaults."""

    server_path = repo_root / "mcp_server.py"
    tree = ast.parse(server_path.read_text(encoding="utf-8"), filename=str(server_path))
    server_config = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "ServerConfig"
        ),
        None,
    )
    if server_config is None:
        raise PipelineError("mcp_server.py does not define ServerConfig")
    return {
        Path(node.value.removeprefix("./")).as_posix()
        for node in ast.walk(server_config)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("./data/")
        and node.value.endswith(".json")
    }


def validate_mcp_data_paths(generators: list[Generator], repo_root: Path = REPO_ROOT) -> int:
    """Prevent MCP config defaults from retaining renamed or deleted data paths."""

    owned = {generator.output.as_posix() for generator in generators}
    failures: list[str] = []
    paths = configured_mcp_data_paths(repo_root)
    for relative in sorted(paths):
        path = _safe_repo_path(relative, repo_root)
        if path.is_symlink() or not path.is_file():
            failures.append(f"configured MCP data file is missing: {relative}")
            continue
        if any(Path(relative).is_relative_to(root) for root in EXCLUSIVE_GENERATED_ROOTS) and relative not in owned:
            failures.append(f"configured MCP evidence file has no live producer: {relative}")
    if failures:
        raise PipelineError("invalid MCP data-path defaults:\n- " + "\n- ".join(failures))
    return len(paths)


def configured_evaluator_data_paths(repo_root: Path = REPO_ROOT) -> set[str]:
    """Return checked-in data files named by evaluator script defaults."""

    paths: set[str] = set()
    for script in sorted((repo_root / "scripts").glob("evaluate_*.py")):
        tree = ast.parse(script.read_text(encoding="utf-8"), filename=str(script))
        paths.update(
            Path(node.value.removeprefix("./")).as_posix()
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.removeprefix("./").startswith("data/")
            and node.value.endswith(".json")
        )
    return paths


def validate_evaluator_data_paths(generators: list[Generator], repo_root: Path = REPO_ROOT) -> int:
    """Prevent evaluator defaults from retaining deleted or renamed artifacts."""

    owned = {generator.output.as_posix() for generator in generators}
    failures: list[str] = []
    paths = configured_evaluator_data_paths(repo_root)
    for relative in sorted(paths):
        path = _safe_repo_path(relative, repo_root)
        if path.is_symlink() or not path.is_file():
            failures.append(f"configured evaluator data file is missing: {relative}")
            continue
        if any(Path(relative).is_relative_to(root) for root in EXCLUSIVE_GENERATED_ROOTS) and relative not in owned:
            failures.append(f"configured evaluator evidence file has no live producer: {relative}")
    if failures:
        raise PipelineError("invalid evaluator data-path defaults:\n- " + "\n- ".join(failures))
    return len(paths)


def _mcp_tool_claims(value: Any, *, location: str = "$") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_location = f"{location}.{key}"
            if "mcp_tools" in key and isinstance(child, list):
                for index, tool in enumerate(child):
                    if isinstance(tool, str) and tool.startswith("recipes_"):
                        yield tool, f"{child_location}[{index}]"
            yield from _mcp_tool_claims(child, location=child_location)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _mcp_tool_claims(child, location=f"{location}[{index}]")


def validate_mcp_tool_claims(generators: list[Generator], repo_root: Path = REPO_ROOT) -> int:
    """Require every generated MCP-tool claim to name an actual registered tool."""

    registered = registered_mcp_tools(repo_root)
    claims: set[str] = set()
    missing: list[str] = []
    for generator in generators:
        payload = json.loads((repo_root / generator.output).read_text(encoding="utf-8"))
        for tool, location in _mcp_tool_claims(payload):
            claims.add(tool)
            if tool not in registered:
                missing.append(f"{generator.output.as_posix()}:{location}: {tool}")
    if missing:
        raise PipelineError("generated artifacts claim unregistered MCP tools:\n- " + "\n- ".join(sorted(set(missing))))
    return len(claims)


def dependency_graph(
    generators: list[Generator], repo_root: Path = REPO_ROOT, *, allow_missing: bool = False
) -> dict[str, set[str]]:
    """Map each generator to generators whose outputs it hashes."""

    producers = {generator.output.as_posix(): generator.name for generator in generators}
    graph: dict[str, set[str]] = {generator.name: set() for generator in generators}
    for generator in generators:
        output_path = repo_root / generator.output
        try:
            payload = json.loads(output_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            if allow_missing:
                continue
            raise PipelineError(f"missing generated artifact: {generator.output.as_posix()}") from exc
        except json.JSONDecodeError as exc:
            raise PipelineError(f"invalid JSON generated artifact {generator.output.as_posix()}: {exc}") from exc
        for path in _hash_paths(payload):
            dependency = producers.get(path)
            if dependency and dependency != generator.name:
                graph[generator.name].add(dependency)
    return graph


def topological_tiers(graph: dict[str, set[str]]) -> list[list[str]]:
    """Return dependency-first tiers or raise with the remaining cycle."""

    unknown = sorted({dependency for dependencies in graph.values() for dependency in dependencies} - set(graph))
    if unknown:
        raise PipelineError(f"dependency graph references unknown generators: {', '.join(unknown)}")

    resolved: set[str] = set()
    remaining = {name: set(dependencies) for name, dependencies in graph.items()}
    tiers: list[list[str]] = []
    while remaining:
        tier = sorted(name for name, dependencies in remaining.items() if dependencies <= resolved)
        if not tier:
            details = "; ".join(
                f"{name} -> {', '.join(sorted(dependencies - resolved))}"
                for name, dependencies in sorted(remaining.items())
            )
            raise PipelineError(f"generator hash dependency cycle detected: {details}")
        tiers.append(tier)
        resolved.update(tier)
        for name in tier:
            remaining.pop(name)
    return tiers


def _run_tiers(
    generators: list[Generator],
    tiers: list[list[str]],
    *,
    check: bool,
    repo_root: Path,
) -> list[tuple[str, int]]:
    by_name = {generator.name: generator for generator in generators}
    failures: list[tuple[str, int]] = []
    completed = 0
    mode = "check" if check else "write"
    for tier_number, tier in enumerate(tiers, start=1):
        print(f"[{mode}] tier {tier_number}/{len(tiers)} ({len(tier)} generators)", flush=True)
        tier_failed = False
        for name in tier:
            generator = by_name[name]
            argv = [sys.executable, generator.script.as_posix()]
            if check:
                argv.append("--check")
            print(f"  + {' '.join(argv)}", flush=True)
            result = subprocess.run(argv, cwd=repo_root, check=False)
            if result.returncode:
                failures.append((name, result.returncode))
                tier_failed = True
            else:
                completed += 1
        if tier_failed and not check:
            print("write stopped before downstream tiers because an upstream generator failed", file=sys.stderr)
            break
    print(f"[{mode}] {completed}/{len(generators)} generators succeeded", flush=True)
    return failures


def run_checks(repo_root: Path = REPO_ROOT) -> int:
    generators = discover_generators(repo_root)
    owned_count = validate_ownership(generators, repo_root)
    print(f"validated exact ownership for {owned_count} generated artifacts", flush=True)
    reference_count = validate_hashed_references(generators, repo_root)
    print(f"validated {reference_count} path/SHA-256 references", flush=True)
    mcp_path_count = validate_mcp_data_paths(generators, repo_root)
    print(f"validated {mcp_path_count} configured MCP data paths", flush=True)
    evaluator_path_count = validate_evaluator_data_paths(generators, repo_root)
    print(f"validated {evaluator_path_count} configured evaluator data paths", flush=True)
    claim_count = validate_mcp_tool_claims(generators, repo_root)
    print(f"validated {claim_count} distinct MCP tool claims against mcp_server.py", flush=True)
    tiers = topological_tiers(dependency_graph(generators, repo_root))
    failures = _run_tiers(generators, tiers, check=True, repo_root=repo_root)
    if failures:
        for name, returncode in failures:
            print(f"- {name}: exit {returncode}", file=sys.stderr)
        return 1
    print(f"all {len(generators)}/{len(generators)} generated artifacts are fresh", flush=True)
    return 0


def regenerate(repo_root: Path = REPO_ROOT) -> int:
    generators = discover_generators(repo_root)
    _, previously_owned = _load_ownership_manifest(repo_root, required=False)
    current_outputs = {generator.output.as_posix() for generator in generators}
    candidates_for_removal = previously_owned - current_outputs
    for root in EXCLUSIVE_GENERATED_ROOTS:
        candidates_for_removal.update(_files_under(root, repo_root) - current_outputs)

    graph = dependency_graph(generators, repo_root, allow_missing=True)
    tiers = topological_tiers(graph)
    failures = _run_tiers(generators, tiers, check=False, repo_root=repo_root)
    if failures:
        for name, returncode in failures:
            print(f"- {name}: exit {returncode}", file=sys.stderr)
        return 1

    next_graph = dependency_graph(generators, repo_root)
    next_tiers = topological_tiers(next_graph)
    if next_graph != graph:
        print("hash dependency graph changed; running one convergence pass", flush=True)
        failures = _run_tiers(generators, next_tiers, check=False, repo_root=repo_root)
        if failures:
            for name, returncode in failures:
                print(f"- {name}: exit {returncode}", file=sys.stderr)
            return 1

    print("running final freshness sweep", flush=True)
    failures = _run_tiers(generators, next_tiers, check=True, repo_root=repo_root)
    if failures:
        for name, returncode in failures:
            print(f"- {name}: exit {returncode}", file=sys.stderr)
        return 1
    reference_count = validate_hashed_references(
        generators,
        repo_root,
        forbidden_paths=candidates_for_removal,
    )
    claim_count = validate_mcp_tool_claims(generators, repo_root)
    mcp_path_count = validate_mcp_data_paths(generators, repo_root)
    evaluator_path_count = validate_evaluator_data_paths(generators, repo_root)
    removed = _remove_owned_outputs(candidates_for_removal, repo_root)
    _write_ownership_manifest(generators, repo_root)
    validate_ownership(generators, repo_root)
    print(
        f"reconciled {len(generators)} owned artifacts; removed {len(removed)} orphans; "
        f"validated {reference_count} path/SHA-256 references, {mcp_path_count} MCP data paths, "
        f"{evaluator_path_count} evaluator data paths, and {claim_count} MCP tool claims",
        flush=True,
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Verify all generated artifacts without writing.")
    mode.add_argument("--write", action="store_true", help="Regenerate in dependency order, then verify freshness.")
    mode.add_argument("--graph", action="store_true", help="Print the dependency tiers without running generators.")
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    try:
        if args.check:
            return run_checks(repo_root)
        if args.write:
            return regenerate(repo_root)
        generators = discover_generators(repo_root)
        graph = dependency_graph(generators, repo_root)
        for tier_number, tier in enumerate(topological_tiers(graph), start=1):
            print(f"tier {tier_number}: {', '.join(tier)}")
        print(f"{len(generators)} generators; {sum(len(items) for items in graph.values())} hash dependencies")
        return 0
    except PipelineError as exc:
        print(f"generator pipeline error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
