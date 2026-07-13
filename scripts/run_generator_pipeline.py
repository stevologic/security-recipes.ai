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
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_GLOB = "generate_*.py"


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

    generators = [
        generator
        for script in sorted((repo_root / "scripts").glob(GENERATOR_GLOB))
        if (generator := _generator_metadata(script, repo_root)) is not None
    ]
    if not generators:
        raise PipelineError("no --check-capable generators were discovered")

    outputs: dict[str, str] = {}
    for generator in generators:
        output = generator.output.as_posix()
        if output in outputs:
            raise PipelineError(f"duplicate generator output {output}: {outputs[output]} and {generator.name}")
        outputs[output] = generator.name
    return generators


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
    generators: list[Generator], repo_root: Path = REPO_ROOT
) -> dict[str, set[str]]:
    """Map each generator to generators whose outputs it hashes."""

    producers = {generator.output.as_posix(): generator.name for generator in generators}
    graph: dict[str, set[str]] = {generator.name: set() for generator in generators}
    for generator in generators:
        output_path = repo_root / generator.output
        try:
            payload = json.loads(output_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
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
    graph = dependency_graph(generators, repo_root)
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
    return run_checks(repo_root)


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
