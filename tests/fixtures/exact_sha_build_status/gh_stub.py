#!/usr/bin/env python3
"""Record `gh` invocations and return canned payloads for exact-SHA harness tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def apply_jq(payload: Any, jq_filter: str) -> str:
    completed = subprocess.run(
        ["jq", "-cr", jq_filter],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout


def parse_args(argv: list[str]) -> dict[str, Any]:
    method = "GET"
    jq_filter = None
    fields: dict[str, str] = {}
    flags: dict[str, str] = {}
    positionals: list[str] = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg in {"--method", "--jq", "--status", "--workflow", "--ref", "--limit", "--json", "--state", "--base"}:
            value = argv[index + 1] if index + 1 < len(argv) else ""
            if arg == "--method":
                method = value
            elif arg == "--jq":
                jq_filter = value
            else:
                flags[arg] = value
            index += 2
            continue
        if arg in {"--raw-field", "--field"}:
            raw = argv[index + 1] if index + 1 < len(argv) else "="
            key, _, value = raw.partition("=")
            fields[key] = value
            index += 2
            continue
        if arg.startswith("-"):
            flags[arg] = ""
            index += 1
            continue
        positionals.append(arg)
        index += 1
    return {
        "method": method,
        "jq": jq_filter,
        "fields": fields,
        "flags": flags,
        "positionals": positionals,
    }


def api_path(positionals: list[str]) -> str:
    for item in positionals:
        if item in {"api", "GET", "POST", "PUT", "PATCH", "DELETE"}:
            continue
        return item.split("?", 1)[0]
    return ""


def commit_sha_from_path(path: str) -> str:
    marker = "/commits/"
    if marker not in path:
        return ""
    remainder = path.split(marker, 1)[1]
    return remainder.split("/", 1)[0]


def main() -> int:
    log_path = Path(os.environ["GH_STUB_LOG"])
    scenario = load_json(Path(os.environ["GH_STUB_SCENARIO"]), {})
    argv = sys.argv[1:]
    parsed = parse_args(argv)
    calls = load_json(log_path, [])
    if not isinstance(calls, list):
        calls = []
    calls.append(
        {
            "argv": argv,
            "method": parsed["method"],
            "fields": parsed["fields"],
            "flags": parsed["flags"],
            "positionals": parsed["positionals"],
            "gh_token": os.environ.get("GH_TOKEN", ""),
        }
    )
    save_json(log_path, calls)

    if not argv:
        print("gh stub: missing command", file=sys.stderr)
        return 1

    if argv[0] == "pr" and "list" in argv:
        sys.stdout.write(json.dumps(scenario.get("pr_list", [])) + "\n")
        return 0

    if argv[0] == "run" and "list" in argv:
        runs = list(scenario.get("run_list", []))
        wanted = parsed["flags"].get("--status")
        if wanted:
            runs = [run for run in runs if run.get("status") == wanted]
        if parsed["jq"]:
            sys.stdout.write(apply_jq(runs, parsed["jq"]))
            return 0
        sys.stdout.write(json.dumps(runs) + "\n")
        return 0

    if argv[0] == "workflow" and "run" in argv:
        return int(scenario.get("workflow_run_exit", 0))

    if argv[0] == "api":
        path = api_path(parsed["positionals"])
        repo = os.environ.get("GITHUB_REPOSITORY", "")
        if parsed["method"] == "POST" and "/statuses/" in path:
            prior_posts = sum(
                1
                for call in calls[:-1]
                if call.get("method") == "POST"
                and any("/statuses/" in str(item) for item in call.get("positionals", []))
            )
            failures = int(scenario.get("status_post_failures", 0))
            if prior_posts < failures:
                return 1
            return int(scenario.get("status_post_exit", 0))
        if path in {f"repos/{repo}", f"repos/{repo}/"}:
            payload = scenario.get("repo", {"default_branch": "main"})
        elif "/pulls/" in path:
            number = path.rsplit("/pulls/", 1)[1].split("/", 1)[0]
            by_number = scenario.get("pulls_by_number")
            canonical = str(scenario.get("pull_number", "480"))
            if isinstance(by_number, dict):
                if number not in by_number:
                    sys.stdout.write("{}\n")
                    return 0
                payload = by_number[number]
            elif number != canonical:
                sys.stdout.write("{}\n")
                return 0
            else:
                payload = scenario.get("pull", {})
        elif "/check-runs" in path:
            payload = scenario.get("check_runs_by_sha", {}).get(
                commit_sha_from_path(path),
                {"check_runs": []},
            )
        elif path.endswith("/status") and "/commits/" in path:
            payload = scenario.get("combined_status_by_sha", {}).get(
                commit_sha_from_path(path),
                {"statuses": []},
            )
        else:
            print(f"gh stub: unhandled api path {path}", file=sys.stderr)
            return 1
        if parsed["jq"]:
            sys.stdout.write(apply_jq(payload, parsed["jq"]))
            return 0
        sys.stdout.write(json.dumps(payload) + "\n")
        return 0

    print(f"gh stub: unhandled invocation {argv}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
