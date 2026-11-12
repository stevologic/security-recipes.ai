#!/usr/bin/env python3
"""Recorded `gh` stand-in for the CVE catalog merge-job harness."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


def _state_path() -> Path:
    raw = os.environ.get("GH_STUB_STATE")
    if not raw:
        raise SystemExit("GH_STUB_STATE is required")
    return Path(raw)


def load_state() -> dict[str, Any]:
    path = _state_path()
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(state: dict[str, Any]) -> None:
    _state_path().write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_log(entry: dict[str, Any]) -> None:
    raw = os.environ.get("GH_STUB_LOG")
    if not raw:
        return
    with Path(raw).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def parse_api_args(args: list[str]) -> dict[str, Any]:
    method = "GET"
    jq = None
    path = None
    raw_fields: dict[str, str] = {}
    fields: dict[str, str] = {}
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--method":
            method = args[index + 1]
            index += 2
            continue
        if token == "--jq":
            jq = args[index + 1]
            index += 2
            continue
        if token == "--paginate":
            index += 1
            continue
        if token == "--raw-field":
            key, value = args[index + 1].split("=", 1)
            raw_fields[key] = value
            index += 2
            continue
        if token == "--field":
            key, value = args[index + 1].split("=", 1)
            fields[key] = value
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        if path is None:
            path = token
        index += 1
    return {
        "method": method,
        "jq": jq,
        "path": path or "",
        "raw_fields": raw_fields,
        "fields": fields,
    }


def parse_workflow_run(args: list[str]) -> dict[str, Any]:
    workflow = args[0] if args else ""
    ref = ""
    fields: dict[str, str] = {}
    index = 1
    while index < len(args):
        token = args[index]
        if token == "--ref":
            ref = args[index + 1]
            index += 2
            continue
        if token == "--field":
            key, value = args[index + 1].split("=", 1)
            fields[key] = value
            index += 2
            continue
        index += 1
    return {"workflow": workflow, "ref": ref, "fields": fields}


def apply_jq(payload: Any, expression: str) -> str:
    completed = subprocess.run(
        ["jq", "-r", expression],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        sys.stderr.write(completed.stderr)
        raise SystemExit(completed.returncode)
    return completed.stdout.rstrip("\n")


def handle_api(state: dict[str, Any], parsed: dict[str, Any]) -> int:
    path = str(parsed["path"])
    method = str(parsed["method"]).upper()
    pr = state["pr"]
    if path.endswith(f"/pulls/{pr['number']}") and method == "GET":
        payload = pr
    elif "/events" in path and method == "GET":
        payload = list(state.get("events") or [])
    elif "/compare/" in path and method == "GET":
        payload = {"status": state.get("compare_status") or "ahead"}
    elif path.endswith("/merge") and method == "PUT":
        state.setdefault("merge_calls", []).append(
            {
                "path": path,
                "raw_fields": parsed["raw_fields"],
                "token": os.environ.get("GH_TOKEN", ""),
            }
        )
        payload = {
            "merged": True,
            "sha": state.get("merge_sha") or pr["head"]["sha"],
        }
    elif path.endswith("/update-branch") and method == "PUT":
        state.setdefault("update_branch_calls", []).append(parsed["raw_fields"])
        payload = {"message": "updated"}
    else:
        payload = {}
    save_state(state)
    jq = parsed.get("jq")
    if jq:
        sys.stdout.write(apply_jq(payload, str(jq)))
        if not str(jq).endswith("-n"):
            sys.stdout.write("\n")
        return 0
    sys.stdout.write(json.dumps(payload) + "\n")
    return 0


def handle_pr_edit(state: dict[str, Any], args: list[str]) -> int:
    if "--add-label" in args:
        label = args[args.index("--add-label") + 1]
        labels = list(state.get("labels_added") or [])
        if label not in labels:
            labels.append(label)
        state["labels_added"] = labels
        pr_labels = list(state["pr"].get("labels") or [])
        names = {item.get("name") for item in pr_labels if isinstance(item, dict)}
        if label not in names:
            pr_labels.append({"name": label})
        state["pr"]["labels"] = pr_labels
    if "--remove-label" in args:
        label = args[args.index("--remove-label") + 1]
        state["pr"]["labels"] = [
            item
            for item in list(state["pr"].get("labels") or [])
            if not (isinstance(item, dict) and item.get("name") == label)
        ]
    save_state(state)
    return 0


def handle_run_list(state: dict[str, Any]) -> int:
    runs = []
    for index, recorded in enumerate(state.get("workflow_runs") or [], start=1):
        request_id = recorded.get("fields", {}).get("request_id", "")
        expected_sha = recorded.get("fields", {}).get("expected_sha", "")
        title = f"CVE catalog validation {request_id} @ {expected_sha}"
        runs.append(
            {
                "databaseId": index,
                "displayTitle": title,
                "headBranch": recorded.get("ref") or "",
                "status": "completed",
                "conclusion": "success",
                "url": f"https://github.com/example/validate/{index}",
            }
        )
    sys.stdout.write(json.dumps(runs) + "\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    state = load_state()
    append_log(
        {
            "argv": args,
            "gh_token": os.environ.get("GH_TOKEN", ""),
            "app_token": os.environ.get("APP_TOKEN", ""),
        }
    )
    state.setdefault("calls", []).append(
        {"argv": args, "gh_token": os.environ.get("GH_TOKEN", "")}
    )
    save_state(state)
    if not args:
        sys.stderr.write("gh stub: missing command\n")
        return 1
    if args[0] == "api":
        return handle_api(state, parse_api_args(args[1:]))
    if args[0] == "workflow" and len(args) > 1 and args[1] == "run":
        recorded = parse_workflow_run(args[2:])
        recorded["token"] = os.environ.get("GH_TOKEN", "")
        state.setdefault("workflow_runs", []).append(recorded)
        save_state(state)
        return 0
    if args[0] == "run" and len(args) > 1 and args[1] == "list":
        return handle_run_list(state)
    if args[0] == "label" and "create" in args:
        return 0
    if args[0] == "pr" and len(args) > 1 and args[1] == "edit":
        return handle_pr_edit(state, args[2:])
    if args[0] == "app-token" and len(args) > 1 and args[1] == "mint":
        state.setdefault("mint_calls", []).append(
            {"argv": args, "token": os.environ.get("GH_TOKEN", "")}
        )
        save_state(state)
        return 0
    if args[0] == "app-token" and len(args) > 1 and args[1] == "attribute":
        state.setdefault("attribute_calls", []).append(
            {"argv": args, "token": os.environ.get("GH_TOKEN", "")}
        )
        save_state(state)
        return 0
    sys.stderr.write("gh stub: unhandled command: " + " ".join(args) + "\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
