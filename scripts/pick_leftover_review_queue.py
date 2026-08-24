#!/usr/bin/env python3
"""Select leftover-gold CVE pages for the daily leftover review.

Leftover-gold criticals and highs drain first. After those close, the daily
job takes up to 100 leftover-gold medium and low pages. Skip-family leftover
dumps stay out of this queue unless a later intentional pass includes them.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CVE_DIR = ROOT / "content" / "recipes" / "cve"
DEFAULT_STATE = ROOT / "data" / "cve" / "leftover-review-state.json"
CLAIM_RE = re.compile(
    r"GHAD names|per GHSA|GHAD-named|first_patched|GHSA-[a-z0-9-]+ names",
    re.I,
)
SKIP_RE = re.compile(
    r"linux.kernel|firefox|thunderbird|safari|ipados|ios |webkit|"
    r"sourcecodester|itsourcecode|code-projects|yashpokharna|"
    r"bixby|qsnapper|ruoyi|tenda |wavlink|edimax|d-link|dcs-|"
    r"zkteco|biotime|hanwang|cisco|catalyst|open babel|openexr|"
    r"freerdp|locutus|qnap|samsung",
    re.I,
)
DEFAULT_SEVERITY_ORDER = ("critical", "high", "medium", "low")


def load_state(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("leftover review state must be an object")
    reviewed = payload.get("reviewed_cves") or []
    if not isinstance(reviewed, list) or not all(isinstance(item, str) for item in reviewed):
        raise ValueError("reviewed_cves must be a list of CVE IDs")
    order = payload.get("severity_order") or list(DEFAULT_SEVERITY_ORDER)
    if not isinstance(order, list) or not all(isinstance(item, str) for item in order):
        raise ValueError("severity_order must be a list of strings")
    limit = payload.get("daily_limit", 100)
    if not isinstance(limit, int) or limit < 1:
        raise ValueError("daily_limit must be a positive integer")
    return {
        "schema_version": payload.get("schema_version", 1),
        "daily_limit": limit,
        "severity_order": [item.lower() for item in order],
        "reviewed_cves": set(reviewed),
    }


def _frontmatter(text: str) -> str:
    parts = text.split("---", 2)
    return parts[1] if len(parts) > 2 else ""


def inventory_leftover_pages(
    cve_dir: Path,
    reviewed: set[str],
    *,
    skip_families: bool = True,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for path in sorted(cve_dir.glob("*.md")):
        text = path.read_text(encoding="utf-8", errors="replace")
        front = _frontmatter(text)
        cve_m = re.search(r'^cve:\s*"?(CVE-\d{4}-\d+)"?', front, re.M)
        title_m = re.search(r'^title:\s*"(.*)"', front, re.M)
        sev_m = re.search(r'^severity:\s*"?([^"\n]+)"?', front, re.M)
        ghsa_m = re.search(r'^ghsa:\s*"?(GHSA-[a-z0-9-]+)"?', front, re.M)
        eco_m = re.search(r'^ecosystem:\s*"?([^"\n]+)"?', front, re.M)
        cve = cve_m.group(1) if cve_m else None
        title = title_m.group(1) if title_m else path.name
        if not cve or cve in reviewed:
            continue
        if not re.search(r"leftover", title + " " + path.name, re.I):
            continue
        if skip_families and (SKIP_RE.search(path.name) or SKIP_RE.search(text[:1400])):
            continue
        if not CLAIM_RE.search(text):
            continue
        rows.append(
            {
                "cve": cve,
                "file": str(path.as_posix()),
                "ghsa": ghsa_m.group(1) if ghsa_m else "",
                "severity": (sev_m.group(1) if sev_m else "").strip().lower() or "unknown",
                "ecosystem": (eco_m.group(1) if eco_m else "").strip(),
                "title": title,
            }
        )
    return rows


def select_queue(
    rows: list[dict[str, str]],
    *,
    limit: int,
    severity_order: list[str],
) -> list[dict[str, str]]:
    rank = {name: index for index, name in enumerate(severity_order)}
    ordered = sorted(
        rows,
        key=lambda row: (rank.get(row["severity"], len(rank)), row["cve"]),
    )
    return ordered[:limit]


def build_queue(
    *,
    cve_dir: Path,
    state_path: Path,
    limit: int | None = None,
) -> dict[str, Any]:
    state = load_state(state_path)
    rows = inventory_leftover_pages(cve_dir, state["reviewed_cves"])
    selected = select_queue(
        rows,
        limit=limit or state["daily_limit"],
        severity_order=state["severity_order"],
    )
    counts = {name: 0 for name in state["severity_order"]}
    for row in rows:
        if row["severity"] in counts:
            counts[row["severity"]] += 1
    return {
        "daily_limit": limit or state["daily_limit"],
        "remaining": counts,
        "remaining_total": len(rows),
        "selected": selected,
        "selected_total": len(selected),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cve-dir", type=Path, default=DEFAULT_CVE_DIR)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    queue = build_queue(cve_dir=args.cve_dir, state_path=args.state, limit=args.limit)
    if args.json:
        print(json.dumps(queue, indent=2))
        return 0
    print(
        "remaining_total",
        queue["remaining_total"],
        "selected",
        queue["selected_total"],
        "remaining",
        queue["remaining"],
    )
    for row in queue["selected"]:
        print(f"{row['cve']}\t{row['severity']}\t{row['ghsa']}\t{row['title']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
