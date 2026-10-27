#!/usr/bin/env python3
"""Independently regenerate and check expiring latest-CVE projections."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.cve_latest_projection import (  # noqa: E402
    project_directory, render_latest, unavailable_projection, utc_timestamp,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=Path("static/api/cve-catalog"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--as-of", help="UTC evaluation instant for reproducible offline runs")
    parser.add_argument("--probe", action="store_true", help="Check the deployed same-origin projection")
    args = parser.parse_args()
    now = utc_timestamp(args.as_of) if args.as_of else datetime.now(timezone.utc)
    problems = []
    try:
        projection = project_directory(args.catalog, now)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        projection = unavailable_projection()
        problems.append(f"Local projection failed: {exc}")
    report = {"evaluated_at": now.isoformat(), "projection": projection}
    if args.probe:
        try:
            request = Request("https://security-recipes.ai/api/cve-latest", headers={"Cache-Control": "no-cache"})
            with urlopen(request, timeout=20) as response:
                raw = response.read(64 * 1024 + 1)
            if len(raw) > 64 * 1024:
                raise ValueError("deployed projection exceeds bound")
            live = json.loads(raw)
            report["deployed_projection"] = live
            # Re-evaluate the returned records against the immutable source
            # timestamp. Never regard an old 'ready' label as proof of freshness.
            verified = project_directory_payload(live, now)
            if verified["status"] != "ready" or verified["records"] != live.get("records"):
                problems.append("Deployed latest view is stale, empty, or inconsistent")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            problems.append(f"Deployed projection check failed: {exc}")
    if projection["status"] != "ready":
        problems.append("No fresh local CVEs remain; latest view is explicitly empty")
    report["problems"] = problems
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "latest.json").write_text(json.dumps(report, indent=2) + "\n")
    (args.output / "latest.html").write_text(render_latest(projection) + "\n")
    print(json.dumps(report, indent=2))
    return 1 if problems else 0


def project_directory_payload(payload: dict, now: datetime) -> dict:
    from scripts.cve_latest_projection import project_latest
    return project_latest({"shard_set_sha256": payload["source_revision"],
                           "catalog_updated_at": payload["source_updated_at"]}, payload["records"], now)


if __name__ == "__main__":
    raise SystemExit(main())
