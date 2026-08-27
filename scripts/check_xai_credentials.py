#!/usr/bin/env python3
"""Classify whether XAI_API_KEY can serve billed Grok automation.

A present key is not enough: an exhausted or rejected key still starts Grok
CLI jobs, fails quickly, and then fans out into AI maintenance. This probe
treats those unusable keys like a missing secret so the jobs stay inactive
instead of failing.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

try:
    from scripts.cve_ai_enrichment import DEFAULT_MODEL, probe_xai_credentials
except ModuleNotFoundError:  # Direct ``python scripts/check_xai_credentials.py``.
    from cve_ai_enrichment import DEFAULT_MODEL, probe_xai_credentials  # type: ignore[no-redef]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)
    model = os.environ.get("XAI_MODEL", "").strip() or DEFAULT_MODEL
    status = probe_xai_credentials(os.environ.get("XAI_API_KEY", ""), model=model)
    if args.github_output is not None:
        args.github_output.parent.mkdir(parents=True, exist_ok=True)
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"usable={'true' if status.usable else 'false'}\n")
            stream.write(f"reason={status.reason}\n")
            if status.http_status is not None:
                stream.write(f"http_status={status.http_status}\n")
                stream.write(f"error_category={status.error_category}\n")
    if status.http_status is not None:
        print(
            f"xAI credential probe: HTTP {status.http_status}; category={status.error_category}.",
            flush=True,
        )
    if status.usable:
        if status.reason == "ready":
            print("xAI credentials are usable (ready).", flush=True)
        else:
            print(
                f"xAI credential readiness is unconfirmed ({status.reason}); "
                "continuing under the transient-probe-error policy.",
                flush=True,
            )
    else:
        print(f"::notice::{status.notice}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
