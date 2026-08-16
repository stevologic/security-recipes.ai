#!/usr/bin/env python3
"""Classify whether OPENAI_API_KEY can serve billed automation requests.

Codex-backed workflows and optional CVE enrichment share one repository secret.
A present key is not enough: an exhausted or rejected key still starts those
jobs, fails in about a minute, and then fans out into AI maintenance. This
probe treats those unusable keys like a missing secret so the jobs stay
inactive instead of failing.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

try:
    from scripts.cve_ai_enrichment import probe_openai_credentials
except ModuleNotFoundError:  # Direct ``python scripts/check_openai_credentials.py``.
    from cve_ai_enrichment import probe_openai_credentials  # type: ignore[no-redef]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)
    status = probe_openai_credentials(os.environ.get("OPENAI_API_KEY", ""))
    if args.github_output is not None:
        args.github_output.parent.mkdir(parents=True, exist_ok=True)
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"usable={'true' if status.usable else 'false'}\n")
            stream.write(f"reason={status.reason}\n")
    if status.usable:
        print(f"OpenAI credentials are usable ({status.reason}).", flush=True)
    else:
        print(f"::notice::{status.notice}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
