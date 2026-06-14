#!/usr/bin/env python3
"""Run CVE intelligence intake fixture regressions."""

from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.evaluate_cve_intelligence_intake import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main(["--run-fixtures", *sys.argv[1:]]))
