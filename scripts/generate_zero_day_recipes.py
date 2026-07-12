#!/usr/bin/env python3
"""Compatibility entry point for the authoritative CVE catalog sync.

The former implementation generated speculative Markdown from short NVD/GHSA
windows.  It did not paginate NVD, treated any CVE mentioned in prose as an
existing primary recipe, and inferred vulnerable code patterns from keywords.
Those behaviors are unsafe for an enterprise or agent-consumable source.

Use ``scripts/sync_cve_catalog.py`` directly for new automation.  This wrapper
keeps old invocations without arguments useful while ensuring they execute the
same exact rolling ten-year, integrity-verified catalog build.
"""

from __future__ import annotations

try:
    from scripts.sync_cve_catalog import main
except ModuleNotFoundError:  # Direct execution adds scripts/ to sys.path.
    from sync_cve_catalog import main


if __name__ == "__main__":
    raise SystemExit(main())
