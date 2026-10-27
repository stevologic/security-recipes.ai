#!/usr/bin/env python3
"""Make one Responses probe for the configured CVE enrichment provider.

Reads ``CVE_ENRICH_MODEL`` (or ``DEFAULT_CVE_ENRICH_MODEL``) and the matching API key.
Prints only ``ok`` or ``denied`` plus the HTTP status. Never prints the API
key or provider response body. Does not run the CVE catalog sync.
"""

from __future__ import annotations

import os

try:
    from scripts.cve_ai_enrichment import (
        DEFAULT_CVE_ENRICH_MODEL,
        parse_cve_enrich_model,
        probe_cve_enrichment_access,
    )
except ModuleNotFoundError:  # Direct ``python scripts/probe_openai_daybreak.py``.
    from cve_ai_enrichment import (  # type: ignore[no-redef]
        DEFAULT_CVE_ENRICH_MODEL,
        parse_cve_enrich_model,
        probe_cve_enrichment_access,
    )


def main(argv: list[str] | None = None) -> int:
    del argv
    spec = (
        os.environ.get("CVE_ENRICH_MODEL", "").strip()
        or os.environ.get("OPENAI_MODEL", "").strip()
        or DEFAULT_CVE_ENRICH_MODEL
    )
    try:
        target = parse_cve_enrich_model(
            spec,
            overlay_program=os.environ.get("OPENAI_DAYBREAK_PROGRAM"),
        )
    except ValueError:
        print("denied 0", flush=True)
        return 0
    outcome, status = probe_cve_enrichment_access(
        os.environ.get(target.api_key_env, ""),
        target=target,
    )
    print(f"{outcome} {status if status is not None else 0}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
