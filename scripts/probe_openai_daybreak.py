#!/usr/bin/env python3
"""Make one OpenAI Responses probe for the configured Daybreak program.

Prints only ``ok`` or ``denied`` plus the HTTP status. Never prints the API
key or provider response body. Does not run the CVE catalog sync.
"""

from __future__ import annotations

import os

try:
    from scripts.cve_ai_enrichment import (
        DEFAULT_OPENAI_MODEL,
        normalize_daybreak_program,
        probe_daybreak_access,
    )
except ModuleNotFoundError:  # Direct ``python scripts/probe_openai_daybreak.py``.
    from cve_ai_enrichment import (  # type: ignore[no-redef]
        DEFAULT_OPENAI_MODEL,
        normalize_daybreak_program,
        probe_daybreak_access,
    )


def main(argv: list[str] | None = None) -> int:
    del argv
    model = os.environ.get("OPENAI_MODEL", "").strip() or DEFAULT_OPENAI_MODEL
    try:
        program = normalize_daybreak_program(os.environ.get("OPENAI_DAYBREAK_PROGRAM"))
    except ValueError:
        print("denied 0", flush=True)
        return 0
    outcome, status = probe_daybreak_access(
        os.environ.get("OPENAI_API_KEY", ""),
        model=model,
        access_program=program,
    )
    print(f"{outcome} {status if status is not None else 0}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
