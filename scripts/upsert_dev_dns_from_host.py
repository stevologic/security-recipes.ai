#!/usr/bin/env python3
"""Find a DigitalOcean token on the droplet and upsert the staging A record.

This is the SSH fallback used when GitHub Actions has a droplet key but no
API token secret. It never prints credential values.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path


TOKEN_RE = re.compile(
    r"(?i)(?:DIGITALOCEAN_ACCESS_TOKEN|DIGITALOCEAN_TOKEN|DO_TOKEN|DO_API_TOKEN|access-token)\s*[:=]\s*(\S+)"
)
SEARCH_PATHS = (
    Path("/etc/security-recipes/deploy.env"),
    Path("/etc/security-recipes/do.env"),
    Path("/root/.config/doctl/config.yaml"),
    Path("/root/.doctlcfg"),
    Path.home() / ".config/doctl/config.yaml",
    Path.home() / ".doctlcfg",
    Path("/opt/security-recipes.ai/.env"),
)


def first_token() -> str:
    for key in (
        "DIGITALOCEAN_ACCESS_TOKEN",
        "DIGITALOCEAN_TOKEN",
        "DO_TOKEN",
        "DO_API_TOKEN",
    ):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    for path in SEARCH_PATHS:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        match = TOKEN_RE.search(text)
        if match:
            return match.group(1).strip().strip("'\"")
    return ""


def main() -> int:
    token = first_token()
    if not token:
        print(
            "No DigitalOcean API token was found on the droplet.",
            file=sys.stderr,
        )
        return 2
    os.environ["DIGITALOCEAN_ACCESS_TOKEN"] = token
    script = Path(__file__).resolve().with_name("upsert_dev_dns_record.py")
    if not script.is_file():
        script = Path("/tmp/upsert_dev_dns_record.py")
    os.execv(sys.executable, [sys.executable, str(script)])


if __name__ == "__main__":
    raise SystemExit(main())
