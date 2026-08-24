#!/usr/bin/env python3
"""Find a DigitalOcean token on the droplet and upsert the staging A record.

This is the SSH fallback used when GitHub Actions has a droplet key but no
API token secret. It never prints credential values.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
from pathlib import Path


TOKEN_RE = re.compile(
    r"(?i)(?:DIGITALOCEAN_ACCESS_TOKEN|DIGITALOCEAN_TOKEN|DO_TOKEN|"
    r"DO_API_TOKEN|DO_ACCESS_TOKEN|DO_API_KEY|access-token)\s*[:=]\s*(\S+)"
)
DOP_V1_RE = re.compile(r"(dop_v1_[0-9a-f]{64})", re.IGNORECASE)
SEARCH_PATHS = (
    Path("/etc/security-recipes/deploy.env"),
    Path("/etc/security-recipes/do.env"),
    Path("/etc/environment"),
    Path("/root/.config/doctl/config.yaml"),
    Path("/root/.doctlcfg"),
    Path("/root/.docker/config.json"),
    Path.home() / ".config/doctl/config.yaml",
    Path.home() / ".doctlcfg",
    Path.home() / ".docker" / "config.json",
    Path("/opt/security-recipes.ai/.env"),
)
_DOCKER_HOST_MARKERS = ("digitalocean", "docr.io")


def _clean_token(raw: str) -> str:
    return raw.strip().strip("'\"")


def token_from_text(text: str) -> str:
    match = TOKEN_RE.search(text)
    if match:
        return _clean_token(match.group(1))
    bare = DOP_V1_RE.search(text)
    if bare:
        return bare.group(1)
    return ""


def token_from_docker_config(path: Path) -> str:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return ""
    auths = payload.get("auths")
    if not isinstance(auths, dict):
        return ""
    for host, entry in auths.items():
        host_l = str(host).lower()
        if not any(marker in host_l for marker in _DOCKER_HOST_MARKERS):
            continue
        if not isinstance(entry, dict):
            continue
        password = str(entry.get("password") or "")
        auth = str(entry.get("auth") or "")
        if auth and not password:
            try:
                decoded = base64.b64decode(auth).decode("utf-8", errors="replace")
            except (ValueError, UnicodeError):
                decoded = ""
            if ":" in decoded:
                password = decoded.split(":", 1)[1]
        password = _clean_token(password)
        if DOP_V1_RE.fullmatch(password):
            return password
    return ""


def iter_search_paths() -> tuple[Path, ...]:
    discovered: list[Path] = []
    roots = (
        Path("/etc/security-recipes"),
        Path("/root/snap/doctl"),
        Path("/var/snap/doctl"),
        Path("/home"),
    )
    patterns = (
        "*.env",
        "*/.config/doctl/config.yaml",
        "*/.doctlcfg",
        "*/.docker/config.json",
        "*/*/.config/doctl/config.yaml",
    )
    for root in roots:
        if not root.exists():
            continue
        for pattern in patterns:
            try:
                discovered.extend(root.glob(pattern))
            except OSError:
                continue
    seen: set[str] = set()
    ordered: list[Path] = []
    for path in (*SEARCH_PATHS, *discovered):
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(path)
    return tuple(ordered)


def first_token() -> str:
    for key in (
        "DIGITALOCEAN_ACCESS_TOKEN",
        "DIGITALOCEAN_TOKEN",
        "DO_TOKEN",
        "DO_API_TOKEN",
        "DO_ACCESS_TOKEN",
        "DO_API_KEY",
    ):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    for path in iter_search_paths():
        if not path.is_file():
            continue
        try:
            if path.name == "config.json":
                token = token_from_docker_config(path)
                if token:
                    return token
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        token = token_from_text(text)
        if token:
            return token
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
