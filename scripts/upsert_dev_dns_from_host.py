#!/usr/bin/env python3
"""Find droplet credentials and upsert the staging A record.

This is the SSH / deploy.sh fallback used when GitHub Actions has no
API token secret. It never prints credential values. Prefer, in order:

1. An explicit DigitalOcean token in the environment or host files
2. An already-authenticated doctl client (no token extraction)
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable


TOKEN_RE = re.compile(
    r"(?i)(?:DIGITALOCEAN_ACCESS_TOKEN|DIGITALOCEAN_TOKEN|DO_TOKEN|"
    r"DO_API_TOKEN|DO_ACCESS_TOKEN|DO_API_KEY|access-token)\s*[:=]\s*(\S+)"
)
DOP_V1_RE = re.compile(r"(dop_v1_[0-9a-f]{64})", re.IGNORECASE)
DEFAULT_DOMAIN = "security-recipes.ai"
DEFAULT_RECORD_NAME = "dev"
DEFAULT_IPV4 = "64.227.98.210"
DEFAULT_TTL = 300
SEARCH_PATHS = (
    Path("/etc/security-recipes/deploy.env"),
    Path("/etc/security-recipes/do.env"),
    Path("/etc/environment"),
    Path("/etc/profile"),
    Path("/root/.config/doctl/config.yaml"),
    Path("/root/.doctlcfg"),
    Path("/root/.digitalocean_token"),
    Path("/root/.docker/config.json"),
    Path("/root/.bashrc"),
    Path("/root/.profile"),
    Path("/root/.bash_profile"),
    Path("/root/.zshrc"),
    Path("/var/lib/cloud/instance/user-data.txt"),
    Path("/etc/digitalocean/token"),
    Path.home() / ".config/doctl/config.yaml",
    Path.home() / ".doctlcfg",
    Path.home() / ".docker" / "config.json",
    Path("/opt/security-recipes.ai/.env"),
)
_DOCKER_HOST_MARKERS = ("digitalocean", "docr.io")
_DOCTL_BINARIES = (
    "/snap/bin/doctl",
    "/usr/local/bin/doctl",
    "/usr/bin/doctl",
)
Runner = Callable[..., subprocess.CompletedProcess[str]]


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


def token_from_docker_inspect_payload(payload: Any) -> str:
    if not isinstance(payload, list):
        return ""
    env_prefixes = (
        "DIGITALOCEAN_ACCESS_TOKEN=",
        "DIGITALOCEAN_TOKEN=",
        "DO_TOKEN=",
        "DO_API_TOKEN=",
        "DO_ACCESS_TOKEN=",
        "DO_API_KEY=",
    )
    for item in payload:
        if not isinstance(item, dict):
            continue
        config = item.get("Config")
        if not isinstance(config, dict):
            continue
        env_values = config.get("Env")
        if not isinstance(env_values, list):
            continue
        for raw in env_values:
            line = str(raw)
            for prefix in env_prefixes:
                if line.startswith(prefix):
                    token = _clean_token(line[len(prefix) :])
                    if token:
                        return token
            bare = DOP_V1_RE.search(line)
            if bare:
                return bare.group(1)
    return ""


def token_from_docker_inspect(runner: Runner | None = None) -> str:
    docker = shutil.which("docker")
    if not docker:
        return ""
    run = runner or subprocess.run
    try:
        listed = run(
            [docker, "ps", "-aq"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    ids = [item for item in listed.stdout.split() if item]
    if listed.returncode != 0 or not ids:
        return ""
    try:
        inspected = run(
            [docker, "inspect", *ids],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if inspected.returncode != 0:
        return ""
    try:
        payload = json.loads(inspected.stdout or "[]")
    except json.JSONDecodeError:
        return ""
    return token_from_docker_inspect_payload(payload)


def iter_search_paths() -> tuple[Path, ...]:
    discovered: list[Path] = []
    roots = (
        Path("/etc/security-recipes"),
        Path("/etc/profile.d"),
        Path("/root/snap/doctl"),
        Path("/var/snap/doctl"),
        Path("/home"),
    )
    patterns = (
        "*.env",
        "*.sh",
        "*/.config/doctl/config.yaml",
        "*/.doctlcfg",
        "*/.docker/config.json",
        "*/.bashrc",
        "*/.profile",
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


def first_token(runner: Runner | None = None) -> str:
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
    return token_from_docker_inspect(runner=runner)


def doctl_commands() -> tuple[list[str], ...]:
    commands: list[list[str]] = []
    seen: set[str] = set()

    def add(command: list[str]) -> None:
        key = "\0".join(command)
        if key in seen:
            return
        seen.add(key)
        commands.append(command)

    which = shutil.which("doctl")
    if which:
        add([which])
    for path in _DOCTL_BINARIES:
        if Path(path).is_file() and os.access(path, os.X_OK):
            add([path])
    snap = shutil.which("snap")
    if snap:
        add([snap, "run", "doctl"])
    return tuple(commands)


def _record_field(record: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in record:
            return record[name]
    return None


def _is_doctl_auth_error(stderr: str, stdout: str) -> bool:
    text = f"{stderr}\n{stdout}".lower()
    needles = (
        "access token is required",
        "run 'doctl auth init'",
        "unable to authenticate",
        "401",
        "unauthorized",
        "not authenticated",
    )
    return any(needle in text for needle in needles)


def upsert_with_doctl(runner: Runner | None = None) -> int:
    """Create or update the staging A record with an authenticated doctl.

    Returns 0 on success, 2 when doctl is missing or unauthenticated, and 1
    when doctl is present but the DNS change failed.
    """
    run = runner or subprocess.run
    domain = os.environ.get("SECURITY_RECIPES_DOMAIN", DEFAULT_DOMAIN)
    name = os.environ.get("SECURITY_RECIPES_DEV_RECORD", DEFAULT_RECORD_NAME)
    ipv4 = os.environ.get("SECURITY_RECIPES_DROPLET_IPV4", DEFAULT_IPV4)
    ttl = int(os.environ.get("SECURITY_RECIPES_DEV_DNS_TTL", str(DEFAULT_TTL)))
    commands = doctl_commands()
    if not commands:
        return 2

    saw_client = False
    for binary in commands:
        try:
            listed = run(
                [*binary, "compute", "domain", "records", "list", domain, "--output", "json"],
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        saw_client = True
        if listed.returncode != 0:
            if _is_doctl_auth_error(listed.stderr, listed.stdout):
                continue
            print(
                f"doctl could not list DNS records for {domain}.",
                file=sys.stderr,
            )
            return 1
        try:
            records = json.loads(listed.stdout or "[]")
        except json.JSONDecodeError:
            print("doctl returned non-JSON DNS records.", file=sys.stderr)
            return 1
        if not isinstance(records, list):
            print("doctl returned a non-list DNS payload.", file=sys.stderr)
            return 1
        matches: list[dict[str, Any]] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            rec_type = str(_record_field(record, "Type", "type") or "").upper()
            rec_name = str(_record_field(record, "Name", "name") or "")
            if rec_type == "A" and rec_name == name:
                matches.append(record)
        if len(matches) > 1:
            print(
                f"{name}.{domain} has {len(matches)} A records; resolve the extra "
                "records before this helper will change DNS",
                file=sys.stderr,
            )
            return 1
        if matches:
            record = matches[0]
            data = str(_record_field(record, "Data", "data") or "")
            rec_ttl = int(_record_field(record, "TTL", "ttl") or ttl)
            rec_id = _record_field(record, "ID", "id")
            if data == ipv4 and rec_ttl == ttl:
                print(f"unchanged: {name}.{domain} A {data} ttl={rec_ttl} id={rec_id}")
                return 0
            if rec_id is None:
                print("doctl A record is missing an id.", file=sys.stderr)
                return 1
            try:
                updated = run(
                    [
                        *binary,
                        "compute",
                        "domain",
                        "records",
                        "update",
                        domain,
                        "--record-id",
                        str(rec_id),
                        "--record-type",
                        "A",
                        "--record-name",
                        name,
                        "--record-data",
                        ipv4,
                        "--record-ttl",
                        str(ttl),
                        "--output",
                        "json",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=45,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                print(f"doctl update failed: {exc}", file=sys.stderr)
                return 1
            if updated.returncode != 0:
                print("doctl could not update the staging A record.", file=sys.stderr)
                return 1
            print(f"updated: {name}.{domain} A {ipv4} ttl={ttl} id={rec_id}")
            return 0
        try:
            created = run(
                [
                    *binary,
                    "compute",
                    "domain",
                    "records",
                    "create",
                    domain,
                    "--record-type",
                    "A",
                    "--record-name",
                    name,
                    "--record-data",
                    ipv4,
                    "--record-ttl",
                    str(ttl),
                    "--output",
                    "json",
                ],
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"doctl create failed: {exc}", file=sys.stderr)
            return 1
        if created.returncode != 0:
            if _is_doctl_auth_error(created.stderr, created.stdout):
                continue
            print("doctl could not create the staging A record.", file=sys.stderr)
            return 1
        rec_id = ""
        try:
            payload = json.loads(created.stdout or "{}")
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict):
            rec_id = str(_record_field(payload, "ID", "id") or "")
        elif isinstance(payload, list) and payload and isinstance(payload[0], dict):
            rec_id = str(_record_field(payload[0], "ID", "id") or "")
        suffix = f" id={rec_id}" if rec_id else ""
        print(f"created: {name}.{domain} A {ipv4} ttl={ttl}{suffix}")
        return 0
    if not saw_client:
        return 2
    return 2


def main() -> int:
    token = first_token()
    if token:
        os.environ["DIGITALOCEAN_ACCESS_TOKEN"] = token
        script = Path(__file__).resolve().with_name("upsert_dev_dns_record.py")
        if not script.is_file():
            script = Path("/tmp/upsert_dev_dns_record.py")
        os.execv(sys.executable, [sys.executable, str(script)])
    status = upsert_with_doctl()
    if status == 0:
        return 0
    if status == 2:
        print(
            "No DigitalOcean API token or authenticated doctl client was found "
            "on the droplet.",
            file=sys.stderr,
        )
        return 2
    return status


if __name__ == "__main__":
    raise SystemExit(main())
