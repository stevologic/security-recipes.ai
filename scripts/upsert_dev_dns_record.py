#!/usr/bin/env python3
"""Create or update the DigitalOcean A record for dev.<domain>.

The production droplet already terminates TLS for security-recipes.ai.
Staging at dev.security-recipes.ai needs a public A record before Caddy
can obtain a certificate. This helper is the operator/CI path for that
record; it does not run on push.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


DEFAULT_DOMAIN = "security-recipes.ai"
DEFAULT_RECORD_NAME = "dev"
DEFAULT_IPV4 = "64.227.98.210"
DEFAULT_TTL = 300
API_ROOT = "https://api.digitalocean.com/v2"


class DnsError(RuntimeError):
    """DigitalOcean DNS API call failed."""


def api_request(
    token: str,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    opener: Any = None,
) -> dict[str, Any]:
    url = f"{API_ROOT}{path}"
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    try:
        if opener is None:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
        else:
            with opener(request, timeout=30) as response:
                raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise DnsError(f"{method} {path} failed: HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise DnsError(f"{method} {path} failed: {exc.reason}") from exc
    if not raw:
        return {}
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise DnsError(f"{method} {path} returned a non-object payload")
    return parsed


def list_a_records(
    token: str,
    domain: str,
    name: str,
    opener: Any = None,
) -> list[dict[str, Any]]:
    query = urllib.parse.urlencode({"type": "A", "name": name, "per_page": 200})
    payload = api_request(
        token,
        "GET",
        f"/domains/{urllib.parse.quote(domain)}/records?{query}",
        opener=opener,
    )
    records = payload.get("domain_records")
    if not isinstance(records, list):
        raise DnsError("DigitalOcean omitted domain_records from the list response")
    matches: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        if str(record.get("type", "")).upper() != "A":
            continue
        if str(record.get("name", "")) != name:
            continue
        matches.append(record)
    return matches


def upsert_a_record(
    token: str,
    domain: str,
    name: str,
    ipv4: str,
    ttl: int,
    opener: Any = None,
) -> dict[str, Any]:
    existing = list_a_records(token, domain, name, opener=opener)
    if len(existing) > 1:
        raise DnsError(
            f"{name}.{domain} has {len(existing)} A records; resolve the extra "
            "records before this helper will change DNS"
        )
    body = {"type": "A", "name": name, "data": ipv4, "ttl": ttl}
    if not existing:
        created = api_request(
            token,
            "POST",
            f"/domains/{urllib.parse.quote(domain)}/records",
            payload=body,
            opener=opener,
        )
        record = created.get("domain_record")
        if not isinstance(record, dict):
            raise DnsError("DigitalOcean omitted domain_record from the create response")
        return {"action": "created", "record": record}
    record = existing[0]
    if str(record.get("data", "")) == ipv4 and int(record.get("ttl") or ttl) == ttl:
        return {"action": "unchanged", "record": record}
    record_id = record.get("id")
    if not isinstance(record_id, int):
        raise DnsError("DigitalOcean A record is missing a numeric id")
    updated = api_request(
        token,
        "PUT",
        f"/domains/{urllib.parse.quote(domain)}/records/{record_id}",
        payload=body,
        opener=opener,
    )
    next_record = updated.get("domain_record", record)
    if not isinstance(next_record, dict):
        raise DnsError("DigitalOcean omitted domain_record from the update response")
    return {"action": "updated", "record": next_record}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create or update the DigitalOcean A record for the staging hostname."
    )
    parser.add_argument(
        "--domain",
        default=os.environ.get("SECURITY_RECIPES_DOMAIN", DEFAULT_DOMAIN),
        help=f"Apex domain hosted on DigitalOcean DNS (default: {DEFAULT_DOMAIN})",
    )
    parser.add_argument(
        "--name",
        default=os.environ.get("SECURITY_RECIPES_DEV_RECORD", DEFAULT_RECORD_NAME),
        help=f"Record name under the apex (default: {DEFAULT_RECORD_NAME})",
    )
    parser.add_argument(
        "--ipv4",
        default=os.environ.get("SECURITY_RECIPES_DROPLET_IPV4", DEFAULT_IPV4),
        help=f"Droplet IPv4 address (default: {DEFAULT_IPV4})",
    )
    parser.add_argument(
        "--ttl",
        type=int,
        default=int(os.environ.get("SECURITY_RECIPES_DEV_DNS_TTL", str(DEFAULT_TTL))),
        help=f"Record TTL in seconds (default: {DEFAULT_TTL})",
    )
    parser.add_argument(
        "--token-env",
        default="DIGITALOCEAN_ACCESS_TOKEN",
        help="Environment variable holding the DigitalOcean API token",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    token = os.environ.get(args.token_env, "").strip()
    if not token:
        print(
            f"{args.token_env} is not set; cannot update {args.name}.{args.domain}",
            file=sys.stderr,
        )
        return 2
    try:
        result = upsert_a_record(
            token,
            args.domain,
            args.name,
            args.ipv4,
            args.ttl,
        )
    except DnsError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    record = result["record"]
    print(
        f"{result['action']}: {args.name}.{args.domain} "
        f"A {record.get('data')} ttl={record.get('ttl')} id={record.get('id')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
