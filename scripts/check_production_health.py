#!/usr/bin/env python3
"""Probe the production site, catalog freshness, deployment revision, and TLS."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USER_AGENT = "security-recipes.ai-production-watchdog/1"
MAX_RESPONSE_BYTES = 10 * 1024 * 1024


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    message: str
    warning: bool = False


def _utc_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _bounded_read(response: Any) -> bytes:
    payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ValueError("response exceeds the 10 MiB watchdog limit")
    return payload


def _request(
    url: str,
    *,
    timeout: float,
    opener: Callable[..., Any],
) -> tuple[bytes, str, str]:
    request = Request(
        url,
        headers={
            "Accept": "application/json,text/html;q=0.9,*/*;q=0.1",
            "Cache-Control": "no-cache",
            "User-Agent": USER_AGENT,
        },
    )
    with opener(request, timeout=timeout) as response:
        raw_status = getattr(response, "status", None)
        status = int(raw_status if raw_status is not None else response.getcode())
        if status != 200:
            raise ValueError(f"HTTP {status}")
        final_url = str(response.geturl())
        expected = urlsplit(url)
        final = urlsplit(final_url)
        if (final.scheme.lower(), final.hostname, final.port) != (
            expected.scheme.lower(),
            expected.hostname,
            expected.port,
        ):
            raise ValueError(f"unexpected cross-origin redirect to {final_url}")
        content_type = str(response.headers.get("Content-Type") or "")
        return _bounded_read(response), content_type, final_url


def _certificate_expiry(
    hostname: str,
    port: int,
    *,
    timeout: float,
) -> datetime:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((hostname, port), timeout=timeout) as connection:
        with context.wrap_socket(connection, server_hostname=hostname) as secure:
            certificate = secure.getpeercert()
    not_after = certificate.get("notAfter")
    if not isinstance(not_after, str):
        raise ValueError("TLS certificate has no notAfter value")
    return datetime.fromtimestamp(
        ssl.cert_time_to_seconds(not_after), tz=timezone.utc
    )


def run_probes(
    *,
    base_url: str,
    expected_revision: str,
    expected_commit_time: datetime,
    now: datetime | None = None,
    max_catalog_age_hours: float = 36.0,
    revision_grace_minutes: float = 45.0,
    min_tls_days: float = 21.0,
    timeout: float = 15.0,
    opener: Callable[..., Any] = urlopen,
    certificate_expiry: Callable[..., datetime] = _certificate_expiry,
    check_tls_expiry: bool = True,
) -> dict[str, Any]:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    normalized_base = base_url.rstrip("/") + "/"
    parsed_base = urlsplit(normalized_base)
    checks: list[Check] = []

    try:
        homepage, content_type, _ = _request(
            normalized_base, timeout=timeout, opener=opener
        )
        if not homepage.strip():
            raise ValueError("response body is empty")
        if "text/html" not in content_type.lower():
            raise ValueError(f"unexpected Content-Type {content_type!r}")
        checks.append(
            Check("homepage", True, f"Homepage returned {len(homepage):,} bytes.")
        )
    except Exception as exc:  # noqa: BLE001 - every probe must become a report.
        checks.append(Check("homepage", False, f"Homepage probe failed: {exc}"))

    manifest: dict[str, Any] | None = None
    manifest_url = urljoin(normalized_base, "api/cve-catalog/manifest.json")
    try:
        payload, content_type, _ = _request(
            manifest_url, timeout=timeout, opener=opener
        )
        if "json" not in content_type.lower():
            raise ValueError(f"unexpected Content-Type {content_type!r}")
        decoded = json.loads(payload)
        if not isinstance(decoded, dict):
            raise ValueError("manifest is not a JSON object")
        manifest = decoded
        totals = manifest.get("totals")
        records = totals.get("catalog_records") if isinstance(totals, dict) else None
        if isinstance(records, bool) or not isinstance(records, int) or records <= 0:
            raise ValueError("manifest catalog_records is missing or empty")
        updated_at = _utc_timestamp(manifest.get("catalog_updated_at"))
        if updated_at is None:
            raise ValueError("manifest catalog_updated_at is invalid")
        age = current - updated_at
        if age < -timedelta(hours=6):
            raise ValueError("manifest timestamp is more than six hours in the future")
        if age > timedelta(hours=max_catalog_age_hours):
            raise ValueError(
                f"catalog is {age.total_seconds() / 3600:.1f} hours old "
                f"(limit {max_catalog_age_hours:g})"
            )
        checks.append(
            Check(
                "catalog",
                True,
                f"Catalog has {records:,} records and is "
                f"{max(0.0, age.total_seconds() / 3600):.1f} hours old.",
            )
        )
    except Exception as exc:  # noqa: BLE001 - every probe must become a report.
        checks.append(Check("catalog", False, f"Catalog probe failed: {exc}"))

    revision_url = urljoin(normalized_base, ".well-known/deploy-revision")
    deployed_revision = ""
    try:
        payload, _, _ = _request(revision_url, timeout=timeout, opener=opener)
        deployed_revision = payload.decode("ascii").strip().lower()
        if not SHA_RE.fullmatch(deployed_revision):
            raise ValueError("revision marker is not a full lowercase Git SHA")
        if deployed_revision == expected_revision.lower():
            checks.append(
                Check(
                    "revision",
                    True,
                    f"Production serves expected revision {deployed_revision[:12]}.",
                )
            )
        else:
            head_age = current - expected_commit_time.astimezone(timezone.utc)
            message = (
                f"Production serves {deployed_revision[:12]}, while main is "
                f"{expected_revision[:12]}."
            )
            if head_age <= timedelta(minutes=revision_grace_minutes):
                checks.append(
                    Check(
                        "revision",
                        True,
                        message
                        + f" Main is within the {revision_grace_minutes:g}-minute "
                        "deployment grace period.",
                        warning=True,
                    )
                )
            else:
                checks.append(Check("revision", False, message))
    except Exception as exc:  # noqa: BLE001 - every probe must become a report.
        checks.append(Check("revision", False, f"Revision probe failed: {exc}"))

    if parsed_base.scheme.lower() == "https" and check_tls_expiry:
        hostname = parsed_base.hostname
        if not hostname:
            checks.append(Check("tls", False, "Production URL has no TLS hostname."))
        else:
            try:
                expires = certificate_expiry(
                    hostname,
                    parsed_base.port or 443,
                    timeout=timeout,
                )
                remaining = expires - current
                if remaining < timedelta(days=min_tls_days):
                    raise ValueError(
                        f"certificate expires in {remaining.total_seconds() / 86400:.1f} "
                        f"days (limit {min_tls_days:g})"
                    )
                checks.append(
                    Check(
                        "tls",
                        True,
                        f"TLS certificate expires in "
                        f"{remaining.total_seconds() / 86400:.1f} days.",
                    )
                )
            except Exception as exc:  # noqa: BLE001 - report TLS failures.
                checks.append(Check("tls", False, f"TLS probe failed: {exc}"))

    failures = [check for check in checks if not check.ok]
    warnings = [check for check in checks if check.warning]
    return {
        "schema_version": 1,
        "checked_at": current.replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "base_url": normalized_base.rstrip("/"),
        "expected_revision": expected_revision.lower(),
        "deployed_revision": deployed_revision or None,
        "catalog_updated_at": (
            manifest.get("catalog_updated_at") if manifest is not None else None
        ),
        "healthy": not failures,
        "checks": [asdict(check) for check in checks],
        "failure_count": len(failures),
        "warning_count": len(warnings),
    }


def markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "## Production watchdog",
        "",
        f"- Overall status: **{'healthy' if report.get('healthy') else 'UNHEALTHY'}**",
        f"- Site: {report.get('base_url')}",
        f"- Checked: {report.get('checked_at')}",
        "",
        "### Checks",
        "",
    ]
    for check in report.get("checks") or []:
        if not isinstance(check, dict):
            continue
        status = "warning" if check.get("warning") else "pass" if check.get("ok") else "FAIL"
        lines.append(
            f"- **{check.get('name', 'unknown')}** — {status}: "
            f"{check.get('message', '')}"
        )
    return "\n".join(lines) + "\n"


def _write_github_output(path: Path, report: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(f"healthy={'true' if report.get('healthy') else 'false'}\n")
        stream.write(f"failure_count={report.get('failure_count', 0)}\n")
        stream.write(f"warning_count={report.get('warning_count', 0)}\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--expected-commit-time", required=True)
    parser.add_argument("--max-catalog-age-hours", type=float, default=36.0)
    parser.add_argument("--revision-grace-minutes", type=float, default=45.0)
    parser.add_argument("--min-tls-days", type=float, default=21.0)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--skip-tls-expiry", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    expected_revision = args.expected_revision.strip().lower()
    expected_time = _utc_timestamp(args.expected_commit_time)
    parsed_base = urlsplit(args.base_url)
    if (
        parsed_base.scheme.lower() not in {"http", "https"}
        or not parsed_base.hostname
        or parsed_base.username is not None
        or parsed_base.password is not None
    ):
        print("--base-url must be an absolute HTTP(S) URL without credentials", file=sys.stderr)
        return 2
    if not SHA_RE.fullmatch(expected_revision):
        print("--expected-revision must be a full lowercase Git SHA", file=sys.stderr)
        return 2
    if expected_time is None:
        print("--expected-commit-time must be an ISO-8601 timestamp", file=sys.stderr)
        return 2
    if (
        args.max_catalog_age_hours <= 0
        or args.revision_grace_minutes < 0
        or args.min_tls_days < 0
        or args.timeout <= 0
    ):
        print("watchdog thresholds must be non-negative and timeout must be positive", file=sys.stderr)
        return 2

    report = run_probes(
        base_url=args.base_url,
        expected_revision=expected_revision,
        expected_commit_time=expected_time,
        max_catalog_age_hours=args.max_catalog_age_hours,
        revision_grace_minutes=args.revision_grace_minutes,
        min_tls_days=args.min_tls_days,
        timeout=args.timeout,
        check_tls_expiry=not args.skip_tls_expiry,
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    args.markdown.write_text(markdown_report(report), encoding="utf-8")
    output_path = args.github_output
    if output_path is None and os.environ.get("GITHUB_OUTPUT"):
        output_path = Path(os.environ["GITHUB_OUTPUT"])
    if output_path is not None:
        _write_github_output(output_path, report)
    print(markdown_report(report), end="")
    return 0 if report["healthy"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
