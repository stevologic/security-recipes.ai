#!/usr/bin/env python3
"""Probe the production site, catalog freshness, deployment revision, and TLS."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import Request, urlopen


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
USER_AGENT = "security-recipes.ai-production-watchdog/1"
GOOGLEBOT_USER_AGENT = (
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)
MAX_RESPONSE_BYTES = 10 * 1024 * 1024
DEFAULT_CVE_PROBE_ID = "CVE-2024-3400"
DEFAULT_EXCLUDED_CVE_PROBE_ID = "CVE-2024-21412"
MAX_SITEMAP_URLS = 49_000
QUALIFIED_CVE_TYPES = frozenset({"stable_markdown", "recipe_ready_ai"})
CVE_SITEMAP_PATH_RE = re.compile(r"^/sitemaps/cves-(\d{4})(?:-\d+)?\.xml$")
FORBIDDEN_SEARCH_SPAM = (
    re.compile(r"\b(?:NADIMTOGEL|BUGISTOTO)\b", re.IGNORECASE),
    re.compile(r"\bslot\s+gacor\b", re.IGNORECASE),
    re.compile(r"\btogel\b", re.IGNORECASE),
    re.compile(r"\bgampang\s+scatter\s+maxwin\b", re.IGNORECASE),
)
CONTENT_INTEGRITY_PROBES = (
    (
        "homepage",
        "",
        re.compile(
            r"<h1\b[^>]*>\s*Search CVEs\. Remediate vulnerabilities with AI agents",
            re.IGNORECASE,
        ),
        (),
    ),
    (
        "CVE database",
        "cve-database/",
        re.compile(r"<h1\b[^>]*>\s*CVE Database\s*</h1>", re.IGNORECASE),
        (
            (
                "database page title",
                re.compile(
                    r"<title>\s*CVE Database\s*\|\s*Security Recipes\s*</title>",
                    re.IGNORECASE,
                ),
            ),
            (
                "database meta description",
                re.compile(
                    r"<meta\b(?=[^>]*\bname=[\"']description[\"'])"
                    r"(?=[^>]*\bcontent=[\"'][^\"']*\bCVE database\b[^\"']*"
                    r"\bsourced facts\b[^\"']*[\"'])[^>]*>",
                    re.IGNORECASE,
                ),
            ),
            (
                "canonical URL",
                re.compile(
                    r"<link\b(?=[^>]*\brel=[\"']canonical[\"'])"
                    r"(?=[^>]*\bhref=[\"']https://security-recipes\.ai/"
                    r"cve-database/[\"'])[^>]*>",
                    re.IGNORECASE,
                ),
            ),
            (
                "indexable robots directive",
                re.compile(
                    r"<meta\b(?=[^>]*\bname=[\"']robots[\"'])"
                    r"(?=[^>]*\bcontent=[\"']index,follow(?:,[^\"']*)?[\"'])[^>]*>",
                    re.IGNORECASE,
                ),
            ),
            (
                "Dataset structured data",
                re.compile(
                    r"[\"']@type[\"']\s*:\s*[\"']Dataset[\"']", re.IGNORECASE
                ),
            ),
            (
                "evidence-qualified CVE route payload",
                re.compile(r"\bdata-cve-qualified-routes\b", re.IGNORECASE),
            ),
        ),
    ),
    (
        "AI agent security guide",
        "agentic-security/",
        re.compile(
            r"<h1\b[^>]*>\s*AI Agent Security: How to Secure AI Agent Systems\s*</h1>",
            re.IGNORECASE,
        ),
        (
            (
                "query-specific page title",
                re.compile(
                    r"<title>\s*AI Agent Security: How to Secure AI Agent Systems\s*</title>",
                    re.IGNORECASE,
                ),
            ),
            (
                "agent-security meta description",
                re.compile(
                    r"<meta\b(?=[^>]*\bname=[\"']description[\"'])"
                    r"(?=[^>]*\bcontent=[\"']Secure AI agent systems against prompt "
                    r"injection, tool abuse, excessive permissions, unsafe memory, "
                    r"connector risk, and weak incident response\.[\"'])[^>]*>",
                    re.IGNORECASE,
                ),
            ),
            (
                "canonical URL",
                re.compile(
                    r"<link\b(?=[^>]*\brel=[\"']canonical[\"'])"
                    r"(?=[^>]*\bhref=[\"']https://security-recipes\.ai/"
                    r"agentic-security/[\"'])[^>]*>",
                    re.IGNORECASE,
                ),
            ),
            (
                "indexable robots directive",
                re.compile(
                    r"<meta\b(?=[^>]*\bname=[\"']robots[\"'])"
                    r"(?=[^>]*\bcontent=[\"']index,follow(?:,[^\"']*)?[\"'])[^>]*>",
                    re.IGNORECASE,
                ),
            ),
            (
                "CollectionPage structured data",
                re.compile(
                    r"[\"']@type[\"']\s*:\s*[\"']CollectionPage[\"']",
                    re.IGNORECASE,
                ),
            ),
        ),
    ),
    (
        "Codex guide",
        "codex/",
        re.compile(
            r"<h1\b[^>]*>\s*Codex(?: Vulnerability Remediation)?\s*</h1>",
            re.IGNORECASE,
        ),
        (),
    ),
    (
        "automation guide",
        "automation/",
        re.compile(
            r"<h1\b[^>]*>\s*(?:Automation(?:, not agentic)?|Automated Vulnerability Remediation"
            r"(?: Without AI Agents)?)\s*</h1>",
            re.IGNORECASE,
        ),
        (),
    ),
    (
        "AI remediation guide",
        "security-remediation/",
        re.compile(
            r"<h1\b[^>]*>\s*How to Remediate Vulnerabilities with AI Agents\s*</h1>",
            re.IGNORECASE,
        ),
        (
            (
                "query-specific page title",
                re.compile(
                    r"<title>\s*How to Remediate Vulnerabilities with AI Agents\s*</title>",
                    re.IGNORECASE,
                ),
            ),
            (
                "remediation meta description",
                re.compile(
                    r"<meta\b(?=[^>]*\bname=[\"']description[\"'])"
                    r"(?=[^>]*\bcontent=[\"']Learn how to remediate software vulnerabilities "
                    r"with AI coding agents using scoped playbooks, source evidence, tests, "
                    r"rollback, and human review\.[\"'])[^>]*>",
                    re.IGNORECASE,
                ),
            ),
            (
                "canonical URL",
                re.compile(
                    r"<link\b(?=[^>]*\brel=[\"']canonical[\"'])"
                    r"(?=[^>]*\bhref=[\"']https://security-recipes\.ai/"
                    r"security-remediation/[\"'])[^>]*>",
                    re.IGNORECASE,
                ),
            ),
            (
                "indexable robots directive",
                re.compile(
                    r"<meta\b(?=[^>]*\bname=[\"']robots[\"'])"
                    r"(?=[^>]*\bcontent=[\"']index,follow(?:,[^\"']*)?[\"'])[^>]*>",
                    re.IGNORECASE,
                ),
            ),
            (
                "HowTo structured data",
                re.compile(r"[\"']@type[\"']\s*:\s*[\"']HowTo[\"']", re.IGNORECASE),
            ),
        ),
    ),
    (
        "AI agent comparison",
        "agents/",
        re.compile(
            r"<h1\b[^>]*>\s*AI Coding Agents for Vulnerability Remediation\s*</h1>",
            re.IGNORECASE,
        ),
        (
            (
                "query-specific page title",
                re.compile(
                    r"<title>\s*AI Coding Agents for Vulnerability Remediation"
                    r"\s*\|\s*Security Recipes\s*</title>",
                    re.IGNORECASE,
                ),
            ),
            (
                "agent-comparison meta description",
                re.compile(
                    r"<meta\b(?=[^>]*\bname=[\"']description[\"'])"
                    r"(?=[^>]*\bcontent=[\"'][^\"']*\bCompare\b[^\"']*"
                    r"\bAI vulnerability remediation\b[^\"']*[\"'])[^>]*>",
                    re.IGNORECASE,
                ),
            ),
            (
                "canonical URL",
                re.compile(
                    r"<link\b(?=[^>]*\brel=[\"']canonical[\"'])"
                    r"(?=[^>]*\bhref=[\"']https://security-recipes\.ai/agents/[\"'])"
                    r"[^>]*>",
                    re.IGNORECASE,
                ),
            ),
            (
                "indexable robots directive",
                re.compile(
                    r"<meta\b(?=[^>]*\bname=[\"']robots[\"'])"
                    r"(?=[^>]*\bcontent=[\"']index,follow(?:,[^\"']*)?[\"'])[^>]*>",
                    re.IGNORECASE,
                ),
            ),
        ),
    ),
)


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
    expected_final_url: str | None = None,
    user_agent: str = USER_AGENT,
) -> tuple[bytes, str, str, dict[str, str]]:
    request = Request(
        url,
        headers={
            "Accept": "application/json,text/html;q=0.9,*/*;q=0.1",
            "Cache-Control": "no-cache",
            "User-Agent": user_agent,
        },
    )
    with opener(request, timeout=timeout) as response:
        raw_status = getattr(response, "status", None)
        status = int(raw_status if raw_status is not None else response.getcode())
        if status != 200:
            raise ValueError(f"HTTP {status}")
        final_url = str(response.geturl())
        expected = urlsplit(expected_final_url or url)
        final = urlsplit(final_url)
        if (final.scheme.lower(), final.hostname, final.port) != (
            expected.scheme.lower(),
            expected.hostname,
            expected.port,
        ):
            raise ValueError(f"unexpected cross-origin redirect to {final_url}")
        if expected_final_url is not None and final_url != expected_final_url:
            raise ValueError(
                f"expected final URL {expected_final_url}, received {final_url}"
            )
        response_headers = {
            str(name).lower(): str(value)
            for name, value in response.headers.items()
        }
        content_type = response_headers.get("content-type", "")
        return _bounded_read(response), content_type, final_url, response_headers


def _robots_meta_directives(page: str) -> set[str]:
    directives: set[str] = set()
    for tag in re.findall(r"<meta\b[^>]*>", page, flags=re.IGNORECASE):
        attributes = {
            name.lower(): value
            for name, _quote, value in re.findall(
                r"([A-Za-z_:][A-Za-z0-9_.:-]*)\s*=\s*([\"'])(.*?)\2",
                tag,
                flags=re.DOTALL,
            )
        }
        if attributes.get("name", "").lower() not in {"robots", "googlebot"}:
            continue
        directives.update(
            token
            for token in re.split(r"[\s,]+", attributes.get("content", "").lower())
            if token
        )
    return directives


def _same_origin(candidate: str, base: Any) -> bool:
    parsed = urlsplit(candidate)
    return (
        parsed.scheme.lower(),
        parsed.hostname,
        parsed.port,
    ) == (
        base.scheme.lower(),
        base.hostname,
        base.port,
    )


def _validate_content_integrity(
    label: str,
    payload: bytes,
    expected_heading: re.Pattern[str],
    required_patterns: tuple[tuple[str, re.Pattern[str]], ...] = (),
) -> None:
    page = payload.decode("utf-8")
    if not expected_heading.search(page):
        raise ValueError(f"{label} is missing its expected primary heading")
    for requirement, pattern in required_patterns:
        if not pattern.search(page):
            raise ValueError(f"{label} is missing its expected {requirement}")
    for pattern in FORBIDDEN_SEARCH_SPAM:
        match = pattern.search(page)
        if match:
            raise ValueError(
                f"{label} contains a known search-spam signature: {match.group(0)!r}"
            )


def _www_probe_url(base_url: str) -> str | None:
    """Return the HTTPS www variant for a public apex hostname, if applicable."""
    parsed = urlsplit(base_url)
    hostname = parsed.hostname
    if parsed.scheme.lower() != "https" or not hostname:
        return None
    normalized_hostname = hostname.rstrip(".").lower()
    if normalized_hostname == "localhost" or normalized_hostname.startswith("www."):
        return None
    try:
        ipaddress.ip_address(normalized_hostname)
    except ValueError:
        pass
    else:
        return None
    if "." not in normalized_hostname:
        return None
    netloc = f"www.{normalized_hostname}"
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    return urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, "")
    )


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
    cve_probe_id: str = DEFAULT_CVE_PROBE_ID,
    excluded_cve_probe_id: str = DEFAULT_EXCLUDED_CVE_PROBE_ID,
    opener: Callable[..., Any] = urlopen,
    certificate_expiry: Callable[..., datetime] = _certificate_expiry,
    check_tls_expiry: bool = True,
) -> dict[str, Any]:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    normalized_base = base_url.rstrip("/") + "/"
    parsed_base = urlsplit(normalized_base)
    checks: list[Check] = []
    homepage_payload: bytes | None = None

    try:
        homepage, content_type, _, _ = _request(
            normalized_base, timeout=timeout, opener=opener
        )
        if not homepage.strip():
            raise ValueError("response body is empty")
        if "text/html" not in content_type.lower():
            raise ValueError(f"unexpected Content-Type {content_type!r}")
        homepage_payload = homepage
        checks.append(
            Check("homepage", True, f"Homepage returned {len(homepage):,} bytes.")
        )
    except Exception as exc:  # noqa: BLE001 - every probe must become a report.
        checks.append(Check("homepage", False, f"Homepage probe failed: {exc}"))

    try:
        compared_pages = 0
        for (
            label,
            relative_url,
            expected_heading,
            required_patterns,
        ) in CONTENT_INTEGRITY_PROBES:
            probe_url = urljoin(normalized_base, relative_url)
            if relative_url == "" and homepage_payload is not None:
                standard_payload = homepage_payload
            else:
                standard_payload, standard_type, _, _ = _request(
                    probe_url,
                    timeout=timeout,
                    opener=opener,
                    expected_final_url=probe_url,
                )
                if "text/html" not in standard_type.lower():
                    raise ValueError(
                        f"{label} returned unexpected Content-Type {standard_type!r}"
                    )
            googlebot_payload, googlebot_type, _, _ = _request(
                probe_url,
                timeout=timeout,
                opener=opener,
                expected_final_url=probe_url,
                user_agent=GOOGLEBOT_USER_AGENT,
            )
            if "text/html" not in googlebot_type.lower():
                raise ValueError(
                    f"{label} returned unexpected Googlebot Content-Type "
                    f"{googlebot_type!r}"
                )
            _validate_content_integrity(
                label,
                standard_payload,
                expected_heading,
                required_patterns,
            )
            _validate_content_integrity(
                f"{label} (Googlebot)",
                googlebot_payload,
                expected_heading,
                required_patterns,
            )
            if not hashlib.sha256(standard_payload).digest() == hashlib.sha256(
                googlebot_payload
            ).digest():
                raise ValueError(
                    f"{label} differs between the standard and Googlebot responses"
                )
            compared_pages += 1
        checks.append(
            Check(
                "content_integrity",
                True,
                f"{compared_pages} representative pages are clean and identical for "
                "standard and Googlebot requests.",
            )
        )
    except Exception as exc:  # noqa: BLE001 - every probe must become a report.
        checks.append(
            Check(
                "content_integrity",
                False,
                f"Content-integrity probe failed: {exc}",
            )
        )

    www_url = _www_probe_url(normalized_base)
    if www_url is not None:
        try:
            homepage, content_type, _, _ = _request(
                www_url,
                timeout=timeout,
                opener=opener,
                expected_final_url=normalized_base,
            )
            if not homepage.strip():
                raise ValueError("response body is empty")
            if "text/html" not in content_type.lower():
                raise ValueError(f"unexpected Content-Type {content_type!r}")
            checks.append(
                Check(
                    "canonical_host",
                    True,
                    f"{www_url} resolves over TLS and consolidates to {normalized_base}.",
                )
            )
        except Exception as exc:  # noqa: BLE001 - every probe becomes a report.
            checks.append(
                Check(
                    "canonical_host",
                    False,
                    f"Canonical-host probe failed for {www_url}: {exc}",
                )
            )

    robots_url = urljoin(normalized_base, "robots.txt")
    try:
        payload, content_type, final_url, _ = _request(
            robots_url, timeout=timeout, opener=opener
        )
        if "text/plain" not in content_type.lower():
            raise ValueError(f"unexpected Content-Type {content_type!r}")
        if final_url != robots_url:
            raise ValueError(f"unexpected robots.txt redirect to {final_url}")
        policy = payload.decode("utf-8")
        if not re.search(r"(?im)^\s*User-agent\s*:\s*\*\s*$", policy):
            raise ValueError("missing the shared User-agent: * group")
        if re.search(r"(?im)^\s*Disallow\s*:\s*(?:#.*)?$", policy):
            raise ValueError("contains a blank Disallow directive")
        if re.search(r"(?im)^\s*Disallow\s*:\s*/traffic(?:/|\s|$)", policy):
            raise ValueError("blocks /traffic/ before crawlers can read its noindex")
        sitemap_directives = {
            match.group(1).strip()
            for match in re.finditer(r"(?im)^\s*Sitemap\s*:\s*(\S+)\s*$", policy)
        }
        expected_sitemap = urljoin(normalized_base, "sitemap.xml")
        if expected_sitemap not in sitemap_directives:
            raise ValueError(f"does not advertise {expected_sitemap}")
        if any(not _same_origin(location, parsed_base) for location in sitemap_directives):
            raise ValueError("advertises a cross-origin sitemap")
        checks.append(
            Check(
                "robots",
                True,
                "robots.txt advertises the canonical sitemap without hiding noindex routes.",
            )
        )
    except Exception as exc:  # noqa: BLE001 - every probe becomes a report.
        checks.append(Check("robots", False, f"robots.txt probe failed: {exc}"))

    manifest: dict[str, Any] | None = None
    manifest_url = urljoin(normalized_base, "api/cve-catalog/manifest.json")
    try:
        payload, content_type, _, _ = _request(
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

    sitemap_url = urljoin(normalized_base, "sitemap.xml")
    qualified_cve_ids: set[str] | None = None
    try:
        qualified_url = urljoin(
            normalized_base, "api/cve-catalog/search-indexable.json"
        )
        qualified_payload, qualified_type, qualified_final, _ = _request(
            qualified_url, timeout=timeout, opener=opener
        )
        if "json" not in qualified_type.lower():
            raise ValueError(
                f"qualified CVE allowlist returned unexpected Content-Type "
                f"{qualified_type!r}"
            )
        if qualified_final != qualified_url:
            raise ValueError(
                f"unexpected qualified CVE allowlist redirect to {qualified_final}"
            )
        qualified_document = json.loads(qualified_payload)
        qualified_records = (
            qualified_document.get("records")
            if isinstance(qualified_document, dict)
            else None
        )
        if not isinstance(qualified_records, list) or not qualified_records:
            raise ValueError("qualified CVE allowlist has no records")
        qualified_cve_ids = set()
        qualified_cve_years: dict[str, str] = {}
        for record in qualified_records:
            if not isinstance(record, dict):
                raise ValueError("qualified CVE allowlist contains a non-object record")
            cve = str(record.get("cve") or "")
            qualification = str(record.get("qualification") or "")
            if not CVE_RE.fullmatch(cve):
                raise ValueError(f"qualified CVE allowlist contains invalid ID {cve!r}")
            if qualification not in QUALIFIED_CVE_TYPES:
                raise ValueError(
                    f"qualified CVE allowlist contains invalid qualification for {cve}"
                )
            published = _utc_timestamp(record.get("published"))
            if published is None:
                raise ValueError(
                    f"qualified CVE allowlist contains invalid publication date for {cve}"
                )
            if cve in qualified_cve_ids:
                raise ValueError(f"qualified CVE allowlist duplicates {cve}")
            qualified_cve_ids.add(cve)
            qualified_cve_years[cve] = str(published.year)
        if cve_probe_id not in qualified_cve_ids:
            raise ValueError(f"indexable probe {cve_probe_id} is absent from the allowlist")
        if excluded_cve_probe_id in qualified_cve_ids:
            raise ValueError(
                f"excluded probe {excluded_cve_probe_id} unexpectedly entered the allowlist"
            )

        payload, content_type, final_url, _ = _request(
            sitemap_url, timeout=timeout, opener=opener
        )
        if "xml" not in content_type.lower():
            raise ValueError(f"unexpected Content-Type {content_type!r}")
        if final_url != sitemap_url:
            raise ValueError(f"unexpected sitemap redirect to {final_url}")
        document = ET.fromstring(payload)
        namespace = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
        if document.tag != f"{namespace}sitemapindex":
            raise ValueError("root sitemap is not a sitemap index")
        locations = [
            str(node.text or "").strip()
            for node in document.findall(f"{namespace}sitemap/{namespace}loc")
        ]
        if not locations or len(locations) != len(set(locations)):
            raise ValueError("root sitemap has missing or duplicate child locations")
        expected_pages = urljoin(normalized_base, "sitemaps/pages.xml")
        if expected_pages not in locations:
            raise ValueError("root sitemap does not include the pages sitemap")
        cve_sitemap_locations = [
            location for location in locations if location != expected_pages
        ]
        if not cve_sitemap_locations:
            raise ValueError("root sitemap does not include a CVE sitemap")
        for location in locations:
            parsed_location = urlsplit(location)
            if not _same_origin(location, parsed_base):
                raise ValueError(f"sitemap index exposes a cross-origin URL: {location}")
            if parsed_location.query or parsed_location.fragment:
                raise ValueError(f"sitemap index exposes a non-canonical URL: {location}")

        pages_payload, pages_type, pages_final, _ = _request(
            expected_pages, timeout=timeout, opener=opener
        )
        if "xml" not in pages_type.lower() or pages_final != expected_pages:
            raise ValueError("pages sitemap is unavailable at its canonical URL")
        pages_document = ET.fromstring(pages_payload)
        if pages_document.tag != f"{namespace}urlset":
            raise ValueError("pages sitemap is not a URL set")
        page_locations = [
            str(node.text or "").strip()
            for node in pages_document.findall(f"{namespace}url/{namespace}loc")
        ]
        if not page_locations or len(page_locations) != len(set(page_locations)):
            raise ValueError("pages sitemap has missing or duplicate URLs")
        page_cve_ids: set[str] = set()
        for location in page_locations:
            if not _same_origin(location, parsed_base):
                raise ValueError(f"pages sitemap exposes a cross-origin URL: {location}")
            parsed_location = urlsplit(location)
            if parsed_location.query or parsed_location.fragment:
                raise ValueError(f"pages sitemap exposes a non-canonical URL: {location}")
            page_cve_ids.update(
                re.findall(r"CVE-\d{4}-\d{4,}", parsed_location.path.upper())
            )

        dynamic_cve_ids: set[str] = set()
        child_url_count = 0
        for location in cve_sitemap_locations:
            parsed_location = urlsplit(location)
            match = CVE_SITEMAP_PATH_RE.fullmatch(parsed_location.path)
            if match is None:
                raise ValueError(f"unexpected sitemap child URL: {location}")
            child_payload, child_type, child_final, _ = _request(
                location, timeout=timeout, opener=opener
            )
            if "xml" not in child_type.lower() or child_final != location:
                raise ValueError(f"CVE sitemap is unavailable at {location}")
            child_document = ET.fromstring(child_payload)
            if child_document.tag != f"{namespace}urlset":
                raise ValueError(f"CVE sitemap is not a URL set: {location}")
            child_locations = [
                str(node.text or "").strip()
                for node in child_document.findall(f"{namespace}url/{namespace}loc")
            ]
            if not 1 <= len(child_locations) <= MAX_SITEMAP_URLS:
                raise ValueError(
                    f"CVE sitemap {location} has {len(child_locations):,} URLs; "
                    f"expected 1..{MAX_SITEMAP_URLS:,}"
                )
            child_url_count += len(child_locations)
            for child_location in child_locations:
                if not _same_origin(child_location, parsed_base):
                    raise ValueError(
                        f"CVE sitemap exposes a cross-origin URL: {child_location}"
                    )
                child_parsed = urlsplit(child_location)
                route_match = re.fullmatch(
                    r"/cve/(CVE-\d{4}-\d{4,})/", child_parsed.path
                )
                if (
                    route_match is None
                    or child_parsed.query
                    or child_parsed.fragment
                ):
                    raise ValueError(
                        f"CVE sitemap exposes a non-canonical URL: {child_location}"
                    )
                cve = route_match.group(1)
                if cve not in qualified_cve_ids:
                    raise ValueError(f"CVE sitemap exposes unqualified record {cve}")
                if qualified_cve_years[cve] != match.group(1):
                    raise ValueError(f"{cve} appears in the wrong yearly sitemap")
                if cve in dynamic_cve_ids:
                    raise ValueError(f"CVE sitemap duplicates {cve}")
                dynamic_cve_ids.add(cve)

        static_qualified_ids = page_cve_ids & qualified_cve_ids
        overlap = dynamic_cve_ids & static_qualified_ids
        if overlap:
            raise ValueError(
                f"qualified CVE appears in both sitemap surfaces: {sorted(overlap)[0]}"
            )
        observed_qualified_ids = dynamic_cve_ids | static_qualified_ids
        if observed_qualified_ids != qualified_cve_ids:
            missing = sorted(qualified_cve_ids - observed_qualified_ids)
            extra = sorted(observed_qualified_ids - qualified_cve_ids)
            detail = f"missing={missing[:3]}, extra={extra[:3]}"
            raise ValueError(f"sitemap membership differs from the allowlist ({detail})")
        if excluded_cve_probe_id in dynamic_cve_ids or excluded_cve_probe_id in page_cve_ids:
            raise ValueError(f"excluded probe {excluded_cve_probe_id} appears in a sitemap")
        checks.append(
            Check(
                "sitemap",
                True,
                f"Sitemaps expose exactly {len(qualified_cve_ids):,} qualified CVEs "
                f"across {len(cve_sitemap_locations):,} bounded CVE children "
                f"({child_url_count:,} dynamic; {len(static_qualified_ids):,} static).",
            )
        )
    except Exception as exc:  # noqa: BLE001 - every probe must become a report.
        checks.append(Check("sitemap", False, f"Sitemap probe failed: {exc}"))

    cve_url = urljoin(normalized_base, f"cve/{cve_probe_id}/")
    try:
        payload, content_type, final_url, _ = _request(
            cve_url, timeout=timeout, opener=opener
        )
        if "text/html" not in content_type.lower():
            raise ValueError(f"unexpected Content-Type {content_type!r}")
        if final_url != cve_url:
            raise ValueError(f"unexpected canonical CVE redirect to {final_url}")
        page = payload.decode("utf-8")
        required_fragments = {
            "title": f"<title>{cve_probe_id}",
            "meta description": '<meta name="description" content="',
            "canonical": f'<link rel="canonical" href="{cve_url}">',
            "indexable robots": '<meta name="robots" content="index,follow',
            "Article JSON-LD": '"@type":"Article"',
            "TechArticle semantics": '"additionalType":"https://schema.org/TechArticle"',
            "server-rendered CVE identity": f'data-cve-initial-id="{cve_probe_id}"',
            "CVE detail stylesheet": '<link rel="stylesheet" href="/css/cve-detail.css">',
            "site-themed CVE body": '<body class="sr-docs-body sr-cve-detail-page"',
            "CVE database breadcrumb": '<a href="/cve-database/">CVE Database</a>',
            "query-specific primary heading": (
                f'<h1 class="sr-page-title">{cve_probe_id}:'
            ),
        }
        missing = [
            label for label, fragment in required_fragments.items() if fragment not in page
        ]
        if missing:
            raise ValueError(f"missing {', '.join(missing)}")
        if "noindex" in _robots_meta_directives(page):
            raise ValueError("canonical CVE page is marked noindex")
        checks.append(
            Check(
                "cve_landing",
                True,
                f"{cve_probe_id} returned an indexable, server-rendered TechArticle.",
            )
        )
    except Exception as exc:  # noqa: BLE001 - every probe must become a report.
        checks.append(Check("cve_landing", False, f"CVE landing probe failed: {exc}"))

    excluded_cve_url = urljoin(
        normalized_base, f"cve/{excluded_cve_probe_id}/"
    )
    try:
        if qualified_cve_ids is None:
            raise ValueError("qualified CVE allowlist could not be verified")
        if excluded_cve_probe_id in qualified_cve_ids:
            raise ValueError("probe is unexpectedly search-indexable")
        payload, content_type, final_url, _ = _request(
            excluded_cve_url, timeout=timeout, opener=opener
        )
        if "text/html" not in content_type.lower():
            raise ValueError(f"unexpected Content-Type {content_type!r}")
        if final_url != excluded_cve_url:
            raise ValueError(f"unexpected excluded CVE redirect to {final_url}")
        page = payload.decode("utf-8")
        directives = _robots_meta_directives(page)
        if "noindex" not in directives:
            raise ValueError("generic excluded CVE page is missing noindex")
        if "index" in directives:
            raise ValueError("generic excluded CVE page has conflicting index directive")
        checks.append(
            Check(
                "excluded_cve",
                True,
                f"{excluded_cve_probe_id} remains available for users but excluded "
                "from search indexing.",
            )
        )
    except Exception as exc:  # noqa: BLE001 - every probe becomes a report.
        checks.append(
            Check("excluded_cve", False, f"Excluded CVE probe failed: {exc}")
        )

    traffic_url = urljoin(normalized_base, "traffic/")
    try:
        _, content_type, final_url, headers = _request(
            traffic_url, timeout=timeout, opener=opener
        )
        if "text/html" not in content_type.lower():
            raise ValueError(f"unexpected Content-Type {content_type!r}")
        if final_url != traffic_url:
            raise ValueError(f"unexpected traffic dashboard redirect to {final_url}")
        directives = {
            token
            for token in re.split(
                r"[\s,]+", headers.get("x-robots-tag", "").lower()
            )
            if token
        }
        if "noindex" not in directives:
            raise ValueError("X-Robots-Tag is missing noindex")
        checks.append(
            Check(
                "traffic_noindex",
                True,
                "Traffic dashboard sends an X-Robots-Tag noindex directive.",
            )
        )
    except Exception as exc:  # noqa: BLE001 - every probe becomes a report.
        checks.append(
            Check(
                "traffic_noindex",
                False,
                f"Traffic dashboard noindex probe failed: {exc}",
            )
        )

    revision_url = urljoin(normalized_base, ".well-known/deploy-revision")
    deployed_revision = ""
    try:
        payload, _, _, _ = _request(revision_url, timeout=timeout, opener=opener)
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
                tls_targets = [(hostname, parsed_base.port or 443)]
                if www_url is not None:
                    parsed_www = urlsplit(www_url)
                    if parsed_www.hostname:
                        tls_targets.append(
                            (parsed_www.hostname, parsed_www.port or 443)
                        )
                remaining_by_host: list[tuple[str, timedelta]] = []
                for tls_hostname, tls_port in tls_targets:
                    expires = certificate_expiry(
                        tls_hostname,
                        tls_port,
                        timeout=timeout,
                    )
                    remaining = expires - current
                    if remaining < timedelta(days=min_tls_days):
                        raise ValueError(
                            f"{tls_hostname} certificate expires in "
                            f"{remaining.total_seconds() / 86400:.1f} days "
                            f"(limit {min_tls_days:g})"
                        )
                    remaining_by_host.append((tls_hostname, remaining))
                shortest = min(
                    remaining.total_seconds() / 86400
                    for _, remaining in remaining_by_host
                )
                checks.append(
                    Check(
                        "tls",
                        True,
                        f"TLS certificates for {len(remaining_by_host)} canonical "
                        f"hostnames remain valid for at least {shortest:.1f} days.",
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
        "cve_probe_id": cve_probe_id,
        "excluded_cve_probe_id": excluded_cve_probe_id,
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
    parser.add_argument(
        "--cve-probe-id",
        default=os.environ.get("WATCHDOG_CVE_PROBE_ID", DEFAULT_CVE_PROBE_ID),
        help="Stable catalog CVE used to verify the canonical HTML landing route.",
    )
    parser.add_argument(
        "--excluded-cve-probe-id",
        default=os.environ.get(
            "WATCHDOG_EXCLUDED_CVE_PROBE_ID", DEFAULT_EXCLUDED_CVE_PROBE_ID
        ),
        help="Catalog CVE outside the search allowlist used to verify noindex.",
    )
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
    cve_probe_id = args.cve_probe_id.strip().upper()
    if not CVE_RE.fullmatch(cve_probe_id):
        print("--cve-probe-id must use canonical CVE-YYYY-NNNN form", file=sys.stderr)
        return 2
    excluded_cve_probe_id = args.excluded_cve_probe_id.strip().upper()
    if not CVE_RE.fullmatch(excluded_cve_probe_id):
        print(
            "--excluded-cve-probe-id must use canonical CVE-YYYY-NNNN form",
            file=sys.stderr,
        )
        return 2
    if excluded_cve_probe_id == cve_probe_id:
        print("CVE indexable and excluded probes must be different", file=sys.stderr)
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
        cve_probe_id=cve_probe_id,
        excluded_cve_probe_id=excluded_cve_probe_id,
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
