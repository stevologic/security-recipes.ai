#!/usr/bin/env python3
"""Build the complete, source-backed Medium/High/Critical CVE recipe catalog.

The catalog is intentionally separate from the hand-curated Markdown recipe
overrides. One normalized CVE record plus all applicable vetted remediation
archetypes is a complete, conservative recipe; a stable Markdown page may
override that composed recipe when a vulnerability needs product-specific
treatment.

Initial backfills use NVD's integrity-hashed annual JSON 2.0 feeds.  The feeds
are partitioned by CVE identifier year, so an exact publication-date window scans
every available identifier-year feed rather than assuming that the CVE year
and publication year are the same.  CISA KEV data is joined by CVE ID and is
never used to invent a severity.
"""

from __future__ import annotations

import argparse
import gc
import gzip
import hashlib
import heapq
import html
import itertools
import json
import os
import re
import sys
import tempfile
from collections import OrderedDict
import time
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen

try:
    from scripts.cve_ai_enrichment import (
        DEFAULT_MODEL as DEFAULT_OPENAI_MODEL,
        DEFAULT_REQUEST_LIMIT as DEFAULT_AI_ENRICHMENT_LIMIT,
        MAX_REQUEST_LIMIT as MAX_AI_ENRICHMENT_LIMIT,
        EnrichmentCache,
        OpenAIEnricher,
    )
except ModuleNotFoundError:  # Direct ``python scripts/sync_cve_catalog.py`` execution.
    from cve_ai_enrichment import (  # type: ignore[no-redef]
        DEFAULT_MODEL as DEFAULT_OPENAI_MODEL,
        DEFAULT_REQUEST_LIMIT as DEFAULT_AI_ENRICHMENT_LIMIT,
        MAX_REQUEST_LIMIT as MAX_AI_ENRICHMENT_LIMIT,
        EnrichmentCache,
        OpenAIEnricher,
    )


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTENT_DIR = ROOT / "content" / "recipes" / "cve"
DEFAULT_ARCHETYPES = ROOT / "data" / "cve" / "remediation-archetypes.json"
DEFAULT_ENRICHMENT_CACHE = ROOT / "data" / "cve" / "ai-enrichments.json"
DEFAULT_OUTPUT_DIR = ROOT / "static" / "api" / "cve-catalog"
DEFAULT_CACHE_DIR = ROOT / "tmp" / "nvd-cve-feeds"

NVD_FEED_ROOT = "https://nvd.nist.gov/feeds/json/cve/2.0"
NVD_DETAIL_ROOT = "https://nvd.nist.gov/vuln/detail"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
USER_AGENT = "security-recipes.ai/cve-catalog-sync"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
BROWSER_SEVERITY_CODES = {"medium": 0, "high": 1, "critical": 2}
VERSION_RANK = {"2.0": 20, "3.0": 30, "3.1": 31, "4.0": 40}
BROWSER_INDEX_FIELDS = [
    "cve",
    "title",
    "severity",
    "score",
    "published",
    "ecosystem_index",
    "kev",
    "archetype_indexes",
    "has_markdown",
]
MAX_STABLE_MARKDOWN_BYTES = 256 * 1024
ARCHETYPE_LIST_FIELDS = (
    "exposure_checks",
    "remediation_steps",
    "containment_steps",
    "verification_steps",
    "rollback_steps",
    "stop_conditions",
    "watch_for",
)
AGENTIC_CONTRACT_SCHEMA_VERSION = 1
AGENTIC_PHASES = (
    "discover",
    "assess",
    "mitigate",
    "remediate",
    "verify",
    "rollback",
    "triage",
)
AGENTIC_ACTION_FIELDS = (
    "id",
    "phase",
    "source_field",
    "operation",
    "target_kinds",
)
AGENTIC_OPERATION_VALUES = (
    "inspect",
    "assess",
    "edit",
    "test",
    "restore",
    "report",
)
AGENTIC_TARGET_KIND_VALUES = (
    "source_code",
    "dependency_manifest",
    "lockfile",
    "configuration",
    "build_definition",
    "deployment_manifest",
    "infrastructure_as_code",
    "runtime_policy",
    "inventory",
    "firmware_image",
    "binary_artifact",
    "test",
    "documentation",
    "triage_report",
)
AGENTIC_PHASE_CONTRACT_FIELDS = frozenset(
    {
        "source_field",
        "operation",
        "mutates_files",
        "requires_rollback_plan",
        "approval_gate",
        "on_failure",
        "required_evidence",
    }
)
AGENTIC_CONTRACT_FIELDS = frozenset(
    {
        "schema_version",
        "action_order",
        "operation_values",
        "target_kind_values",
        "phase_contracts",
        "required_outputs",
        "fixed_version_policy",
        "safety_boundaries",
    }
)
AGENTIC_PHASE_POLICIES = {
    "discover": ("exposure_checks", "inspect", False, False, "none", "triage"),
    "assess": ("watch_for", "assess", False, False, "none", "triage"),
    "mitigate": (
        "containment_steps",
        "edit",
        True,
        True,
        "before_external_or_production_change",
        "rollback_then_triage",
    ),
    "remediate": (
        "remediation_steps",
        "edit",
        True,
        True,
        "before_external_or_production_change",
        "rollback_then_triage",
    ),
    "verify": ("verification_steps", "test", False, False, "none", "triage"),
    "rollback": (
        "rollback_steps",
        "restore",
        True,
        False,
        "before_external_or_production_change",
        "stop_and_triage",
    ),
    "triage": ("stop_conditions", "report", True, False, "none", "stop"),
}
AGENTIC_REQUIRED_OUTPUTS = {
    "discover": "affected-surface-inventory",
    "assess": "exposure-decision",
    "mitigate": "mitigation-change-set",
    "remediate": "remediation-change-set",
    "verify": "verification-report",
    "rollback": "rollback-report",
    "triage": "TRIAGE.md",
}
INFERRED_ECOSYSTEMS = frozenset(
    {
        "apple/platform",
        "browser",
        "hardware/firmware",
        "java/maven",
        "javascript/npm",
        "linux/kernel",
        "operating-system",
        "php/wordpress",
        "python/pypi",
        "software/application",
        "windows/system",
    }
)
VENDOR_CONTROLLED_ECOSYSTEMS = frozenset(
    {
        "apple/platform",
        "browser",
        "hardware/firmware",
        "linux/kernel",
        "operating-system",
        "windows/system",
    }
)
# This ordering is deliberately independent of JSON object/CWE order.  It
# chooses the family that best communicates immediate impact while preserving
# every other applicable family in the full ordered list.
ARCHETYPE_RISK_PRECEDENCE = (
    "command_code_injection",
    "unsafe_deserialization",
    "memory_corruption",
    "use_after_free",
    "privilege_escalation",
    "authentication_bypass",
    "authorization_idor",
    "sql_query_injection",
    "ssrf",
    "xxe",
    "path_traversal_file_handling",
    "supply_chain_update_integrity",
    "http_request_smuggling",
    "crypto_certificate_validation",
    "information_disclosure",
    "cross_site_scripting",
    "race_lifetime",
    "resource_exhaustion_dos",
)
FRONTMATTER_RE = re.compile(r"\A---\s*\n(?P<body>.*?)\n---\s*\n", re.DOTALL)
FRONTMATTER_CVE_RE = re.compile(r'^cve:\s*["\']?(CVE-\d{4}-\d+)["\']?\s*$', re.MULTILINE | re.I)
FRONTMATTER_MATURITY_RE = re.compile(r'^maturity:\s*["\']?([^"\'\r\n]+)', re.MULTILINE | re.I)
FRONTMATTER_TITLE_RE = re.compile(r'^title:\s*(.+?)\s*$', re.MULTILINE | re.I)


@dataclass(frozen=True)
class Metric:
    version: str
    score: float
    severity: str
    vector: str
    source: str
    metric_type: str


@dataclass(frozen=True)
class ExistingRecipe:
    cve: str
    path: str
    maturity: str
    title: str
    content_markdown: str


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def parse_date(value: str) -> date:
    return date.fromisoformat(value.strip()[:10])


def ten_year_cutoff(today: date) -> date:
    try:
        return today.replace(year=today.year - 10)
    except ValueError:  # February 29.
        return today.replace(year=today.year - 10, day=28)


def normalize_space(value: object, *, limit: int | None = None) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if limit and len(text) > limit:
        text = text[: max(1, limit - 1)].rstrip(" ,;:-") + "…"
    return text


def safe_markdown_text(value: object, *, limit: int | None = None) -> str:
    return html.escape(normalize_space(value, limit=limit), quote=False)


def fetch_bytes(url: str, *, attempts: int = 4, timeout: int = 180) -> bytes:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/plain, */*"})
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            with urlopen(request, timeout=timeout) as response:
                return response.read()
        except HTTPError as exc:
            last_error = exc
            # NVD's CDN can briefly return 404 while annual feed objects rotate.
            # The same immutable feed URL is available again seconds later, so a
            # bounded retry is safer than abandoning a complete daily refresh.
            if exc.code not in {404, 408, 429, 500, 502, 503, 504}:
                raise
            retry_after = exc.headers.get("Retry-After")
            delay = float(retry_after) if retry_after and retry_after.isdigit() else 2**attempt
            time.sleep(min(delay, 30))
        except (TimeoutError, URLError, OSError) as exc:
            last_error = exc
            time.sleep(min(2**attempt, 30))
    if last_error is None:
        raise RuntimeError(f"failed to fetch {url}")
    raise last_error


def write_if_changed(path: Path, payload: bytes, *, dry_run: bool = False) -> bool:
    if path.exists() and path.read_bytes() == payload:
        return False
    if not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        try:
            temporary.write_bytes(payload)
            os.replace(temporary, path)
        finally:
            # A normal write failure must not leave a second, unowned catalog
            # representation behind. Hard process termination is handled by
            # the whole-tree reconciliation at the start of the next sync.
            if temporary.is_symlink() or temporary.exists():
                temporary.unlink()
    return True


def json_bytes(value: object, *, pretty: bool = False) -> bytes:
    if pretty:
        rendered = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
    else:
        rendered = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return (rendered + "\n").encode("utf-8")


def index_json_bytes(index: dict[str, Any]) -> bytes:
    """Serialize the large index with one compact record per diffable line."""
    lines = ["{"]
    metadata = {key: value for key, value in index.items() if key != "records"}
    metadata_items = sorted(metadata.items())
    for key, value in metadata_items:
        lines.append(
            "  "
            + json.dumps(key, ensure_ascii=False)
            + ": "
            + json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            + ","
        )
    lines.append('  "records": [')
    records = index.get("records") or []
    for position, record in enumerate(records):
        suffix = "," if position + 1 < len(records) else ""
        lines.append("    " + json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + suffix)
    lines.extend(["  ]", "}"])
    return ("\n".join(lines) + "\n").encode("utf-8")


def parse_meta(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in text.splitlines():
        key, separator, value = raw_line.partition(":")
        if separator:
            result[key.strip()] = value.strip()
    if not result.get("sha256"):
        raise ValueError("NVD feed metadata did not include sha256")
    return result


def verify_gzip_payload(path: Path, expected_sha256: str) -> None:
    digest = hashlib.sha256()
    with gzip.open(path, "rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual.lower() != expected_sha256.lower():
        raise ValueError(f"NVD feed integrity failure for {path.name}: expected {expected_sha256}, got {actual}")


def cache_feed(year: int, cache_dir: Path, *, offline: bool = False) -> tuple[Path, dict[str, str]]:
    stem = f"nvdcve-2.0-{year}"
    meta_path = cache_dir / f"{stem}.meta"
    gzip_path = cache_dir / f"{stem}.json.gz"
    verified_path = cache_dir / f"{stem}.verified"

    if offline:
        if not meta_path.exists() or not gzip_path.exists():
            raise FileNotFoundError(f"offline cache is missing {stem}")
        meta_text = meta_path.read_text(encoding="utf-8")
    else:
        meta_text = fetch_bytes(f"{NVD_FEED_ROOT}/{stem}.meta").decode("utf-8", errors="strict")
        write_if_changed(meta_path, meta_text.encode("utf-8"))

    metadata = parse_meta(meta_text)
    expected_sha = metadata["sha256"].lower()
    verified_sha = verified_path.read_text(encoding="ascii").strip().lower() if verified_path.exists() else ""
    if not gzip_path.exists() or verified_sha != expected_sha:
        if offline and not gzip_path.exists():
            raise FileNotFoundError(f"offline cache is missing {gzip_path}")
        if not offline:
            payload = fetch_bytes(f"{NVD_FEED_ROOT}/{stem}.json.gz")
            write_if_changed(gzip_path, payload)
    # The marker records which upstream metadata was checked; it is not proof
    # that cached bytes still match. Rehash decompressed feed contents on every
    # run, including offline runs and matching-marker fast paths.
    try:
        verify_gzip_payload(gzip_path, expected_sha)
    except (OSError, EOFError, ValueError):
        if offline:
            raise
        payload = fetch_bytes(f"{NVD_FEED_ROOT}/{stem}.json.gz")
        write_if_changed(gzip_path, payload)
        verify_gzip_payload(gzip_path, expected_sha)
    write_if_changed(verified_path, (expected_sha + "\n").encode("ascii"))
    return gzip_path, metadata


def load_feed(path: Path) -> dict[str, Any]:
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise ValueError(f"invalid NVD JSON 2.0 feed: {path}")
    return payload


def cache_kev(cache_dir: Path, *, offline: bool = False) -> tuple[dict[str, Any], bytes]:
    path = cache_dir / "known_exploited_vulnerabilities.json"
    if offline:
        payload = path.read_bytes()
    else:
        payload = fetch_bytes(CISA_KEV_URL)
        write_if_changed(path, payload)
    data = json.loads(payload)
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("invalid CISA KEV JSON feed")
    return data, payload


def kev_by_cve(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in data.get("vulnerabilities", []):
        cve = str(item.get("cveID") or "").upper()
        if re.fullmatch(r"CVE-\d{4}-\d+", cve):
            result[cve] = item
    return result


def severity_for_score(version: str, score: float, supplied: object = "") -> str:
    supplied_severity = str(supplied or "").strip().lower()
    if supplied_severity in {"medium", "high", "critical"}:
        return supplied_severity
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if version.startswith("2"):
        return "high"
    return "critical" if score >= 9.0 else "high"


def extract_metrics(cve: dict[str, Any]) -> list[Metric]:
    metrics: list[Metric] = []
    seen: set[tuple[object, ...]] = set()
    for key, observations in (cve.get("metrics") or {}).items():
        if not str(key).startswith("cvssMetric") or not isinstance(observations, list):
            continue
        for observation in observations:
            if not isinstance(observation, dict):
                continue
            data = observation.get("cvssData") or {}
            try:
                score = float(data.get("baseScore"))
            except (TypeError, ValueError):
                continue
            version = normalize_space(data.get("version") or str(key).removeprefix("cvssMetricV").replace("1", ".1"))
            severity = severity_for_score(version, score, data.get("baseSeverity") or observation.get("baseSeverity"))
            metric = Metric(
                version=version,
                score=score,
                severity=severity,
                vector=normalize_space(data.get("vectorString"), limit=240),
                source=normalize_space(observation.get("source") or cve.get("sourceIdentifier"), limit=160),
                metric_type=normalize_space(observation.get("type"), limit=40),
            )
            identity = (metric.version, metric.score, metric.severity, metric.vector, metric.source, metric.metric_type)
            if identity not in seen:
                metrics.append(metric)
                seen.add(identity)
    metrics.sort(
        key=lambda metric: (
            SEVERITY_RANK.get(metric.severity, 0),
            metric.score,
            VERSION_RANK.get(metric.version, 0),
            metric.metric_type.lower() == "primary",
        ),
        reverse=True,
    )
    return metrics


def selected_metric(metrics: list[Metric]) -> Metric | None:
    return next((metric for metric in metrics if metric.score >= 4.0), None)


def english_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") or []
    value = next(
        (item.get("value") for item in descriptions if isinstance(item, dict) and item.get("lang") == "en"),
        "",
    )
    if not value:
        value = next((item.get("value") for item in descriptions if isinstance(item, dict) and item.get("value")), "")
    return normalize_space(value, limit=1200) or (
        "No description is present in the NVD record; consult the linked NVD entry and vendor references."
    )


def extract_cwes(cve: dict[str, Any]) -> list[str]:
    found: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for description in weakness.get("description") or []:
            value = str(description.get("value") or "").upper()
            found.extend(re.findall(r"CWE-\d+", value))
    return list(dict.fromkeys(found))[:12]


def split_cpe(value: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
    parts.append("".join(current))
    return parts


def iter_cpe_matches(value: object) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        matches = value.get("cpeMatch")
        if isinstance(matches, list):
            for match in matches:
                if isinstance(match, dict) and match.get("vulnerable", True):
                    yield match
        for nested in value.values():
            yield from iter_cpe_matches(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from iter_cpe_matches(nested)


def extract_products(cve: dict[str, Any]) -> tuple[list[dict[str, str]], int]:
    products: list[dict[str, str]] = []
    seen: set[tuple[str, ...]] = set()
    total = 0
    for match in iter_cpe_matches(cve.get("configurations") or []):
        total += 1
        criteria = normalize_space(match.get("criteria"), limit=500)
        parts = split_cpe(criteria)
        part = unquote(parts[2]) if len(parts) > 2 else ""
        vendor = unquote(parts[3]) if len(parts) > 3 else ""
        product = unquote(parts[4]) if len(parts) > 4 else ""
        version = unquote(parts[5]) if len(parts) > 5 else ""
        entry = {
            "part": part,
            "vendor": vendor,
            "product": product,
            "version": version,
            "version_start_including": normalize_space(match.get("versionStartIncluding"), limit=100),
            "version_start_excluding": normalize_space(match.get("versionStartExcluding"), limit=100),
            "version_end_including": normalize_space(match.get("versionEndIncluding"), limit=100),
            "version_end_excluding": normalize_space(match.get("versionEndExcluding"), limit=100),
            "cpe": criteria,
        }
        identity = tuple(entry.values())
        if identity not in seen and len(products) < 12:
            products.append(entry)
            seen.add(identity)
    return products, total


def extract_references(cve: dict[str, Any]) -> list[dict[str, Any]]:
    references: list[dict[str, Any]] = []
    seen: set[str] = set()
    for reference in cve.get("references") or []:
        if not isinstance(reference, dict):
            continue
        url = normalize_space(reference.get("url"), limit=2000)
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or url in seen:
            continue
        references.append({"url": url, "tags": sorted(str(tag) for tag in (reference.get("tags") or []))[:8]})
        seen.add(url)
    nvd_url = f"{NVD_DETAIL_ROOT}/{cve.get('id')}"
    if nvd_url not in seen:
        references.append({"url": nvd_url, "tags": ["NVD"]})

    priority_tags = {"Patch": 0, "Vendor Advisory": 1, "Release Notes": 2, "Mitigation": 3, "NVD": 9}

    def priority(reference: dict[str, Any]) -> tuple[int, str]:
        rank = min((priority_tags.get(tag, 5) for tag in reference["tags"]), default=5)
        return rank, reference["url"]

    references.sort(key=priority)
    return references[:16]


def _nonempty_string_list(value: object) -> bool:
    return isinstance(value, list) and bool(value) and all(
        isinstance(item, str) and bool(item.strip()) for item in value
    )


def _unique_nonempty_string_list(value: object) -> bool:
    return _nonempty_string_list(value) and len(value) == len(set(value))


def _archetype_definition_errors(archetype_id: object, archetype: object) -> list[str]:
    prefix = f"archetype {archetype_id!r}"
    if not isinstance(archetype_id, str) or not archetype_id.strip():
        return ["archetype IDs must be nonempty strings"]
    if not isinstance(archetype, dict):
        return [f"{prefix} must be an object"]

    errors: list[str] = []
    for field in ("title", "description"):
        if not isinstance(archetype.get(field), str) or not archetype[field].strip():
            errors.append(f"{prefix} has invalid {field}")
    for field in ARCHETYPE_LIST_FIELDS:
        values = archetype.get(field)
        if not _unique_nonempty_string_list(values):
            errors.append(f"{prefix} has invalid {field}: expected a nonempty unique string list")
    matching_cwes = archetype.get("matching_cwes", archetype.get("cwes", []))
    if not isinstance(matching_cwes, list) or any(
        not isinstance(cwe, str) or not re.fullmatch(r"CWE-\d+", cwe.upper()) for cwe in matching_cwes
    ) or len(matching_cwes) != len(set(matching_cwes)):
        errors.append(f"{prefix} has invalid matching_cwes")
    return errors


def _agentic_header_errors(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    contract = payload.get("agentic_contract")
    if not isinstance(contract, dict):
        return ["agentic_contract must be an object"]
    if contract.get("schema_version") != AGENTIC_CONTRACT_SCHEMA_VERSION:
        errors.append(
            f"agentic_contract schema_version must be {AGENTIC_CONTRACT_SCHEMA_VERSION}"
        )
    if set(contract) != AGENTIC_CONTRACT_FIELDS:
        errors.append(
            "agentic_contract fields must exactly match the versioned contract: "
            f"expected={sorted(AGENTIC_CONTRACT_FIELDS)}, actual={sorted(contract)}"
        )
    if contract.get("action_order") != list(AGENTIC_PHASES):
        errors.append("agentic_contract action_order must contain the seven supported phases in order")
    if contract.get("operation_values") != list(AGENTIC_OPERATION_VALUES):
        errors.append("agentic_contract operation_values do not match the supported operations")
    if contract.get("target_kind_values") != list(AGENTIC_TARGET_KIND_VALUES):
        errors.append("agentic_contract target_kind_values do not match the supported target kinds")

    phase_contracts = contract.get("phase_contracts")
    if not isinstance(phase_contracts, dict) or list(phase_contracts) != list(AGENTIC_PHASES):
        errors.append("agentic_contract phase_contracts must cover exactly the seven supported phases")
    else:
        for phase in AGENTIC_PHASES:
            policy = phase_contracts[phase]
            prefix = f"agentic_contract phase {phase!r}"
            if not isinstance(policy, dict):
                errors.append(f"{prefix} must be an object")
                continue
            if set(policy) != AGENTIC_PHASE_CONTRACT_FIELDS:
                errors.append(f"{prefix} fields do not match the phase contract")
            if policy.get("source_field") not in ARCHETYPE_LIST_FIELDS:
                errors.append(f"{prefix} has invalid source_field")
            if policy.get("operation") not in AGENTIC_OPERATION_VALUES:
                errors.append(f"{prefix} has invalid operation")
            for field in ("mutates_files", "requires_rollback_plan"):
                if type(policy.get(field)) is not bool:
                    errors.append(f"{prefix} has invalid {field}: expected a boolean")
            if not isinstance(policy.get("approval_gate"), str) or not policy["approval_gate"].strip():
                errors.append(f"{prefix} has invalid approval_gate")
            if not isinstance(policy.get("on_failure"), str) or not policy["on_failure"].strip():
                errors.append(f"{prefix} has invalid on_failure")
            if not _unique_nonempty_string_list(policy.get("required_evidence")):
                errors.append(f"{prefix} has invalid required_evidence")
            expected_policy = AGENTIC_PHASE_POLICIES[phase]
            actual_policy = (
                policy.get("source_field"),
                policy.get("operation"),
                policy.get("mutates_files"),
                policy.get("requires_rollback_plan"),
                policy.get("approval_gate"),
                policy.get("on_failure"),
            )
            if actual_policy != expected_policy:
                errors.append(f"{prefix} does not match the version 1 safety policy")

    required_outputs = contract.get("required_outputs")
    if not isinstance(required_outputs, dict) or list(required_outputs) != list(AGENTIC_PHASES):
        errors.append("agentic_contract required_outputs must follow action_order")
    elif required_outputs != AGENTIC_REQUIRED_OUTPUTS:
        errors.append("agentic_contract required_outputs do not match the version 1 outputs")
    safety_boundaries = contract.get("safety_boundaries")
    if not _unique_nonempty_string_list(safety_boundaries):
        errors.append("agentic_contract has invalid safety_boundaries")
    else:
        boundary_text = " ".join(safety_boundaries).lower()
        for concept in (
            "scope", "exploit", "invent", "rollback", "secrets", "incident response",
            "untrusted evidence", "embedded commands",
        ):
            if concept not in boundary_text:
                errors.append(f"agentic_contract safety_boundaries do not cover {concept!r}")
    fixed_version_policy = contract.get("fixed_version_policy")
    if not isinstance(fixed_version_policy, dict) or set(fixed_version_policy) != {
        "allowed_sources",
        "require_source_record",
        "when_unknown",
    }:
        errors.append("agentic_contract has invalid fixed_version_policy")
    else:
        if not _unique_nonempty_string_list(fixed_version_policy.get("allowed_sources")):
            errors.append("agentic_contract fixed_version_policy has invalid allowed_sources")
        if fixed_version_policy.get("require_source_record") is not True:
            errors.append("agentic_contract fixed_version_policy must require a source record")
        when_unknown = fixed_version_policy.get("when_unknown")
        if not isinstance(when_unknown, str) or not when_unknown.strip():
            errors.append("agentic_contract fixed_version_policy has invalid when_unknown")
        else:
            lowered = when_unknown.lower()
            if (
                "do not" not in lowered
                or not all(term in lowered for term in ("invent", "infer", "guess"))
                or "triage.md" not in lowered
            ):
                errors.append(
                    "agentic_contract fixed_version_policy when_unknown must prohibit invention and require TRIAGE.md"
                )

    target_hints = payload.get("ecosystem_target_hints")
    if not isinstance(target_hints, dict):
        errors.append("ecosystem_target_hints must be an object")
    else:
        actual = set(target_hints)
        if actual != INFERRED_ECOSYSTEMS:
            missing = sorted(INFERRED_ECOSYSTEMS - actual)
            extra = sorted(actual - INFERRED_ECOSYSTEMS)
            errors.append(
                f"ecosystem_target_hints must exactly cover inferred ecosystems: missing={missing}, extra={extra}"
            )
        for ecosystem, hints in target_hints.items():
            prefix = f"ecosystem_target_hints {ecosystem!r}"
            if not isinstance(hints, dict) or set(hints) != {
                "file_globs",
                "target_kinds",
                "safe_edit_intent",
            }:
                errors.append(f"{prefix} must contain file_globs, target_kinds, and safe_edit_intent")
                continue
            if not _unique_nonempty_string_list(hints.get("file_globs")):
                errors.append(f"{prefix} has invalid file_globs")
            elif any(
                "\\" in glob
                or ":" in glob
                or PurePosixPath(glob).is_absolute()
                or ".." in PurePosixPath(glob).parts
                for glob in hints["file_globs"]
            ):
                errors.append(f"{prefix} contains an unsafe file glob")
            kinds = hints.get("target_kinds")
            if not _nonempty_string_list(kinds) or any(
                kind not in AGENTIC_TARGET_KIND_VALUES for kind in kinds
            ):
                errors.append(f"{prefix} has invalid target_kinds")
            elif ecosystem in VENDOR_CONTROLLED_ECOSYSTEMS and "source_code" in kinds:
                errors.append(f"{prefix} must not direct agents to edit vendor-controlled source")
            if not isinstance(hints.get("safe_edit_intent"), str) or not hints["safe_edit_intent"].strip():
                errors.append(f"{prefix} has invalid safe_edit_intent")
    return errors


def _agentic_archetype_errors(
    archetype_id: object, archetype: object, contract: object
) -> list[str]:
    prefix = f"archetype {archetype_id!r}"
    if not isinstance(archetype_id, str) or not isinstance(archetype, dict):
        return [f"{prefix} cannot carry agentic actions"]
    actions = archetype.get("agentic_actions")
    if not isinstance(actions, list) or not actions:
        return [f"{prefix} has invalid agentic_actions: expected a nonempty action list"]

    errors: list[str] = []
    phases: list[str] = []
    phase_contracts = contract.get("phase_contracts") if isinstance(contract, dict) else {}
    for position, action in enumerate(actions):
        action_prefix = f"{prefix} agentic_actions[{position}]"
        if not isinstance(action, dict):
            errors.append(f"{action_prefix} must be an object")
            continue
        if set(action) != set(AGENTIC_ACTION_FIELDS):
            errors.append(f"{action_prefix} fields do not match the action contract")
            continue
        action_id = action.get("id")
        if not isinstance(action_id, str) or re.fullmatch(r"[a-z0-9][a-z0-9._-]*", action_id) is None:
            errors.append(f"{action_prefix} has invalid id")
        phase = action.get("phase")
        if phase not in AGENTIC_PHASES:
            errors.append(f"{action_prefix} has unsupported phase {phase!r}")
        else:
            phases.append(phase)
            expected_id = f"{archetype_id}.{phase}"
            if action_id != expected_id:
                errors.append(f"{action_prefix} id must be {expected_id!r}")
        source_field = action.get("source_field")
        if source_field not in ARCHETYPE_LIST_FIELDS:
            errors.append(f"{action_prefix} has unsupported source_field {source_field!r}")
        elif not _nonempty_string_list(archetype.get(source_field)):
            errors.append(f"{action_prefix} source_field {source_field!r} is not resolvable")
        if action.get("operation") not in AGENTIC_OPERATION_VALUES:
            errors.append(f"{action_prefix} has invalid operation")
        target_kinds = action.get("target_kinds")
        if not _unique_nonempty_string_list(target_kinds) or any(
            target_kind not in AGENTIC_TARGET_KIND_VALUES for target_kind in (target_kinds or [])
        ):
            errors.append(f"{action_prefix} has invalid target_kinds")
        elif phase == "triage" and "triage_report" not in target_kinds:
            errors.append(f"{action_prefix} must target triage_report")
        elif phase in {"mitigate", "remediate"} and not (
            set(target_kinds) - {"test", "documentation", "triage_report"}
        ):
            errors.append(f"{action_prefix} has no mutable implementation target")
        phase_policy = phase_contracts.get(phase) if isinstance(phase_contracts, dict) else None
        if isinstance(phase_policy, dict) and (
            source_field != phase_policy.get("source_field")
            or action.get("operation") != phase_policy.get("operation")
        ):
            errors.append(f"{action_prefix} does not match its phase contract")

    if phases != list(AGENTIC_PHASES):
        errors.append(f"{prefix} agentic_actions must contain all seven supported phases in order")
    return errors


def archetype_contract_errors(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if payload.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    definitions = payload.get("archetypes")
    if not isinstance(definitions, dict) or not definitions:
        return [*errors, "archetypes must be a nonempty object"]
    default = payload.get("default_archetype")
    if not isinstance(default, str) or default not in definitions:
        errors.append("default_archetype is not present in archetypes")

    errors.extend(_agentic_header_errors(payload))
    action_owners: dict[str, list[str]] = {}
    for archetype_id, archetype in definitions.items():
        errors.extend(_archetype_definition_errors(archetype_id, archetype))
        errors.extend(
            _agentic_archetype_errors(archetype_id, archetype, payload.get("agentic_contract"))
        )
        if isinstance(archetype_id, str) and isinstance(archetype, dict):
            for action in archetype.get("agentic_actions") or []:
                if isinstance(action, dict) and isinstance(action.get("id"), str):
                    action_owners.setdefault(action["id"], []).append(archetype_id)
    for action_id, owners in sorted(action_owners.items()):
        if len(owners) > 1:
            errors.append(f"agentic action id {action_id!r} is not globally unique: {owners}")
    target_hints = payload.get("ecosystem_target_hints")
    if isinstance(target_hints, dict):
        for archetype_id, archetype in definitions.items():
            if not isinstance(archetype_id, str) or not isinstance(archetype, dict):
                continue
            for action in archetype.get("agentic_actions") or []:
                if not isinstance(action, dict):
                    continue
                phase = str(action.get("phase") or "")
                raw_targets = set(action.get("target_kinds") or [])
                for ecosystem, hint in target_hints.items():
                    if not isinstance(hint, dict):
                        continue
                    effective = raw_targets & set(hint.get("target_kinds") or [])
                    if phase == "triage" and "triage_report" in raw_targets:
                        effective.add("triage_report")
                    if not effective:
                        errors.append(
                            f"agentic action {action.get('id')!r} has no effective target for ecosystem {ecosystem!r}"
                        )
    return errors


def valid_archetype_ids(payload: dict[str, Any]) -> set[str]:
    definitions = payload.get("archetypes")
    if not isinstance(definitions, dict):
        return set()
    valid: set[str] = set()
    for archetype_id, archetype in definitions.items():
        if not _archetype_definition_errors(archetype_id, archetype):
            valid.add(archetype_id)
    return valid


def valid_agentic_archetype_ids(payload: dict[str, Any]) -> set[str]:
    definitions = payload.get("archetypes")
    if not isinstance(definitions, dict) or _agentic_header_errors(payload):
        return set()
    valid = {
        archetype_id
        for archetype_id, archetype in definitions.items()
        if isinstance(archetype_id, str)
        and not _archetype_definition_errors(archetype_id, archetype)
        and not _agentic_archetype_errors(
            archetype_id, archetype, payload.get("agentic_contract")
        )
    }
    action_owners: dict[str, set[str]] = {}
    for archetype_id, archetype in definitions.items():
        if not isinstance(archetype_id, str) or not isinstance(archetype, dict):
            continue
        for action in archetype.get("agentic_actions") or []:
            if isinstance(action, dict) and isinstance(action.get("id"), str):
                action_owners.setdefault(action["id"], set()).add(archetype_id)
    for owners in action_owners.values():
        if len(owners) > 1:
            valid.difference_update(owners)
    return valid


def load_archetypes(path: Path) -> tuple[dict[str, Any], dict[str, list[str]]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    errors = archetype_contract_errors(payload)
    if errors:
        raise ValueError(f"invalid remediation archetypes in {path}: " + "; ".join(errors))
    mapping: dict[str, list[str]] = {}
    for archetype_id, archetype in payload["archetypes"].items():
        for cwe in archetype.get("matching_cwes") or archetype.get("cwes") or []:
            families = mapping.setdefault(str(cwe).upper(), [])
            if archetype_id not in families:
                families.append(archetype_id)
    return payload, mapping


KEYWORD_ARCHETYPES: list[tuple[str, tuple[str, ...]]] = [
    (
        "command_code_injection",
        (
            "command injection",
            "os command",
            "shell injection",
            "code injection",
            "remote code execution",
            "execute arbitrary code",
            "arbitrary code execution",
        ),
    ),
    ("sql_query_injection", ("sql injection", "sqli")),
    ("unsafe_deserialization", ("deserialization of untrusted", "unsafe deserialization")),
    ("authentication_bypass", ("authentication bypass", "improper authentication")),
    ("authorization_idor", ("missing authorization", "improper authorization", "idor")),
    ("path_traversal_file_handling", ("path traversal", "directory traversal", "arbitrary file")),
    ("ssrf", ("server-side request forgery", "ssrf")),
    ("cross_site_scripting", ("cross-site scripting", " xss ")),
    ("xxe", ("external entity", " xxe ")),
    ("http_request_smuggling", ("request smuggling",)),
    ("use_after_free", ("use-after-free", "use after free", "double free")),
    ("memory_corruption", ("buffer overflow", "out-of-bounds", "memory corruption", "integer overflow")),
    ("resource_exhaustion_dos", ("denial of service", "resource consumption", "infinite loop")),
    ("crypto_certificate_validation", ("certificate validation", "cryptographic", "signature verification")),
    ("information_disclosure", ("information disclosure", "information exposure", "sensitive information")),
    ("privilege_escalation", ("privilege escalation", "elevation of privilege")),
]


def _mapped_families(mapping: dict[str, list[str] | str], cwe: str) -> list[str]:
    value = mapping.get(cwe, [])
    return [value] if isinstance(value, str) else list(value)


def choose_archetypes(
    cwes: list[str], summary: str, mapping: dict[str, list[str] | str], default: str
) -> list[str]:
    cwe_families: set[str] = set()
    for cwe in cwes:
        cwe_families.update(_mapped_families(mapping, cwe))
    candidates = set(cwe_families)
    # CWE evidence is authoritative for family composition. Keyword inference
    # is a fallback only when no CWE maps; mixing it into mapped records turns
    # impact phrases such as "remote code execution" into false injection
    # families for memory-safety defects.
    if not cwe_families:
        available = {
            family for value in mapping.values() for family in ([value] if isinstance(value, str) else value)
        }
        lowered = f" {summary.lower()} "
        keyword_candidates = {
            archetype_id
            for archetype_id, needles in KEYWORD_ARCHETYPES
            if archetype_id in available and any(needle in lowered for needle in needles)
        }
        precedence = {archetype_id: position for position, archetype_id in enumerate(ARCHETYPE_RISK_PRECEDENCE)}
        if keyword_candidates:
            candidates.add(
                min(
                    keyword_candidates,
                    key=lambda archetype_id: (precedence.get(archetype_id, len(precedence)), archetype_id),
                )
            )
    if not candidates:
        return [default]
    candidates.discard(default)
    precedence = {archetype_id: position for position, archetype_id in enumerate(ARCHETYPE_RISK_PRECEDENCE)}
    return sorted(candidates, key=lambda archetype_id: (precedence.get(archetype_id, len(precedence)), archetype_id))


def choose_archetype(cwes: list[str], summary: str, mapping: dict[str, list[str] | str], default: str) -> str:
    """Backward-compatible primary-family helper."""
    return choose_archetypes(cwes, summary, mapping, default)[0]


def normalized_tokens(value: object) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9]+", unquote(str(value or "")).lower()) if token}


def infer_ecosystem(products: list[dict[str, str]], summary: str) -> str:
    # NVD configurations frequently list an OS CPE before the vulnerable
    # application. Taxonomy follows the first application CPE when one exists,
    # while retaining the first product as the fallback for OS/firmware CVEs.
    primary = next((entry for entry in products if str(entry.get("part") or "").lower() == "a"), None)
    primary = primary or (products[0] if products else {})
    part = str(primary.get("part") or "").lower()
    vendor_tokens = normalized_tokens(primary.get("vendor"))
    product_tokens = normalized_tokens(primary.get("product"))
    summary_tokens = normalized_tokens(summary)
    primary_tokens = vendor_tokens | product_tokens

    if vendor_tokens == {"linux"} and {"linux", "kernel"} <= product_tokens:
        return "linux/kernel"
    if "microsoft" in vendor_tokens or "windows" in product_tokens:
        return "windows/system"
    if "apple" in vendor_tokens:
        return "apple/platform"
    if primary_tokens & {"chrome", "chromium", "firefox", "webkit"}:
        return "browser"
    if "wordpress" in primary_tokens:
        return "php/wordpress"
    if primary_tokens & {"nodejs", "npm", "javascript"} or {"node", "js"} <= primary_tokens:
        return "javascript/npm"
    if primary_tokens & {"python", "pypi", "pip"}:
        return "python/pypi"
    if (
        primary_tokens & {"java", "maven", "log4j", "log4j2"}
        or {"spring", "framework"} <= primary_tokens
        or ("apache" in vendor_tokens and bool(product_tokens & {"log4j", "log4j2"}))
    ):
        return "java/maven"
    if part == "o":
        return "operating-system"
    if part == "h":
        return "hardware/firmware"

    # Description inference is a fallback only when the primary CPE does not
    # identify a platform/package family. Exact tokens prevent `ios` from
    # matching Nagios or BIOS, and a primary Cisco IOS CPE has already returned
    # as an operating system above.
    if {"linux", "kernel"} <= summary_tokens:
        return "linux/kernel"
    if "microsoft" in summary_tokens or "windows" in summary_tokens:
        return "windows/system"
    apple_products = {"ios", "ipados", "macos", "watchos", "tvos", "iphone"}
    if "apple" in summary_tokens and bool(summary_tokens & apple_products):
        return "apple/platform"
    if summary_tokens & {"chrome", "chromium", "firefox", "webkit"}:
        return "browser"
    if "wordpress" in summary_tokens:
        return "php/wordpress"
    if summary_tokens & {"nodejs", "npm", "javascript"} or {"node", "js"} <= summary_tokens:
        return "javascript/npm"
    if summary_tokens & {"python", "pypi", "pip"}:
        return "python/pypi"
    if summary_tokens & {"java", "maven", "log4j", "log4j2"} or {
        "spring",
        "framework",
    } <= summary_tokens:
        return "java/maven"
    return "software/application"


def display_product(products: list[dict[str, str]]) -> str:
    if not products:
        return "Affected product"
    first = products[0]
    values = [first.get("vendor", ""), first.get("product", "")]
    text = " ".join(value.replace("_", " ") for value in values if value and value not in {"*", "-"})
    return normalize_space(text.title(), limit=72) or "Affected product"


def candidate_title(cve_id: str, summary: str, products: list[dict[str, str]], kev: dict[str, Any] | None) -> str:
    if kev and kev.get("vulnerabilityName"):
        return normalize_space(kev["vulnerabilityName"], limit=140)
    sentence = re.split(r"(?<=[.!?])\s+", summary, maxsplit=1)[0]
    sentence = re.sub(rf"^{re.escape(cve_id)}\s*[:—-]?\s*", "", sentence, flags=re.I)
    if 20 <= len(sentence) <= 140:
        return sentence.rstrip(" .")
    return normalize_space(f"{display_product(products)} security vulnerability", limit=140)


def normalize_kev(item: dict[str, Any] | None) -> dict[str, Any] | None:
    if not item:
        return None
    return {
        "date_added": item.get("dateAdded"),
        "due_date": item.get("dueDate"),
        "vendor_project": item.get("vendorProject"),
        "product": item.get("product"),
        "vulnerability_name": item.get("vulnerabilityName"),
        "required_action": item.get("requiredAction"),
        "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"),
        "notes": item.get("notes"),
        "cwes": item.get("cwes") or [],
        "source": CISA_KEV_URL,
    }


def frontmatter_scalar(frontmatter: str, pattern: re.Pattern[str]) -> str:
    match = pattern.search(frontmatter)
    if not match:
        return ""
    value = match.group(1).strip()
    if value.startswith('"') and value.endswith('"'):
        try:
            parsed = json.loads(value)
            return normalize_space(parsed)
        except json.JSONDecodeError:
            pass
    return normalize_space(value.strip("\"'"))


def markdown_inventory(content_dir: Path) -> dict[str, list[ExistingRecipe]]:
    inventory: dict[str, list[ExistingRecipe]] = {}
    for path in sorted(content_dir.glob("*.md")):
        text = path.read_text(encoding="utf-8", errors="replace")
        frontmatter = FRONTMATTER_RE.match(text)
        if not frontmatter:
            continue
        body = frontmatter.group("body")
        cve_match = FRONTMATTER_CVE_RE.search(body)
        if not cve_match:
            continue
        maturity = frontmatter_scalar(body, FRONTMATTER_MATURITY_RE).lower()
        title = frontmatter_scalar(body, FRONTMATTER_TITLE_RE)
        content_markdown = text[frontmatter.end() :].strip() if maturity == "stable" else ""
        if len(content_markdown.encode("utf-8")) > MAX_STABLE_MARKDOWN_BYTES:
            raise ValueError(
                f"stable Markdown override exceeds {MAX_STABLE_MARKDOWN_BYTES} bytes: {path}"
            )
        cve = cve_match.group(1).upper()
        inventory.setdefault(cve, []).append(
            ExistingRecipe(
                cve=cve,
                path=path.relative_to(ROOT).as_posix(),
                maturity=maturity,
                title=title,
                content_markdown=content_markdown,
            )
        )
    return inventory


def serialize_markdown_recipe(recipe: ExistingRecipe) -> dict[str, str]:
    result = {
        "cve": recipe.cve,
        "path": recipe.path,
        "maturity": recipe.maturity,
        "title": recipe.title,
    }
    if recipe.maturity == "stable":
        result["content_markdown"] = recipe.content_markdown
    return result


def normalize_cve(
    cve: dict[str, Any],
    *,
    start_date: date,
    end_date: date,
    kev_map: dict[str, dict[str, Any]],
    cwe_mapping: dict[str, list[str] | str],
    default_archetype: str,
    existing: dict[str, list[ExistingRecipe]],
) -> dict[str, Any] | None:
    cve_id = str(cve.get("id") or "").upper()
    if not re.fullmatch(r"CVE-\d{4}-\d+", cve_id):
        return None
    if str(cve.get("vulnStatus") or "").lower() in {"reject", "rejected"}:
        return None
    try:
        published = parse_date(str(cve.get("published") or ""))
    except ValueError:
        return None
    if published < start_date or published > end_date:
        return None

    metrics = extract_metrics(cve)
    selected = selected_metric(metrics)
    if selected is None:
        return None

    summary = english_description(cve)
    cwes = extract_cwes(cve)
    products, product_match_count = extract_products(cve)
    products_stored = len(products)
    references = extract_references(cve)
    kev_item = kev_map.get(cve_id)
    recipe_files = existing.get(cve_id, [])
    stable_recipe_files = [recipe for recipe in recipe_files if recipe.maturity == "stable"]
    selected_archetypes = choose_archetypes(cwes, summary, cwe_mapping, default_archetype)
    archetype = selected_archetypes[0]
    record = {
        "cve": cve_id,
        "title": candidate_title(cve_id, summary, products, kev_item),
        "summary": summary,
        "published": published.isoformat(),
        "last_modified": normalize_space(cve.get("lastModified"), limit=64),
        "status": normalize_space(cve.get("vulnStatus"), limit=64),
        "source_identifier": normalize_space(cve.get("sourceIdentifier"), limit=160),
        "severity": selected.severity,
        "score": selected.score,
        "cvss_version": selected.version,
        "vector": selected.vector,
        "metric_source": selected.source,
        "metric_type": selected.metric_type,
        "metrics": [asdict(metric) for metric in metrics[:4]],
        "cwes": cwes,
        "products": products,
        "product_match_count": product_match_count,
        "products_stored": products_stored,
        "products_truncated": product_match_count > products_stored,
        "references": references,
        "kev": bool(kev_item),
        "kev_details": normalize_kev(kev_item),
        "ecosystem": infer_ecosystem(products, summary),
        "archetype": archetype,
        "archetypes": selected_archetypes,
        "recipe_kind": (
            "markdown-override" if stable_recipe_files else "markdown-draft" if recipe_files else "composed"
        ),
        "markdown": [serialize_markdown_recipe(recipe) for recipe in recipe_files],
        "quality": "curated" if stable_recipe_files else "metadata-backed",
        "nvd_url": f"{NVD_DETAIL_ROOT}/{cve_id}",
    }
    return record


def cve_shard(record: dict[str, Any]) -> str:
    match = re.fullmatch(r"CVE-(\d{4})-(\d+)", record["cve"])
    if not match:
        raise ValueError(f"invalid CVE ID in normalized record: {record['cve']}")
    year, sequence = match.groups()
    bucket = int(sequence) // 1000
    return f"shards/{year}/{bucket:04d}.jsonl.gz"


def compact_index_record(record: dict[str, Any], shard: str) -> dict[str, Any]:
    return {
        "cve": record["cve"],
        "title": record["title"],
        "severity": record["severity"],
        "score": record["score"],
        "published": record["published"],
        "ecosystem": record["ecosystem"],
        "kev": record["kev"],
        "archetype": record["archetype"],
        "archetypes": record["archetypes"],
        # Authoritative override content is embedded only for stable Markdown.
        "has_markdown": record["recipe_kind"] == "markdown-override",
        "shard": shard,
    }


def browser_index_payload(index_records: list[dict[str, Any]]) -> tuple[bytes, bytes]:
    ecosystems = sorted({str(record["ecosystem"]) for record in index_records})
    archetypes = sorted({family for record in index_records for family in record["archetypes"]})
    ecosystem_indexes = {value: position for position, value in enumerate(ecosystems)}
    archetype_indexes = {value: position for position, value in enumerate(archetypes)}
    records = [
        [
            record["cve"],
            record["title"],
            BROWSER_SEVERITY_CODES[record["severity"]],
            record["score"],
            record["published"],
            ecosystem_indexes[record["ecosystem"]],
            record["kev"],
            [archetype_indexes[family] for family in record["archetypes"]],
            record["has_markdown"],
        ]
        for record in index_records
    ]
    uncompressed = json_bytes(
        {
            "schema_version": 2,
            "severity_codes": {str(code): severity for severity, code in BROWSER_SEVERITY_CODES.items()},
            "fields": BROWSER_INDEX_FIELDS,
            "ecosystems": ecosystems,
            "archetypes": archetypes,
            "records": records,
        }
    )
    return uncompressed, gzip.compress(uncompressed, compresslevel=9, mtime=0)


def hash_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def agentic_recipe_contract_payload(archetypes: dict[str, Any]) -> bytes:
    """Return the canonical shared agent contract without duplicating it per CVE."""
    definitions = archetypes.get("archetypes")
    recipes = {
        str(archetype_id): {
            "agentic_actions": archetype.get("agentic_actions"),
            "instruction_sources": {
                field: archetype.get(field) for field in ARCHETYPE_LIST_FIELDS
            },
        }
        for archetype_id, archetype in sorted(
            definitions.items() if isinstance(definitions, dict) else []
        )
        if isinstance(archetype, dict)
    }
    return json_bytes(
        {
            "agentic_contract": archetypes.get("agentic_contract"),
            "ecosystem_target_hints": archetypes.get("ecosystem_target_hints"),
            "archetypes": recipes,
        }
    )


def count_ecosystem_target_hints(archetypes: dict[str, Any]) -> int:
    target_hints = archetypes.get("ecosystem_target_hints")
    if not isinstance(target_hints, dict):
        return 0
    return sum(1 for hints in target_hints.values() if isinstance(hints, dict))


def catalog_timestamp(feed_metadata: Iterable[dict[str, str]], kev_data: dict[str, Any]) -> str:
    candidates = [metadata.get("lastModifiedDate", "") for metadata in feed_metadata]
    candidates.extend([str(kev_data.get("dateReleased") or ""), str(kev_data.get("catalogVersion") or "")])
    valid: list[datetime] = []
    for candidate in candidates:
        if not candidate or "T" not in candidate:
            continue
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            valid.append(parsed.astimezone(timezone.utc))
        except ValueError:
            continue
    return (max(valid) if valid else utc_now()).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def record_has_valid_composition(
    record: dict[str, Any], valid_ids: set[str], default_archetype: str
) -> bool:
    families = record.get("archetypes")
    if not isinstance(families, list) or not families or any(not isinstance(value, str) for value in families):
        return False
    if len(families) != len(set(families)) or record.get("archetype") != families[0]:
        return False
    if any(family not in valid_ids for family in families):
        return False
    if default_archetype in families and families != [default_archetype]:
        return False
    return True


def build_outputs(
    records: Iterable[dict[str, Any]],
    *,
    start_date: date,
    end_date: date,
    feed_sources: list[dict[str, Any]],
    kev_data: dict[str, Any],
    kev_payload: bytes,
    archetypes: dict[str, Any],
    existing: dict[str, list[ExistingRecipe]],
    presorted: bool = False,
) -> tuple[dict[Path, bytes], dict[str, Any]]:
    outputs: dict[Path, bytes] = {}
    index_records: list[dict[str, Any]] = []
    by_year: dict[str, dict[str, int]] = {}
    by_severity: dict[str, int] = {}
    in_scope_kev = 0
    record_count = 0
    composed_coverage = 0
    agentic_coverage = 0
    authoritative_markdown = 0
    markdown_drafts = 0
    markdown_pages = 0
    ai_enriched = 0
    ai_enrichment_complete = 0
    ai_enrichment_insufficient = 0
    valid_ids = valid_archetype_ids(archetypes)
    valid_agentic_ids = valid_agentic_archetype_ids(archetypes)
    default_archetype = str(archetypes.get("default_archetype") or "")
    shard_manifest: list[dict[str, Any]] = []
    shard_counts: dict[str, int] = {}

    ordered_records = records if presorted else sorted(records, key=lambda item: item["cve"])
    with tempfile.TemporaryDirectory(prefix="security-recipes-cve-shards-") as shard_tmp:
        shard_tmp_root = Path(shard_tmp)
        shard_spools: dict[str, Path] = {}
        open_spools: OrderedDict[str, Any] = OrderedDict()

        def append_shard_record(shard: str, payload: bytes) -> None:
            stream = open_spools.get(shard)
            if stream is None:
                if len(open_spools) >= 64:
                    _, oldest = open_spools.popitem(last=False)
                    oldest.close()
                spool = shard_spools.get(shard)
                if spool is None:
                    spool = shard_tmp_root / Path(shard).with_suffix("")
                    spool.parent.mkdir(parents=True, exist_ok=True)
                    shard_spools[shard] = spool
                stream = spool.open("ab")
                open_spools[shard] = stream
            else:
                open_spools.move_to_end(shard)
            stream.write(payload)

        try:
            for record in ordered_records:
                shard = cve_shard(record)
                append_shard_record(shard, json_bytes(record))
                shard_counts[shard] = shard_counts.get(shard, 0) + 1
                index_records.append(compact_index_record(record, shard))
                record_count += 1
                year = record["published"][:4]
                counts = by_year.setdefault(year, {"critical": 0, "high": 0, "medium": 0, "total": 0})
                counts[record["severity"]] = counts.get(record["severity"], 0) + 1
                counts["total"] += 1
                by_severity[record["severity"]] = by_severity.get(record["severity"], 0) + 1
                in_scope_kev += int(record["kev"])
                composed_coverage += int(
                    record_has_valid_composition(record, valid_ids, default_archetype)
                )
                agentic_coverage += int(
                    record_has_valid_composition(record, valid_agentic_ids, default_archetype)
                )
                authoritative_markdown += int(record["recipe_kind"] == "markdown-override")
                markdown_drafts += int(record["recipe_kind"] == "markdown-draft")
                markdown_pages += len(record["markdown"])
                enrichment = record.get("ai_enrichment")
                if isinstance(enrichment, dict):
                    ai_enriched += 1
                    ai_enrichment_complete += int(enrichment.get("status") == "complete")
                    ai_enrichment_insufficient += int(enrichment.get("status") == "insufficient_evidence")
        finally:
            for stream in open_spools.values():
                stream.close()

        for shard, spool in sorted(shard_spools.items()):
            uncompressed = spool.read_bytes()
            payload = gzip.compress(uncompressed, compresslevel=9, mtime=0)
            outputs[Path(shard)] = payload
            shard_manifest.append(
                {
                    "path": shard,
                    "records": shard_counts[shard],
                    "sha256": hash_bytes(payload),
                    "bytes": len(payload),
                    "uncompressed_bytes": len(uncompressed),
                }
            )

    shard_set_payload = json_bytes(
        [
            {"path": entry["path"], "sha256": entry["sha256"]}
            for entry in shard_manifest
        ]
    )
    shard_set_sha256 = hash_bytes(shard_set_payload)
    archetypes_payload = json_bytes(archetypes, pretty=True)
    agentic_contract_payload = agentic_recipe_contract_payload(archetypes)
    definitions = archetypes.get("archetypes")
    action_count = sum(
        len(archetype.get("agentic_actions") or [])
        for archetype in (definitions.values() if isinstance(definitions, dict) else [])
        if isinstance(archetype, dict)
    )
    target_hints = archetypes.get("ecosystem_target_hints")
    agentic_contract = archetypes.get("agentic_contract")
    archetypes_manifest = {
        "path": "archetypes.json",
        "bytes": len(archetypes_payload),
        "sha256": hash_bytes(archetypes_payload),
        "agentic_contract": {
            "schema_version": (
                agentic_contract.get("schema_version")
                if isinstance(agentic_contract, dict)
                else None
            ),
            "sha256": hash_bytes(agentic_contract_payload),
            "bytes": len(agentic_contract_payload),
            "archetypes": len(valid_agentic_ids),
            "actions": action_count,
            "phases": len(AGENTIC_PHASES),
            "ecosystems": len(target_hints) if isinstance(target_hints, dict) else 0,
            "target_hints": count_ecosystem_target_hints(archetypes),
        },
    }

    source_timestamp = catalog_timestamp((source["metadata"] for source in feed_sources), kev_data)
    duplicate_markdown = {
        cve: [recipe.path for recipe in recipes]
        for cve, recipes in sorted(existing.items())
        if len(recipes) > 1
    }
    coverage_percent = round((composed_coverage * 100.0 / record_count), 6) if record_count else 0.0
    agentic_coverage_percent = round((agentic_coverage * 100.0 / record_count), 6) if record_count else 0.0

    browser_uncompressed, browser_compressed = browser_index_payload(index_records)
    browser_path = "browser-index.json.gz"
    outputs[Path(browser_path)] = browser_compressed
    browser_manifest = {
        "path": browser_path,
        "records": len(index_records),
        "sha256": hash_bytes(browser_compressed),
        "bytes": len(browser_compressed),
        "uncompressed_bytes": len(browser_uncompressed),
    }
    manifest = {
        "schema_version": 2,
        "catalog_updated_at": source_timestamp,
        "scope": {
            "published_start": start_date.isoformat(),
            "published_end": end_date.isoformat(),
            "statuses_excluded": ["Reject", "Rejected"],
            "metric_policy": "Any NVD-supplied CVSS v2/v3/v4 observation with baseScore >= 4.0; effective severity is the highest supplied/derived severity.",
            "recipe_policy": "Every record composes with all applicable vetted remediation archetypes. Only maturity=stable Markdown is an authoritative self-contained override; has_markdown excludes drafts.",
        },
        "totals": {
            "catalog_records": record_count,
            "composed_recipe_coverage": composed_coverage,
            "coverage_percent": coverage_percent,
            "agentic_recipe_coverage": agentic_coverage,
            "agentic_coverage_percent": agentic_coverage_percent,
            "markdown_overrides": authoritative_markdown,
            "markdown_drafts": markdown_drafts,
            "markdown_pages": markdown_pages,
            "stable_markdown_overrides": authoritative_markdown,
            "ai_enriched_records": ai_enriched,
            "ai_enrichment_complete": ai_enrichment_complete,
            "ai_enrichment_insufficient_evidence": ai_enrichment_insufficient,
            "in_scope_kev": in_scope_kev,
            "shards": len(shard_manifest),
        },
        "by_severity": dict(sorted(by_severity.items())),
        "by_publication_year": dict(sorted(by_year.items())),
        "sources": {
            "nvd": {
                "feed_root": NVD_FEED_ROOT,
                "feeds": feed_sources,
            },
            "cisa_kev": {
                "url": CISA_KEV_URL,
                "catalog_version": kev_data.get("catalogVersion"),
                "date_released": kev_data.get("dateReleased"),
                "sha256": hash_bytes(kev_payload),
                "catalog_records": len(kev_data.get("vulnerabilities") or []),
            },
        },
        "markdown_duplicate_ids": duplicate_markdown,
        "browser_index": browser_manifest,
        "archetypes_asset": archetypes_manifest,
        "shard_set_sha256": shard_set_sha256,
        "shard_manifest": shard_manifest,
    }
    # The audit manifest intentionally carries every source and shard hash and
    # is therefore much larger than the metadata the interactive catalog needs
    # at startup.  Keep a compact, independently hashed bootstrap document so
    # the common page-load path does not transfer the full audit manifest.
    runtime_summary = {
        "schema_version": 2,
        "catalog_updated_at": source_timestamp,
        "scope": {
            "published_start": start_date.isoformat(),
            "published_end": end_date.isoformat(),
        },
        "totals": manifest["totals"],
        "by_severity": manifest["by_severity"],
        "by_publication_year": manifest["by_publication_year"],
        "browser_index": browser_manifest,
        "archetypes": archetypes_manifest,
        "shard_set_sha256": shard_set_sha256,
    }
    runtime_summary_payload = json_bytes(runtime_summary)
    runtime_summary_path = "runtime-summary.json"
    outputs[Path(runtime_summary_path)] = runtime_summary_payload
    manifest["runtime_summary"] = {
        "path": runtime_summary_path,
        "bytes": len(runtime_summary_payload),
        "sha256": hash_bytes(runtime_summary_payload),
    }
    index_partitions: list[dict[str, Any]] = []
    records_by_year: dict[str, list[dict[str, Any]]] = {}
    for record in index_records:
        records_by_year.setdefault(str(record["published"])[:4], []).append(record)
    for year, year_records in sorted(records_by_year.items()):
        relative = Path("indexes") / f"{year}.json.gz"
        uncompressed = index_json_bytes(
            {
                "schema_version": 2,
                "catalog_updated_at": source_timestamp,
                "year": year,
                "total": len(year_records),
                "records": year_records,
            }
        )
        compressed = gzip.compress(uncompressed, compresslevel=9, mtime=0)
        outputs[relative] = compressed
        index_partitions.append(
            {
                "year": year,
                "path": relative.as_posix(),
                "records": len(year_records),
                "sha256": hash_bytes(compressed),
                "bytes": len(compressed),
                "uncompressed_bytes": len(uncompressed),
            }
        )
    index = {
        "schema_version": 2,
        "catalog_updated_at": source_timestamp,
        "total": len(index_records),
        "scope": manifest["scope"],
        "partition_key": "published_year",
        "partitions": index_partitions,
    }
    outputs[Path("index.json")] = json_bytes(index, pretty=True)
    manifest["complete_index"] = {
        "path": "index.json",
        "format": "published-year-partitions",
        "records": len(index_records),
        "partitions": index_partitions,
    }
    outputs[Path("manifest.json")] = json_bytes(manifest, pretty=True)
    outputs[Path("archetypes.json")] = archetypes_payload
    return outputs, manifest


def _is_link_or_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or bool(is_junction and is_junction())


def _validated_output_paths(outputs: dict[Path, bytes]) -> dict[str, bytes]:
    expected: dict[str, bytes] = {}
    for relative_path, payload in outputs.items():
        relative = relative_path.as_posix()
        pure = PurePosixPath(relative)
        if (
            not relative
            or relative == "."
            or "\\" in relative
            or ":" in relative
            or pure.is_absolute()
            or ".." in pure.parts
        ):
            raise ValueError(f"unsafe generated catalog output path: {relative!r}")
        if relative in expected:
            raise ValueError(f"duplicate generated catalog output path: {relative}")
        expected[relative] = payload
    return expected


def _expected_output_dirs(expected: set[str]) -> set[str]:
    directories: set[str] = set()
    for relative in expected:
        for parent in PurePosixPath(relative).parents:
            if str(parent) != ".":
                directories.add(parent.as_posix())
    return directories


def _catalog_tree_entries(output_dir: Path) -> list[tuple[Path, str, str]]:
    """Return catalog entries post-order without following links or junctions."""
    if _is_link_or_junction(output_dir):
        raise ValueError(f"catalog output root must not be a link or junction: {output_dir}")
    if output_dir.exists() and not output_dir.is_dir():
        raise NotADirectoryError(f"catalog output root is not a directory: {output_dir}")
    if not output_dir.exists():
        return []

    entries: list[tuple[Path, str, str]] = []

    def visit(directory: Path) -> None:
        with os.scandir(directory) as scanned:
            children = sorted(scanned, key=lambda entry: entry.name)
        for child in children:
            path = Path(child.path)
            relative = path.relative_to(output_dir).as_posix()
            if child.is_symlink() or _is_link_or_junction(path):
                entries.append((path, relative, "link"))
            elif child.is_dir(follow_symlinks=False):
                visit(path)
                entries.append((path, relative, "directory"))
            elif child.is_file(follow_symlinks=False):
                entries.append((path, relative, "file"))
            else:
                entries.append((path, relative, "special"))

    visit(output_dir)
    return entries


def reconcile_output_tree(
    output_dir: Path,
    expected: set[str],
    *,
    dry_run: bool = False,
) -> int:
    """Remove every unowned node from the generated catalog tree.

    Links are never valid generated outputs, even when their path is expected:
    following one while updating the catalog could write outside ``output_dir``.
    Directories are retained only when they are parents of expected files.
    """
    expected_dirs = _expected_output_dirs(expected)
    removed = 0
    for path, relative, kind in _catalog_tree_entries(output_dir):
        should_remove = (
            kind in {"link", "special"}
            or (kind == "file" and relative not in expected)
            or (kind == "directory" and relative not in expected_dirs)
        )
        if not should_remove:
            continue
        removed += 1
        if dry_run:
            continue
        if kind == "directory":
            path.rmdir()
        elif kind == "link" and bool(
            getattr(path, "is_junction", lambda: False)()
        ) and not path.is_symlink():
            path.rmdir()
        else:
            path.unlink()
    return removed


def _current_output_matches(output_dir: Path, relative: str, payload: bytes) -> bool:
    current = output_dir
    for part in PurePosixPath(relative).parts[:-1]:
        current /= part
        if _is_link_or_junction(current) or not current.is_dir():
            return False
    target = output_dir / Path(relative)
    return (
        not _is_link_or_junction(target)
        and target.is_file()
        and target.read_bytes() == payload
    )


def write_outputs(output_dir: Path, outputs: dict[Path, bytes], *, dry_run: bool = False) -> dict[str, int]:
    expected_payloads = _validated_output_paths(outputs)
    expected = set(expected_payloads)
    removed = reconcile_output_tree(output_dir, expected, dry_run=dry_run)
    changed = 0
    unchanged = 0
    for relative, payload in expected_payloads.items():
        if dry_run:
            is_changed = not _current_output_matches(output_dir, relative, payload)
        else:
            is_changed = write_if_changed(output_dir / Path(relative), payload)
        if is_changed:
            changed += 1
        else:
            unchanged += 1
    return {"changed": changed, "unchanged": unchanged, "removed": removed}


def parse_ai_enrichment_limit(value: str) -> int:
    try:
        limit = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("AI enrichment limit must be an integer") from exc
    if not 0 <= limit <= MAX_AI_ENRICHMENT_LIMIT:
        raise argparse.ArgumentTypeError(
            f"AI enrichment limit must be between 0 and {MAX_AI_ENRICHMENT_LIMIT}"
        )
    return limit


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    today = utc_now().date()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start-date", default=ten_year_cutoff(today).isoformat())
    parser.add_argument("--end-date", default=today.isoformat())
    parser.add_argument(
        "--feed-start-year",
        type=int,
        default=2002,
        help="Earliest NVD identifier-year feed to scan. Use 2002 for exact publication-window coverage.",
    )
    parser.add_argument("--feed-end-year", type=int, default=today.year)
    parser.add_argument("--content-dir", type=Path, default=DEFAULT_CONTENT_DIR)
    parser.add_argument("--archetypes", type=Path, default=DEFAULT_ARCHETYPES)
    parser.add_argument("--enrichment-cache", type=Path, default=DEFAULT_ENRICHMENT_CACHE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument(
        "--openai-model",
        default=os.environ.get("OPENAI_MODEL", DEFAULT_OPENAI_MODEL),
        help="Responses API model for optional evidence-constrained enrichment.",
    )
    parser.add_argument(
        "--ai-enrichment-limit",
        type=parse_ai_enrichment_limit,
        default=os.environ.get("OPENAI_ENRICHMENT_LIMIT", str(DEFAULT_AI_ENRICHMENT_LIMIT)),
        help=(
            "Maximum new/source-changed CVEs enriched per run when OPENAI_API_KEY is set "
            f"(0-{MAX_AI_ENRICHMENT_LIMIT})."
        ),
    )
    parser.add_argument(
        "--disable-ai-enrichment",
        action="store_true",
        help="Attach valid cached enrichments but make no OpenAI requests.",
    )
    parser.add_argument("--offline", action="store_true", help="Use only cached NVD and KEV inputs.")
    parser.add_argument("--dry-run", action="store_true", help="Fetch and validate sources without writing catalog files.")
    parser.add_argument("--limit", type=int, help="Development-only cap after normalization.")
    return parser.parse_args(argv)


def resolve_path(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def iter_record_spool(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("rb") as stream:
        for line in stream:
            if line.strip():
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError(f"invalid normalized CVE spool record in {path}")
                yield record


def merged_record_spools(paths: Iterable[Path]) -> Iterator[dict[str, Any]]:
    iterators = [iter_record_spool(path) for path in paths]
    yield from heapq.merge(*iterators, key=lambda record: str(record.get("cve") or ""))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    start_date = parse_date(args.start_date)
    end_date = parse_date(args.end_date)
    if start_date > end_date:
        raise ValueError("--start-date must not be later than --end-date")
    if args.feed_start_year > args.feed_end_year:
        raise ValueError("--feed-start-year must not be later than --feed-end-year")
    if args.ai_enrichment_limit < 0:
        raise ValueError("--ai-enrichment-limit must not be negative")

    cache_dir = resolve_path(args.cache_dir)
    content_dir = resolve_path(args.content_dir)
    archetype_path = resolve_path(args.archetypes)
    enrichment_cache_path = resolve_path(args.enrichment_cache)
    output_dir = resolve_path(args.output_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)

    archetypes, cwe_mapping = load_archetypes(archetype_path)
    default_archetype = str(archetypes["default_archetype"])
    existing = markdown_inventory(content_dir)
    kev_data, kev_payload = cache_kev(cache_dir, offline=args.offline)
    kev_map = kev_by_cve(kev_data)
    enrichment_cache = EnrichmentCache.load(enrichment_cache_path)
    openai_key = os.environ.get("OPENAI_API_KEY", "").strip()
    openai_client: OpenAIEnricher | None = None
    if openai_key and not args.disable_ai_enrichment and not args.offline and not args.dry_run:
        openai_client = OpenAIEnricher(openai_key, model=args.openai_model)
        print(
            f"Optional OpenAI enrichment enabled with model {openai_client.model!r} "
            f"and limit {args.ai_enrichment_limit}.",
            flush=True,
        )
    elif not openai_key:
        print("OPENAI_API_KEY is not set; source sync and valid cached enrichments will continue.", flush=True)
    else:
        disabled_reason = (
            "--disable-ai-enrichment"
            if args.disable_ai_enrichment
            else "offline mode"
            if args.offline
            else "dry-run mode"
        )
        print(f"Optional OpenAI requests are disabled by {disabled_reason}.", flush=True)

    feed_sources: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="normalized-cve-records-", dir=cache_dir) as spool_tmp:
        spool_root = Path(spool_tmp)
        spool_paths: list[Path] = []
        seen_cves: set[str] = set()
        years = range(args.feed_start_year, args.feed_end_year + 1)
        for year in years:
            print(f"[{year}] fetching and validating NVD feed", flush=True)
            feed_path, metadata = cache_feed(year, cache_dir, offline=args.offline)
            payload = load_feed(feed_path)
            year_records: dict[str, bytes] = {}
            for item in payload["vulnerabilities"]:
                cve = item.get("cve") if isinstance(item, dict) else None
                if not isinstance(cve, dict):
                    continue
                record = normalize_cve(
                    cve,
                    start_date=start_date,
                    end_date=end_date,
                    kev_map=kev_map,
                    cwe_mapping=cwe_mapping,
                    default_archetype=default_archetype,
                    existing=existing,
                )
                if record is None:
                    continue
                cve_id = record["cve"]
                if cve_id in year_records or cve_id in seen_cves:
                    raise ValueError(f"NVD feeds contain duplicate normalized identity {cve_id}")
                year_records[cve_id] = json_bytes(record)

            spool_path = spool_root / f"{year}.jsonl"
            with spool_path.open("wb") as stream:
                for cve_id in sorted(year_records):
                    stream.write(year_records[cve_id])
            spool_paths.append(spool_path)
            seen_cves.update(year_records)
            accepted = len(year_records)
            feed_sources.append(
                {
                    "year": year,
                    "url": f"{NVD_FEED_ROOT}/nvdcve-2.0-{year}.json.gz",
                    "accepted_records": accepted,
                    "metadata": metadata,
                }
            )
            print(f"[{year}] accepted {accepted:,} in-scope Medium/High/Critical records", flush=True)
            del payload, year_records
            gc.collect()

        def output_records() -> Iterable[dict[str, Any]]:
            records: Iterable[dict[str, Any]] = merged_record_spools(spool_paths)
            if args.limit is not None:
                records = itertools.islice(records, max(0, args.limit))
            return records

        enrichment_cache.select_candidates(
            output_records(),
            limit=args.ai_enrichment_limit if openai_client is not None else 0,
        )
        records = enrichment_cache.apply(output_records(), client=openai_client)
        outputs, manifest = build_outputs(
            records,
            start_date=start_date,
            end_date=end_date,
            feed_sources=feed_sources,
            kev_data=kev_data,
            kev_payload=kev_payload,
            archetypes=archetypes,
            existing=existing,
            presorted=True,
        )
    write_summary = write_outputs(output_dir, outputs, dry_run=args.dry_run)
    enrichment_cache_changed = enrichment_cache.write(dry_run=args.dry_run)
    print(
        json.dumps(
            {
                "scope": manifest["scope"],
                "totals": manifest["totals"],
                "output": str(output_dir),
                "writes": write_summary,
                "ai_enrichment": {
                    **enrichment_cache.stats,
                    "cache": str(enrichment_cache_path),
                    "cache_changed": enrichment_cache_changed,
                    "api_enabled": openai_client is not None,
                },
                "dry_run": args.dry_run,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
