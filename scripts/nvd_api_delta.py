"""Reconcile verified NVD annual feeds with a bounded, stabilized official API delta."""

from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Iterator
from urllib.parse import urlencode


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
MAX_PAGES = 200
MAX_RECORDS = 100000
MAX_WINDOW = timedelta(days=120)
WINDOW_STEP = timedelta(days=1)
REQUEST_INTERVAL = 6.1  # Public API, without requesting or discovering a key.
CVE_ID = re.compile(r"CVE-([0-9]{4})-[0-9]{4,}")


def source_datetime(value: object) -> datetime:
    if not isinstance(value, str) or "T" not in value:
        raise ValueError("NVD source timestamp is missing or invalid")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    # NVD API timestamps are UTC without an offset; feed metadata has an offset.
    return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def baseline_digest(feeds: list[dict[str, Any]]) -> str:
    baseline = [{"year": feed["year"], "metadata": feed["metadata"]} for feed in feeds]
    return hashlib.sha256(json.dumps(baseline, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def fetch_delta(
    feeds: list[dict[str, Any]],
    *,
    end: datetime,
    fetch: Callable[[str], bytes],
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Require matching complete daily traversals, or fail without a partial result.

    Starting at the oldest feed is deliberate: identifier-year feeds that rarely
    change may have much older watermarks. A recent-publications-only query misses
    older CVEs gaining scores, being rejected, or receiving corrected evidence.
    """
    if not feeds:
        raise ValueError("NVD API delta requires verified annual feed metadata")
    start = min(source_datetime(feed["metadata"]["lastModifiedDate"]) for feed in feeds)
    end = source_datetime(timestamp(end))
    if start > end or end - start > MAX_WINDOW:
        raise ValueError("NVD API delta window must be between zero and 120 days; refresh annual feeds first")
    records: dict[str, dict[str, Any]] = {}
    seen: dict[str, tuple[str, datetime]] = {}
    baselines = {feed["year"]: source_datetime(feed["metadata"]["lastModifiedDate"]) for feed in feeds}
    pages: list[dict[str, Any]] = []
    boundary_duplicates = 0
    window_start = start
    while True:
        window_end = min(window_start + WINDOW_STEP, end)
        # Counts alone cannot detect equal-total membership changes between
        # pages. Require two complete traversals with identical CVE content.
        # These are stable observations, not an atomic upstream snapshot.
        for window_attempt in range(2):
            page_indices: list[int] = []
            drift = False
            previous_digest: str | None = None
            for _ in range(2):
                offset = 0
                expected_total: int | None = None
                window_records: dict[str, dict[str, Any]] = {}
                scan_indices: list[int] = []
                while True:
                    if len(pages) >= MAX_PAGES:
                        raise ValueError("NVD API delta exceeded its bounded page budget")
                    if pages:
                        sleep(REQUEST_INTERVAL)
                    url = NVD_API_URL + "?" + urlencode({
                        "lastModStartDate": timestamp(window_start),
                        "lastModEndDate": timestamp(window_end),
                        "resultsPerPage": PAGE_SIZE, "startIndex": offset,
                    })
                    raw = fetch(url)
                    page = json.loads(raw)
                    if not isinstance(page, dict):
                        raise ValueError("NVD API delta response is not an object")
                    total, count, position = (page.get(key) for key in ("totalResults", "resultsPerPage", "startIndex"))
                    rows = page.get("vulnerabilities")
                    if (
                        any(type(value) is not int or value < 0 for value in (total, count, position))
                        or position != offset or not isinstance(rows, list) or count != len(rows)
                        or count > PAGE_SIZE or offset + count > total or (count == 0 and offset < total)
                    ):
                        raise ValueError("NVD API delta pagination is incomplete or malformed")
                    if total > MAX_RECORDS:
                        raise ValueError("NVD API delta exceeds its bounded record budget")
                    scan_indices.append(len(pages))
                    pages.append({"url": url, "records": count, "total_results": total,
                                  "accepted": False, "sha256": hashlib.sha256(raw).hexdigest(),
                                  "scan_sha256": None})
                    if expected_total is None:
                        expected_total = total
                    elif total != expected_total:
                        drift = True
                        break
                    for row in rows:
                        cve = row.get("cve") if isinstance(row, dict) else None
                        if not isinstance(cve, dict) or CVE_ID.fullmatch(str(cve.get("id") or "")) is None:
                            raise ValueError("NVD API delta contains an invalid CVE identity")
                        identity = cve["id"]
                        modified = source_datetime(cve.get("lastModified"))
                        source_datetime(cve.get("published"))
                        if not window_start <= modified <= window_end:
                            raise ValueError(f"NVD API delta {identity} falls outside its modification window")
                        if identity in window_records:
                            drift = True
                            break
                        window_records[identity] = cve
                    if drift:
                        break
                    offset += count
                    if offset == total:
                        break
                page_indices.extend(scan_indices)
                if drift:
                    break
                scan_digest = hashlib.sha256(json.dumps(
                    window_records, sort_keys=True, separators=(",", ":"),
                ).encode()).hexdigest()
                for position in scan_indices:
                    pages[position]["scan_sha256"] = scan_digest
                if previous_digest is not None and previous_digest != scan_digest:
                    drift = True
                    break
                previous_digest = scan_digest
            if not drift:
                for position in page_indices:
                    pages[position]["accepted"] = True
                break
            if window_attempt == 1:
                raise ValueError("NVD API delta window keeps drifting; no partial snapshot is publishable")
        for identity, cve in window_records.items():
            modified = source_datetime(cve["lastModified"])
            digest = hashlib.sha256(json.dumps(cve, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if identity in seen:
                previous_digest, previous_end = seen[identity]
                if digest == previous_digest and previous_end == window_start and modified == window_start:
                    boundary_duplicates += 1
                    continue
                raise ValueError(f"NVD API delta contains conflicting identity {identity}")
            seen[identity] = (digest, window_end)
            if len(seen) > MAX_RECORDS:
                raise ValueError("NVD API delta exceeds its bounded record budget")
            # Retain only revisions not already covered by their own feed.
            baseline = baselines.get(int(identity.split("-")[1]))
            if baseline is not None and modified >= baseline:
                records[identity] = cve
        if window_end == end:
            break
        window_start = window_end
    newest = max((source_datetime(cve["lastModified"]) for cve in records.values()), default=None)
    return records, {
        "url": NVD_API_URL,
        "baseline_sha256": baseline_digest(feeds),
        "last_mod_start": timestamp(start),
        "last_mod_end": timestamp(end),
        "latest_record_modified": timestamp(newest) if newest is not None else None,
        "records": len(seen),
        "overlay_records": len(records),
        "boundary_duplicates": boundary_duplicates,
        "pages": pages,
    }


def overlay_year(
    annual: Iterable[dict[str, Any]], delta: dict[str, dict[str, Any]], year: int,
) -> Iterator[dict[str, Any]]:
    """Overlay before normalization so rejections and score downgrades remove rows too."""
    remaining = {identity for identity in delta if int(identity.split("-")[1]) == year}
    seen: set[str] = set()
    for item in annual:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict):
            continue
        identity = str(cve.get("id") or "")
        if identity in seen:
            raise ValueError(f"NVD annual feed contains duplicate identity {identity}")
        seen.add(identity)
        replacement = delta.get(identity)
        if replacement is not None:
            remaining.discard(identity)
            # A feed fetched after the API snapshot can contain a newer revision.
            if source_datetime(replacement["lastModified"]) >= source_datetime(cve.get("lastModified")):
                cve = replacement
        yield {"cve": cve}
    for identity in sorted(remaining):
        yield {"cve": delta[identity]}
