"""Read-only expiry of the latest-CVE view; historical catalog data is untouched."""

from __future__ import annotations

import gzip
import hashlib
import html
import io
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Existing deployment freshness gate and watchdog freshness limit, respectively.
# Publication dates have day precision: expire conservatively from UTC midnight.
CATALOG_MAX_AGE_HOURS = 36
PUBLICATION_MAX_AGE_HOURS = 72
MAX_ITEMS = 10
MAX_PARTITION_BYTES = 64 * 1024 * 1024


def utc_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp requires a timezone")
    return parsed.astimezone(timezone.utc)


def project_latest(
    manifest: dict[str, Any], records: list[dict[str, Any]], now: datetime,
) -> dict[str, Any]:
    """Derive an expiring view without changing a source date or input record."""
    if now.tzinfo is None:
        raise ValueError("evaluation time requires a timezone")
    now = now.astimezone(timezone.utc)
    revision = manifest.get("shard_set_sha256")
    source_stamp = manifest.get("catalog_updated_at")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}", revision):
        raise ValueError("missing catalog revision")
    if not isinstance(source_stamp, str):
        raise ValueError("missing source timestamp")
    source_time = utc_timestamp(source_stamp)
    if source_time > now:
        raise ValueError("source timestamp is in the future")
    source_expiry = source_time + timedelta(hours=CATALOG_MAX_AGE_HOURS)
    result: dict[str, Any] = {
        "schema_version": 1,
        "source_revision": revision,
        "source_updated_at": source_stamp,
        "catalog_max_age_hours": CATALOG_MAX_AGE_HOURS,
        "publication_max_age_hours": PUBLICATION_MAX_AGE_HOURS,
        "status": "stale" if now >= source_expiry else "empty",
        "evaluated_at": now.isoformat().replace("+00:00", "Z"),
        "stage": "prune",
        "pipeline": manifest.get("pipeline", {}),
        "records": [],
    }
    if now >= source_expiry:
        return result
    seen: set[str] = set()
    selected = []
    for raw in records:
        cve = raw.get("cve")
        published = raw.get("published")
        if not isinstance(cve, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            continue
        if cve in seen or not isinstance(published, str):
            continue
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", published):
            continue
        try:
            publication = utc_timestamp(published + "T00:00:00Z")
        except ValueError:
            continue
        expiry = min(source_expiry, publication + timedelta(hours=PUBLICATION_MAX_AGE_HOURS))
        if not publication <= now < expiry:
            continue
        severity = raw.get("severity")
        title = raw.get("title")
        score = raw.get("score")
        if (severity not in {"medium", "high", "critical"}
            or not isinstance(title, str) or not title.strip()
            or type(score) not in (int, float) or not 4 <= score <= 10):
            continue
        seen.add(cve)
        selected.append({
            "cve": cve, "title": title[:180], "severity": severity,
            "score": score, "published": published, "kev": raw.get("kev") is True,
            "expires_at": expiry.isoformat().replace("+00:00", "Z"),
        })
    # Match the bounded runtime's existing newest browse order. With the same
    # order, taking its first 100 candidates cannot change our first 10 records.
    selected.sort(key=lambda r: (r["published"], r["cve"]), reverse=True)
    result["records"] = selected[:MAX_ITEMS]
    if result["records"]:
        result["status"] = "ready"
    return result


def unavailable_projection() -> dict[str, Any]:
    return {"schema_version": 1, "status": "unavailable", "records": []}


def project_runtime(catalog: Any, now: datetime) -> dict[str, Any]:
    """Pin the existing read-only runtime to one immutable catalog generation."""
    manifest = catalog.info()["manifest"]
    revision = manifest["shard_set_sha256"]
    # No need to load/query the catalog when its source is already stale.
    result = project_latest(manifest, [], now)
    if result["status"] != "stale":
        records, _ = catalog.search_page("", limit=100, expected_revision=revision)
        result = project_latest(manifest, records, now)
    if catalog.active_revision() != revision:
        raise ValueError("catalog changed during projection")
    return result


def project_directory(root: Path, now: datetime) -> dict[str, Any]:
    """Offline generator used by the independent workflow, with read consistency."""
    manifest_path = root / "manifest.json"
    original = manifest_path.read_bytes()
    manifest = json.loads(original)
    if manifest.get("schema_version") != 2:
        raise ValueError("unsupported catalog schema")
    result = project_latest(manifest, [], now)
    records = []
    if result["status"] != "stale":
        for entry in manifest["complete_index"]["partitions"]:
            relative = entry["path"]
            if not re.fullmatch(r"indexes/\d{4}\.json\.gz", relative):
                raise ValueError("invalid partition path")
            # Only years intersecting the 72-hour window can contribute.
            if int(entry["year"]) < (now - timedelta(hours=PUBLICATION_MAX_AGE_HOURS)).year:
                continue
            target = root / relative
            if target.is_symlink() or not target.resolve().is_relative_to(root.resolve()):
                raise ValueError("partition escapes catalog")
            if target.stat().st_size > MAX_PARTITION_BYTES:
                raise ValueError("compressed partition exceeds size bound")
            compressed = target.read_bytes()
            if hashlib.sha256(compressed).hexdigest() != entry["sha256"]:
                raise ValueError("partition hash mismatch")
            with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
                raw = stream.read(MAX_PARTITION_BYTES + 1)
            if len(raw) > MAX_PARTITION_BYTES:
                raise ValueError("partition exceeds size bound")
            payload = json.loads(raw)
            if payload.get("schema_version") != 2 or payload.get("year") != entry["year"]:
                raise ValueError("partition identity mismatch")
            records.extend(payload["records"])
        result = project_latest(manifest, records, now)
    if manifest_path.read_bytes() != original:
        raise ValueError("catalog changed during projection")
    result["manifest_sha256"] = hashlib.sha256(original).hexdigest()
    return result


def render_latest(projection: dict[str, Any]) -> str:
    """Small escaped SSI fragment; no static stale-card fallback is included."""
    records = projection.get("records", [])
    if projection.get("status") != "ready" or not records:
        return ('<p class="cve-latest-status" role="status">'
                'Fresh CVE updates are unavailable. '
                '<a href="/cve-database/">Browse the historical CVE catalog</a>.</p>')
    items = []
    for record in records:
        cve = html.escape(record["cve"], quote=True)
        title = html.escape(record["title"], quote=True)
        severity = record["severity"]
        published = record["published"]
        label = datetime.strptime(published, "%Y-%m-%d").strftime("%b %d").replace(" 0", " ")
        items.append(
            '<li><a class="cve-ticker__item" data-cve-ticker-link '
            f'href="/cve/{cve}/" aria-label="{cve}: {title}. {severity}, published {published}.">'
            f'<span class="cve-ticker__id">{cve}</span>'
            f'<span class="cve-ticker__title">{title}</span>'
            f'<span class="cve-ticker__severity cve-ticker__severity--{severity}">{severity}</span>'
            + ('<span class="cve-ticker__kev">KEV</span>' if record["kev"] else '')
            + f'<time class="cve-ticker__date" datetime="{published}">{label}</time></a></li>'
        )
    listing = ''.join(items)
    return ('<div class="cve-ticker__viewport"><div class="cve-ticker__track">'
            f'<ul class="cve-ticker__list">{listing}</ul>'
            f'<ul class="cve-ticker__list" aria-hidden="true" inert>{listing}</ul>'
            '</div></div><button class="cve-ticker__toggle" type="button" '
            'data-cve-ticker-toggle aria-label="Pause latest CVE ticker" aria-pressed="false" '
            'title="Pause ticker" hidden>Pause</button>')
