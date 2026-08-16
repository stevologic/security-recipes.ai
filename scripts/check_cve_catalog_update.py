#!/usr/bin/env python3
"""Quarantine suspicious CVE catalog refreshes before they can auto-merge."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1


@dataclass(frozen=True)
class Finding:
    code: str
    message: str


def _load_object(path: Path, *, description: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{description} is not readable JSON: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{description} must be a JSON object: {path}")
    return payload


def _integer(mapping: object, key: str) -> int | None:
    if not isinstance(mapping, dict):
        return None
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _drop_is_suspicious(
    before: int,
    after: int,
    *,
    relative: float,
    absolute: int,
) -> bool:
    return (
        before > 0
        and after < before
        and before - after >= absolute
        and (before - after) / before >= relative
    )


def _nvd_feed_counts(manifest: dict[str, Any]) -> dict[int, int]:
    sources = manifest.get("sources")
    nvd = sources.get("nvd") if isinstance(sources, dict) else None
    feeds = nvd.get("feeds") if isinstance(nvd, dict) else None
    if not isinstance(feeds, list):
        return {}
    result: dict[int, int] = {}
    for feed in feeds:
        if not isinstance(feed, dict):
            continue
        year = feed.get("year")
        accepted = feed.get("accepted_records")
        if (
            isinstance(year, int)
            and not isinstance(year, bool)
            and isinstance(accepted, int)
            and not isinstance(accepted, bool)
            and accepted >= 0
        ):
            result[year] = accepted
    return result


def _nvd_feed_timestamps(manifest: dict[str, Any]) -> dict[int, datetime]:
    sources = manifest.get("sources")
    nvd = sources.get("nvd") if isinstance(sources, dict) else None
    feeds = nvd.get("feeds") if isinstance(nvd, dict) else None
    if not isinstance(feeds, list):
        return {}
    result: dict[int, datetime] = {}
    for feed in feeds:
        if not isinstance(feed, dict):
            continue
        year = feed.get("year")
        metadata = feed.get("metadata")
        modified = (
            _timestamp(metadata.get("lastModifiedDate"))
            if isinstance(metadata, dict)
            else None
        )
        if isinstance(year, int) and not isinstance(year, bool) and modified is not None:
            result[year] = modified
    return result


def _year_totals(manifest: dict[str, Any]) -> dict[str, int]:
    raw = manifest.get("by_publication_year")
    if not isinstance(raw, dict):
        return {}
    result: dict[str, int] = {}
    for year, counts in raw.items():
        total = _integer(counts, "total")
        if isinstance(year, str) and total is not None and total >= 0:
            result[year] = total
    return result


def catalog_anomalies(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    sync_report: dict[str, Any],
) -> list[Finding]:
    """Return conservative signals that require a person to inspect the refresh."""

    findings: list[Finding] = []
    before_totals = baseline.get("totals")
    after_totals = candidate.get("totals")
    before_records = _integer(before_totals, "catalog_records")
    after_records = _integer(after_totals, "catalog_records")
    if after_records is None or after_records <= 0:
        findings.append(
            Finding("catalog-empty", "Candidate catalog record count is missing or empty.")
        )
    elif before_records is not None:
        if after_records < max(1_000, int(before_records * 0.80)):
            findings.append(
                Finding(
                    "catalog-implausibly-small",
                    f"Catalog fell from {before_records:,} to {after_records:,} records.",
                )
            )
        elif _drop_is_suspicious(
            before_records, after_records, relative=0.005, absolute=250
        ):
            findings.append(
                Finding(
                    "catalog-record-drop",
                    f"Catalog lost {before_records - after_records:,} records "
                    f"({before_records:,} → {after_records:,}).",
                )
            )

    baseline_time = _timestamp(baseline.get("catalog_updated_at"))
    candidate_time = _timestamp(candidate.get("catalog_updated_at"))
    if candidate_time is None:
        findings.append(
            Finding(
                "catalog-timestamp-invalid",
                "Candidate catalog_updated_at is absent or not an ISO-8601 timestamp.",
            )
        )
    elif baseline_time is not None and candidate_time < baseline_time:
        findings.append(
            Finding(
                "catalog-timestamp-regressed",
                "Catalog source timestamp moved backward "
                f"({baseline.get('catalog_updated_at')} → "
                f"{candidate.get('catalog_updated_at')}).",
            )
        )

    before_years = _year_totals(baseline)
    after_years = _year_totals(candidate)
    missing_years = sorted(set(before_years) - set(after_years))
    if missing_years:
        findings.append(
            Finding(
                "publication-years-missing",
                "Publication-year partitions disappeared: " + ", ".join(missing_years),
            )
        )
    for year in sorted(set(before_years) & set(after_years)):
        before = before_years[year]
        after = after_years[year]
        if _drop_is_suspicious(before, after, relative=0.10, absolute=100):
            findings.append(
                Finding(
                    "publication-year-drop",
                    f"Publication year {year} lost {before - after:,} records "
                    f"({before:,} → {after:,}).",
                )
            )

    before_kev = _integer(before_totals, "in_scope_kev")
    after_kev = _integer(after_totals, "in_scope_kev")
    if after_kev is None or after_kev <= 0:
        findings.append(
            Finding("in-scope-kev-empty", "In-scope CISA KEV count became empty.")
        )
    elif before_kev is not None and _drop_is_suspicious(
        before_kev, after_kev, relative=0.05, absolute=25
    ):
        findings.append(
            Finding(
                "in-scope-kev-drop",
                f"In-scope CISA KEV count fell from {before_kev:,} to {after_kev:,}.",
            )
        )

    before_sources = baseline.get("sources")
    after_sources = candidate.get("sources")
    before_cisa = (
        before_sources.get("cisa_kev") if isinstance(before_sources, dict) else None
    )
    after_cisa = (
        after_sources.get("cisa_kev") if isinstance(after_sources, dict) else None
    )
    before_kev_source = _integer(before_cisa, "catalog_records")
    after_kev_source = _integer(after_cisa, "catalog_records")
    if after_kev_source is None or after_kev_source <= 0:
        findings.append(
            Finding("kev-feed-empty", "CISA KEV source feed became empty or malformed.")
        )
    elif before_kev_source is not None and _drop_is_suspicious(
        before_kev_source, after_kev_source, relative=0.05, absolute=25
    ):
        findings.append(
            Finding(
                "kev-feed-drop",
                f"CISA KEV source feed fell from {before_kev_source:,} to "
                f"{after_kev_source:,} records.",
            )
        )
    before_kev_time = (
        _timestamp(before_cisa.get("date_released"))
        if isinstance(before_cisa, dict)
        else None
    )
    after_kev_time = (
        _timestamp(after_cisa.get("date_released"))
        if isinstance(after_cisa, dict)
        else None
    )
    if before_kev_time is not None and (
        after_kev_time is None or after_kev_time < before_kev_time
    ):
        findings.append(
            Finding(
                "kev-source-timestamp-regressed",
                "CISA KEV date_released disappeared or moved backward.",
            )
        )

    before_feeds = _nvd_feed_counts(baseline)
    after_feeds = _nvd_feed_counts(candidate)
    missing_feeds = sorted(set(before_feeds) - set(after_feeds))
    if missing_feeds:
        findings.append(
            Finding(
                "nvd-feeds-missing",
                "NVD identifier-year feeds disappeared: "
                + ", ".join(str(year) for year in missing_feeds),
            )
        )
    for year in sorted(set(before_feeds) & set(after_feeds)):
        before = before_feeds[year]
        after = after_feeds[year]
        if _drop_is_suspicious(before, after, relative=0.25, absolute=50):
            findings.append(
                Finding(
                    "nvd-feed-record-drop",
                    f"NVD feed {year} accepted count fell from {before:,} to "
                    f"{after:,}.",
                )
            )
    before_feed_times = _nvd_feed_timestamps(baseline)
    after_feed_times = _nvd_feed_timestamps(candidate)
    regressed_feed_times = [
        year
        for year in sorted(set(before_feed_times) & set(after_feed_times))
        if after_feed_times[year] < before_feed_times[year]
    ]
    if regressed_feed_times:
        findings.append(
            Finding(
                "nvd-source-timestamp-regressed",
                "NVD lastModifiedDate moved backward for feeds: "
                + ", ".join(str(year) for year in regressed_feed_times),
            )
        )

    for key, label, relative, absolute in (
        ("shards", "Catalog shard", 0.05, 10),
        ("markdown_drafts", "Generated recipe draft", 0.05, 25),
        ("markdown_pages", "Recipe page", 0.05, 25),
    ):
        before = _integer(before_totals, key)
        after = _integer(after_totals, key)
        if (
            before is not None
            and after is not None
            and _drop_is_suspicious(
                before, after, relative=relative, absolute=absolute
            )
        ):
            findings.append(
                Finding(
                    f"{key.replace('_', '-')}-drop",
                    f"{label} count fell from {before:,} to {after:,}.",
                )
            )

    recipes = sync_report.get("generated_recipes")
    deleted = _integer(recipes, "deleted")
    if deleted is not None and deleted >= 25:
        findings.append(
            Finding(
                "generated-recipe-deletion-spike",
                f"The generator proposes deleting {deleted:,} owned recipe drafts.",
            )
        )
    return findings


def enrichment_health(sync_report: dict[str, Any]) -> dict[str, Any]:
    raw = sync_report.get("ai_enrichment")
    if not isinstance(raw, dict):
        return {
            "healthy": False,
            "metrics": {},
            "alerts": ["Synchronization report is missing AI enrichment metrics."],
            "warnings": [],
        }

    metrics = {
        key: _integer(raw, key) or 0
        for key in ("eligible", "cached", "selected", "generated", "failed")
    }
    api_enabled = raw.get("api_enabled") is True
    metrics["api_enabled"] = api_enabled
    provider_error = raw.get("provider_error")
    if isinstance(provider_error, str) and provider_error.strip():
        metrics["provider_error"] = provider_error.strip()
    else:
        provider_error = ""
    alerts: list[str] = []
    warnings: list[str] = []
    if provider_error == "insufficient_quota":
        alerts.append(
            "OpenAI quota or credits are exhausted; add billing credits to resume enrichment."
        )
    elif provider_error == "invalid_key":
        alerts.append(
            "OpenAI rejected the API key; replace the OPENAI_API_KEY repository secret."
        )
    elif provider_error:
        alerts.append(
            f"OpenAI enrichment stopped after a provider error ({provider_error})."
        )
    elif not api_enabled:
        alerts.append(
            "OpenAI enrichment was not enabled; verify the OPENAI_API_KEY repository secret."
        )
    selected = int(metrics["selected"])
    generated = int(metrics["generated"])
    failed = int(metrics["failed"])
    unprocessed = max(0, selected - generated - failed)
    metrics["unprocessed"] = unprocessed
    if selected > 0 and generated == 0:
        alerts.append(
            f"Zero of {selected} selected enrichment candidates completed."
        )
    if failed >= 3 or (selected > 0 and failed / selected >= 0.5):
        alerts.append(
            f"{failed} of {selected} selected enrichment requests failed; "
            "the provider circuit breaker may have opened."
        )
    elif failed:
        warnings.append(f"{failed} enrichment request(s) failed but the run continued.")
    if unprocessed >= max(2, selected // 4):
        if provider_error:
            alerts.append(
                f"{unprocessed} selected enrichment candidates were skipped after "
                "the provider became unavailable."
            )
        else:
            alerts.append(
                f"{unprocessed} selected enrichment candidates were not processed before "
                "the request budget or time budget ended."
            )
    elif unprocessed:
        warnings.append(
            f"{unprocessed} selected enrichment candidate(s) were not processed."
        )
    return {
        "healthy": not alerts,
        "metrics": metrics,
        "alerts": alerts,
        "warnings": warnings,
    }


def build_report(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    sync_report: dict[str, Any],
) -> dict[str, Any]:
    anomalies = catalog_anomalies(baseline, candidate, sync_report)
    return {
        "schema_version": SCHEMA_VERSION,
        "checked_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "safe_to_merge": not anomalies,
        "anomalies": [asdict(item) for item in anomalies],
        "enrichment": enrichment_health(sync_report),
        "baseline": {
            "catalog_updated_at": baseline.get("catalog_updated_at"),
            "catalog_records": _integer(baseline.get("totals"), "catalog_records"),
            "in_scope_kev": _integer(baseline.get("totals"), "in_scope_kev"),
        },
        "candidate": {
            "catalog_updated_at": candidate.get("catalog_updated_at"),
            "catalog_records": _integer(candidate.get("totals"), "catalog_records"),
            "in_scope_kev": _integer(candidate.get("totals"), "in_scope_kev"),
        },
    }


def markdown_report(report: dict[str, Any]) -> str:
    safe = report.get("safe_to_merge") is True
    lines = [
        "## CVE refresh safety report",
        "",
        f"- Merge disposition: **{'safe' if safe else 'QUARANTINED'}**",
        (
            f"- Catalog records: {report['baseline']['catalog_records']:,} → "
            f"{report['candidate']['catalog_records']:,}"
            if isinstance(report["baseline"]["catalog_records"], int)
            and isinstance(report["candidate"]["catalog_records"], int)
            else "- Catalog records: unavailable"
        ),
        (
            f"- In-scope CISA KEVs: {report['baseline']['in_scope_kev']:,} → "
            f"{report['candidate']['in_scope_kev']:,}"
            if isinstance(report["baseline"]["in_scope_kev"], int)
            and isinstance(report["candidate"]["in_scope_kev"], int)
            else "- In-scope CISA KEVs: unavailable"
        ),
    ]
    anomalies = report.get("anomalies")
    if isinstance(anomalies, list) and anomalies:
        lines.extend(["", "### Quarantine reasons", ""])
        lines.extend(
            f"- `{item['code']}`: {item['message']}"
            for item in anomalies
            if isinstance(item, dict)
        )
    enrichment = report.get("enrichment")
    if isinstance(enrichment, dict):
        metrics = enrichment.get("metrics")
        lines.extend(
            [
                "",
                "### Optional enrichment health",
                "",
                f"- Status: **{'healthy' if enrichment.get('healthy') else 'attention required'}**",
            ]
        )
        if isinstance(metrics, dict):
            lines.append(
                "- Requests: "
                f"{metrics.get('selected', 0)} selected, "
                f"{metrics.get('generated', 0)} generated, "
                f"{metrics.get('failed', 0)} failed; "
                f"{metrics.get('unprocessed', 0)} unprocessed; "
                f"{metrics.get('cached', 0)} cached"
            )
        for alert in enrichment.get("alerts") or []:
            lines.append(f"- Alert: {alert}")
        for warning in enrichment.get("warnings") or []:
            lines.append(f"- Warning: {warning}")
    return "\n".join(lines) + "\n"


def _write_github_output(path: Path, report: dict[str, Any]) -> None:
    enrichment = report.get("enrichment")
    healthy = isinstance(enrichment, dict) and enrichment.get("healthy") is True
    with path.open("a", encoding="utf-8") as stream:
        stream.write(
            f"safe_to_merge={'true' if report.get('safe_to_merge') else 'false'}\n"
        )
        stream.write(f"enrichment_healthy={'true' if healthy else 'false'}\n")
        stream.write(f"anomaly_count={len(report.get('anomalies') or [])}\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--sync-report", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--fail-on-anomaly", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        baseline = _load_object(args.baseline, description="baseline manifest")
        candidate = _load_object(args.candidate, description="candidate manifest")
        sync_report = _load_object(
            args.sync_report, description="synchronization report"
        )
        report = build_report(baseline, candidate, sync_report)
    except ValueError as exc:
        message = str(exc)
        print(message, file=sys.stderr)
        report = {
            "schema_version": SCHEMA_VERSION,
            "checked_at": datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "safe_to_merge": False,
            "anomalies": [
                asdict(
                    Finding(
                        "catalog-safety-check-failed",
                        f"The safety checker could not validate this refresh: {message}",
                    )
                )
            ],
            "enrichment": {
                "healthy": False,
                "metrics": {},
                "alerts": ["Enrichment health could not be evaluated."],
                "warnings": [],
            },
            "baseline": {
                "catalog_updated_at": None,
                "catalog_records": None,
                "in_scope_kev": None,
            },
            "candidate": {
                "catalog_updated_at": None,
                "catalog_records": None,
                "in_scope_kev": None,
            },
        }

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    rendered = markdown_report(report)
    if args.markdown is not None:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(rendered, encoding="utf-8")
    output_path = args.github_output
    if output_path is None and os.environ.get("GITHUB_OUTPUT"):
        output_path = Path(os.environ["GITHUB_OUTPUT"])
    if output_path is not None:
        _write_github_output(output_path, report)
    print(rendered, end="")
    if args.fail_on_anomaly and not report["safe_to_merge"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
