#!/usr/bin/env python3
"""Opt-in end-to-end scale gate for a 500,000-record CVE catalog.

This is deliberately not part of the ordinary pull-request test suite.  It
generates a deterministic normalized catalog in a temporary directory and
then exercises the production publisher, immutable SQLite/FTS builder and
runtime, exact-shard reader, and Eleventy sitemap/indexability primitives.

The complete run defaults to 500,000 records.  A smaller local smoke run uses
the same paths, for example::

    python tests/scale/cve_500k_e2e.py --records 2000

Only a bounded reviewed subset is search/index qualified.  This reflects the
production SEO policy: scale the complete lookup/search catalog without
publishing hundreds of thousands of thin static pages.
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import gc
import hashlib
import heapq
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import time
import traceback
from datetime import date
from pathlib import Path
from typing import Any, Iterable, Iterator


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import mcp_server  # noqa: E402
from scripts import build_cve_search_db  # noqa: E402
from scripts import cve_search_runtime  # noqa: E402
from scripts import sync_cve_catalog  # noqa: E402


DEFAULT_RECORDS = 500_000
MAX_QUALIFIED_RECORDS = 100
BASE_SEQUENCE = 1_000_000
CATALOG_TIMESTAMP = "2026-08-26T00:00:00Z"
PUBLISHED_DATE = "2026-01-15"
UPDATED_TOKEN = "scalegateuniquetoken"
MIB = 1024 * 1024
CVE_ID_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


class ScaleGateError(RuntimeError):
    """The generated corpus violated a scale or correctness invariant."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ScaleGateError(message)


def elapsed_seconds(start: float) -> float:
    return round(time.perf_counter() - start, 6)


def phase(report: dict[str, Any], name: str, action: Any) -> Any:
    started = time.perf_counter()
    try:
        return action()
    finally:
        report.setdefault("phases", {})[name] = {
            "seconds": elapsed_seconds(started),
            "peak_rss_mib": round(peak_rss_bytes() / MIB, 3),
        }


def peak_rss_bytes() -> int:
    """Return this process's peak resident set size on Windows and POSIX."""

    if os.name == "nt":
        from ctypes import wintypes

        size_type = ctypes.c_size_t

        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", size_type),
                ("WorkingSetSize", size_type),
                ("QuotaPeakPagedPoolUsage", size_type),
                ("QuotaPagedPoolUsage", size_type),
                ("QuotaPeakNonPagedPoolUsage", size_type),
                ("QuotaNonPagedPoolUsage", size_type),
                ("PagefileUsage", size_type),
                ("PeakPagefileUsage", size_type),
            ]

        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.argtypes = []
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ProcessMemoryCounters),
            wintypes.DWORD,
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        process = kernel32.GetCurrentProcess()
        succeeded = psapi.GetProcessMemoryInfo(
            process,
            ctypes.byref(counters),
            counters.cb,
        )
        if not succeeded:
            raise OSError("GetProcessMemoryInfo failed")
        return int(counters.PeakWorkingSetSize)

    import resource

    maximum = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    # Linux and the BSDs report KiB; macOS reports bytes.
    return maximum if sys.platform == "darwin" else maximum * 1024


def sequence_for_index(index: int, record_count: int) -> int:
    """Keep full runs dense while making even tiny smoke runs span two shards."""

    if record_count <= 1_000 and index == record_count - 1:
        return BASE_SEQUENCE + 1_000
    return BASE_SEQUENCE + index


def cve_for_index(index: int, record_count: int) -> str:
    return f"CVE-2026-{sequence_for_index(index, record_count)}"


def stable_markdown_cve_ids() -> tuple[str, ...]:
    inventory = sync_cve_catalog.markdown_inventory(ROOT / "content" / "recipes" / "cve")
    return tuple(
        sorted(
            cve
            for cve, recipes in inventory.items()
            if any(recipe.maturity == "stable" for recipe in recipes)
        )
    )


def content_linked_cve_ids() -> tuple[str, ...]:
    linked: set[str] = set()
    for source in (ROOT / "content").rglob("*.md"):
        linked.update(
            re.findall(
                r"/cve/(CVE-[0-9]{4}-[0-9]{4,})/",
                source.read_text(encoding="utf-8"),
            )
        )
    return tuple(sorted(linked))


def qualified_record_count(record_count: int, stable_count: int) -> int:
    return min(MAX_QUALIFIED_RECORDS, max(stable_count, record_count // 100))


def catalog_identities(
    record_count: int,
    *,
    stable_ids: tuple[str, ...],
    required_ids: tuple[str, ...],
    qualified_count: int,
) -> Iterator[tuple[str, bool]]:
    synthetic_count = record_count - len(required_ids)
    extra_qualified = qualified_count - len(stable_ids)
    qualified_synthetic = {
        cve_for_index(index, synthetic_count) for index in range(extra_qualified)
    }
    synthetic = (
        (cve_for_index(index, synthetic_count), False)
        for index in range(synthetic_count)
    )
    required = ((cve, cve in stable_ids) for cve in required_ids)
    for cve, is_stable in heapq.merge(synthetic, required, key=lambda item: item[0]):
        yield cve, is_stable or cve in qualified_synthetic


def normalized_record(
    index: int,
    *,
    cve: str,
    archetype_id: str,
    reviewed: bool,
    stable_ids: frozenset[str],
) -> dict[str, Any]:
    """Return one deterministic record shaped like the real NVD normalizer output."""

    severities = ("medium", "high", "critical")
    scores = (5.3, 8.1, 9.8)
    severity = severities[index % len(severities)]
    score = scores[index % len(scores)]
    is_kev = index % 10_000 == 0
    published = f"{cve[4:8]}-01-15" if cve in stable_ids else PUBLISHED_DATE
    markdown: list[dict[str, str]] = []
    if reviewed:
        markdown = [
            {
                "cve": cve,
                "path": f"content/recipes/cve/scale/{cve.lower()}.md",
                "maturity": "stable",
                "title": f"Reviewed remediation for {cve}",
                "description": f"Synthetic reviewed guidance for {cve}, used only by the 500k scale gate.",
                "date": published,
                "lastmod": "2026-01-16",
                "content_markdown": (
                    f"# Reviewed remediation for {cve}\n\n"
                    "Confirm exposure, install the authoritative fixed release, test, and retain rollback evidence.\n"
                ),
            }
        ]

    return {
        "cve": cve,
        "title": "ScaleWidget synthetic vulnerability",
        "summary": (
            "A deterministic test-only ScaleWidget flaw permits remote code execution "
            "when an affected interface is exposed."
        ),
        "published": published,
        "last_modified": "2026-01-16T00:00:00.000Z",
        "status": "Analyzed",
        "source_identifier": "scale-gate@example.invalid",
        "severity": severity,
        "score": score,
        "cvss_version": "3.1",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "metric_source": "scale-gate@example.invalid",
        "metric_type": "Primary",
        "metrics": [
            {
                "version": "3.1",
                "score": score,
                "severity": severity,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "source": "scale-gate@example.invalid",
                "metric_type": "Primary",
            }
        ],
        "cwes": ["CWE-78"],
        "products": [{"vendor": "Scale Labs", "product": "ScaleWidget"}],
        "product_match_count": 1,
        "products_stored": 1,
        "products_truncated": False,
        "affected_data": [],
        "affected_data_count": 0,
        "affected_data_stored": 0,
        "affected_data_truncated": False,
        "references": [
            {
                "url": "https://example.invalid/security/scale-widget",
                "source": "scale-gate@example.invalid",
                "tags": ["Vendor Advisory"],
            }
        ],
        "kev": is_kev,
        "kev_details": (
            {
                "date_added": "2026-01-16",
                "due_date": "2026-02-06",
                "vendor_project": "Scale Labs",
                "product": "ScaleWidget",
                "vulnerability_name": "Synthetic ScaleWidget vulnerability",
                "required_action": "Apply the test-only fixed release and verify exposure is removed.",
                "known_ransomware_campaign_use": "Unknown",
                "notes": "Synthetic scale-gate provenance; not a real vulnerability.",
                "cwes": ["CWE-78"],
                "source": sync_cve_catalog.CISA_KEV_URL,
            }
            if is_kev
            else None
        ),
        "ecosystem": "software/application",
        "archetype": archetype_id,
        "archetypes": [archetype_id],
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve}",
        "recipe_kind": "markdown-override" if reviewed else "composed",
        "markdown": markdown,
        "quality": "curated" if reviewed else "metadata-backed",
    }


def generate_source(
    destination: Path,
    *,
    record_count: int,
    archetype_id: str,
    qualified_count: int,
    stable_ids: tuple[str, ...],
    required_ids: tuple[str, ...],
) -> dict[str, Any]:
    digest = hashlib.sha256()
    stable_id_set = frozenset(stable_ids)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as stream:
        for index, (cve, reviewed) in enumerate(
            catalog_identities(
                record_count,
                stable_ids=stable_ids,
                required_ids=required_ids,
                qualified_count=qualified_count,
            )
        ):
            payload = sync_cve_catalog.json_bytes(
                normalized_record(
                    index,
                    cve=cve,
                    archetype_id=archetype_id,
                    reviewed=reviewed,
                    stable_ids=stable_id_set,
                )
            )
            stream.write(payload)
            digest.update(payload)
    return {
        "path": str(destination),
        "bytes": destination.stat().st_size,
        "sha256": digest.hexdigest(),
    }


def iter_source_records(
    source_path: Path,
    *,
    record_count: int,
    updated_cve: str | None = None,
) -> Iterator[dict[str, Any]]:
    seen = 0
    with source_path.open("rb") as stream:
        for index, line in enumerate(stream):
            record = json.loads(line)
            require(isinstance(record, dict), f"source line {index + 1} is not an object")
            if record.get("cve") == updated_cve:
                record = dict(record)
                record["title"] = f"{record['title']} {UPDATED_TOKEN}"
                record["summary"] = f"{record['summary']} {UPDATED_TOKEN}."
                record["last_modified"] = "2026-01-17T00:00:00.000Z"
            seen += 1
            yield record
    require(seen == record_count, f"source record count changed: expected {record_count}, found {seen}")


def build_catalog_outputs(
    records: Iterable[dict[str, Any]],
    *,
    record_count: int,
    source_sha256: str,
    archetypes: dict[str, Any],
    source_patch: dict[str, Any] | None = None,
) -> tuple[dict[Path, bytes], dict[str, Any]]:
    return sync_cve_catalog.build_outputs(
        records,
        start_date=date(2016, 8, 26),
        end_date=date(2026, 8, 26),
        feed_sources=[],
        kev_data={},
        kev_payload=b"",
        archetypes=archetypes,
        existing={},
        presorted=True,
        source_timestamp_override=CATALOG_TIMESTAMP,
        sources_override={
            "synthetic_scale_gate": {
                "records": record_count,
                "base_source_sha256": source_sha256,
                "deterministic_patch": source_patch,
                "network_access": False,
            }
        },
    )


def catalog_tree_metrics(root: Path) -> dict[str, int]:
    files = [path for path in root.rglob("*") if path.is_file() and not path.is_symlink()]
    return {"files": len(files), "bytes": sum(path.stat().st_size for path in files)}


def manifest_from(catalog_root: Path) -> dict[str, Any]:
    payload = json.loads((catalog_root / "manifest.json").read_bytes())
    require(isinstance(payload, dict), "catalog manifest is not an object")
    return payload


def shard_inventory(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = manifest.get("shard_manifest")
    require(isinstance(raw, list) and raw, "catalog manifest has no shard inventory")
    inventory = {
        str(entry["path"]): dict(entry)
        for entry in raw
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    }
    require(len(inventory) == len(raw), "catalog manifest has duplicate or invalid shard entries")
    return inventory


NODE_SITEMAP_GATE = r"""
"use strict";
const crypto = require("node:crypto");
const path = require("node:path");
const { performance } = require("node:perf_hooks");

const catalogRoot = path.resolve(process.argv[1]);
const stressCount = Number(process.argv[2]);
if (!Number.isSafeInteger(stressCount) || stressCount < 2) {
  throw new Error("stress record count must be an integer of at least two");
}

const started = performance.now();
const { loadCveSearchIndexableRecords } = require("./lib/cve-indexability");
const {
  CVE_SITEMAP_URL_LIMIT,
  planCveSitemaps,
  renderCveSitemap,
} = require("./eleventy.config").cveSitemaps;

const qualified = loadCveSearchIndexableRecords(catalogRoot);
const qualifiedPlan = planCveSitemaps(qualified, CVE_SITEMAP_URL_LIMIT);
let qualifiedRenderedUrls = 0;
for (const entry of qualifiedPlan) {
  if (entry.count > CVE_SITEMAP_URL_LIMIT) {
    throw new Error(`qualified sitemap exceeds URL ceiling: ${entry.outputPath}`);
  }
  const xml = renderCveSitemap(entry);
  const urls = (xml.match(/<url>/g) || []).length;
  if (urls !== entry.count) {
    throw new Error(`rendered sitemap count mismatch: ${entry.outputPath}`);
  }
  qualifiedRenderedUrls += urls;
}
if (qualifiedRenderedUrls !== qualified.length) {
  throw new Error("qualified sitemap membership differs from the integrity-checked allowlist");
}

// Stress the exact planner used by Eleventy without claiming the synthetic
// records are SEO-qualified.  Production qualification remains the bounded
// allowlist above; this separate pass proves the standards headroom at 500k.
const stressRecords = new Array(stressCount);
for (let index = 0; index < stressCount; index += 1) {
  stressRecords[index] = {
    cve: `CVE-2099-${1000000 + index}`,
    published: "2099-01-15",
  };
}
const stressPlan = planCveSitemaps(stressRecords, CVE_SITEMAP_URL_LIMIT);
const expectedChildren = Math.ceil(stressCount / CVE_SITEMAP_URL_LIMIT);
if (stressPlan.length !== expectedChildren) {
  throw new Error(`stress sitemap child count mismatch: ${stressPlan.length} != ${expectedChildren}`);
}
const stressTotal = stressPlan.reduce((total, entry) => total + entry.count, 0);
const stressMaximum = Math.max(...stressPlan.map((entry) => entry.count));
if (stressTotal !== stressCount || stressMaximum > CVE_SITEMAP_URL_LIMIT) {
  throw new Error("stress sitemap plan is incomplete or unbounded");
}
for (const entry of [stressPlan[0], stressPlan[stressPlan.length - 1]]) {
  const xml = renderCveSitemap(entry);
  if ((xml.match(/<url>/g) || []).length !== entry.count) {
    throw new Error(`stress sitemap render mismatch: ${entry.outputPath}`);
  }
}

const qualifiedIds = qualified.map((record) => record.cve);
process.stdout.write(JSON.stringify({
  qualified_records: qualified.length,
  qualified_ids_sha256: crypto.createHash("sha256").update(qualifiedIds.join("\n")).digest("hex"),
  qualified_first: qualifiedIds[0] || "",
  qualified_last: qualifiedIds[qualifiedIds.length - 1] || "",
  qualified_children: qualifiedPlan.length,
  qualified_max_urls: qualifiedPlan.length ? Math.max(...qualifiedPlan.map((entry) => entry.count)) : 0,
  stress_records: stressCount,
  stress_children: stressPlan.length,
  stress_max_urls: stressMaximum,
  sitemap_url_limit: CVE_SITEMAP_URL_LIMIT,
  seconds: Number(((performance.now() - started) / 1000).toFixed(6)),
  peak_rss_mib: Number((process.resourceUsage().maxRSS / 1024).toFixed(3)),
}));
"""


def run_sitemap_gate(catalog_root: Path, record_count: int) -> dict[str, Any]:
    completed = subprocess.run(
        ["node", "-e", NODE_SITEMAP_GATE, str(catalog_root), str(record_count)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=600,
    )
    if completed.returncode != 0:
        raise ScaleGateError(
            "Node sitemap/indexability gate failed:\n"
            f"stdout: {completed.stdout[-4000:]}\n"
            f"stderr: {completed.stderr[-4000:]}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ScaleGateError(f"Node sitemap gate returned invalid JSON: {completed.stdout[-4000:]}") from exc
    require(isinstance(payload, dict), "Node sitemap gate returned a non-object")
    return payload


def run_checked_command(
    label: str,
    command: list[str],
    *,
    environment: dict[str, str],
    timeout: float,
) -> dict[str, Any]:
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    seconds = elapsed_seconds(started)
    if completed.returncode != 0:
        raise ScaleGateError(
            f"{label} failed with exit code {completed.returncode}:\n"
            f"stdout: {completed.stdout[-6000:]}\n"
            f"stderr: {completed.stderr[-6000:]}"
        )
    return {
        "seconds": seconds,
        "stdout_tail": completed.stdout[-1000:].strip(),
        "stderr_tail": completed.stderr[-1000:].strip(),
    }


def run_real_site_build(
    catalog_root: Path,
    output_root: Path,
    *,
    qualified_count: int,
    stable_ids: tuple[str, ...],
    timeout: float,
) -> dict[str, Any]:
    require(not output_root.exists(), "temporary site output unexpectedly exists before Eleventy")
    environment = os.environ.copy()
    environment["SECURITY_RECIPES_CVE_CATALOG_ROOT"] = str(catalog_root.resolve())
    environment["SITE_OUTPUT_DIR"] = str(output_root.resolve())
    node = "node"
    commands: dict[str, dict[str, Any]] = {}

    commands["eleventy"] = run_checked_command(
        "Eleventy",
        [
            node,
            str(ROOT / "node_modules" / "@11ty" / "eleventy" / "cmd.cjs"),
            "--quiet",
            f"--output={output_root}",
        ],
        environment=environment,
        timeout=timeout,
    )
    require((output_root / ".nojekyll").is_file(), "Eleventy lost the static .nojekyll passthrough")
    catalog_output = output_root / "api" / "cve-catalog"
    require(
        not catalog_output.exists(),
        "Eleventy copied the CVE catalog instead of leaving it to the post-build boundary",
    )

    commands["qualified_page_materializer"] = run_checked_command(
        "qualified CVE page materializer",
        [sys.executable, str(ROOT / "scripts" / "materialize_cve_pages.py"), "--output", str(output_root)],
        environment=environment,
        timeout=timeout,
    )
    historical_ids = set(stable_ids) & set(mcp_server._CVE_STATIC_CANONICAL_ROUTES)
    expected_dynamic = qualified_count - len(historical_ids)
    materialized = [
        child
        for child in (output_root / "cve").iterdir()
        if child.is_dir() and CVE_ID_RE.fullmatch(child.name)
    ]
    require(
        len(materialized) == expected_dynamic,
        f"real page materializer wrote {len(materialized)} CVEs; expected {expected_dynamic}",
    )

    commands["catalog_post_copy"] = run_checked_command(
        "validated CVE catalog post-copy",
        [node, str(ROOT / "scripts" / "copy_cve_catalog.js"), "--output", str(output_root)],
        environment=environment,
        timeout=timeout,
    )
    source_metrics = catalog_tree_metrics(catalog_root)
    copied_metrics = catalog_tree_metrics(catalog_output)
    require(copied_metrics == source_metrics, "post-copy catalog tree differs from its validated source")
    require(
        (catalog_output / "manifest.json").read_bytes() == (catalog_root / "manifest.json").read_bytes(),
        "post-copy catalog manifest is not byte-identical",
    )

    commands["prepare_static_assets"] = run_checked_command(
        "static asset preparation",
        [node, str(ROOT / "scripts" / "prepare_static_assets.js")],
        environment=environment,
        timeout=timeout,
    )
    commands["site_performance"] = run_checked_command(
        "site performance and discovery check",
        [node, str(ROOT / "scripts" / "check_site_performance.js")],
        environment=environment,
        timeout=timeout,
    )
    output_metrics = catalog_tree_metrics(output_root)
    return {
        **output_metrics,
        "output": str(output_root),
        "materialized_cves": len(materialized),
        "catalog_files_before_precompression": copied_metrics["files"],
        "catalog_bytes_before_precompression": copied_metrics["bytes"],
        "commands": commands,
    }


def run_public_record_route(
    catalog: mcp_server.CVERecipeCatalog,
    *,
    cve_id: str,
    revision: str,
) -> dict[str, Any]:
    route = f"/api/cve-catalog/records/{cve_id}"
    request = mcp_server.Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": route,
            "raw_path": route.encode("ascii"),
            "path_params": {"cve_id": cve_id},
            "query_string": f"revision={revision}".encode("ascii"),
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("scale-gate", 443),
        }
    )
    previous_catalog = mcp_server.cve_catalog
    mcp_server.cve_catalog = catalog
    try:
        response = asyncio.run(mcp_server.cve_catalog_record(request))
    finally:
        mcp_server.cve_catalog = previous_catalog

    require(response.status_code == 200, f"public exact-record route returned {response.status_code}")
    require(
        len(response.body) <= 512 * 1024,
        f"public exact-record route returned {len(response.body)} bytes",
    )
    payload = json.loads(response.body)
    require(
        isinstance(payload, dict)
        and payload.get("schema_version") == 1
        and payload.get("revision") == revision,
        "public exact-record route response contract changed",
    )
    record = payload.get("record")
    require(
        isinstance(record, dict)
        and record.get("cve") == cve_id
        and UPDATED_TOKEN in str(record.get("summary") or ""),
        "public exact-record route returned a missing, mismatched, or stale record",
    )
    headers = response.headers
    require("max-age=300" in headers.get("cache-control", ""), "public record cache header changed")
    require(
        headers.get("x-robots-tag") == "noindex, nofollow, noarchive",
        "public record noindex header changed",
    )
    require(
        headers.get("x-cve-record-backend") == "verified-shard",
        "public record backend header changed",
    )
    require(
        headers.get("x-cve-catalog-revision") == revision,
        "public record revision header changed",
    )
    return {
        "status": response.status_code,
        "bytes": len(response.body),
        "schema_version": payload["schema_version"],
        "revision": payload["revision"],
        "record_cve": record["cve"],
        "headers": {
            "cache-control": headers["cache-control"],
            "x-robots-tag": headers["x-robots-tag"],
            "x-cve-record-backend": headers["x-cve-record-backend"],
            "x-cve-catalog-revision": headers["x-cve-catalog-revision"],
        },
    }


def timed_query(action: Any) -> tuple[Any, float]:
    started = time.perf_counter()
    value = action()
    return value, round((time.perf_counter() - started) * 1000, 3)


def write_report(path: Path | None, report: dict[str, Any]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def enforce_budgets(report: dict[str, Any], args: argparse.Namespace) -> None:
    phases = report["phases"]
    phase_budgets = {
        "generate_source": args.max_generation_seconds,
        "initial_catalog_publication": args.max_publication_seconds,
        "one_record_update": args.max_update_seconds,
        "sqlite_build": args.max_database_seconds,
        "sitemap_and_seo": args.max_sitemap_seconds,
        "real_site_build": args.max_site_build_seconds,
    }
    for name, budget in phase_budgets.items():
        actual = float(phases[name]["seconds"])
        require(actual <= budget, f"{name} took {actual:.3f}s; budget is {budget:.3f}s")

    total = float(report["total_seconds"])
    require(total <= args.max_total_seconds, f"gate took {total:.3f}s; budget is {args.max_total_seconds:.3f}s")
    python_rss = float(report["peak_rss_mib"])
    node_rss = float(report["sitemap"]["peak_rss_mib"])
    require(python_rss <= args.max_rss_mib, f"Python peak RSS is {python_rss:.1f} MiB; budget is {args.max_rss_mib:.1f} MiB")
    require(node_rss <= args.max_node_rss_mib, f"Node peak RSS is {node_rss:.1f} MiB; budget is {args.max_node_rss_mib:.1f} MiB")

    source_mib = int(report["source"]["bytes"]) / MIB
    catalog_mib = int(report["catalog"]["bytes"]) / MIB
    database_mib = int(report["sqlite"]["bytes"]) / MIB
    require(source_mib <= args.max_source_mib, f"source is {source_mib:.1f} MiB; budget is {args.max_source_mib:.1f} MiB")
    require(catalog_mib <= args.max_catalog_mib, f"catalog is {catalog_mib:.1f} MiB; budget is {args.max_catalog_mib:.1f} MiB")
    require(database_mib <= args.max_database_mib, f"SQLite is {database_mib:.1f} MiB; budget is {args.max_database_mib:.1f} MiB")
    require(int(report["catalog"]["files"]) <= args.max_catalog_files, "catalog file-count budget exceeded")
    site_mib = int(report["site_build"]["bytes"]) / MIB
    require(site_mib <= args.max_site_output_mib, f"site output is {site_mib:.1f} MiB; budget is {args.max_site_output_mib:.1f} MiB")
    require(
        int(report["site_build"]["files"]) <= args.max_site_output_files,
        "site output file-count budget exceeded",
    )

    for name, milliseconds in report["queries_ms"].items():
        require(
            float(milliseconds) <= args.max_query_ms,
            f"{name} took {milliseconds:.3f}ms; budget is {args.max_query_ms:.3f}ms",
        )


def execute(args: argparse.Namespace, report: dict[str, Any]) -> None:
    started = time.perf_counter()
    require(2 <= args.records <= 1_000_000, "--records must be between 2 and 1,000,000")
    require(args.max_catalog_files > 0, "--max-catalog-files must be greater than zero")
    require(args.max_site_output_files > 0, "--max-site-output-files must be greater than zero")
    stable_ids = stable_markdown_cve_ids()
    required_ids = tuple(sorted(set(stable_ids) | set(content_linked_cve_ids())))
    require(
        args.records > len(required_ids),
        f"--records must exceed the {len(required_ids)} repository-linked CVEs required by the real build",
    )
    qualified_count = qualified_record_count(args.records, len(stable_ids))
    require(qualified_count < args.records, "scale corpus must contain at least one unqualified record")

    archetypes, _ = sync_cve_catalog.load_archetypes(sync_cve_catalog.DEFAULT_ARCHETYPES)
    valid_agentic = sync_cve_catalog.valid_agentic_archetype_ids(archetypes)
    archetype_id = "command_code_injection"
    require(archetype_id in valid_agentic, f"required agentic archetype is unavailable: {archetype_id}")

    report.update(
        {
            "schema_version": 1,
            "status": "running",
            "records": args.records,
            "qualified_records": qualified_count,
            "stable_markdown_records": len(stable_ids),
            "repository_linked_records": len(required_ids),
            "archetype": archetype_id,
            "catalog_timestamp": CATALOG_TIMESTAMP,
            "budgets": {
                "max_generation_seconds": args.max_generation_seconds,
                "max_publication_seconds": args.max_publication_seconds,
                "max_update_seconds": args.max_update_seconds,
                "max_database_seconds": args.max_database_seconds,
                "max_sitemap_seconds": args.max_sitemap_seconds,
                "max_site_build_seconds": args.max_site_build_seconds,
                "max_total_seconds": args.max_total_seconds,
                "max_rss_mib": args.max_rss_mib,
                "max_node_rss_mib": args.max_node_rss_mib,
                "max_source_mib": args.max_source_mib,
                "max_catalog_mib": args.max_catalog_mib,
                "max_database_mib": args.max_database_mib,
                "max_catalog_files": args.max_catalog_files,
                "max_site_output_mib": args.max_site_output_mib,
                "max_site_output_files": args.max_site_output_files,
                "max_query_ms": args.max_query_ms,
            },
        }
    )

    with tempfile.TemporaryDirectory(prefix="security-recipes-cve-500k-") as temporary:
        work_root = Path(temporary)
        source_path = work_root / "source" / "records.jsonl"
        catalog_root = work_root / "catalog"
        database_path = work_root / "runtime" / "cve-search.sqlite3"
        metadata_path = Path(f"{database_path}.metadata.json")

        source = phase(
            report,
            "generate_source",
            lambda: generate_source(
                source_path,
                record_count=args.records,
                archetype_id=archetype_id,
                qualified_count=qualified_count,
                stable_ids=stable_ids,
                required_ids=required_ids,
            ),
        )
        report["source"] = source

        def initial_publication() -> dict[str, Any]:
            outputs, manifest = build_catalog_outputs(
                iter_source_records(source_path, record_count=args.records),
                record_count=args.records,
                source_sha256=str(source["sha256"]),
                archetypes=archetypes,
                source_patch=None,
            )
            require(manifest["totals"]["catalog_records"] == args.records, "publisher lost records")
            require(
                manifest["totals"]["search_indexable_records"] == qualified_count,
                "publisher qualification count mismatch",
            )
            writes = sync_cve_catalog.write_outputs(catalog_root, outputs)
            result = {"writes": writes, "output_files": len(outputs)}
            del outputs
            gc.collect()
            return result

        initial_result = phase(report, "initial_catalog_publication", initial_publication)
        baseline_manifest = manifest_from(catalog_root)
        baseline_inventory = shard_inventory(baseline_manifest)
        baseline_mtimes = {
            relative: (catalog_root / Path(relative)).stat().st_mtime_ns
            for relative in baseline_inventory
        }
        report["initial_publication"] = initial_result

        synthetic_count = args.records - len(required_ids)
        target_cve = cve_for_index(synthetic_count - 1, synthetic_count)
        target_shard = sync_cve_catalog.cve_shard({"cve": target_cve})

        def one_record_update() -> dict[str, Any]:
            outputs, manifest = build_catalog_outputs(
                iter_source_records(
                    source_path,
                    record_count=args.records,
                    updated_cve=target_cve,
                ),
                record_count=args.records,
                source_sha256=str(source["sha256"]),
                archetypes=archetypes,
                source_patch={
                    "cve": target_cve,
                    "fields": ["last_modified", "summary", "title"],
                    "token": UPDATED_TOKEN,
                },
            )
            require(manifest["totals"]["catalog_records"] == args.records, "update lost records")
            writes = sync_cve_catalog.write_outputs(catalog_root, outputs)
            result = {"writes": writes, "output_files": len(outputs)}
            del outputs
            gc.collect()
            return result

        update_result = phase(report, "one_record_update", one_record_update)
        updated_manifest = manifest_from(catalog_root)
        updated_inventory = shard_inventory(updated_manifest)
        require(set(updated_inventory) == set(baseline_inventory), "one update changed shard paths")
        changed_shards = sorted(
            relative
            for relative in baseline_inventory
            if baseline_inventory[relative]["sha256"] != updated_inventory[relative]["sha256"]
        )
        require(changed_shards == [target_shard], f"one update changed unexpected shards: {changed_shards}")
        unchanged_rewritten = [
            relative
            for relative in baseline_inventory
            if relative != target_shard
            and (catalog_root / Path(relative)).stat().st_mtime_ns != baseline_mtimes[relative]
        ]
        require(not unchanged_rewritten, f"publisher rewrote unchanged shards: {unchanged_rewritten[:5]}")
        require(
            update_result["writes"]["unchanged"] >= len(updated_inventory) - 1,
            "publisher did not preserve unchanged outputs",
        )
        require(
            update_result["writes"]["changed"] <= 10
            and update_result["writes"]["changed"] < update_result["output_files"],
            "one record update rewrote more than its shard and bounded global projections",
        )
        report["incremental_update"] = {
            **update_result,
            "target_cve": target_cve,
            "target_shard": target_shard,
            "changed_shards": changed_shards,
            "unchanged_shards": len(updated_inventory) - len(changed_shards),
            "old_revision": baseline_manifest["shard_set_sha256"],
            "new_revision": updated_manifest["shard_set_sha256"],
        }
        require(
            baseline_manifest["shard_set_sha256"] != updated_manifest["shard_set_sha256"],
            "one record update did not advance the shard-set revision",
        )

        catalog_metrics = catalog_tree_metrics(catalog_root)
        browser_entry = updated_manifest.get("browser_index")
        search_entry = updated_manifest.get("search_index")
        report["catalog"] = {
            **catalog_metrics,
            "shards": len(updated_inventory),
            "revision": updated_manifest["shard_set_sha256"],
            "manifest_bytes": (catalog_root / "manifest.json").stat().st_size,
            "browser_index_bytes": (
                browser_entry.get("bytes") if isinstance(browser_entry, dict) else 0
            ),
            "search_index_bytes": search_entry.get("bytes") if isinstance(search_entry, dict) else 0,
        }
        runtime_summary = json.loads((catalog_root / "runtime-summary.json").read_bytes())
        expected_record_api = {
            "schema_version": 1,
            "path": "records/{cve}",
            "max_response_bytes": 524_288,
        }
        require(
            isinstance(runtime_summary, dict)
            and runtime_summary.get("record_api") == expected_record_api,
            "runtime summary exact-record API contract changed",
        )
        report["catalog"]["record_api"] = expected_record_api
        require(
            isinstance(search_entry, dict)
            and search_entry.get("records") == qualified_count
            and int(search_entry.get("bytes") or 0) <= 1024 * 1024,
            "bounded SEO allowlist contract was not preserved",
        )

        sitemap = phase(
            report,
            "sitemap_and_seo",
            lambda: run_sitemap_gate(catalog_root, args.records),
        )
        report["sitemap"] = sitemap
        search_index_payload = json.loads((catalog_root / "search-indexable.json").read_bytes())
        qualified_ids = [
            str(record["cve"])
            for record in search_index_payload.get("records", [])
            if isinstance(record, dict) and isinstance(record.get("cve"), str)
        ]
        require(len(qualified_ids) == qualified_count, "qualified identity payload count mismatch")
        expected_qualified_digest = hashlib.sha256("\n".join(qualified_ids).encode()).hexdigest()
        require(sitemap["qualified_records"] == qualified_count, "real SEO loader count mismatch")
        require(
            sitemap["qualified_ids_sha256"] == expected_qualified_digest,
            "real SEO loader membership mismatch",
        )
        require(sitemap["stress_records"] == args.records, "sitemap stress count mismatch")
        require(sitemap["stress_max_urls"] <= 49_000, "sitemap planner exceeded 49,000 URLs")

        site_build = phase(
            report,
            "real_site_build",
            lambda: run_real_site_build(
                catalog_root,
                work_root / "site",
                qualified_count=qualified_count,
                stable_ids=stable_ids,
                timeout=args.max_site_build_seconds,
            ),
        )
        report["site_build"] = site_build

        database_result = phase(
            report,
            "sqlite_build",
            lambda: build_cve_search_db.build_search_database(
                catalog_root,
                database_path,
                metadata_path=metadata_path,
            ),
        )
        require(database_result["records"] == args.records, "SQLite builder lost records")
        require(database_result["shards"] == len(updated_inventory), "SQLite shard count mismatch")
        report["sqlite"] = database_result

        runtime_started = time.perf_counter()
        runtime = cve_search_runtime.CVESearchRuntime(
            database_path,
            expected_revision=str(database_result["shard_set_sha256"]),
            expected_record_count=args.records,
            expected_manifest_sha256=str(database_result["manifest_sha256"]),
            expected_database_sha256=str(database_result["database_sha256"]),
        )
        report["phases"]["sqlite_runtime_validation"] = {
            "seconds": elapsed_seconds(runtime_started),
            "peak_rss_mib": round(peak_rss_bytes() / MIB, 3),
        }
        require(runtime.record_count == args.records, "runtime record count mismatch")
        require(runtime.active_revision == updated_manifest["shard_set_sha256"], "runtime revision mismatch")

        exact_result, exact_ms = timed_query(lambda: runtime.search(target_cve, limit=5))
        require(exact_result["total_matches"] == 1, "SQLite exact lookup did not find one record")
        require(exact_result["results"][0]["cve"] == target_cve, "SQLite exact lookup found wrong record")
        fts_result, fts_ms = timed_query(lambda: runtime.search(UPDATED_TOKEN, limit=5))
        require(fts_result["total_matches"] == 1, "SQLite FTS update token did not find one record")
        require(fts_result["results"][0]["cve"] == target_cve, "SQLite FTS found wrong record")
        broad_result, broad_ms = timed_query(
            lambda: runtime.search("remote code execution", limit=5)
        )
        require(
            broad_result["total_matches"] == args.records,
            "SQLite broad FTS query did not cover the complete corpus",
        )
        require(broad_result["truncated"] is True, "SQLite broad FTS query was not bounded")
        browse_result, browse_ms = timed_query(
            lambda: runtime.search("", severity="critical", published_year=2026, limit=5)
        )
        require(browse_result["total_matches"] > 0, "SQLite filtered browse returned no records")

        catalog_started = time.perf_counter()
        catalog = mcp_server.CVERecipeCatalog(
            str(catalog_root),
            str(database_path),
            require_search_database=True,
        )
        report["phases"]["mcp_catalog_validation"] = {
            "seconds": elapsed_seconds(catalog_started),
            "peak_rss_mib": round(peak_rss_bytes() / MIB, 3),
        }
        require(catalog.search_backend() == "sqlite", "MCP catalog did not select SQLite")
        require(not catalog._shard_cache, "MCP exact-shard cache was unexpectedly warm")
        public_record, public_record_ms = timed_query(
            lambda: run_public_record_route(
                catalog,
                cve_id=target_cve,
                revision=str(updated_manifest["shard_set_sha256"]),
            )
        )
        route_cached_shards = list(catalog._shard_cache)
        require(
            route_cached_shards == [target_shard],
            f"public exact-record route opened unexpected shards: {route_cached_shards}",
        )
        source_record, record_ms = timed_query(
            lambda: catalog.get_record(
                target_cve,
                expected_revision=str(updated_manifest["shard_set_sha256"]),
            )
        )
        require(source_record is not None, "MCP exact-record API did not find target CVE")
        require(source_record["cve"] == target_cve, "MCP exact-record API found wrong CVE")
        require(UPDATED_TOKEN in source_record["summary"], "MCP exact-record API saw stale data")
        record_cached_shards = list(catalog._shard_cache)
        require(
            record_cached_shards == [target_shard],
            f"MCP exact-record API opened unexpected shards: {record_cached_shards}",
        )
        recipe, recipe_ms = timed_query(lambda: catalog.get_recipe(target_cve))
        require(recipe.get("found") is True, "MCP exact lookup did not find target CVE")
        require(recipe["source_record"]["cve"] == target_cve, "MCP exact lookup found wrong CVE")
        require(UPDATED_TOKEN in recipe["source_record"]["summary"], "MCP exact lookup saw stale data")
        cached_shards = list(catalog._shard_cache)
        require(cached_shards == [target_shard], f"MCP exact lookup opened unexpected shards: {cached_shards}")
        require(
            cached_shards == record_cached_shards,
            "MCP composed-recipe lookup expanded the exact-record shard cache",
        )
        require(
            recipe["agentic_change_plan"]["catalog_provenance"]["source_shard"]["path"]
            == target_shard,
            "MCP provenance did not pin the deterministic source shard",
        )

        qualified_cve = qualified_ids[0]
        qualified_policy, qualification_ms = timed_query(
            lambda: catalog.search_qualification(qualified_cve)
        )
        unqualified_policy = catalog.search_qualification(target_cve)
        require(qualified_policy == "stable_markdown", "reviewed record lost SEO qualification")
        require(unqualified_policy == "", "thin record unexpectedly gained SEO qualification")

        try:
            runtime.search("x" * 121)
        except cve_search_runtime.CVESearchQueryError:
            pass
        else:
            raise ScaleGateError("runtime accepted an overlong query")

        report["queries_ms"] = {
            "sqlite_exact": exact_ms,
            "sqlite_fts": fts_ms,
            "sqlite_broad_fts": broad_ms,
            "sqlite_filtered_browse": browse_ms,
            "mcp_exact_record": record_ms,
            "public_exact_record_route": public_record_ms,
            "mcp_exact_one_shard": recipe_ms,
            "mcp_seo_qualification": qualification_ms,
        }
        report["exact_lookup"] = {
            "cve": target_cve,
            "shard": target_shard,
            "record_api": expected_record_api,
            "record_api_cached_shards": record_cached_shards,
            "public_route": public_record,
            "public_route_cached_shards": route_cached_shards,
            "cached_shards": cached_shards,
            "found": True,
        }
        report["seo"] = {
            "qualified_cve": qualified_cve,
            "qualified_policy": qualified_policy,
            "unqualified_cve": target_cve,
            "unqualified_policy": unqualified_policy,
        }

    report["total_seconds"] = elapsed_seconds(started)
    report["peak_rss_mib"] = round(peak_rss_bytes() / MIB, 3)
    enforce_budgets(report, args)
    report["status"] = "passed"


def positive_number(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--records",
        type=int,
        default=DEFAULT_RECORDS,
        help=f"deterministic records to generate (default: {DEFAULT_RECORDS})",
    )
    parser.add_argument("--report", type=Path, help="write the machine-readable gate report here")
    parser.add_argument("--max-generation-seconds", type=positive_number, default=300.0)
    parser.add_argument("--max-publication-seconds", type=positive_number, default=900.0)
    parser.add_argument("--max-update-seconds", type=positive_number, default=900.0)
    parser.add_argument("--max-database-seconds", type=positive_number, default=900.0)
    parser.add_argument("--max-sitemap-seconds", type=positive_number, default=300.0)
    parser.add_argument("--max-site-build-seconds", type=positive_number, default=900.0)
    parser.add_argument("--max-total-seconds", type=positive_number, default=2_700.0)
    parser.add_argument("--max-rss-mib", type=positive_number, default=4_096.0)
    parser.add_argument("--max-node-rss-mib", type=positive_number, default=2_048.0)
    parser.add_argument("--max-source-mib", type=positive_number, default=1_024.0)
    parser.add_argument("--max-catalog-mib", type=positive_number, default=2_048.0)
    parser.add_argument("--max-database-mib", type=positive_number, default=2_048.0)
    parser.add_argument("--max-catalog-files", type=int, default=2_000)
    parser.add_argument("--max-site-output-mib", type=positive_number, default=320.0)
    parser.add_argument("--max-site-output-files", type=int, default=3_000)
    parser.add_argument("--max-query-ms", type=positive_number, default=750.0)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report: dict[str, Any] = {}
    try:
        execute(args, report)
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = f"{type(exc).__name__}: {exc}"
        report.setdefault("peak_rss_mib", round(peak_rss_bytes() / MIB, 3))
        write_report(args.report, report)
        traceback.print_exc()
        return 1

    write_report(args.report, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
