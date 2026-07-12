from __future__ import annotations

import asyncio
import concurrent.futures
import gzip
import hashlib
import json
import tempfile
import threading
import time
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

import mcp_server
from mcp_server import CVERecipeCatalog


REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO_ROOT / "static" / "api" / "cve-catalog"


def recipe_archetype(title: str, prefix: str) -> dict[str, object]:
    return {
        "title": title,
        "matching_cwes": [],
        "exposure_checks": ["Shared exposure check", f"{prefix} exposure check"],
        "remediation_steps": ["Shared remediation step", f"{prefix} remediation step"],
        "containment_steps": [f"{prefix} containment step"],
        "verification_steps": [f"{prefix} verification step"],
        "stop_conditions": [f"{prefix} stop condition"],
        "watch_for": [f"{prefix} watch item"],
    }


def write_synthetic_catalog(catalog_dir: Path) -> None:
    shard = "shards/2021/0044.jsonl.gz"
    compact = {
        "cve": "CVE-2021-44228",
        "title": "Apache Log4j remote code execution",
        "severity": "critical",
        "score": 10.0,
        "published": "2021-12-10",
        "ecosystem": "java/maven",
        "kev": True,
        "archetype": "command_code_injection",
        "archetypes": ["command_code_injection", "unsafe_deserialization"],
        "has_markdown": False,
        "shard": shard,
    }
    medium_compact = {
        "cve": "CVE-2021-44229",
        "title": "Apache Log4j moderate information exposure",
        "severity": "medium",
        "score": 6.4,
        "published": "2021-12-11",
        "ecosystem": "java/maven",
        "kev": False,
        "archetype": "generic",
        "archetypes": ["generic"],
        "has_markdown": False,
        "shard": shard,
    }
    full = {
        **compact,
        "summary": "Log4Shell permits remote code execution through unsafe lookup and deserialization behavior.",
        "metrics": [{"version": "3.1", "score": 10.0, "severity": "critical"}],
        "products": [{"vendor": "apache", "product": "log4j"}],
        "product_match_count": 5,
        "products_stored": 1,
        "products_truncated": True,
        "references": [],
        "markdown": [],
        "recipe_kind": "composed",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    }
    medium_full = {
        **medium_compact,
        "summary": "A synthetic medium-severity information exposure used to exercise catalog filtering.",
        "metrics": [{"version": "3.1", "score": 6.4, "severity": "medium"}],
        "products": [{"vendor": "apache", "product": "log4j"}],
        "product_match_count": 1,
        "products_stored": 1,
        "products_truncated": False,
        "references": [],
        "markdown": [],
        "recipe_kind": "composed",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44229",
    }
    archetypes = {
        "schema_version": 1,
        "default_archetype": "generic",
        "archetypes": {
            "generic": recipe_archetype("Generic", "Generic"),
            "command_code_injection": recipe_archetype("Command injection", "Command"),
            "unsafe_deserialization": recipe_archetype("Unsafe deserialization", "Deserialization"),
        },
    }
    # index.json remains as a compatibility artifact, but the MCP catalog must
    # not read it: exact lookups use shards and text search uses the much
    # smaller browser index.
    (catalog_dir / "index.json").write_text(
        json.dumps({"schema_version": 2, "total": 2, "partition_key": "published_year", "partitions": []}),
        encoding="utf-8",
    )
    archetypes_payload = json.dumps(archetypes).encode("utf-8")
    (catalog_dir / "archetypes.json").write_bytes(archetypes_payload)
    shard_path = catalog_dir / shard
    shard_path.parent.mkdir(parents=True)
    shard_uncompressed = (json.dumps(full) + "\n" + json.dumps(medium_full) + "\n").encode("utf-8")
    shard_compressed = gzip.compress(shard_uncompressed, mtime=0)
    shard_path.write_bytes(shard_compressed)
    browser_uncompressed = json.dumps(
        {
            "schema_version": 2,
            "severity_codes": {"0": "medium", "1": "high", "2": "critical"},
            "fields": list(CVERecipeCatalog.BROWSER_INDEX_FIELDS),
            "ecosystems": ["java/maven"],
            "archetypes": ["command_code_injection", "unsafe_deserialization", "generic"],
            "records": [
                [
                    "CVE-2021-44228",
                    "Apache Log4j remote code execution",
                    2,
                    10.0,
                    "2021-12-10",
                    0,
                    True,
                    [0, 1],
                    False,
                ],
                [
                    "CVE-2021-44229",
                    "Apache Log4j moderate information exposure",
                    0,
                    6.4,
                    "2021-12-11",
                    0,
                    False,
                    [2],
                    False,
                ],
            ],
        },
        separators=(",", ":"),
    ).encode("utf-8")
    browser_compressed = gzip.compress(browser_uncompressed, mtime=0)
    (catalog_dir / "browser-index.json.gz").write_bytes(browser_compressed)
    manifest = {
        "schema_version": 2,
        "scope": {},
        "totals": {"catalog_records": 2},
        "archetypes_asset": {
            "path": "archetypes.json",
            "bytes": len(archetypes_payload),
            "sha256": hashlib.sha256(archetypes_payload).hexdigest(),
        },
        "browser_index": {
            "path": "browser-index.json.gz",
            "records": 2,
            "bytes": len(browser_compressed),
            "uncompressed_bytes": len(browser_uncompressed),
            "sha256": hashlib.sha256(browser_compressed).hexdigest(),
        },
        "shard_manifest": [
            {
                "path": shard,
                "records": 2,
                "bytes": len(shard_compressed),
                "uncompressed_bytes": len(shard_uncompressed),
                "sha256": hashlib.sha256(shard_compressed).hexdigest(),
            }
        ],
    }
    (catalog_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


class StubRecipeIndex:
    def __init__(self, recipe: dict[str, object] | None = None, *, fail_if_called: bool = False):
        self.recipe = recipe
        self.fail_if_called = fail_if_called
        self.lookups: list[str] = []

    async def get_doc(self, source_path: str) -> dict[str, object] | None:
        if self.fail_if_called:
            raise AssertionError("recipe index must not be used when embedded Markdown is available")
        self.lookups.append(source_path)
        return self.recipe


class StubCatalog:
    def __init__(self, recipe: dict[str, object]):
        self.recipe = recipe
        self.thread_ids: list[int] = []

    def info(self) -> dict[str, object]:
        self.thread_ids.append(threading.get_ident())
        return {"available": True}

    def search(self, query: str, **_: object) -> list[dict[str, object]]:
        self.thread_ids.append(threading.get_ident())
        return [{"cve": query.upper()}]

    def get_recipe(self, _: str) -> dict[str, object]:
        self.thread_ids.append(threading.get_ident())
        return deepcopy(self.recipe)


def catalog_result(markdown: list[dict[str, object]], *, recipe_kind: str) -> dict[str, object]:
    return {
        "found": True,
        "cve": "CVE-2021-44228",
        "source_record": {
            "cve": "CVE-2021-44228",
            "recipe_kind": recipe_kind,
            "markdown": markdown,
        },
        "composed_recipe": {
            "archetype_id": "command_code_injection",
            "primary_archetype_id": "command_code_injection",
            "archetype_ids": ["command_code_injection", "unsafe_deserialization"],
        },
    }


class CVERecipeCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        manifest = json.loads((CATALOG_PATH / "manifest.json").read_text(encoding="utf-8"))
        if manifest.get("schema_version") != 2:
            raise unittest.SkipTest("generated schema-v2 catalog fixture is not present")
        cls.catalog = CVERecipeCatalog(str(CATALOG_PATH))

    def test_catalog_reports_complete_declared_coverage(self) -> None:
        info = self.catalog.info()

        self.assertTrue(info["available"])
        totals = info["manifest"]["totals"]
        self.assertGreaterEqual(totals["catalog_records"], 260_000)
        self.assertGreaterEqual(info["manifest"]["by_severity"]["medium"], 110_000)
        self.assertEqual(info["manifest"]["browser_index"]["records"], totals["catalog_records"])
        self.assertEqual(totals["catalog_records"], totals["composed_recipe_coverage"])
        self.assertEqual(totals["coverage_percent"], 100.0)
        self.assertGreaterEqual(totals["in_scope_kev"], 1_200)
        self.assertNotIn("shard_manifest", info["manifest"])

    def test_exact_search_and_recipe_cover_previously_missing_critical_kev(self) -> None:
        results = self.catalog.search("CVE-2024-3400", limit=1)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["cve"], "CVE-2024-3400")
        self.assertEqual(results[0]["severity"], "critical")
        self.assertTrue(results[0]["kev"])

        recipe = self.catalog.get_recipe("cve-2024-3400")
        self.assertTrue(recipe["found"])
        self.assertEqual(recipe["source_record"]["cve"], "CVE-2024-3400")
        self.assertTrue(recipe["source_record"]["kev_details"])
        self.assertEqual(recipe["composed_recipe"]["archetype_id"], "command_code_injection")
        self.assertTrue(recipe["composed_recipe"]["exposure_checks"])
        self.assertTrue(recipe["composed_recipe"]["remediation_steps"])
        self.assertTrue(recipe["composed_recipe"]["verification_steps"])
        self.assertTrue(recipe["composed_recipe"]["stop_conditions"])

    def test_exact_search_and_get_cover_every_supported_severity(self) -> None:
        samples = {
            "CVE-1999-0199": "critical",
            "CVE-2002-20001": "high",
            "CVE-2002-20002": "medium",
        }

        for cve, severity in samples.items():
            with self.subTest(cve=cve, severity=severity):
                search = self.catalog.search(cve, severity=severity, limit=1)
                recipe = self.catalog.get_recipe(cve)

                self.assertEqual([result["cve"] for result in search], [cve])
                self.assertEqual(search[0]["severity"], severity)
                self.assertTrue(recipe["found"])
                self.assertEqual(recipe["source_record"]["severity"], severity)
                self.assertEqual(recipe["source_record"]["cve"], cve)

    def test_exact_lookup_and_query_limits(self) -> None:
        exact = self.catalog.search("cve-2024-3400", limit=50)

        self.assertEqual([record["cve"] for record in exact], ["CVE-2024-3400"])
        for query, message in (
            ("", "must not be blank"),
            ("   ", "must not be blank"),
            ("!@#$", "searchable term"),
            ("x" * 121, "at most 120 characters"),
            ("one two three four five six seven eight nine", "at most 8 terms"),
        ):
            with self.subTest(query=query), self.assertRaisesRegex(ValueError, message):
                self.catalog.search(query)
        for partial in ("CVE-2024-3", "CVE-2024-34", "CVE-2024-340"):
            with self.subTest(partial=partial), self.assertRaisesRegex(ValueError, "canonical"):
                self.catalog.get_recipe(partial)

    def test_exact_lookup_timing_does_not_scale_with_full_catalog_scan(self) -> None:
        catalog = CVERecipeCatalog(str(CATALOG_PATH))
        started = time.perf_counter()
        for _ in range(25):
            result = catalog.search("CVE-2024-3400", limit=1)
            self.assertEqual(result[0]["cve"], "CVE-2024-3400")
        elapsed = time.perf_counter() - started

        self.assertLess(elapsed, 2.0)
        self.assertFalse(catalog._search_records)
        self.assertFalse(catalog._search_postings)
        self.assertIsNone(catalog._search_signature)
        self.assertLessEqual(catalog._shard_cache_bytes, catalog.SHARD_CACHE_MAX_BYTES)

    def test_out_of_scope_or_invalid_ids_fail_closed(self) -> None:
        missing = self.catalog.get_recipe("CVE-1999-0001")

        self.assertFalse(missing["found"])
        self.assertIn("intake gate", missing["next_action"])
        with self.assertRaises(ValueError):
            self.catalog.get_recipe("not-a-cve")

    def test_partial_cve_id_search_uses_all_id_tokens(self) -> None:
        for prefix in ("CVE-2024", "CVE-2024-3", "CVE-2024-34", "CVE-2024-340"):
            with self.subTest(prefix=prefix):
                results = self.catalog.search(prefix, limit=50)
                self.assertTrue(results)
                self.assertTrue(all(record["cve"].startswith(prefix) for record in results))

        with self.assertRaisesRegex(ValueError, "too broad"):
            self.catalog.search("cve", limit=50)

    def test_prefix_and_plain_token_queries_do_not_share_cache_entries(self) -> None:
        prefix = self.catalog.search("CVE-2024", limit=5)
        plain = self.catalog.search("CVE 2024", limit=5)

        self.assertTrue(all(record["cve"].startswith("CVE-2024-") for record in prefix))
        self.assertTrue(plain)
        keys = list(self.catalog._query_cache)
        self.assertTrue(any(key[0] == ("cve-prefix", "CVE-2024") for key in keys))
        self.assertTrue(any(key[0] == ("cve", "2024") for key in keys))

    def test_runtime_search_artifact_limits_have_growth_headroom(self) -> None:
        manifest = json.loads((CATALOG_PATH / "manifest.json").read_text(encoding="utf-8"))
        browser = manifest["browser_index"]
        self.assertLessEqual(browser["bytes"], self.catalog.MAX_SEARCH_INDEX_COMPRESSED_BYTES)
        self.assertLessEqual(browser["uncompressed_bytes"], self.catalog.MAX_SEARCH_INDEX_UNCOMPRESSED_BYTES)
        self.assertLessEqual(browser["records"], self.catalog.MAX_SEARCH_RECORDS)


class CVERecipeCompositionTests(unittest.TestCase):
    def test_medium_exact_lookup_text_search_and_severity_filter_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            catalog_dir = Path(tmpdir)
            write_synthetic_catalog(catalog_dir)
            catalog = CVERecipeCatalog(str(catalog_dir))

            exact = catalog.search("CVE-2021-44229", severity="medium")
            text = catalog.search("moderate information", severity="medium")
            excluded = catalog.search("moderate information", severity="high")
            recipe = catalog.get_recipe("CVE-2021-44229")

        self.assertEqual([record["cve"] for record in exact], ["CVE-2021-44229"])
        self.assertEqual(exact[0]["severity"], "medium")
        self.assertEqual([record["cve"] for record in text], ["CVE-2021-44229"])
        self.assertEqual(excluded, [])
        self.assertTrue(recipe["found"])
        self.assertEqual(recipe["source_record"]["severity"], "medium")
        source = recipe["source_record"]
        self.assertTrue(source["summary"])
        self.assertTrue(source["metrics"])
        self.assertTrue(source["products"])
        self.assertTrue(source["nvd_url"])
        composed = recipe["composed_recipe"]
        for field in (
            "exposure_checks",
            "remediation_steps",
            "containment_steps",
            "verification_steps",
            "stop_conditions",
            "watch_for",
        ):
            self.assertTrue(composed[field], field)
        self.assertTrue(composed["required_output"])
        self.assertTrue(recipe["safety_boundary"])
        self.assertEqual(recipe["data_limits"], {})

    def test_log4shell_composes_all_archetypes_and_deduplicates_steps(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            catalog_dir = Path(tmpdir)
            write_synthetic_catalog(catalog_dir)
            catalog = CVERecipeCatalog(str(catalog_dir))

            search = catalog.search("unsafe deserialization", limit=5)
            recipe = catalog.get_recipe("CVE-2021-44228")

        self.assertEqual([record["cve"] for record in search], ["CVE-2021-44228"])
        composed = recipe["composed_recipe"]
        self.assertEqual(composed["primary_archetype_id"], "command_code_injection")
        self.assertEqual(
            composed["archetype_ids"],
            ["command_code_injection", "unsafe_deserialization"],
        )
        self.assertEqual(composed["exposure_checks"].count("Shared exposure check"), 1)
        self.assertEqual(composed["remediation_steps"].count("Shared remediation step"), 1)
        self.assertIn("Command remediation step", composed["remediation_steps"])
        self.assertIn("Deserialization remediation step", composed["remediation_steps"])
        self.assertTrue(recipe["data_limits"]["affected_products"]["truncated"])
        self.assertEqual(recipe["data_limits"]["affected_products"]["stored"], 1)
        self.assertEqual(recipe["data_limits"]["affected_products"]["total_matches"], 5)

    def test_exact_lookup_does_not_depend_on_the_full_or_search_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            catalog_dir = Path(tmpdir)
            write_synthetic_catalog(catalog_dir)
            (catalog_dir / "index.json").write_text("not json", encoding="utf-8")
            (catalog_dir / "browser-index.json.gz").write_bytes(b"not gzip")
            catalog = CVERecipeCatalog(str(catalog_dir))

            info = catalog.info()
            search = catalog.search("CVE-2021-44228")
            recipe = catalog.get_recipe("CVE-2021-44228")

        self.assertTrue(info["available"])
        self.assertFalse(info["runtime"]["full_index_required"])
        self.assertEqual([record["cve"] for record in search], ["CVE-2021-44228"])
        self.assertTrue(recipe["found"])
        self.assertFalse(catalog._search_records)

    def test_text_search_uses_compact_index_without_full_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            catalog_dir = Path(tmpdir)
            write_synthetic_catalog(catalog_dir)
            (catalog_dir / "index.json").unlink()
            catalog = CVERecipeCatalog(str(catalog_dir))

            first = catalog.search("unsafe deserialization", limit=5)
            cache_entries = len(catalog._query_cache)
            second = catalog.search("unsafe deserialization", limit=5)
            cross_field_and = catalog.search("CVE-2021 unsafe", limit=5)
            wrong_year_and = catalog.search("CVE-2024 unsafe", limit=5)

        self.assertEqual([record["cve"] for record in first], ["CVE-2021-44228"])
        self.assertEqual(second, first)
        self.assertTrue(catalog._search_records)
        self.assertTrue(catalog._search_postings)
        self.assertTrue(catalog._search_posting_masks)
        self.assertTrue(
            all(
                len(posting) == len(catalog._search_posting_masks[token])
                for token, posting in catalog._search_postings.items()
            )
        )
        self.assertEqual(cache_entries, 1)
        self.assertEqual([record["cve"] for record in cross_field_and], ["CVE-2021-44228"])
        self.assertEqual(wrong_year_and, [])
        self.assertEqual(len(catalog._query_cache), 3)

    def test_text_query_cache_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            catalog_dir = Path(tmpdir)
            write_synthetic_catalog(catalog_dir)
            catalog = CVERecipeCatalog(str(catalog_dir))

            for index in range(catalog.QUERY_CACHE_MAX_ENTRIES + 32):
                self.assertEqual(catalog.search(f"missing{index}"), [])

        self.assertEqual(len(catalog._query_cache), catalog.QUERY_CACHE_MAX_ENTRIES)

    def test_concurrent_exact_reads_share_a_bounded_integrity_checked_shard_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            catalog_dir = Path(tmpdir)
            write_synthetic_catalog(catalog_dir)
            catalog = CVERecipeCatalog(str(catalog_dir))

            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
                results = list(executor.map(catalog.get_recipe, ["CVE-2021-44228"] * 128))

        self.assertTrue(all(result["found"] for result in results))
        self.assertEqual(len(catalog._shard_cache), 1)
        self.assertLessEqual(catalog._shard_cache_bytes, catalog.SHARD_CACHE_MAX_BYTES)

    def test_shard_integrity_failure_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            catalog_dir = Path(tmpdir)
            write_synthetic_catalog(catalog_dir)
            shard = catalog_dir / "shards/2021/0044.jsonl.gz"
            shard.write_bytes(shard.read_bytes() + b"tampered")
            catalog = CVERecipeCatalog(str(catalog_dir))

            with self.assertRaisesRegex(ValueError, "size does not match"):
                catalog.get_recipe("CVE-2021-44228")

    def test_archetype_integrity_failure_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            catalog_dir = Path(tmpdir)
            write_synthetic_catalog(catalog_dir)
            archetypes = catalog_dir / "archetypes.json"
            archetypes.write_bytes(archetypes.read_bytes() + b" ")
            catalog = CVERecipeCatalog(str(catalog_dir))

            with self.assertRaisesRegex(ValueError, "archetype integrity"):
                catalog.get_recipe("CVE-2021-44228")


class CVERecipeToolTests(unittest.TestCase):
    def test_mcp_search_forwards_medium_severity_filter(self) -> None:
        class CapturingCatalog(StubCatalog):
            def __init__(self) -> None:
                super().__init__(catalog_result([], recipe_kind="composed"))
                self.kwargs: dict[str, object] = {}

            def search(self, query: str, **kwargs: object) -> list[dict[str, object]]:
                self.thread_ids.append(threading.get_ident())
                self.kwargs = kwargs
                return [{"cve": query.upper(), "severity": "medium"}]

        stub_catalog = CapturingCatalog()
        with patch.object(mcp_server, "cve_catalog", stub_catalog):
            result = asyncio.run(
                mcp_server.recipes_cve_search(
                    "moderate information",
                    severity="medium",
                    published_year=2021,
                )
            )

        self.assertEqual(result["count"], 1)
        self.assertEqual(result["results"][0]["severity"], "medium")
        self.assertEqual(stub_catalog.kwargs["severity"], "medium")
        self.assertEqual(stub_catalog.kwargs["published_year"], 2021)
        self.assertEqual(result["details"]["tool"], "recipes_cve_get")
        self.assertEqual(result["details"]["argument"], "cve")

    def test_catalog_wrappers_offload_synchronous_work(self) -> None:
        main_thread = threading.get_ident()
        stub_catalog = StubCatalog(catalog_result([], recipe_kind="composed"))

        async def call_tools() -> None:
            info = await mcp_server.recipes_cve_catalog_info()
            search = await mcp_server.recipes_cve_search("CVE-2024-3400")
            result = await mcp_server.recipes_cve_get("CVE-2021-44228")
            self.assertTrue(info["available"])
            self.assertEqual(search["count"], 1)
            self.assertEqual(result["recommended_recipe"]["kind"], "composed")

        with patch.object(mcp_server, "cve_catalog", stub_catalog):
            asyncio.run(call_tools())

        self.assertEqual(len(stub_catalog.thread_ids), 3)
        self.assertTrue(all(thread_id != main_thread for thread_id in stub_catalog.thread_ids))

    def test_slow_text_search_cannot_starve_exact_lookup_executor(self) -> None:
        started = threading.Event()
        release = threading.Event()

        class SlowSearchCatalog(StubCatalog):
            def search(self, query: str, **_: object) -> list[dict[str, object]]:
                self.thread_ids.append(threading.get_ident())
                if query == "slow broad search":
                    started.set()
                    release.wait(timeout=2)
                return [{"cve": query.upper()}]

        stub_catalog = SlowSearchCatalog(catalog_result([], recipe_kind="composed"))

        async def exercise() -> None:
            slow = asyncio.create_task(mcp_server.recipes_cve_search("slow broad search"))
            for _ in range(100):
                if started.is_set():
                    break
                await asyncio.sleep(0.005)
            self.assertTrue(started.is_set())
            exact = await asyncio.wait_for(
                mcp_server.recipes_cve_search("CVE-2024-3400"),
                timeout=0.5,
            )
            self.assertEqual(exact["count"], 1)
            release.set()
            await slow

        with patch.object(mcp_server, "cve_catalog", stub_catalog):
            asyncio.run(exercise())

    def test_text_search_admission_rejects_excess_without_submitting_work(self) -> None:
        case = self

        class RejectAdmission:
            def acquire(self, *, blocking: bool) -> bool:
                case.assertFalse(blocking)
                return False

            def release(self) -> None:
                raise AssertionError("rejected admission must not be released")

        stub_catalog = StubCatalog(catalog_result([], recipe_kind="composed"))
        with (
            patch.object(mcp_server, "cve_catalog", stub_catalog),
            patch.object(mcp_server, "cve_text_search_admission", RejectAdmission()),
        ):
            result = asyncio.run(mcp_server.recipes_cve_search("broad title query"))

        self.assertEqual(result["count"], 0)
        self.assertIn("busy", result["error"])
        self.assertFalse(stub_catalog.thread_ids)

    def test_stable_embedded_markdown_is_authoritative_without_index_lookup(self) -> None:
        entry = {
            "path": "content/prompt-library/cve/cve-2021-44228-log4shell.md",
            "maturity": "stable",
            "content_markdown": "## Authoritative Log4Shell recipe\n\nUpgrade and verify.",
        }
        stub_catalog = StubCatalog(catalog_result([entry], recipe_kind="markdown-override"))
        stub_index = StubRecipeIndex(fail_if_called=True)

        with (
            patch.object(mcp_server, "cve_catalog", stub_catalog),
            patch.object(mcp_server, "index", stub_index),
        ):
            result = asyncio.run(mcp_server.recipes_cve_get("CVE-2021-44228"))

        self.assertEqual(result["recommended_recipe"]["kind"], "markdown-override")
        self.assertEqual(result["authoritative_recipe"]["maturity"], "stable")
        self.assertIn("Authoritative Log4Shell", result["authoritative_recipe"]["content_markdown"])
        self.assertNotIn("content", result["authoritative_recipe"])
        encoded_body = json.dumps(entry["content_markdown"])[1:-1]
        self.assertEqual(json.dumps(result).count(encoded_body), 1)
        self.assertNotIn("content_markdown", result["source_record"]["markdown"][0])
        self.assertTrue(result["source_record"]["markdown"][0]["content_available"])
        self.assertNotIn("content_markdown", result["composed_recipe"]["product_specific_override"][0])
        self.assertEqual(result["composed_recipe"]["role"], "fallback")

    def test_stable_legacy_override_resolves_through_recipe_index(self) -> None:
        entry = {
            "path": "content/prompt-library/cve/cve-2021-44228-log4shell.md",
            "maturity": "stable",
        }
        stub_catalog = StubCatalog(catalog_result([entry], recipe_kind="markdown-override"))
        stub_index = StubRecipeIndex(
            {
                "title": "CVE-2021-44228 - Log4Shell",
                "source_file": "prompt-library/cve/cve-2021-44228-log4shell.md",
                "content": "Full indexed Log4Shell recipe body",
            }
        )

        with (
            patch.object(mcp_server, "cve_catalog", stub_catalog),
            patch.object(mcp_server, "index", stub_index),
        ):
            result = asyncio.run(mcp_server.recipes_cve_get("CVE-2021-44228"))

        self.assertEqual(stub_index.lookups, ["prompt-library/cve/cve-2021-44228-log4shell.md"])
        self.assertEqual(result["recommended_recipe"]["kind"], "markdown-override")
        self.assertEqual(
            result["authoritative_recipe"]["content_markdown"],
            "Full indexed Log4Shell recipe body",
        )
        self.assertNotIn("content", result["authoritative_recipe"])

    def test_oversized_stable_override_fails_closed_without_returning_body(self) -> None:
        body = "oversized authoritative body"
        entry = {
            "path": "content/prompt-library/cve/cve-2021-44228-log4shell.md",
            "maturity": "stable",
            "content_markdown": body,
        }
        stub_catalog = StubCatalog(catalog_result([entry], recipe_kind="markdown-override"))
        stub_index = StubRecipeIndex(fail_if_called=True)

        with (
            patch.object(mcp_server, "cve_catalog", stub_catalog),
            patch.object(mcp_server, "index", stub_index),
            patch.object(CVERecipeCatalog, "MAX_STABLE_MARKDOWN_BYTES", 8),
        ):
            result = asyncio.run(mcp_server.recipes_cve_get("CVE-2021-44228"))

        self.assertTrue(result["triage_required"])
        self.assertIn("size limit", result["error"])
        self.assertNotIn(body, json.dumps(result))

    def test_development_metadata_never_replaces_composed_recipe(self) -> None:
        entry = {
            "path": "content/prompt-library/cve/cve-2021-44228-log4shell.md",
            "maturity": "development",
            "content_markdown": "Draft content must not be authoritative.",
        }
        stub_catalog = StubCatalog(catalog_result([entry], recipe_kind="markdown-override"))
        stub_index = StubRecipeIndex(fail_if_called=True)

        with (
            patch.object(mcp_server, "cve_catalog", stub_catalog),
            patch.object(mcp_server, "index", stub_index),
        ):
            result = asyncio.run(mcp_server.recipes_cve_get("CVE-2021-44228"))

        self.assertEqual(result["recommended_recipe"]["kind"], "composed")
        self.assertIsNone(result["authoritative_recipe"])
        self.assertEqual(result["composed_recipe"]["role"], "recommended")
        self.assertNotIn("Draft content", json.dumps(result))

    def test_stable_metadata_without_override_recipe_kind_stays_composed(self) -> None:
        entry = {
            "path": "content/prompt-library/cve/cve-2021-44228-log4shell.md",
            "maturity": "stable",
            "content_markdown": "Stable content must still require the override recipe kind.",
        }
        stub_catalog = StubCatalog(catalog_result([entry], recipe_kind="composed"))
        stub_index = StubRecipeIndex(fail_if_called=True)

        with (
            patch.object(mcp_server, "cve_catalog", stub_catalog),
            patch.object(mcp_server, "index", stub_index),
        ):
            result = asyncio.run(mcp_server.recipes_cve_get("CVE-2021-44228"))

        self.assertEqual(result["recommended_recipe"]["kind"], "composed")
        self.assertIsNone(result["authoritative_recipe"])
        self.assertEqual(result["composed_recipe"]["role"], "recommended")

    def test_declared_override_without_stable_resolvable_body_fails_closed(self) -> None:
        entry = {
            "path": "content/prompt-library/cve/cve-2021-44228-log4shell.md",
            "maturity": "stable",
        }
        stub_catalog = StubCatalog(catalog_result([entry], recipe_kind="markdown-override"))
        stub_index = StubRecipeIndex()

        with (
            patch.object(mcp_server, "cve_catalog", stub_catalog),
            patch.object(mcp_server, "index", stub_index),
        ):
            result = asyncio.run(mcp_server.recipes_cve_get("CVE-2021-44228"))

        self.assertTrue(result["triage_required"])
        self.assertEqual(result["recommended_recipe"]["kind"], "markdown-override")
        self.assertFalse(result["recommended_recipe"]["available"])
        self.assertIsNone(result["authoritative_recipe"])
        self.assertEqual(result["composed_recipe"]["role"], "fallback")
        self.assertIn("TRIAGE.md", result["next_action"])


if __name__ == "__main__":
    unittest.main()
