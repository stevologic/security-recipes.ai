from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch
from urllib.parse import parse_qs, urlparse
from urllib.error import HTTPError

from scripts import nvd_api_delta as delta
from scripts import sync_cve_catalog as catalog
from scripts import validate_cve_catalog as validator
from tests.test_sync_cve_catalog import archetype_payload, cvss_observation, nvd_record


END = datetime(2026, 10, 19, 22, tzinfo=timezone.utc)


def feeds() -> list[dict]:
    return [{
        "year": year, "accepted_records": 0,
        "url": f"{catalog.NVD_FEED_ROOT}/nvdcve-2.0-{year}.json.gz",
        "metadata": {"lastModifiedDate": "2026-10-19T00:00:00Z", "sha256": f"{year:064x}",
                     "size": "100", "gzSize": "50", "zipSize": "50"},
    } for year in range(2002, 2027)]


def current_record(identity="CVE-2026-76788", **kwargs) -> dict:
    result = nvd_record(identity, published="2026-10-19T21:18:01.000", **kwargs)
    result["lastModified"] = "2026-10-19T21:20:00.000"
    return result


def page(rows: list[dict], *, start=0, total=None) -> bytes:
    return json.dumps({"startIndex": start, "resultsPerPage": len(rows),
                       "totalResults": len(rows) if total is None else total,
                       "vulnerabilities": [{"cve": cve} for cve in rows]}).encode()


class NvdApiDeltaTests(unittest.TestCase):
    def test_pages_entire_modification_window_with_pacing_and_hash_receipts(self):
        first = current_record()
        second = current_record("CVE-2020-12345")
        data = [page([first], total=2), page([second], start=1, total=2)]
        fetch, sleep = Mock(side_effect=data), Mock()
        records, metadata = delta.fetch_delta(feeds(), end=END, fetch=fetch, sleep=sleep)
        self.assertEqual(set(records), {first["id"], second["id"]})
        self.assertEqual(metadata["records"], 2)
        self.assertEqual(metadata["latest_record_modified"], "2026-10-19T21:20:00.000Z")
        self.assertEqual(metadata["last_mod_start"], "2026-10-19T00:00:00.000Z")
        self.assertEqual(metadata["pages"][0]["sha256"], hashlib.sha256(data[0]).hexdigest())
        second_query = parse_qs(urlparse(fetch.call_args_list[1].args[0]).query)
        self.assertEqual(second_query["startIndex"], ["1"])
        self.assertEqual(second_query["lastModEndDate"], ["2026-10-19T22:00:00.000Z"])
        self.assertNotIn("pubStartDate", second_query)
        sleep.assert_called_once_with(delta.REQUEST_INTERVAL)

    def test_uses_oldest_identifier_year_feed_even_when_current_year_is_recent(self):
        sources = feeds()
        sources[0]["metadata"]["lastModifiedDate"] = "2026-08-28T03:04:26-04:00"
        _, metadata = delta.fetch_delta(sources, end=END, fetch=Mock(return_value=page([])), sleep=Mock())
        self.assertEqual(metadata["last_mod_start"], "2026-08-28T07:04:26.000Z")

    def test_only_a_drifting_day_is_retried_and_partial_records_are_discarded(self):
        old, fresh = current_record(), current_record("CVE-2026-112393")
        data = [page([old], total=2), page([], start=1, total=1), page([fresh])]
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(catalog, "utc_now", return_value=END), \
                patch.object(catalog, "fetch_bytes", side_effect=data), patch.object(catalog.time, "sleep"):
            records, receipt = catalog.cache_api_delta(feeds(), Path(directory))
            self.assertEqual(set(records), {fresh["id"]})
            self.assertEqual([entry["accepted"] for entry in receipt["pages"]], [False, False, True])
            self.assertEqual(catalog.cache_api_delta(feeds(), Path(directory), offline=True), (records, receipt))
        errors = []
        validator.validate_api_delta(receipt, feeds(), errors)
        self.assertEqual(errors, [])

    def test_adjacent_day_boundary_is_deduplicated_without_a_coverage_gap(self):
        sources = feeds()
        for source in sources:
            source["metadata"]["lastModifiedDate"] = "2026-10-18T00:00:00Z"
        boundary = current_record("CVE-2024-12345")
        boundary["published"] = "2026-10-18T00:00:00Z"
        boundary["lastModified"] = "2026-10-19T00:00:00Z"
        records, receipt = delta.fetch_delta(sources, end=END, fetch=Mock(side_effect=[
            page([boundary]), page([boundary, current_record()]),
        ]), sleep=Mock())
        self.assertEqual(len(records), 2)
        self.assertEqual(receipt["boundary_duplicates"], 1)
        errors = []
        validator.validate_api_delta(receipt, sources, errors)
        self.assertEqual(errors, [])

    def test_day_retries_obey_the_global_page_budget(self):
        with patch.object(delta, "MAX_PAGES", 1), self.assertRaisesRegex(ValueError, "page budget"):
            delta.fetch_delta(feeds(), end=END, fetch=Mock(return_value=page([current_record()], total=2)))

    def test_empty_api_result_does_not_advance_source_watermark_to_check_time(self):
        _, metadata = delta.fetch_delta(feeds(), end=END, fetch=Mock(return_value=page([])))
        self.assertIsNone(metadata["latest_record_modified"])
        self.assertEqual(metadata["last_mod_end"], "2026-10-19T22:00:00.000Z")

    def test_drops_revisions_already_covered_by_their_identifier_year_feed(self):
        sources = feeds()
        sources[0]["metadata"]["lastModifiedDate"] = "2026-10-18T00:00:00Z"
        covered = current_record()
        covered["lastModified"] = "2026-10-18T12:00:00Z"
        records, metadata = delta.fetch_delta(sources, end=END, fetch=Mock(side_effect=[page([covered]), page([])]), sleep=Mock())
        self.assertEqual(records, {})
        self.assertEqual(metadata["records"], 1)
        self.assertEqual(metadata["overlay_records"], 0)
        self.assertIsNone(metadata["latest_record_modified"])

    def test_fails_closed_for_truncated_changing_or_malformed_pages(self):
        valid = json.loads(page([current_record()], total=2))
        variants = [
            {**valid, "startIndex": 1}, {**valid, "resultsPerPage": 2},
            {**valid, "totalResults": True}, {**valid, "totalResults": 100001},
            {**valid, "vulnerabilities": []}, {**valid, "vulnerabilities": [None]},
        ]
        for invalid in variants:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                delta.fetch_delta(feeds(), end=END, fetch=Mock(return_value=json.dumps(invalid).encode()))
        for second in (page([], start=1, total=2), page([current_record()], start=1, total=3),
                       page([current_record()], start=1, total=2)):
            with self.subTest(second=second), self.assertRaises(ValueError):
                delta.fetch_delta(feeds(), end=END, fetch=Mock(side_effect=[json.dumps(valid).encode(), second] * 2),
                                  sleep=Mock())

    def test_rejects_missing_timestamps_out_of_window_records_and_excessive_window(self):
        for field, value in (("id", "bad"), ("lastModified", "bad"), ("published", "bad"),
                             ("lastModified", "2026-10-20T00:00:00Z")):
            record = current_record()
            record[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                delta.fetch_delta(feeds(), end=END, fetch=Mock(return_value=page([record])))
        old = feeds()
        old[0]["metadata"]["lastModifiedDate"] = "2025-01-01T00:00:00Z"
        fetch = Mock()
        with self.assertRaisesRegex(ValueError, "120 days"):
            delta.fetch_delta(old, end=END, fetch=fetch)
        fetch.assert_not_called()

    def test_overlay_adds_old_id_new_publications_and_removes_rejected_and_downgraded_rows(self):
        baseline = [nvd_record("CVE-2020-12345"), nvd_record("CVE-2020-12346")]
        rejected = current_record("CVE-2020-12345", status="Rejected")
        low = current_record("CVE-2020-12346", observations=[cvss_observation("3.1", 2.0)])
        added = current_record("CVE-2020-12347")
        replacements = {row["id"]: row for row in [rejected, low, added, current_record()]}
        overlaid = list(delta.overlay_year([{"cve": row} for row in baseline], replacements, 2020))
        normalized = [catalog.normalize_cve(row["cve"], start_date=END.date().replace(year=2016),
                      end_date=END.date(), kev_map={}, cwe_mapping={}, default_archetype="generic-remediation",
                      existing={}) for row in overlaid]
        self.assertEqual([row["cve"] for row in normalized if row], [added["id"]])

    def test_newer_annual_record_wins_and_duplicate_annual_identity_fails(self):
        annual = current_record()
        annual["lastModified"] = "2026-10-19T21:59:00Z"
        result = list(delta.overlay_year([{"cve": annual}], {annual["id"]: current_record()}, 2026))
        self.assertEqual(result, [{"cve": annual}])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            list(delta.overlay_year([{"cve": annual}, {"cve": annual}], {}, 2026))

    def test_cache_offline_replay_is_exact_and_detects_tampering_or_changed_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(catalog, "utc_now", return_value=END), \
                    patch.object(catalog, "fetch_bytes", return_value=page([current_record()])):
                online = catalog.cache_api_delta(feeds(), root)
            with patch.object(catalog, "fetch_bytes", side_effect=AssertionError("offline network access")):
                self.assertEqual(catalog.cache_api_delta(feeds(), root, offline=True), online)
                changed = feeds()
                changed[0]["metadata"]["sha256"] = "f" * 64
                with self.assertRaisesRegex(ValueError, "annual feeds"):
                    catalog.cache_api_delta(changed, root, offline=True)
                (root / "nvd-api-delta-page-0000.json").write_bytes(b"tampered")
                with self.assertRaisesRegex(ValueError, "integrity"):
                    catalog.cache_api_delta(feeds(), root, offline=True)

    def test_transient_api_read_timeout_retries_same_page_with_public_api_pacing(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = page([current_record()])
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(catalog, "utc_now", return_value=END), \
                patch.object(catalog, "urlopen", side_effect=[TimeoutError("slow public API"), response]) as opener, \
                patch.object(catalog.time, "sleep") as sleep:
            records, receipt = catalog.cache_api_delta(feeds(), Path(directory))
        self.assertEqual(len(records), 1)
        self.assertEqual(len(receipt["pages"]), 1)
        self.assertEqual(opener.call_count, 2)
        self.assertEqual(opener.call_args_list[0].args[0].full_url, opener.call_args_list[1].args[0].full_url)
        self.assertEqual(opener.call_args.kwargs["timeout"], 180)
        sleep.assert_called_once_with(delta.REQUEST_INTERVAL)

    def test_api_rate_limit_and_access_refusals_stop_without_retry(self):
        for status in (401, 403, 429):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory, \
                    patch.object(catalog, "utc_now", return_value=END), \
                    patch.object(catalog, "urlopen", side_effect=HTTPError(
                        delta.NVD_API_URL, status, "refused", {"Retry-After": "120"}, None,
                    )) as opener, patch.object(catalog.time, "sleep") as sleep:
                with self.assertRaises(HTTPError):
                    catalog.cache_api_delta(feeds(), Path(directory))
                self.assertEqual(opener.call_count, 1)
                sleep.assert_not_called()

    def test_validator_rejects_api_receipts_with_missing_pages_or_a_different_baseline(self):
        _, receipt = delta.fetch_delta(feeds(), end=END, fetch=Mock(return_value=page([current_record()])))
        errors = []
        validator.validate_api_delta(receipt, feeds(), errors)
        self.assertEqual(errors, [])
        for mutate in (
            lambda value: value.update(records=2),
            lambda value: value.update(baseline_sha256="0" * 64),
            lambda value: value.update(latest_record_modified="2026-10-20T00:00:00Z"),
            lambda value: value["pages"][0].update(url=value["pages"][0]["url"] + "&cvssV3Severity=HIGH"),
            lambda value: value["pages"][0].update(sha256="bad"),
        ):
            invalid = deepcopy(receipt)
            mutate(invalid)
            errors = []
            validator.validate_api_delta(invalid, feeds(), errors)
            self.assertTrue(errors)

    def test_complete_main_sync_publishes_api_record_with_real_source_watermark(self):
        with tempfile.TemporaryDirectory(dir=catalog.ROOT) as directory:
            root = Path(directory)
            content = root / "content"
            content.mkdir()
            feed = root / "feed.json.gz"
            feed.write_bytes(gzip.compress(b'{"vulnerabilities":[]}'))
            kev = {"catalogVersion": "2026.10.16", "dateReleased": "2026-10-16T17:15:48Z",
                   "vulnerabilities": []}
            archetypes = archetype_payload()
            with patch.object(catalog, "cache_feed", side_effect=lambda year, *a, **kw:
                              (feed, deepcopy(feeds()[year-2002]["metadata"]))), \
                    patch.object(catalog, "cache_kev", return_value=(kev, json.dumps(kev).encode())), \
                    patch.object(catalog, "load_archetypes", return_value=(archetypes, {})), \
                    patch.object(catalog, "fetch_bytes", return_value=page([current_record()])), \
                    patch.object(catalog, "utc_now", return_value=END):
                result = catalog.main([
                    "--start-date", "2016-10-19", "--end-date", "2026-10-19", "--nvd-api-delta",
                    "--disable-ai-enrichment", "--content-dir", str(content), "--output-dir", str(root / "catalog"),
                    "--cache-dir", str(root / "cache"), "--enrichment-cache", str(root / "enrichment.json"),
                    "--generated-recipe-manifest", str(root / "generated.json"),
                ])
            self.assertEqual(result, 0)
            validation = validator.validate(root / "catalog", content)
            self.assertTrue(validation["ok"], validation["failures"])
            manifest = json.loads((root / "catalog" / "manifest.json").read_bytes())
            self.assertEqual(manifest["totals"]["catalog_records"], 1)
            self.assertEqual(manifest["catalog_updated_at"], "2026-10-19T21:20:00Z")
            self.assertEqual(manifest["sources"]["nvd"]["api_delta"]["last_mod_end"],
                             "2026-10-19T22:00:00.000Z")
            self.assertEqual(manifest["sources"]["nvd"]["feeds"][-1]["accepted_records"], 1)
            # Adding factual records does not claim reviewed/indexable remediation.
            self.assertEqual(manifest["totals"]["search_indexable_records"], 0)

            # A failed source check cannot publish a partial or annual-only catalog.
            before = (root / "catalog" / "manifest.json").read_bytes()
            with patch.object(catalog, "cache_feed", return_value=(feed, feeds()[-1]["metadata"])), \
                    patch.object(catalog, "cache_kev", return_value=(kev, json.dumps(kev).encode())), \
                    patch.object(catalog, "load_archetypes", return_value=(archetypes, {})), \
                    patch.object(catalog, "cache_api_delta", side_effect=TimeoutError("NVD API unavailable")), \
                    patch.object(catalog, "write_outputs") as write:
                with self.assertRaises(TimeoutError):
                    catalog.main([
                        "--start-date", "2016-10-19", "--end-date", "2026-10-19", "--nvd-api-delta",
                        "--disable-ai-enrichment", "--content-dir", str(content),
                        "--output-dir", str(root / "catalog"), "--cache-dir", str(root / "cache"),
                        "--enrichment-cache", str(root / "enrichment.json"),
                        "--generated-recipe-manifest", str(root / "generated.json"),
                    ])
                write.assert_not_called()
            self.assertEqual((root / "catalog" / "manifest.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
