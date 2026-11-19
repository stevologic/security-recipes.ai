#!/usr/bin/env python3
"""String-patch mutants for the CVE search validation deadline freeze.

Not loaded by default unittest discovery. Apply one mutant, run the mapped
behavioural test, then restore. A kill is an AssertionError from that test.
Import errors and other nonzero exits are not kills.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

EDITS: dict[str, tuple[str, tuple[tuple[str, str, str], ...], tuple[str, ...]]] = {
    "M-D4": (
        "Drop validation_timeout_seconds from the production CVESearchRuntime caller.",
        (
            (
                "mcp_server.py",
                "                        query_timeout_seconds=self.SEARCH_DATABASE_QUERY_TIMEOUT_SECONDS,\n"
                "                        validation_timeout_seconds=resolve_validation_timeout_seconds(\n"
                "                            database_path.stat().st_size\n"
                "                        ),\n",
                "                        query_timeout_seconds=self.SEARCH_DATABASE_QUERY_TIMEOUT_SECONDS,\n",
            ),
        ),
        (
            "tests.test_cve_recipe_catalog.CVERecipeCatalogTests.test_d4_catalog_passes_resolved_validation_timeout_to_runtime",
            "tests.test_cve_recipe_catalog.CVERecipeCatalogTests.test_configured_sqlite_runtime_preempts_legacy_browser_index",
        ),
    ),
    "M-D5a": (
        "Skip the whole-file digest mismatch check.",
        (
            (
                "scripts/cve_search_runtime.py",
                "        if self._database_sha256(validation_deadline) != self._expected_database_sha256:\n"
                "            raise CVESearchDatabaseError(\"CVE search database digest does not match deployment configuration\")\n",
                "        self._database_sha256(validation_deadline)\n",
            ),
        ),
        (
            "tests.test_cve_search_validation_deadline.CVESearchValidationDeadlineTests.test_d5_sha_mismatch_still_fails_closed_under_long_deadline",
        ),
    ),
    "M-D5b": (
        "Skip SQLite validation after the digest, so header and mid-file corruption survive.",
        (
            (
                "scripts/cve_search_runtime.py",
                "        self._metadata = self._validate_database(validation_deadline)\n",
                "        self._metadata = {}\n",
            ),
        ),
        (
            "tests.test_cve_search_validation_deadline.CVESearchValidationDeadlineTests.test_d5_header_and_mid_file_corruption_still_fail_closed",
        ),
    ),
    "M-D5c": (
        "Skip the FTS/content count mismatch check.",
        (
            (
                "scripts/cve_search_runtime.py",
                "            if actual_count != metadata_count or fts_count != metadata_count:\n"
                "                raise CVESearchDatabaseError(\"CVE search database content count does not match metadata\")\n",
                "",
            ),
        ),
        (
            "tests.test_cve_search_validation_deadline.CVESearchValidationDeadlineTests.test_d5_fts_count_mismatch_still_fails_closed",
        ),
    ),
    "M-D5d": (
        "Skip the FTS docsize coverage check.",
        (
            (
                "scripts/cve_search_runtime.py",
                "            if docsize_count != metadata_count or missing_docsize is not None or unexpected_docsize is not None:\n"
                "                raise CVESearchDatabaseError(\"CVE search database FTS document coverage is inconsistent\")\n",
                "",
            ),
        ),
        (
            "tests.test_cve_search_validation_deadline.CVESearchValidationDeadlineTests.test_d5_docsize_gap_still_fails_closed",
        ),
    ),
    "M-D5e": (
        "Skip the FTS boundary posting check.",
        (
            (
                "scripts/cve_search_runtime.py",
                "                    if indexed is None:\n"
                "                        raise CVESearchDatabaseError(\"CVE search database FTS index is incomplete\")\n",
                "",
            ),
        ),
        (
            "tests.test_cve_search_validation_deadline.CVESearchValidationDeadlineTests.test_d5_fts_boundary_row_missing_still_fails_closed",
        ),
    ),
    "M-D5f": (
        "Skip the quick_check != ok check.",
        (
            (
                "scripts/cve_search_runtime.py",
                "            if quick_check != [\"ok\"]:\n"
                "                raise CVESearchDatabaseError(\"CVE search database failed SQLite's structural integrity check\")\n",
                "",
            ),
        ),
        (
            "tests.test_cve_search_validation_deadline.CVESearchValidationDeadlineTests.test_d5_quick_check_not_ok_still_fails_closed",
        ),
    ),
    "M-D6a": (
        "Remove digest-phase deadline checks.",
        (
            (
                "scripts/cve_search_runtime.py",
                "        if self._clock() >= deadline:\n"
                "            raise CVESearchDatabaseError(\"CVE search database digest validation exceeded its deadline\")\n"
                "        digest = hashlib.sha256()\n",
                "        digest = hashlib.sha256()\n",
            ),
            (
                "scripts/cve_search_runtime.py",
                "                while chunk := stream.read(MIB):\n"
                "                    if self._clock() >= deadline:\n"
                "                        raise CVESearchDatabaseError(\"CVE search database digest validation exceeded its deadline\")\n"
                "                    digest.update(chunk)\n",
                "                while chunk := stream.read(MIB):\n"
                "                    digest.update(chunk)\n",
            ),
        ),
        (
            "tests.test_cve_search_validation_deadline.CVESearchValidationDeadlineTests.test_d6_deadline_is_enforced_in_digest_phase",
        ),
    ),
    "M-D6b": (
        "Remove SQLite-phase deadline enforcement.",
        (
            (
                "scripts/cve_search_runtime.py",
                "        if self._clock() >= deadline:\n"
                "            raise CVESearchDatabaseError(\"CVE search database validation exceeded its deadline\")\n"
                "        connection = self._connect(deadline)\n",
                "        connection = self._connect(deadline)\n",
            ),
            (
                "scripts/cve_search_runtime.py",
                "            connection.set_progress_handler(\n"
                "                lambda: 1 if self._clock() >= deadline else 0,\n"
                "                PROGRESS_HANDLER_STEPS,\n"
                "            )\n",
                "            connection.set_progress_handler(lambda: 0, PROGRESS_HANDLER_STEPS)\n",
            ),
        ),
        (
            "tests.test_cve_search_validation_deadline.CVESearchValidationDeadlineTests.test_d6_deadline_is_enforced_in_sqlite_phase",
        ),
    ),
    "M-D7": (
        "Give the SQLite phase a fresh timeout budget after digest.",
        (
            (
                "scripts/cve_search_runtime.py",
                "        if self._database_sha256(validation_deadline) != self._expected_database_sha256:\n"
                "            raise CVESearchDatabaseError(\"CVE search database digest does not match deployment configuration\")\n"
                "        self._metadata = self._validate_database(validation_deadline)\n",
                "        if self._database_sha256(validation_deadline) != self._expected_database_sha256:\n"
                "            raise CVESearchDatabaseError(\"CVE search database digest does not match deployment configuration\")\n"
                "        validation_deadline = self._clock() + validation_timeout\n"
                "        self._metadata = self._validate_database(validation_deadline)\n",
            ),
        ),
        (
            "tests.test_cve_search_validation_deadline.CVESearchValidationDeadlineTests.test_d7_shared_budget_leaves_digest_remainder_for_sqlite",
        ),
    ),
}


def apply_edits(root: Path, mutant_id: str) -> None:
    _title, edits, _tests = EDITS[mutant_id]
    for relative, old, new in edits:
        path = root / relative
        text = path.read_text(encoding="utf-8")
        count = text.count(old)
        if count != 1:
            raise AssertionError(f"{mutant_id}: {relative} old string occurs {count} times")
        path.write_text(text.replace(old, new, 1), encoding="utf-8")


def run_mutant(mutant_id: str) -> int:
    if mutant_id not in EDITS:
        raise SystemExit(f"unknown mutant {mutant_id}")
    _title, edits, tests = EDITS[mutant_id]
    originals = {(ROOT / relative): (ROOT / relative).read_text(encoding="utf-8") for relative, _old, _new in edits}
    try:
        apply_edits(ROOT, mutant_id)
        command = [sys.executable, "-m", "unittest", *tests]
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result.returncode
    finally:
        for path, text in originals.items():
            path.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mutant_id", choices=sorted(EDITS))
    args = parser.parse_args()
    return run_mutant(args.mutant_id)


if __name__ == "__main__":
    raise SystemExit(main())
