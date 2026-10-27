from __future__ import annotations

import unittest

from scripts.cve_catalog_data_paths import (
    CATALOG_DATA_FILES,
    CATALOG_DATA_PATH_PREFIXES,
    DiffPath,
    allowlisted_catalog_paths,
    catalog_commit_pathspecs,
    evaluate_catalog_diff,
    generated_behavior_output_pathspecs,
    is_catalog_data_path,
    normalize_repo_path,
    parse_name_status_lines,
    parse_name_status_z,
    parse_raw_z,
    path_matches_prefix,
)


SHA = "0a7e0100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
OTHER = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def decide(*paths: DiffPath, expected: str = SHA, actual: str = SHA):
    return evaluate_catalog_diff(paths, expected_sha=expected, actual_sha=actual)


class CveCatalogDataPathTests(unittest.TestCase):
    def test_allowlist_covers_generated_catalog_data_only(self) -> None:
        allowed = allowlisted_catalog_paths()
        self.assertIn("data/cve/ai-enrichments.json", allowed)
        self.assertIn("data/cve/ai-generated-recipes.json", allowed)
        self.assertIn("data/cve/enrichment-carryover.json", allowed)
        self.assertNotIn("data/context/secure-context-release-pack.json", allowed)
        self.assertNotIn("data/policy/mcp-gateway-policy.json", allowed)
        self.assertNotIn("scripts/generated-output-ownership.json", allowed)
        self.assertNotIn("data/evidence/", allowed)
        self.assertIn("static/api/cve-catalog/", allowed)
        self.assertIn("content/recipes/cve/*.md", allowed)
        self.assertTrue(is_catalog_data_path("static/api/cve-catalog/manifest.json"))
        self.assertTrue(is_catalog_data_path("content/recipes/cve/ai-enrichment-cve-2026-0001.md"))
        self.assertFalse(is_catalog_data_path("data/evidence/cve-2026-0001.json"))
        self.assertEqual(CATALOG_DATA_PATH_PREFIXES, ("static/api/cve-catalog/",))
        self.assertTrue(CATALOG_DATA_FILES)
        self.assertIn(":(glob)content/recipes/cve/*.md", catalog_commit_pathspecs())
        self.assertIn("data/policy/mcp-gateway-policy.json", generated_behavior_output_pathspecs())

    def test_data_only_diff_passes(self) -> None:
        decision = decide(
            DiffPath("M", "static/api/cve-catalog/manifest.json"),
            DiffPath("A", "data/cve/ai-enrichments.json"),
            DiffPath("M", "data/cve/ai-generated-recipes.json"),
            DiffPath("A", "data/cve/enrichment-carryover.json"),
            DiffPath("A", "content/recipes/cve/ai-enrichment-cve-2026-0001.md"),
        )
        self.assertTrue(decision.data_only)
        self.assertTrue(decision.sha_matches)
        self.assertEqual(decision.rejected_paths, ())
        self.assertEqual(decision.unsafe_paths, ())

    def test_behavior_changing_pipeline_outputs_fail_closed(self) -> None:
        for path in (
            "data/policy/mcp-gateway-policy.json",
            "scripts/generated-output-ownership.json",
            "data/context/secure-context-release-pack.json",
            "data/evidence/cve-2026-0001.json",
        ):
            with self.subTest(path=path):
                decision = decide(DiffPath("M", path))
                self.assertFalse(decision.data_only)
                self.assertIn(path, decision.rejected_paths)

    def test_recipe_non_markdown_fails_closed(self) -> None:
        decision = decide(DiffPath("A", "content/recipes/cve/evil.py"))
        self.assertFalse(decision.data_only)
        self.assertEqual(decision.rejected_paths, ("content/recipes/cve/evil.py",))
        self.assertFalse(is_catalog_data_path("content/recipes/cve/evil.py"))
        self.assertFalse(is_catalog_data_path("content/recipes/cve/notes.txt"))
        self.assertTrue(is_catalog_data_path("content/recipes/cve/ok.md"))

    def test_prefix_matching_requires_directory_boundary(self) -> None:
        self.assertFalse(path_matches_prefix("static/api/cve-catalog-evil/x", "static/api/cve-catalog"))
        self.assertFalse(path_matches_prefix("static/api/cve-catalog-evil/x", "static/api/cve-catalog/"))
        self.assertTrue(path_matches_prefix("static/api/cve-catalog/manifest.json", "static/api/cve-catalog"))
        decision = decide(DiffPath("A", "static/api/cve-catalog-evil/x"))
        self.assertFalse(decision.data_only)
        self.assertEqual(decision.rejected_paths, ("static/api/cve-catalog-evil/x",))
        self.assertFalse(is_catalog_data_path("static/api/cve-catalog-evil/x"))

    def test_workflow_path_fails_closed(self) -> None:
        decision = decide(
            DiffPath("M", "static/api/cve-catalog/manifest.json"),
            DiffPath("M", ".github/workflows/cve-catalog-sync.yml"),
        )
        self.assertFalse(decision.data_only)
        self.assertIn(".github/workflows/cve-catalog-sync.yml", decision.rejected_paths)
        self.assertIn("require karen-qa and real checks", decision.reason)

    def test_script_path_fails_closed(self) -> None:
        decision = decide(DiffPath("M", "scripts/sync_cve_catalog.py"))
        self.assertFalse(decision.data_only)
        self.assertEqual(decision.rejected_paths, ("scripts/sync_cve_catalog.py",))

    def test_docs_path_fails_closed(self) -> None:
        decision = decide(DiffPath("M", ".github/AUTOMATION.md"))
        self.assertFalse(decision.data_only)
        self.assertEqual(decision.rejected_paths, (".github/AUTOMATION.md",))

    def test_mcp_server_file_fails_closed(self) -> None:
        decision = decide(DiffPath("M", "mcp_server.py"))
        self.assertFalse(decision.data_only)
        self.assertEqual(decision.rejected_paths, ("mcp_server.py",))

    def test_sha_mismatch_fails_closed(self) -> None:
        decision = decide(
            DiffPath("M", "static/api/cve-catalog/manifest.json"),
            expected=SHA,
            actual=OTHER,
        )
        self.assertFalse(decision.data_only)
        self.assertFalse(decision.sha_matches)
        self.assertIn("SHA mismatch", decision.reason)

    def test_invalid_sha_fails_closed(self) -> None:
        decision = decide(
            DiffPath("M", "static/api/cve-catalog/manifest.json"),
            expected="not-a-sha",
            actual="not-a-sha",
        )
        self.assertFalse(decision.sha_matches)
        self.assertFalse(decision.data_only)

    def test_path_traversal_fails_closed(self) -> None:
        sneaky = "static/api/cve-catalog/../../../.github/workflows/evil.yml"
        self.assertIsNone(normalize_repo_path(sneaky))
        decision = decide(DiffPath("A", sneaky))
        self.assertFalse(decision.data_only)
        self.assertEqual(decision.unsafe_paths, (sneaky,))
        self.assertIn("path-traversal", decision.reason)

    def test_absolute_and_windows_paths_fail_closed(self) -> None:
        self.assertIsNone(normalize_repo_path("/etc/passwd"))
        self.assertIsNone(normalize_repo_path("C:\\Windows\\system32"))
        decision = decide(DiffPath("A", "/tmp/mcp_server.py"))
        self.assertFalse(decision.data_only)
        self.assertEqual(decision.unsafe_paths, ("/tmp/mcp_server.py",))

    def test_rename_into_code_path_fails_closed(self) -> None:
        decision = decide(
            DiffPath(
                "R",
                "scripts/sync_cve_catalog.py",
                previous_path="static/api/cve-catalog/manifest.json",
            )
        )
        self.assertFalse(decision.data_only)
        self.assertIn("scripts/sync_cve_catalog.py", decision.rejected_paths)

    def test_rename_from_code_path_fails_closed(self) -> None:
        decision = decide(
            DiffPath(
                "R",
                "static/api/cve-catalog/manifest.json",
                previous_path="mcp_server.py",
            )
        )
        self.assertFalse(decision.data_only)
        self.assertIn("mcp_server.py", decision.rejected_paths)

    def test_symlink_fails_closed(self) -> None:
        decision = decide(
            DiffPath(
                "T",
                "static/api/cve-catalog/manifest.json",
                src_mode="100644",
                dst_mode="120000",
            )
        )
        self.assertFalse(decision.data_only)
        self.assertTrue(any("symlink" in item or "type-change" in item for item in decision.unsafe_paths))

    def test_mode_change_fails_closed(self) -> None:
        decision = decide(
            DiffPath(
                "M",
                "static/api/cve-catalog/manifest.json",
                src_mode="100644",
                dst_mode="100755",
            )
        )
        self.assertFalse(decision.data_only)
        self.assertTrue(any("mode-change" in item for item in decision.unsafe_paths))

    def test_raw_parser_reads_modes_and_renames(self) -> None:
        parsed = parse_raw_z(
            b":100644 100755 0123456789abcdef0123456789abcdef01234567 "
            b"89abcdef0123456789abcdef0123456789abcdef M\0static/api/cve-catalog/manifest.json\0"
            b":100644 100644 0123456789abcdef0123456789abcdef01234567 "
            b"89abcdef0123456789abcdef0123456789abcdef R100\0"
            b"static/api/cve-catalog/old.json\0scripts/evil.py\0"
        )
        self.assertEqual(parsed[0].dst_mode, "100755")
        self.assertEqual(parsed[1].previous_path, "static/api/cve-catalog/old.json")
        self.assertEqual(parsed[1].path, "scripts/evil.py")

    def test_name_status_parsers_keep_rename_both_sides(self) -> None:
        lines = parse_name_status_lines(
            "R100\tstatic/api/cve-catalog/old.json\tscripts/evil.py\n"
            "M\tstatic/api/cve-catalog/manifest.json\n"
        )
        self.assertEqual(lines[0].previous_path, "static/api/cve-catalog/old.json")
        self.assertEqual(lines[0].path, "scripts/evil.py")
        parsed = parse_name_status_z(
            b"R100\0static/api/cve-catalog/old.json\0scripts/evil.py\0"
            b"M\0static/api/cve-catalog/manifest.json\0"
        )
        self.assertEqual(parsed[0].path, "scripts/evil.py")
        self.assertEqual(parsed[1].path, "static/api/cve-catalog/manifest.json")


if __name__ == "__main__":
    unittest.main()
