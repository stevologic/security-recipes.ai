from __future__ import annotations

import gzip
import os
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RETIRED_NAME = re.compile(rb"prompt[-_ ]?library", re.IGNORECASE)
EXCLUDED_DIRS = {
    ".git",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "node_modules",
    "public",
    "tmp",
}
TEXT_SUFFIXES = {
    ".conf",
    ".css",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".lock",
    ".md",
    ".mjs",
    ".njk",
    ".py",
    ".svg",
    ".toml",
    ".txt",
    ".webmanifest",
    ".xml",
    ".yaml",
    ".yml",
}
TEXT_NAMES = {"CNAME", "Dockerfile", "LICENSE"}


class RecipeNamespaceTests(unittest.TestCase):
    def test_retired_namespace_is_absent_from_paths_text_and_catalog_payloads(self) -> None:
        failures: list[str] = []
        catalog_root = ROOT / "static" / "api" / "cve-catalog"

        for current, directories, files in os.walk(ROOT, topdown=True):
            directories[:] = sorted(
                name for name in directories if name not in EXCLUDED_DIRS
            )
            current_path = Path(current)

            for name in [*directories, *files]:
                relative = (current_path / name).relative_to(ROOT).as_posix()
                if RETIRED_NAME.search(relative.encode("utf-8")):
                    failures.append(f"retired namespace in path: {relative}")

            for name in files:
                path = current_path / name
                if path.suffix.lower() in TEXT_SUFFIXES or name in TEXT_NAMES:
                    if RETIRED_NAME.search(path.read_bytes()):
                        failures.append(
                            f"retired namespace in text: {path.relative_to(ROOT).as_posix()}"
                        )
                elif path.suffix.lower() == ".gz" and path.is_relative_to(catalog_root):
                    with gzip.open(path, "rb") as handle:
                        if RETIRED_NAME.search(handle.read()):
                            failures.append(
                                "retired namespace in catalog payload: "
                                f"{path.relative_to(ROOT).as_posix()}"
                            )

        self.assertEqual([], failures[:20], "\n".join(failures[:20]))


if __name__ == "__main__":
    unittest.main()
