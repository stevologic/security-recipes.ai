from __future__ import annotations

import asyncio
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp_server import (
    PublicMCPServerCatalog,
    ServerConfig,
    recipes_mcp_server_get,
    recipes_mcp_servers_list,
    recipes_server_info,
)


ROOT = Path(__file__).resolve().parents[1]


def run(coro):
    return asyncio.run(coro)


class PublicMCPServerCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.path = ROOT / "data" / "mcp" / "public-servers.json"
        cls.catalog = PublicMCPServerCatalog(str(cls.path))
        cls.payload = json.loads(cls.path.read_text(encoding="utf-8"))

    def test_default_config_uses_bundled_catalog(self) -> None:
        self.assertEqual(
            ServerConfig().public_mcp_server_catalog_path,
            "./data/mcp/public-servers.json",
        )

    def test_catalog_covers_every_external_server_documented_on_the_page(self) -> None:
        expected = {
            "github",
            "semgrep-docs",
            "snyk-studio",
            "aws-labs",
            "azure",
            "cloudflare",
            "docker",
        }
        self.assertEqual({server["id"] for server in self.payload["servers"]}, expected)
        metadata = self.catalog.metadata()
        self.assertTrue(metadata["available"])
        self.assertEqual(metadata["server_count"], len(expected))
        self.assertEqual(metadata["source_page"], "https://security-recipes.ai/mcp-servers/")

    def test_search_filters_capabilities_and_returns_isolated_results(self) -> None:
        cloud = self.catalog.list_servers(query="cloud observability")
        self.assertEqual([server["id"] for server in cloud["servers"]], ["cloudflare"])
        self.assertIn("discovery metadata only", cloud["connection_boundary"])
        cloud["servers"][0]["name"] = "mutated"
        self.assertEqual(self.catalog.get_server("cloudflare")["name"], "Cloudflare MCP servers")

    def test_get_and_mcp_tools_are_read_only_discovery_surfaces(self) -> None:
        with patch("mcp_server.public_mcp_server_catalog", self.catalog):
            listed = run(recipes_mcp_servers_list(query="repository code security"))
            fetched = run(recipes_mcp_server_get("github"))
            missing = run(recipes_mcp_server_get("missing"))
            info = run(recipes_server_info())

        self.assertEqual([server["id"] for server in listed["servers"]], ["github"])
        self.assertTrue(fetched["found"])
        self.assertIn("github.com/github/github-mcp-server", fetched["server"]["official_url"])
        self.assertFalse(missing["found"])
        self.assertTrue(info["public_mcp_server_catalog"]["available"])
        self.assertEqual(info["public_mcp_server_catalog"]["server_count"], 7)

    def test_rejects_duplicate_ids_unsafe_urls_and_invalid_limits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            duplicate = copy.deepcopy(self.payload)
            duplicate["servers"].append(copy.deepcopy(duplicate["servers"][0]))
            path.write_text(json.dumps(duplicate), encoding="utf-8")
            self.assertFalse(PublicMCPServerCatalog(str(path)).metadata()["available"])

            unsafe = copy.deepcopy(self.payload)
            unsafe["servers"][0]["official_url"] = "http://user:secret@example.test/mcp"
            path.write_text(json.dumps(unsafe), encoding="utf-8")
            self.assertIn("credential-free HTTPS", PublicMCPServerCatalog(str(path)).metadata()["error"])

        with self.assertRaisesRegex(ValueError, "limit must be between"):
            self.catalog.list_servers(limit=0)


if __name__ == "__main__":
    unittest.main()
