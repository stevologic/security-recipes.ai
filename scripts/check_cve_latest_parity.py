#!/usr/bin/env python3
"""Check actual HTTP homepage/latest and MCP tool parity on built paired images."""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from urllib.request import urlopen

from fastmcp import Client


def fetch(url: str) -> bytes:
    with urlopen(url, timeout=15) as response:
        body = response.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise ValueError("response exceeds bound")
        return body


async def check(site: str, mcp: str) -> None:
    latest = json.loads(fetch(site + "/api/cve-latest"))
    home = fetch(site + "/").decode()
    assert "<!--# include" not in home, "nginx did not process homepage SSI"
    async with Client(mcp + "/mcp") as client:
        result = await client.call_tool("recipes_cve_catalog_info", {})
        info = result.data
        assert isinstance(info, dict), "MCP catalog info is not structured data"
        projected = info["latest_projection"]
        for field in ("source_revision", "source_updated_at", "status", "records"):
            assert latest.get(field) == projected.get(field), f"website/MCP mismatch: {field}"
        assert latest["source_revision"] == info["manifest"]["shard_set_sha256"]
        revision = latest["source_revision"]
        browse = json.loads(fetch(site + "/api/cve-catalog/search?limit=50&revision=" + revision))
        unenhanced = None
        for row in browse["results"]:
            time.sleep(0.1)  # Stay below the existing exact-record rate limit.
            raw = json.loads(fetch(site + "/api/cve-catalog/records/" + row["cve"] + "?revision=" + revision))["record"]
            if not raw.get("ai_enrichment") and raw.get("recipe_kind") != "markdown-override":
                unenhanced = raw
                break
        assert unenhanced is not None, "no deterministic-only CVE available for parity proof"
        raw_detail = await client.call_tool("recipes_cve_get", {"cve": unenhanced["cve"]})
        assert raw_detail.data["found"] is True
        for field in ("cve", "published", "last_modified", "severity", "score"):
            assert raw_detail.data["source_record"][field] == unenhanced[field]
        assert raw_detail.data["recommended_recipe"]["kind"] != "markdown-override"
        assert not raw_detail.data["recommended_recipe"].get("ai_enrichment"), "raw facts were mislabeled AI guidance"
        # Trailing punctuation avoids the exact-ID fast path and exercises
        # indexed token search with a deterministic, unique source identifier.
        broad = await client.call_tool("recipes_cve_search", {"query": unenhanced["cve"] + ".", "limit": 50})
        assert any(row["cve"] == unenhanced["cve"] for row in broad.data["results"])
        assert unenhanced["cve"] in fetch(site + "/cve/" + unenhanced["cve"] + "/").decode()
        for row in latest["records"]:
            assert row["cve"] in home and row["published"] in home
            detail = await client.call_tool("recipes_cve_get", {"cve": row["cve"]})
            assert detail.data["found"] is True
        if not latest["records"]:
            assert "Fresh CVE updates are unavailable" in home
            assert "data-cve-ticker-link" not in home
        # This known reviewed historical record must survive current-view expiry.
        historic = await client.call_tool("recipes_cve_get", {"cve": "CVE-2024-3400"})
        assert historic.data["found"] is True
    print(json.dumps({"status": latest["status"], "revision": latest["source_revision"],
                      "website_mcp_parity": True, "historical_record_retained": True,
                      "unenhanced_cve": unenhanced["cve"]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", required=True)
    parser.add_argument("--mcp", required=True)
    args = parser.parse_args()
    asyncio.run(check(args.site.rstrip("/"), args.mcp.rstrip("/")))
