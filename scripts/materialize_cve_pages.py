#!/usr/bin/env python3
"""Materialize evidence-qualified canonical CVE pages with the runtime renderer.

Eleventy owns the surrounding static site and sitemap generation. This build
step intentionally imports the production MCP landing-page lookup and renderer
instead of maintaining a second HTML implementation. The generated documents
therefore have the same metadata, structured data, and content contract as the
runtime fallback used for catalog records that are not search-indexable.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_ROOT = ROOT / "public"
DEFAULT_CATALOG_ROOT = ROOT / "static" / "api" / "cve-catalog"
DEFAULT_PUBLIC_BASE_URL = "https://security-recipes.ai/"
CANONICAL_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
CVE_LIKE_OUTPUT_DIRECTORY = re.compile(
    r"CVE-[0-9]{4}-[0-9]{4,}",
    re.IGNORECASE,
)

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import mcp_server  # noqa: E402  (repository root must be importable first)


BUILD_CVE_CATALOG = mcp_server.CVERecipeCatalog(str(DEFAULT_CATALOG_ROOT))
BUILD_PLAYBOOK_REGISTRY = mcp_server.PlaybookRegistry(
    str(ROOT / "data" / "remediation_suite" / "playbooks.json")
)


@contextmanager
def build_renderer_context():
    """Point the runtime lookup at this exact source revision for one build."""

    previous_catalog = mcp_server.cve_catalog
    previous_playbooks = mcp_server.playbook_registry
    mcp_server.cve_catalog = BUILD_CVE_CATALOG
    mcp_server.playbook_registry = BUILD_PLAYBOOK_REGISTRY
    try:
        yield
    finally:
        mcp_server.cve_catalog = previous_catalog
        mcp_server.playbook_registry = previous_playbooks


class LandingPageContractParser(HTMLParser):
    """Collect only the fields needed to enforce the canonical SEO contract."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.canonicals: list[str] = []
        self.robots: list[str] = []
        self.h1_count = 0
        self.element_ids: set[str] = set()
        self.element_id_counts: dict[str, int] = {}
        self.time_datetimes: set[str] = set()
        self.structured_data: list[str] = []
        self._json_ld_buffer: list[str] | None = None

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attributes = {name.lower(): value or "" for name, value in attrs}
        lower_tag = tag.lower()
        if attributes.get("id"):
            self.element_ids.add(attributes["id"])
            self.element_id_counts[attributes["id"]] = (
                self.element_id_counts.get(attributes["id"], 0) + 1
            )
        if lower_tag == "time" and attributes.get("datetime"):
            self.time_datetimes.add(attributes["datetime"])
        if lower_tag == "link" and attributes.get("rel", "").lower() == "canonical":
            self.canonicals.append(attributes.get("href", ""))
        elif lower_tag == "meta" and attributes.get("name", "").lower() == "robots":
            self.robots.append(attributes.get("content", ""))
        elif lower_tag == "h1":
            self.h1_count += 1
        elif (
            lower_tag == "script"
            and attributes.get("type", "").lower() == "application/ld+json"
        ):
            self._json_ld_buffer = []

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._json_ld_buffer is not None:
            self.structured_data.append("".join(self._json_ld_buffer))
            self._json_ld_buffer = None

    def handle_data(self, data: str) -> None:
        if self._json_ld_buffer is not None:
            self._json_ld_buffer.append(data)


def _walk_json(value: Any):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json(child)


def validate_landing_page_contract(
    document: str,
    *,
    cve_id: str,
    canonical_url: str,
    require_remediation_summary: bool = False,
) -> None:
    """Fail closed when a materialized page drifts from the runtime SEO contract."""

    parser = LandingPageContractParser()
    parser.feed(document)
    parser.close()

    if parser.canonicals != [canonical_url]:
        raise ValueError(
            f"{cve_id} canonical mismatch: expected {canonical_url!r}, "
            f"found {parser.canonicals!r}"
        )
    if len(parser.robots) != 1:
        raise ValueError(f"{cve_id} must have exactly one robots directive")
    robots_tokens = {
        token.strip().lower()
        for token in parser.robots[0].split(",")
        if token.strip()
    }
    if "index" not in robots_tokens or "follow" not in robots_tokens:
        raise ValueError(f"{cve_id} materialized page must be index,follow")
    if "noindex" in robots_tokens or "nofollow" in robots_tokens:
        raise ValueError(f"{cve_id} materialized page cannot be noindex or nofollow")
    if parser.h1_count != 1:
        raise ValueError(f"{cve_id} must have exactly one H1, found {parser.h1_count}")
    if require_remediation_summary:
        required_ids = {
            "overview-heading",
            "products-heading",
            "remediation-authority-heading",
            "use-ai-heading",
            "sources-heading",
            "cite-record-heading",
        }
        missing_ids = sorted(required_ids - parser.element_ids)
        if missing_ids:
            raise ValueError(
                f"{cve_id} is missing required flat CVE sections: {missing_ids}"
            )
        if parser.element_id_counts.get("remediation-authority-heading") != 1:
            raise ValueError(f"{cve_id} must expose exactly one remediation authority")
        if (
            re.search(r"<details\b", document, flags=re.IGNORECASE)
            or "data-cve-record-loader" in document
            or 'id="complete-record"' in document
        ):
            raise ValueError(f"{cve_id} contains nested or deferred record UI")

    structured_objects: list[Any] = []
    for source in parser.structured_data:
        try:
            structured_objects.extend(_walk_json(json.loads(source)))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{cve_id} contains invalid JSON-LD") from exc
    article = next(
        (
            value
            for value in structured_objects
            if isinstance(value, dict)
            and value.get("@type") == "Article"
            and value.get("additionalType") == "https://schema.org/TechArticle"
        ),
        None,
    )
    if article is None:
        raise ValueError(f"{cve_id} must expose Article + TechArticle JSON-LD")
    main_entity = article.get("mainEntityOfPage")
    main_entity_url = (
        main_entity.get("@id") if isinstance(main_entity, dict) else main_entity
    )
    if (
        article.get("url") != canonical_url
        or not isinstance(main_entity_url, str)
        or not main_entity_url.startswith(canonical_url)
    ):
        raise ValueError(f"{cve_id} structured-data canonical URL does not match")
    date_modified = article.get("dateModified")
    if require_remediation_summary and (
        not isinstance(date_modified, str) or not date_modified
    ):
        raise ValueError(f"{cve_id} Article dateModified is required")
    if isinstance(date_modified, str) and date_modified:
        if date_modified not in parser.time_datetimes:
            raise ValueError(
                f"{cve_id} Article dateModified is not visible in a matching time element"
            )


def load_search_indexable_cve_ids() -> tuple[str, ...]:
    """Load the manifest-verified, evidence-qualified CVE identity set."""

    search_index_path = DEFAULT_CATALOG_ROOT / "search-indexable.json"
    payload = json.loads(search_index_path.read_text(encoding="utf-8"))
    records = payload.get("records")
    if not isinstance(records, list):
        raise ValueError("CVE search-indexable payload has no records array")
    cve_ids = tuple(str(record.get("cve") or "") for record in records)
    if (
        any(CANONICAL_CVE_ID.fullmatch(cve_id) is None for cve_id in cve_ids)
        or any(
            index > 0 and cve_ids[index - 1] >= cve_id
            for index, cve_id in enumerate(cve_ids)
        )
    ):
        raise ValueError("CVE search-indexable identities are invalid or unsorted")

    # This call validates the search allowlist's manifest metadata, byte count,
    # SHA-256 digest, record schema, and complete sorted identity set. Repeating
    # it is cheap after the first call because the runtime catalog caches the
    # verified set for the current catalog signature.
    if any(not BUILD_CVE_CATALOG.is_search_indexable(cve_id) for cve_id in cve_ids):
        raise ValueError("CVE search-indexable payload disagrees with the runtime catalog")
    return cve_ids


def materialized_cve_ids(search_indexable_ids: tuple[str, ...]) -> tuple[str, ...]:
    """Return allowlisted IDs whose canonical owner is the /cve/ namespace."""

    historical = mcp_server._CVE_STATIC_CANONICAL_ROUTES
    return tuple(cve_id for cve_id in search_indexable_ids if cve_id not in historical)


def _canonical_base_url(value: str) -> str:
    return f"{mcp_server._cve_landing_public_base_url(value)}/"


def materialize_cve_pages(
    output_root: Path,
    *,
    public_base_url: str,
) -> tuple[str, ...]:
    """Render all qualified /cve/ canonical owners into the static output."""

    output_root = output_root.resolve()
    search_indexable_ids = load_search_indexable_cve_ids()
    cve_ids = materialized_cve_ids(search_indexable_ids)
    base_url = _canonical_base_url(public_base_url).rstrip("/")

    with build_renderer_context():
        for cve_id in cve_ids:
            recipe = mcp_server._bounded_cve_landing_lookup(cve_id)
            if not isinstance(recipe, dict) or recipe.get("found") is not True:
                raise ValueError(f"qualified CVE {cve_id} is missing from the runtime catalog")
            source_record = recipe.get("source_record")
            if (
                not isinstance(source_record, dict)
                or str(source_record.get("cve") or "").upper() != cve_id
                or not mcp_server._cve_landing_is_search_indexable(source_record)
            ):
                raise ValueError(
                    f"qualified CVE {cve_id} failed the runtime indexability contract"
                )

            document = mcp_server._render_cve_landing_page(
                recipe,
                public_base_url=public_base_url,
            )
            canonical_url = f"{base_url}/cve/{cve_id}/"
            validate_landing_page_contract(
                document,
                cve_id=cve_id,
                canonical_url=canonical_url,
                require_remediation_summary=True,
            )
            destination = output_root / "cve" / cve_id / "index.html"
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(document.encode("utf-8"))

    return cve_ids


def _sitemap_locations(path: Path) -> list[str]:
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        raise ValueError(f"cannot parse generated sitemap {path}") from exc
    return [
        str(element.text or "").strip()
        for element in root.findall(".//{*}loc")
        if str(element.text or "").strip()
    ]


def _route_output_path(output_root: Path, route: str) -> Path:
    if not route.startswith("/") or not route.endswith("/") or ".." in route.split("/"):
        raise ValueError(f"unsafe canonical route: {route!r}")
    return output_root.joinpath(*[part for part in route.split("/") if part], "index.html")


def verify_materialized_build(
    output_root: Path,
    *,
    public_base_url: str,
    search_indexable_ids: tuple[str, ...],
) -> None:
    """Prove sitemap parity and reject static output for nonqualified CVEs."""

    output_root = output_root.resolve()
    expected_dynamic = set(materialized_cve_ids(search_indexable_ids))
    base_url = _canonical_base_url(public_base_url).rstrip("/")

    cve_sitemaps = sorted((output_root / "sitemaps").glob("cves-*.xml"))
    if expected_dynamic and not cve_sitemaps:
        raise ValueError("generated build has no CVE sitemaps")
    sitemap_ids: list[str] = []
    for sitemap in cve_sitemaps:
        for location in _sitemap_locations(sitemap):
            parsed = urlparse(location)
            match = re.search(r"/cve/(CVE-[0-9]{4}-[0-9]{4,})/$", parsed.path)
            if match is None or parsed.query or parsed.fragment:
                raise ValueError(f"invalid canonical CVE sitemap URL: {location!r}")
            sitemap_ids.append(match.group(1))
    if len(sitemap_ids) != len(set(sitemap_ids)):
        raise ValueError("generated CVE sitemaps contain a duplicate canonical URL")
    if set(sitemap_ids) != expected_dynamic:
        raise ValueError("generated CVE sitemap identities do not match materialized pages")

    cve_root = output_root / "cve"
    # Treat every case-insensitive CVE-shaped directory as owned output. A
    # stale lowercase/mixed-case path must fail the build instead of becoming a
    # second filesystem representation on case-sensitive production hosts.
    actual_dynamic = (
        {
            child.name
            for child in cve_root.iterdir()
            if child.is_dir() and CVE_LIKE_OUTPUT_DIRECTORY.fullmatch(child.name)
        }
        if cve_root.is_dir()
        else set()
    )
    if actual_dynamic != expected_dynamic:
        extra = sorted(actual_dynamic - expected_dynamic)
        missing = sorted(expected_dynamic - actual_dynamic)
        raise ValueError(
            f"materialized CVE identity mismatch (extra={extra}, missing={missing})"
        )

    for cve_id in sorted(expected_dynamic):
        document_path = cve_root / cve_id / "index.html"
        if not document_path.is_file():
            raise ValueError(f"CVE sitemap URL has no physical document: {cve_id}")
        validate_landing_page_contract(
            document_path.read_text(encoding="utf-8"),
            cve_id=cve_id,
            canonical_url=f"{base_url}/cve/{cve_id}/",
            require_remediation_summary=True,
        )

    pages_sitemap = output_root / "sitemaps" / "pages.xml"
    page_locations = set(_sitemap_locations(pages_sitemap))
    historical_ids = set(search_indexable_ids) & set(
        mcp_server._CVE_STATIC_CANONICAL_ROUTES
    )
    for cve_id in sorted(historical_ids):
        route = mcp_server._CVE_STATIC_CANONICAL_ROUTES[cve_id]
        canonical_url = f"{base_url}{route}"
        if canonical_url not in page_locations:
            raise ValueError(f"historical canonical {cve_id} is absent from pages sitemap")
        document_path = _route_output_path(output_root, route)
        if not document_path.is_file():
            raise ValueError(f"historical canonical {cve_id} has no physical document")
        validate_landing_page_contract(
            document_path.read_text(encoding="utf-8"),
            cve_id=cve_id,
            canonical_url=canonical_url,
        )

    if expected_dynamic | historical_ids != set(search_indexable_ids):
        raise ValueError("not every evidence-qualified CVE has one physical canonical document")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_ROOT,
        help="Eleventy output directory (default: public)",
    )
    parser.add_argument(
        "--base-url",
        default=(
            os.environ.get("SECURITY_RECIPES_BASE_URL")
            or os.environ.get("BASE_URL")
            or DEFAULT_PUBLIC_BASE_URL
        ),
        help="Canonical public site base URL",
    )
    args = parser.parse_args()

    rendered = materialize_cve_pages(
        args.output,
        public_base_url=args.base_url,
    )
    qualified = load_search_indexable_cve_ids()
    verify_materialized_build(
        args.output,
        public_base_url=args.base_url,
        search_indexable_ids=qualified,
    )
    print(
        f"Materialized {len(rendered)} canonical CVE pages from "
        f"{len(qualified)} evidence-qualified records."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
