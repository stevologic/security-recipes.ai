"""Retrieve published site pages used to ground Recipe chat answers."""

from __future__ import annotations

import re
from typing import Any, Protocol
from urllib.parse import urljoin

from .config import MAX_SOURCE_CHARS, MAX_SOURCES, site_base_url

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

SYSTEM_INSTRUCTIONS = """You answer from published security-recipes.ai pages only.

You are Recipe chat on security-recipes.ai. Stay specific and human. Do not use slogans. Do not call yourself an AI security copilot.

This product is read-only. You are not a scanner, autofix, deployer, or exploit writer. Do not claim you can write files, open pull requests, scan hosts, or ship changes.

Ground every answer in the supplied site sources. Link the real recipe, CVE, playbook, or docs URL from those sources. If the question is not covered on this site, say so. Do not invent CVEs, CVSS scores, employers, patches, or fixed versions.

If a CVE the visitor named is marked missing from the catalog, say it is not on this site. Do not invent a record for it.

Keep answers short. Prefer the smallest published recipe or CVE page that matches."""


class RecipeSearcher(Protocol):
    async def search(self, query: str, limit: int | None = None) -> list[dict[str, Any]]:
        ...

    async def get_doc(self, slug_or_path: str) -> dict[str, Any] | None:
        ...


class CveLookup(Protocol):
    def get_recipe(self, cve: str) -> dict[str, Any]:
        ...


class PlaybookLookup(Protocol):
    def list_playbooks(self, query: str | None = None, limit: int = 8) -> dict[str, Any]:
        ...

    def get_playbook(self, playbook_id: str) -> dict[str, Any] | None:
        ...


def extract_cves(text: str) -> list[str]:
    seen: list[str] = []
    for match in CVE_RE.findall(text or ""):
        cve = match.upper()
        if cve not in seen:
            seen.append(cve)
    return seen


def absolute_url(path_or_url: str) -> str:
    raw = str(path_or_url or "").strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    base = site_base_url().rstrip("/") + "/"
    return urljoin(base, raw.lstrip("/"))


def clip(text: str, limit: int = MAX_SOURCE_CHARS) -> str:
    cleaned = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 1].rstrip() + "…"


def cve_page_url(cve: str) -> str:
    return absolute_url(f"/cve/{cve.upper()}/")


async def retrieve_sources(
    message: str,
    *,
    recipe_index: RecipeSearcher | None,
    cve_catalog: CveLookup | None,
    playbook_registry: PlaybookLookup | None,
    page_url: str = "",
) -> dict[str, Any]:
    sources: list[dict[str, str]] = []
    missing_cves: list[str] = []
    known_cves: list[str] = []

    for cve in extract_cves(message):
        record = None
        if cve_catalog is not None:
            try:
                record = cve_catalog.get_recipe(cve)
            except ValueError:
                record = None
        if isinstance(record, dict) and record.get("found") is True:
            source_record = record.get("source_record") if isinstance(record.get("source_record"), dict) else {}
            title = str(source_record.get("title") or cve)
            summary = str(source_record.get("summary") or "")
            sources.append(
                {
                    "kind": "cve",
                    "title": title,
                    "url": cve_page_url(cve),
                    "excerpt": clip(f"{cve}. {summary}"),
                }
            )
            known_cves.append(cve)
        else:
            missing_cves.append(cve)

    if recipe_index is not None:
        try:
            hits = await recipe_index.search(message, limit=MAX_SOURCES)
        except Exception:
            hits = []
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            slug = str(hit.get("slug") or hit.get("recipe_id") or hit.get("path") or "")
            doc = None
            if slug:
                try:
                    doc = await recipe_index.get_doc(slug)
                except Exception:
                    doc = None
            payload = doc if isinstance(doc, dict) else hit
            url = absolute_url(str(payload.get("url") or payload.get("path") or ""))
            if not url:
                continue
            if any(item["url"] == url for item in sources):
                continue
            excerpt = clip(str(payload.get("content") or payload.get("summary") or hit.get("summary") or ""))
            sources.append(
                {
                    "kind": "recipe",
                    "title": str(payload.get("title") or hit.get("title") or slug),
                    "url": url,
                    "excerpt": excerpt,
                }
            )
            if len(sources) >= MAX_SOURCES:
                break

    if playbook_registry is not None and len(sources) < MAX_SOURCES:
        try:
            listed = playbook_registry.list_playbooks(query=message, limit=3)
        except Exception:
            listed = {}
        results = listed.get("results") if isinstance(listed, dict) else None
        for preview in results or []:
            if not isinstance(preview, dict):
                continue
            playbook_id = str(preview.get("id") or "")
            profile = None
            if playbook_id:
                try:
                    profile = playbook_registry.get_playbook(playbook_id)
                except Exception:
                    profile = None
            payload = profile if isinstance(profile, dict) else preview
            page = str(payload.get("page") or "")
            url = absolute_url(page) if page else ""
            if not url or any(item["url"] == url for item in sources):
                continue
            sources.append(
                {
                    "kind": "playbook",
                    "title": str(payload.get("title") or playbook_id),
                    "url": url,
                    "excerpt": clip(str(payload.get("summary") or "")),
                }
            )
            if len(sources) >= MAX_SOURCES:
                break

    if page_url and len(sources) < MAX_SOURCES:
        current = absolute_url(page_url)
        if current and not any(item["url"] == current for item in sources):
            sources.append(
                {
                    "kind": "page",
                    "title": "Current page",
                    "url": current,
                    "excerpt": "Visitor is reading this published page.",
                }
            )

    return {
        "sources": sources[:MAX_SOURCES],
        "missing_cves": missing_cves,
        "known_cves": known_cves,
    }


def format_context(retrieval: dict[str, Any]) -> str:
    parts: list[str] = []
    missing = retrieval.get("missing_cves") or []
    if missing:
        parts.append(
            "Missing from this site's published catalog: " + ", ".join(missing) + "."
        )
    sources = retrieval.get("sources") or []
    if not sources:
        parts.append("No matching published pages were retrieved.")
        return "\n".join(parts)
    parts.append("Published sources:")
    for index, source in enumerate(sources, start=1):
        parts.append(
            f"{index}. {source.get('title')} ({source.get('url')})\n{source.get('excerpt')}"
        )
    return "\n\n".join(parts)


def invented_cves(text: str, retrieval: dict[str, Any]) -> list[str]:
    allowed = {cve.upper() for cve in (retrieval.get("known_cves") or [])}
    for source in retrieval.get("sources") or []:
        allowed.update(extract_cves(str(source.get("title") or "") + " " + str(source.get("excerpt") or "")))
        allowed.update(extract_cves(str(source.get("url") or "")))
    invented: list[str] = []
    for cve in extract_cves(text):
        if cve not in allowed and cve not in invented:
            invented.append(cve)
    return invented


def missing_named_cve_reply(cves: list[str]) -> str:
    if len(cves) == 1:
        return (
            f"{cves[0]} is not in the published catalog on this site. "
            "I will not invent a CVE record, CVSS score, or employer for it. "
            "Search the CVE database for an identifier that is on security-recipes.ai, "
            "or ask about a listed recipe or playbook."
        )
    joined = ", ".join(cves)
    return (
        f"{joined} are not in the published catalog on this site. "
        "I will not invent CVE records for them. Ask about a page that is actually published here."
    )
