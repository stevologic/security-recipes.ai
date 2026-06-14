"""Core planner for the security-recipes.ai remediation suite.

The suite is intentionally read-mostly. It normalizes findings, imports
site recipes, selects the matching remediation domain, and produces a
reviewable packet for an agent, reviewer, or enterprise orchestrator.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DOMAIN_REGISTRY = REPO_ROOT / "data" / "remediation_suite" / "domains.json"
DEFAULT_LOCAL_RECIPES = REPO_ROOT / "public" / "api" / "recipes.json"
DEFAULT_REMOTE_RECIPES = "https://security-recipes.ai/api/recipes.json"


@dataclasses.dataclass(frozen=True)
class Finding:
    """Normalized finding shape used by every domain tool."""

    finding_id: str
    title: str
    source: str
    severity: str
    asset: str
    location: str
    description: str
    raw: dict[str, Any]

    def searchable_text(self) -> str:
        parts = [
            self.finding_id,
            self.title,
            self.source,
            self.severity,
            self.asset,
            self.location,
            self.description,
            json.dumps(self.raw, sort_keys=True, default=str)[:6000],
        ]
        return " ".join(part for part in parts if part).lower()


def load_domain_registry(path: str | Path | None = None) -> dict[str, Any]:
    registry_path = Path(path) if path else DEFAULT_DOMAIN_REGISTRY
    with registry_path.open("r", encoding="utf-8") as handle:
        registry = json.load(handle)
    domains = registry.get("domains")
    if not isinstance(domains, list) or not domains:
        raise ValueError(f"domain registry has no domains: {registry_path}")
    return registry


def domain_by_key(registry: dict[str, Any], key: str | None) -> dict[str, Any]:
    domains = registry["domains"]
    if not key:
        raise ValueError("domain or tool command is required")
    wanted = key.strip().lower()
    for domain in domains:
        if wanted in {
            str(domain.get("id", "")).lower(),
            str(domain.get("command", "")).lower(),
            str(domain.get("title", "")).lower(),
        }:
            return domain
    available = ", ".join(sorted(str(item["id"]) for item in domains))
    raise ValueError(f"unknown remediation domain '{key}'. Available: {available}")


def load_finding(path: str | Path) -> list[Finding]:
    raw_text = sys.stdin.read() if str(path) == "-" else Path(path).read_text(encoding="utf-8")
    return load_finding_text(raw_text)


def load_finding_text(raw_text: str) -> list[Finding]:
    raw_text = str(raw_text or "").strip()
    if not raw_text:
        return [
            Finding(
                finding_id="manual-input",
                title="Manual remediation request",
                source="manual",
                severity="unknown",
                asset="",
                location="",
                description="",
                raw={},
            )
        ]

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError:
        return [
            Finding(
                finding_id=_extract_identifier(raw_text) or "free-text-finding",
                title=_first_line(raw_text),
                source="free-text",
                severity=_extract_severity(raw_text),
                asset="",
                location="",
                description=raw_text,
                raw={"text": raw_text},
            )
        ]

    return normalize_findings(payload)


def normalize_findings(payload: Any) -> list[Finding]:
    if isinstance(payload, dict) and isinstance(payload.get("runs"), list):
        findings = _normalize_sarif(payload)
        if findings:
            return findings

    if isinstance(payload, list):
        findings: list[Finding] = []
        for index, item in enumerate(payload):
            if isinstance(item, dict):
                findings.append(_normalize_generic_dict(item, str(index + 1)))
        return findings or [_normalize_generic_dict({"items": payload}, "1")]

    if isinstance(payload, dict):
        candidates = payload.get("findings") or payload.get("alerts") or payload.get("results")
        if isinstance(candidates, list):
            findings = []
            for index, item in enumerate(candidates):
                if isinstance(item, dict):
                    findings.append(_normalize_generic_dict(item, str(index + 1)))
            if findings:
                return findings
        return [_normalize_generic_dict(payload, "1")]

    return [_normalize_generic_dict({"value": payload}, "1")]


def _normalize_sarif(payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for run in payload.get("runs", []):
        tool = run.get("tool", {}) if isinstance(run, dict) else {}
        driver = tool.get("driver", {}) if isinstance(tool, dict) else {}
        rules = {
            str(rule.get("id")): rule
            for rule in driver.get("rules", [])
            if isinstance(rule, dict) and rule.get("id")
        }
        source = str(driver.get("name") or "sarif")
        for index, result in enumerate(run.get("results", []) if isinstance(run, dict) else []):
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or result.get("rule_id") or f"sarif-result-{index + 1}")
            rule = rules.get(rule_id, {})
            message = result.get("message", {})
            title = _message_text(message) or str(rule.get("shortDescription", {}).get("text") or rule_id)
            locations = result.get("locations") or []
            location = _sarif_location(locations[0]) if locations else ""
            severity = _extract_sarif_severity(result, rule)
            findings.append(
                Finding(
                    finding_id=rule_id,
                    title=title,
                    source=source,
                    severity=severity,
                    asset="",
                    location=location,
                    description=_message_text(message) or json.dumps(result)[:1200],
                    raw=result,
                )
            )
    return findings


def _normalize_generic_dict(item: dict[str, Any], fallback_id: str) -> Finding:
    finding_id = str(
        item.get("id")
        or item.get("finding_id")
        or item.get("alert_id")
        or item.get("ruleId")
        or item.get("rule_id")
        or item.get("cve")
        or item.get("ghsa")
        or item.get("CVE")
        or _extract_identifier(json.dumps(item, default=str))
        or f"finding-{fallback_id}"
    )
    title = str(
        item.get("title")
        or item.get("name")
        or item.get("summary")
        or item.get("package")
        or item.get("rule")
        or finding_id
    )
    source = str(
        item.get("source")
        or item.get("tool")
        or item.get("scanner")
        or item.get("source_system")
        or item.get("provider")
        or "generic-json"
    )
    severity = str(item.get("severity") or item.get("level") or item.get("risk") or "unknown")
    asset = str(
        item.get("asset")
        or item.get("package")
        or item.get("dependency")
        or item.get("image")
        or item.get("file")
        or item.get("path")
        or ""
    )
    location = str(item.get("location") or item.get("file_path") or item.get("path") or item.get("uri") or "")
    description = str(
        item.get("description")
        or item.get("details")
        or item.get("message")
        or item.get("body")
        or item.get("text")
        or title
    )
    return Finding(finding_id, title, source, severity, asset, location, description, item)


def import_recipes(source: str | Path | None = None, timeout: int = 15) -> list[dict[str, Any]]:
    selected = str(source) if source else str(DEFAULT_LOCAL_RECIPES if DEFAULT_LOCAL_RECIPES.exists() else DEFAULT_REMOTE_RECIPES)
    if selected.startswith(("http://", "https://")):
        request = urllib.request.Request(selected, headers={"User-Agent": "security-recipes-remediation-suite/2026.06"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    else:
        with Path(selected).open("r", encoding="utf-8") as handle:
            payload = json.load(handle)

    if isinstance(payload, dict) and isinstance(payload.get("recipes"), list):
        return [item for item in payload["recipes"] if isinstance(item, dict)]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    raise ValueError(f"recipe source did not contain a recipe list: {selected}")


def build_remediation_packet(
    *,
    domain_key: str,
    findings: list[Finding],
    registry: dict[str, Any],
    recipe_source: str | Path | None = None,
    tooling: list[str] | None = None,
    ecosystem: str | None = None,
    llm_config: dict[str, Any] | None = None,
    llm_mode: str = "off",
    max_recipes: int = 6,
) -> dict[str, Any]:
    domain = domain_by_key(registry, domain_key)
    recipes = import_recipes(recipe_source)
    selected_findings = findings or []
    primary = selected_findings[0] if selected_findings else _empty_finding()
    domain_scores = score_domains(registry, primary)
    recipe_matches = match_recipes(recipes, domain, primary, limit=max_recipes)
    prompt = build_agent_prompt(domain, primary, recipe_matches, ecosystem)
    compatible_tooling = select_enterprise_tooling(domain, tooling or [])
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    packet: dict[str, Any] = {
        "kind": "security-recipes.remediation-packet",
        "generated_at": now,
        "suite": registry.get("suite", {}),
        "domain": _domain_summary(domain),
        "classification": {
            "requested_domain": domain_key,
            "top_domain_scores": domain_scores[:5],
            "selected_domain_score": next(
                (item["score"] for item in domain_scores if item["id"] == domain.get("id")),
                0,
            ),
        },
        "finding_count": len(selected_findings),
        "findings": [_finding_summary(item) for item in selected_findings[:10]],
        "recipe_import": {
            "source": str(recipe_source or (DEFAULT_LOCAL_RECIPES if DEFAULT_LOCAL_RECIPES.exists() else DEFAULT_REMOTE_RECIPES)),
            "recipe_count": len(recipes),
            "matched_count": len(recipe_matches),
            "matches": recipe_matches,
        },
        "enterprise_tooling": compatible_tooling,
        "workflow": {
            "purpose": domain.get("purpose"),
            "inputs": domain.get("inputs", []),
            "allowed_actions": domain.get("allowed_actions", []),
            "stop_conditions": domain.get("stop_conditions", []),
            "evidence_required": domain.get("evidence", []),
            "expected_outputs": domain.get("outputs", []),
            "ecosystem": ecosystem or "auto-detect",
        },
        "agent_handoff": {
            "prompt": prompt,
            "guardrail_summary": summarize_guardrails(domain),
        },
        "llm_assist": build_llm_assist(domain, primary, prompt, llm_config or {}, llm_mode),
    }
    return packet


def score_domains(registry: dict[str, Any], finding: Finding) -> list[dict[str, Any]]:
    text = finding.searchable_text()
    scored = []
    for domain in registry["domains"]:
        score = 0
        reasons = []
        for token in [domain.get("id", ""), domain.get("command", ""), domain.get("title", "")]:
            for word in _interesting_words(str(token)):
                if word in text:
                    score += 2
                    reasons.append(f"matched domain word '{word}'")
        for signal in domain.get("signals", []):
            signal_text = str(signal).lower()
            if signal_text and signal_text in text:
                score += 3
                reasons.append(f"matched signal '{signal_text}'")
        for query in domain.get("recipe_queries", []):
            query_text = str(query).lower()
            if query_text and query_text in text:
                score += 2
                reasons.append(f"matched recipe query '{query_text}'")
        scored.append(
            {
                "id": domain.get("id"),
                "title": domain.get("title"),
                "command": domain.get("command"),
                "score": score,
                "reasons": reasons[:6],
            }
        )
    return sorted(scored, key=lambda item: (-int(item["score"]), str(item["id"])))


def match_recipes(
    recipes: list[dict[str, Any]],
    domain: dict[str, Any],
    finding: Finding,
    *,
    limit: int,
) -> list[dict[str, Any]]:
    finding_words = set(_interesting_words(finding.searchable_text()))
    query_words = set()
    for query in domain.get("recipe_queries", []):
        query_words.update(_interesting_words(str(query)))
    domain_words = set(_interesting_words(str(domain.get("title", "")) + " " + str(domain.get("id", ""))))
    wanted = query_words | domain_words | set(list(finding_words)[:40])
    scored: list[dict[str, Any]] = []
    for recipe in recipes:
        haystack = " ".join(
            str(recipe.get(key, ""))
            for key in ("title", "summary", "content_text", "ecosystem", "severity", "agent", "slug")
        )
        tags = recipe.get("tags") or []
        if isinstance(tags, list):
            haystack += " " + " ".join(str(tag) for tag in tags)
        lower = haystack.lower()
        score = 0
        hits = []
        for word in wanted:
            if len(word) >= 3 and word in lower:
                score += 1
                if len(hits) < 8:
                    hits.append(word)
        if recipe.get("zero_day"):
            score += 1
        if score:
            scored.append(
                {
                    "title": recipe.get("title") or recipe.get("link_title"),
                    "url": recipe.get("url") or recipe.get("path"),
                    "path": recipe.get("path"),
                    "severity": recipe.get("severity"),
                    "ecosystem": recipe.get("ecosystem"),
                    "agent": recipe.get("agent"),
                    "score": score,
                    "why": hits,
                }
            )
    return sorted(scored, key=lambda item: (-int(item["score"]), str(item.get("title"))))[:limit]


def select_enterprise_tooling(domain: dict[str, Any], requested: list[str]) -> dict[str, Any]:
    requested_norm = [item.strip().lower() for item in requested if item.strip()]
    categories = domain.get("enterprise_tools", {})
    shaped = []
    for category, tools in categories.items():
        category_tools = []
        for tool in tools:
            tool_name = str(tool)
            matched = bool(requested_norm) and any(
                req in tool_name.lower() or req in str(category).lower() for req in requested_norm
            )
            category_tools.append({"name": tool_name, "requested_match": matched})
        shaped.append({"category": category, "tools": category_tools})
    return {
        "requested": requested,
        "compatible_categories": shaped,
        "note": "requested_match flags are advisory; connector credentials and write access stay outside this planner.",
    }


def build_agent_prompt(
    domain: dict[str, Any],
    finding: Finding,
    recipe_matches: list[dict[str, Any]],
    ecosystem: str | None,
) -> str:
    recipe_lines = "\n".join(
        f"- {item.get('title')} ({item.get('url') or item.get('path')})"
        for item in recipe_matches[:5]
    ) or "- No imported recipe match; use the domain page and write triage if evidence is weak."
    allowed = "\n".join(f"- {item}" for item in domain.get("allowed_actions", []))
    stops = "\n".join(f"- {item}" for item in domain.get("stop_conditions", []))
    evidence = "\n".join(f"- {item}" for item in domain.get("evidence", []))
    return "\n".join(
        [
            f"You are running the security-recipes.ai {domain.get('title')} tool.",
            "",
            "Scope:",
            f"- Domain: {domain.get('id')}",
            f"- Ecosystem: {ecosystem or 'auto-detect'}",
            f"- Finding id: {finding.finding_id}",
            f"- Finding title: {finding.title}",
            f"- Source: {finding.source}",
            f"- Severity: {finding.severity}",
            f"- Asset: {finding.asset or 'unknown'}",
            f"- Location: {finding.location or 'unknown'}",
            "",
            "Imported recipes to prefer:",
            recipe_lines,
            "",
            "Allowed actions:",
            allowed,
            "",
            "Stop conditions:",
            stops,
            "",
            "Evidence required before a PR or handoff:",
            evidence,
            "",
            "Produce exactly one output: a bounded remediation plan, a reviewer-ready",
            "PR handoff, or a TRIAGE.md note explaining why the tool stopped.",
            "Do not broaden scope, auto-merge, bypass CI, transmit secrets, or mutate",
            "enterprise systems outside the explicit remediation plan.",
        ]
    )


def summarize_guardrails(domain: dict[str, Any]) -> str:
    stops = domain.get("stop_conditions", [])
    if not stops:
        return "Stop on missing evidence, broad scope, or human-owned production actions."
    return "Stop when: " + "; ".join(str(item) for item in stops[:4])


def build_llm_assist(
    domain: dict[str, Any],
    finding: Finding,
    prompt: str,
    config: dict[str, Any],
    mode: str,
) -> dict[str, Any]:
    mode = (mode or "off").lower()
    shaped: dict[str, Any] = {
        "mode": mode,
        "domain_guidance": domain.get("llm_assist"),
        "prompt": prompt,
        "called": False,
    }
    if mode in {"off", "prompt"}:
        return shaped
    if mode != "call":
        shaped["error"] = f"unsupported llm mode '{mode}'"
        return shaped

    endpoint = str(config.get("endpoint") or "").strip()
    model = str(config.get("model") or "").strip()
    api_key_env = str(config.get("api_key_env") or "OPENAI_API_KEY").strip()
    api_key = os.environ.get(api_key_env, "")
    if not endpoint or not model or not api_key:
        shaped["error"] = "llm call requested but endpoint, model, or api key env is missing"
        shaped["required_config"] = {"endpoint": endpoint, "model": model, "api_key_env": api_key_env}
        return shaped

    body = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You help draft bounded security remediation plans from deterministic evidence. You do not approve merges or broaden scope.",
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": float(config.get("temperature", 0.2)),
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "security-recipes-remediation-suite/2026.06",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=int(config.get("timeout", 30))) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:  # pragma: no cover - external services vary
        shaped["error"] = f"llm call failed: {exc}"
        return shaped

    shaped["called"] = True
    shaped["response"] = payload
    return shaped


def load_llm_config(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {}
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_packet(packet: dict[str, Any], output_path: str | Path | None) -> None:
    text = json.dumps(packet, indent=2, sort_keys=True)
    if not output_path or str(output_path) == "-":
        print(text)
        return
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")


def _finding_summary(finding: Finding) -> dict[str, Any]:
    return dataclasses.asdict(finding) | {"raw": finding.raw}


def _domain_summary(domain: dict[str, Any]) -> dict[str, Any]:
    keys = ["id", "title", "command", "page", "purpose"]
    return {key: domain.get(key) for key in keys}


def _empty_finding() -> Finding:
    return Finding("manual-input", "Manual remediation request", "manual", "unknown", "", "", "", {})


def _message_text(message: Any) -> str:
    if isinstance(message, dict):
        return str(message.get("text") or message.get("markdown") or "")
    return str(message or "")


def _sarif_location(location: dict[str, Any]) -> str:
    physical = location.get("physicalLocation", {}) if isinstance(location, dict) else {}
    artifact = physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
    region = physical.get("region", {}) if isinstance(physical, dict) else {}
    uri = artifact.get("uri") or ""
    line = region.get("startLine")
    return f"{uri}:{line}" if uri and line else str(uri)


def _extract_sarif_severity(result: dict[str, Any], rule: dict[str, Any]) -> str:
    for source in (result, rule, rule.get("properties", {}) if isinstance(rule, dict) else {}):
        if isinstance(source, dict):
            for key in ("level", "severity", "security-severity", "problem.severity"):
                if source.get(key):
                    return str(source[key])
    return "unknown"


def _extract_identifier(text: str) -> str | None:
    match = re.search(r"\b(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})\b", text, re.I)
    return match.group(1).upper() if match else None


def _extract_severity(text: str) -> str:
    match = re.search(r"\b(critical|high|medium|moderate|low|info|informational)\b", text, re.I)
    return match.group(1).lower() if match else "unknown"


def _first_line(text: str) -> str:
    return next((line.strip() for line in text.splitlines() if line.strip()), "Free-text finding")[:160]


def _interesting_words(text: str) -> list[str]:
    words = [word.strip("._-") for word in re.findall(r"[a-z0-9][a-z0-9_.-]{2,}", text.lower())]
    stop = {
        "and",
        "the",
        "for",
        "with",
        "that",
        "this",
        "from",
        "into",
        "security",
        "remediation",
        "tool",
        "tools",
    }
    return [word for word in words if word and word not in stop]
