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
REDACTION_MARKER = "[REDACTED]"

_SENSITIVE_KEY_NAMES = frozenset(
    {
        "api_key",
        "api_token",
        "apikey",
        "access_key",
        "access_key_id",
        "account_key",
        "authorization",
        "aws_access_key_id",
        "aws_secret_access_key",
        "bearer_token",
        "client_secret",
        "connection_string",
        "cookie",
        "credential",
        "credential_json",
        "credentials",
        "credentials_json",
        "database_url",
        "database_dsn",
        "db_pass",
        "dsn",
        "encryption_key",
        "id_token",
        "master_key",
        "password",
        "passwd",
        "passphrase",
        "private_key",
        "private_key_data",
        "proxy_authorization",
        "pwd",
        "refresh_token",
        "secret",
        "secret_access_key",
        "secret_key",
        "secret_value",
        "service_account_key",
        "service_account_json",
        "session",
        "session_cookie",
        "session_id",
        "set_cookie",
        "signing_key",
        "signing_secret",
        "ssh_key",
        "token",
        "webhook_secret",
    }
)
_SENSITIVE_KEY_SUFFIXES = (
    "_access_token",
    "_account_key",
    "_api_key",
    "_api_token",
    "_auth_token",
    "_client_secret",
    "_credential",
    "_credential_json",
    "_credentials",
    "_credentials_json",
    "_password",
    "_passphrase",
    "_passwd",
    "_pwd",
    "_private_key",
    "_refresh_token",
    "_secret",
    "_secret_access_key",
    "_access_key",
    "_access_key_id",
    "_encryption_key",
    "_dsn",
    "_master_key",
    "_private_key_data",
    "_secret_value",
    "_service_account_key",
    "_service_account_json",
    "_session_token",
    "_signing_key",
    "_ssh_key",
    "_token",
)
_SENSITIVE_COMPACT_KEY_NAMES = frozenset(
    {
        "dbpass",
        "pgpass",
    }
)
_SENSITIVE_COMPACT_KEY_SUFFIXES = (
    "accesskey",
    "accesskeyid",
    "accesstoken",
    "accountkey",
    "apikey",
    "apitoken",
    "authorization",
    "authtoken",
    "bearertoken",
    "clientsecret",
    "connectionstring",
    "credentialjson",
    "credentials",
    "credentialsjson",
    "databasedsn",
    "databaseurl",
    "encryptionkey",
    "masterkey",
    "passphrase",
    "passwd",
    "password",
    "privatekey",
    "privatekeydata",
    "proxyauthorization",
    "pwd",
    "refreshtoken",
    "secret",
    "secretaccesskey",
    "secretvalue",
    "serviceaccountjson",
    "serviceaccountkey",
    "sessioncookie",
    "sessiontoken",
    "signingkey",
    "signingsecret",
    "sshkey",
    "token",
    "webhooksecret",
)
_SENSITIVE_STRONG_KEY_TOKENS = frozenset(
    {
        "bearer",
        "credential",
        "credentials",
        "passphrase",
        "passwd",
        "password",
        "pwd",
        "secret",
    }
)
_SENSITIVE_KEY_TOKEN_PAIRS = (
    frozenset({"access", "key"}),
    frozenset({"account", "key"}),
    frozenset({"api", "key"}),
    frozenset({"basic", "auth"}),
    frozenset({"encryption", "key"}),
    frozenset({"master", "key"}),
    frozenset({"private", "key"}),
)
_BENIGN_METADATA_KEY_SUFFIXES = (
    "_algorithm",
    "_count",
    "_detected",
    "_enabled",
    "_method",
    "_type",
)
_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----.*?"
    r"-----END(?: [A-Z0-9]+)* PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_SENSITIVE_HEADER_RE = re.compile(
    r"(\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*)[^\r\n]+",
    re.IGNORECASE,
)
_CREDENTIAL_URL_RE = re.compile(
    r"\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)([^@\s/]+)(@)",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"(\bbearer\s+)([A-Za-z0-9._~+/=-]{6,})", re.IGNORECASE)
_LINE_BREAK_RE = re.compile(r"[\r\n]")
_ASSIGNMENT_PREFIX_RE = re.compile(
    r"""(?<![A-Za-z0-9_.-])(?P<key>
        \\+"[^"\r\n]{1,128}\\+" |
        \\+'[^'\r\n]{1,128}\\+' |
        "(?:\\.|[^"\\]){1,128}" |
        '(?:\\.|[^'\\]){1,128}' |
        [A-Za-z][A-Za-z0-9_.-]{0,127}
    )(?P<separator>\s*[:=]\s*)""",
    re.VERBOSE,
)
_KNOWN_SECRET_RE = re.compile(
    r"\b(?:"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|"
    r"sk-[A-Za-z0-9_-]{16,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_-]{35}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r")\b"
)


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


def redact_sensitive_data(value: Any) -> Any:
    """Return a JSON-compatible copy with credential material removed.

    Findings often originate in scanner exports that contain request headers,
    environment variables, or full connection strings. Remediation packets are
    designed for cross-system handoff, so they must never carry those values.
    """

    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            if _is_sensitive_key(key) and item is not None and not isinstance(item, bool):
                redacted[key] = REDACTION_MARKER
            else:
                redacted[key] = redact_sensitive_data(item)
        return redacted
    if isinstance(value, (list, tuple, set)):
        return [redact_sensitive_data(item) for item in value]
    if isinstance(value, bytes):
        return REDACTION_MARKER
    if isinstance(value, str):
        return _redact_sensitive_text(value)
    return value


def _is_sensitive_key(key: Any) -> bool:
    raw_key = str(key).strip()
    snake_key = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", raw_key)
    snake_key = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", snake_key)
    normalized = re.sub(r"[^a-z0-9]+", "_", snake_key.lower()).strip("_")
    if not normalized:
        return False
    compact = normalized.replace("_", "")
    if (
        normalized in _SENSITIVE_KEY_NAMES
        or normalized.endswith(_SENSITIVE_KEY_SUFFIXES)
        or compact in _SENSITIVE_COMPACT_KEY_NAMES
        or compact.endswith(_SENSITIVE_COMPACT_KEY_SUFFIXES)
    ):
        return True
    if normalized.endswith(_BENIGN_METADATA_KEY_SUFFIXES):
        return False
    tokens = frozenset(normalized.split("_"))
    return bool(tokens & _SENSITIVE_STRONG_KEY_TOKENS) or any(
        pair.issubset(tokens) for pair in _SENSITIVE_KEY_TOKEN_PAIRS
    )


def _redact_sensitive_text(value: str) -> str:
    redacted = _PEM_PRIVATE_KEY_RE.sub(REDACTION_MARKER, value)
    redacted = _SENSITIVE_HEADER_RE.sub(rf"\1{REDACTION_MARKER}", redacted)
    redacted = _CREDENTIAL_URL_RE.sub(rf"\1{REDACTION_MARKER}\3", redacted)
    redacted = _BEARER_RE.sub(rf"\1{REDACTION_MARKER}", redacted)
    redacted = _KNOWN_SECRET_RE.sub(REDACTION_MARKER, redacted)
    return _redact_secret_assignments(redacted)


def _redact_secret_assignments(value: str) -> str:
    """Redact sensitive key/value assignments in JSON, env, and free text."""

    chunks: list[str] = []
    cursor = 0
    search_from = 0
    while True:
        match = _ASSIGNMENT_PREFIX_RE.search(value, search_from)
        if match is None:
            chunks.append(value[cursor:])
            break

        raw_key = match.group("key")
        key = _decode_assignment_key(raw_key)
        if not _is_sensitive_key(key):
            search_from = match.end()
            continue

        value_start = match.end()
        if value_start >= len(value):
            chunks.append(value[cursor:])
            break

        chunks.append(value[cursor:value_start])
        chunks.append(REDACTION_MARKER)

        line_break = _LINE_BREAK_RE.search(value, value_start)
        line_end = line_break.start() if line_break is not None else len(value)

        # YAML block scalars place the credential on following indented lines.
        # Consume the bounded block as well as the indicator line.
        scalar_indicator = value[value_start:line_end].strip()
        cursor = line_end
        if scalar_indicator.startswith(("|", ">")):
            cursor = _yaml_block_end(value, line_end, match.start())
        search_from = cursor
    return "".join(chunks)


def _decode_assignment_key(raw_key: str) -> str:
    """Decode bounded JSON escapes in a quoted assignment key."""

    quote_positions = [index for index, character in enumerate(raw_key) if character in {'"', "'"}]
    key = raw_key
    if len(quote_positions) >= 2:
        key = raw_key[quote_positions[0] + 1 : quote_positions[-1]]
    for _ in range(3):
        decoded = re.sub(
            r"\\u([0-9a-fA-F]{4})",
            lambda match: chr(int(match.group(1), 16)),
            key,
        )
        decoded = decoded.replace(r"\"", '"').replace(r"\'", "'").replace(r"\\", "\\")
        if decoded == key:
            break
        key = decoded
    return key


def _yaml_block_end(value: str, indicator_line_end: int, assignment_start: int) -> int:
    """Return the end of an indented YAML block following a secret key."""

    line_start = max(value.rfind("\n", 0, assignment_start), value.rfind("\r", 0, assignment_start)) + 1
    base_indent = len(value[line_start:assignment_start]) - len(
        value[line_start:assignment_start].lstrip(" \t")
    )
    cursor = indicator_line_end
    block_end = indicator_line_end
    while cursor < len(value):
        if value.startswith("\r\n", cursor):
            newline_width = 2
        elif value[cursor] in "\r\n":
            newline_width = 1
        else:
            break
        next_start = cursor + newline_width
        next_break = _LINE_BREAK_RE.search(value, next_start)
        next_end = next_break.start() if next_break is not None else len(value)
        line = value[next_start:next_end]
        if line.strip():
            indent = len(line) - len(line.lstrip(" \t"))
            if indent <= base_indent:
                break
        block_end = next_end
        cursor = next_end
    return block_end


def _redacted_finding(finding: Finding) -> Finding:
    return Finding(
        finding_id=str(redact_sensitive_data(finding.finding_id)),
        title=str(redact_sensitive_data(finding.title)),
        source=str(redact_sensitive_data(finding.source)),
        severity=str(redact_sensitive_data(finding.severity)),
        asset=str(redact_sensitive_data(finding.asset)),
        location=str(redact_sensitive_data(finding.location)),
        description=str(redact_sensitive_data(finding.description)),
        raw=redact_sensitive_data(finding.raw),
    )


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
    safe_primary = _redacted_finding(primary)
    domain_scores = score_domains(registry, safe_primary)
    recipe_matches = match_recipes(recipes, domain, safe_primary, limit=max_recipes)
    prompt = build_agent_prompt(domain, safe_primary, recipe_matches, ecosystem)
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
        "llm_assist": build_llm_assist(domain, safe_primary, prompt, llm_config or {}, llm_mode),
    }
    return redact_sensitive_data(packet)


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
    text = json.dumps(redact_sensitive_data(packet), indent=2, sort_keys=True)
    if not output_path or str(output_path) == "-":
        print(text)
        return
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")


def _finding_summary(finding: Finding) -> dict[str, Any]:
    return dataclasses.asdict(_redacted_finding(finding))


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
