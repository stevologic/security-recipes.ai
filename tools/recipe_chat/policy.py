"""Refuse scan, exploit, autofix, and deploy asks before any model call."""

from __future__ import annotations

import re
from dataclasses import dataclass

REFUSAL_KIND_SCAN = "scan"
REFUSAL_KIND_EXPLOIT = "exploit"
REFUSAL_KIND_AUTOFIX = "autofix"
REFUSAL_KIND_DEPLOY = "deploy"

_SCAN_RE = re.compile(
    r"\b("
    r"scan(?:ner|ning)?|nmap|masscan|nuclei|nikto|openvas|nessus|zap|"
    r"vulnerability\s+scan|port\s+scan|run\s+a\s+scan|scan\s+(?:my|the|this|our)"
    r")\b",
    re.IGNORECASE,
)
_EXPLOIT_RE = re.compile(
    r"\b("
    r"exploit(?:ation|s)?|weaponiz(?:e|ation)|poc\b|proof[-\s]?of[-\s]?concept|"
    r"payload|reverse\s+shell|metasploit|c2\b|command\s+and\s+control|"
    r"write\s+(?:an?\s+)?exploit|drop(?:per)?\s+a\s+shell|rce\s+payload"
    r")\b",
    re.IGNORECASE,
)
_AUTOFIX_RE = re.compile(
    r"\b("
    r"autofix|auto[-\s]?fix|auto[-\s]?patch|apply\s+(?:the\s+)?(?:fix|patch)|"
    r"patch\s+(?:my|the|this)\s+(?:repo|repository|codebase|production)|"
    r"fix\s+(?:it|this)\s+(?:for\s+me|in\s+(?:my|the)\s+repo)|"
    r"open\s+(?:a\s+)?pr\s+that\s+(?:fixes|patches)|commit\s+the\s+fix"
    r")\b",
    re.IGNORECASE,
)
_DEPLOY_RE = re.compile(
    r"\b("
    r"deploy(?:ment)?(?:\s+\w+){0,3}\s+to\s+(?:prod|production|live)|"
    r"push\s+to\s+(?:prod|production)|"
    r"roll\s+(?:this\s+)?out\s+to\s+production|"
    r"ship\s+(?:this\s+)?to\s+production"
    r")\b",
    re.IGNORECASE,
)

_REFUSAL_TEXT = {
    REFUSAL_KIND_SCAN: (
        "This chat is read-only. It does not scan hosts, repositories, or networks. "
        "Use the scanner you already run, then ask about a published recipe, CVE page, "
        "or playbook on this site."
    ),
    REFUSAL_KIND_EXPLOIT: (
        "This chat will not help write exploits, payloads, or proof-of-concept attacks. "
        "Ask about a published remediation recipe, CVE record, or playbook instead."
    ),
    REFUSAL_KIND_AUTOFIX: (
        "This chat does not patch repositories or open pull requests. It can point you "
        "at a published recipe or CVE page; a reviewer still has to apply the change."
    ),
    REFUSAL_KIND_DEPLOY: (
        "This chat does not deploy anything. Mutation stays in a separately approved "
        "workflow. I can only point at published recipes, CVE pages, and playbooks."
    ),
}


@dataclass(frozen=True)
class Refusal:
    kind: str
    message: str


def classify_request(message: str) -> Refusal | None:
    text = str(message or "")
    if _EXPLOIT_RE.search(text):
        return Refusal(REFUSAL_KIND_EXPLOIT, _REFUSAL_TEXT[REFUSAL_KIND_EXPLOIT])
    if _SCAN_RE.search(text):
        return Refusal(REFUSAL_KIND_SCAN, _REFUSAL_TEXT[REFUSAL_KIND_SCAN])
    if _AUTOFIX_RE.search(text):
        return Refusal(REFUSAL_KIND_AUTOFIX, _REFUSAL_TEXT[REFUSAL_KIND_AUTOFIX])
    if _DEPLOY_RE.search(text):
        return Refusal(REFUSAL_KIND_DEPLOY, _REFUSAL_TEXT[REFUSAL_KIND_DEPLOY])
    return None
