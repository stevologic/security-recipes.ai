#!/usr/bin/env python3
"""Generate the SecurityRecipes context poisoning guard pack.

SecurityRecipes is the secure context layer for agentic AI. That means
registered context should be inspected before it is returned through MCP,
not only hashed after the fact. This generator scans every registered
context source for instruction-like poisoning markers and emits a
deterministic evidence pack with source, line, rule, disposition, and
promotion decision metadata.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Pattern


PACK_SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/context-poisoning-guard-profile.json")
DEFAULT_REGISTRY = Path("data/context/secure-context-registry.json")
DEFAULT_OUTPUT = Path("data/evidence/context-poisoning-guard-pack.json")

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]+$")
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_DECISIONS = {
    "pass",
    "allow_with_adversarial_examples",
    "hold_for_context_review",
    "block_until_removed",
}


RULE_PATTERNS: dict[str, Pattern[str]] = {
    "direct-instruction-override": re.compile(
        r"\b(ignore|disregard|forget|override)\b.{0,80}\b(previous|prior|above|system|developer|tool|safety|instructions?)\b",
        re.IGNORECASE,
    ),
    "secret-exfiltration-request": re.compile(
        r"\b(send|post|upload|submit|forward|exfiltrat(?:e|ion)|dump|print)\b.{0,140}\b(secret|token|credential|api key|private key|environment variables?|/etc/shadow|shadow file|signing material)\b",
        re.IGNORECASE,
    ),
    "approval-bypass-request": re.compile(
        r"(\b(skip|bypass)\b.{0,100}\b(review|approval|guardrail|policy|branch protection|ci|scanner|hook)\b|\b(disable|turn off)\b.{0,100}\b(review|approval|guardrail|branch protection|ci|scanner|hook)\b)",
        re.IGNORECASE,
    ),
    "hidden-html-instruction": re.compile(
        r"(<[^>]+style\s*=\s*['\"][^'\"]*(display\s*:\s*none|opacity\s*:\s*0|font-size\s*:\s*0|color\s*:\s*#?fff)|<!--\s*(system|assistant|developer|ignore|tool)[\s:-])",
        re.IGNORECASE,
    ),
    "external-callback-instruction": re.compile(
        r"\b(send|post|submit|upload|callback|webhook|exfiltrat(?:e|ion))\b.{0,120}https?://",
        re.IGNORECASE,
    ),
    "encoded-payload": re.compile(r"\b[A-Za-z0-9+/]{180,}={0,2}\b"),
    "zero-width-control": re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e]"),
}


class ContextPoisoningGuardError(RuntimeError):
    """Raised when the context poisoning guard pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ContextPoisoningGuardError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ContextPoisoningGuardError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ContextPoisoningGuardError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ContextPoisoningGuardError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContextPoisoningGuardError(f"{label} must be an object")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def normalize_path(path: Path) -> str:
    return path.as_posix()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def canonical_text_byte_count(path: Path) -> int:
    """Count UTF-8 text bytes after universal-newline normalization.

    Git may materialize the same tracked text with CRLF on Windows and LF on
    Linux. Evidence metrics must describe canonical content, not checkout
    mechanics, or a pack generated on one platform will be stale on another.
    """

    return len(path.read_text(encoding="utf-8").encode("utf-8"))


def hash_source(repo_root: Path, files: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in files:
        rel = normalize_path(path.relative_to(repo_root))
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_text(encoding="utf-8").encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def matches_any(path: Path, repo_root: Path, patterns: list[str]) -> bool:
    rel = normalize_path(path.relative_to(repo_root))
    name = path.name
    return any(fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(rel, pattern) for pattern in patterns)


def source_files(repo_root: Path, source: dict[str, Any], output_path: Path) -> list[Path]:
    # Generated evidence packs expose their own deterministic validators and
    # frequently consume this foundational pack. A narrower scan_root keeps
    # runtime retrieval broad without recursively scanning derived evidence.
    root = repo_root / str(source.get("scan_root") or source.get("root", ""))
    allowed = [str(pattern) for pattern in source.get("allowed_file_globs", [])]
    excluded = [str(pattern) for pattern in source.get("exclude_file_globs", []) or []]

    if root.is_file():
        candidates = [root]
    elif root.is_dir():
        candidates = [path for path in root.rglob("*") if path.is_file()]
    else:
        return []

    matched: list[Path] = []
    for path in candidates:
        if path.resolve() == output_path.resolve():
            continue
        if not matches_any(path, repo_root, allowed):
            continue
        if excluded and matches_any(path, repo_root, excluded):
            continue
        matched.append(path)
    return sorted(matched, key=lambda item: normalize_path(item.relative_to(repo_root)))


def validate_inputs(profile: dict[str, Any], registry: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 80, failures, "profile intent must explain the product goal")
    require(registry.get("schema_version") == "1.0", failures, "secure context registry schema_version must be 1.0")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 5, failures, "standards_alignment must include at least five references")
    standard_ids: set[str] = set()
    for idx, standard in enumerate(standards):
        label = f"standards_alignment[{idx}]"
        if not isinstance(standard, dict):
            failures.append(f"{label} must be an object")
            continue
        standard_id = str(standard.get("id", "")).strip()
        require(bool(ID_RE.match(standard_id)), failures, f"{label}.id must be kebab-case")
        require(standard_id not in standard_ids, failures, f"{label}.id duplicates {standard_id}")
        standard_ids.add(standard_id)
        require(str(standard.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")

    contract = as_dict(profile.get("decision_contract"), "decision_contract")
    require(contract.get("default_decision") in VALID_DECISIONS, failures, "decision_contract.default_decision is invalid")
    decisions = {
        str(decision.get("decision"))
        for decision in as_list(contract.get("decisions"), "decision_contract.decisions")
        if isinstance(decision, dict)
    }
    require(VALID_DECISIONS.issubset(decisions), failures, "decision_contract must define every guard decision")

    rules = as_list(profile.get("scanner_rules"), "scanner_rules")
    require(len(rules) >= 6, failures, "scanner_rules must define at least six rules")
    rule_ids: set[str] = set()
    for idx, rule in enumerate(rules):
        label = f"scanner_rules[{idx}]"
        if not isinstance(rule, dict):
            failures.append(f"{label} must be an object")
            continue
        rule_id = str(rule.get("id", "")).strip()
        rule_ids.add(rule_id)
        require(rule_id in RULE_PATTERNS, failures, f"{rule_id}: no matcher exists in generator")
        require(str(rule.get("severity")) in VALID_SEVERITIES, failures, f"{rule_id}: severity is invalid")
        require(str(rule.get("risk_family", "")).strip(), failures, f"{rule_id}: risk_family is required")

    missing_matchers = sorted(set(RULE_PATTERNS) - rule_ids)
    require(not missing_matchers, failures, f"profile is missing matcher metadata: {missing_matchers}")
    require(bool(as_list(profile.get("allowed_adversarial_context_globs"), "allowed_adversarial_context_globs")), failures, "allowed_adversarial_context_globs are required")
    require(bool(as_list(profile.get("defensive_language_prefixes"), "defensive_language_prefixes")), failures, "defensive_language_prefixes are required")

    sources = as_list(registry.get("context_sources"), "context_sources")
    require(bool(sources), failures, "secure context registry must include context_sources")
    return failures


def rule_by_id(profile: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(rule.get("id")): rule
        for rule in as_list(profile.get("scanner_rules"), "scanner_rules")
        if isinstance(rule, dict) and rule.get("id")
    }


def is_defensive_language(line: str, match_start: int, prefixes: list[str]) -> bool:
    before = line[:match_start].strip().lower()
    after = line[match_start:].strip().lower()
    window = before[-120:]
    normalized_before = re.sub(r"[^a-z0-9]+", " ", window).strip()
    normalized_line = re.sub(r"[^a-z0-9]+", " ", line.lower()).strip()
    normalized_after = re.sub(r"[^a-z0-9]+", " ", after).strip()
    if any(re.search(rf"(^| )({re.escape(prefix.strip())})( |$)", normalized_before) for prefix in prefixes):
        return True
    return any(
        marker in normalized_line or normalized_after.startswith(marker)
        for marker in (
            "reject",
            "refuse",
            "denied",
            "blocked",
            "no exceptions",
            "safe",
            "restrict",
            "if ci fails",
            "will never",
            "must never",
            "should never",
        )
    )


def finding_disposition(
    *,
    path: Path,
    repo_root: Path,
    line: str,
    match_start: int,
    profile: dict[str, Any],
) -> tuple[str, bool]:
    allowed_globs = [str(pattern) for pattern in profile.get("allowed_adversarial_context_globs", [])]
    prefixes = [str(prefix).lower() for prefix in profile.get("defensive_language_prefixes", [])]

    if matches_any(path, repo_root, allowed_globs):
        return "documented_adversarial_example", False
    if is_defensive_language(line, match_start, prefixes):
        return "defensive_control_language", False
    return "actionable_context_poisoning_risk", True


def snippet(line: str, start: int, end: int) -> str:
    left = max(0, start - 80)
    right = min(len(line), end + 80)
    value = line[left:right].strip()
    if left > 0:
        value = "..." + value
    if right < len(line):
        value = value + "..."
    return value


def scan_file(
    *,
    path: Path,
    source: dict[str, Any],
    repo_root: Path,
    profile: dict[str, Any],
    rules: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [
            {
                "actionable": True,
                "disposition": "actionable_context_poisoning_risk",
                "line": 0,
                "match": "unreadable non-utf8 content",
                "path": normalize_path(path.relative_to(repo_root)),
                "risk_family": "context_poisoning",
                "rule_id": "non-utf8-context",
                "severity": "high",
                "source_id": source.get("id"),
            }
        ]

    findings: list[dict[str, Any]] = []
    per_rule_counts: Counter[str] = Counter()
    rel = normalize_path(path.relative_to(repo_root))
    for line_no, line in enumerate(text.splitlines(), start=1):
        for rule_id, pattern in RULE_PATTERNS.items():
            if per_rule_counts[rule_id] >= 5:
                continue
            for match in pattern.finditer(line):
                rule = rules[rule_id]
                disposition, actionable = finding_disposition(
                    path=path,
                    repo_root=repo_root,
                    line=line,
                    match_start=match.start(),
                    profile=profile,
                )
                findings.append(
                    {
                        "actionable": actionable,
                        "disposition": disposition,
                        "line": line_no,
                        "match": snippet(line, match.start(), match.end()),
                        "path": rel,
                        "risk_family": rule.get("risk_family"),
                        "rule_id": rule_id,
                        "severity": rule.get("severity"),
                        "source_id": source.get("id"),
                    }
                )
                per_rule_counts[rule_id] += 1
                break
    return findings


def source_decision(findings: list[dict[str, Any]]) -> str:
    actionable = [finding for finding in findings if finding.get("actionable")]
    if not findings:
        return "pass"
    if not actionable:
        return "allow_with_adversarial_examples"
    if any(finding.get("severity") == "critical" for finding in actionable):
        return "block_until_removed"
    return "hold_for_context_review"


def source_preview(
    *,
    source: dict[str, Any],
    files: list[Path],
    repo_root: Path,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    severity_counts = Counter(str(finding.get("severity")) for finding in findings)
    disposition_counts = Counter(str(finding.get("disposition")) for finding in findings)
    actionable = [finding for finding in findings if finding.get("actionable")]
    decision = source_decision(findings)
    return {
        "actionable_finding_count": len(actionable),
        "decision": decision,
        "disposition_counts": dict(sorted(disposition_counts.items())),
        "file_count": len(files),
        "finding_count": len(findings),
        "owner": source.get("owner", {}),
        "registered_files_sample": [
            normalize_path(path.relative_to(repo_root))
            for path in files[:20]
        ],
        "risk_family_counts": dict(sorted(Counter(str(finding.get("risk_family")) for finding in findings).items())),
        "root": source.get("root"),
        "severity_counts": dict(sorted(severity_counts.items())),
        "source_hash": hash_source(repo_root, files) if files else None,
        "source_id": source.get("id"),
        "title": source.get("title"),
        "trust_tier": source.get("trust_tier"),
    }


def build_pack(
    *,
    profile: dict[str, Any],
    registry: dict[str, Any],
    profile_path: Path,
    registry_path: Path,
    profile_ref: Path,
    registry_ref: Path,
    output_path: Path,
    repo_root: Path,
    generated_at: str | None,
    validation_failures: list[str],
) -> dict[str, Any]:
    rules = rule_by_id(profile)
    all_findings: list[dict[str, Any]] = []
    source_results: list[dict[str, Any]] = []
    file_count = 0
    byte_count = 0

    for source in as_list(registry.get("context_sources"), "context_sources"):
        if not isinstance(source, dict):
            continue
        files = source_files(repo_root, source, output_path)
        source_findings: list[dict[str, Any]] = []
        for path in files:
            file_count += 1
            byte_count += canonical_text_byte_count(path)
            file_findings = scan_file(
                path=path,
                source=source,
                repo_root=repo_root,
                profile=profile,
                rules=rules,
            )
            source_findings.extend(file_findings)
        all_findings.extend(source_findings)
        source_results.append(
            source_preview(
                source=source,
                files=files,
                repo_root=repo_root,
                findings=source_findings,
            )
        )

    decision_counts = Counter(str(source.get("decision")) for source in source_results)
    severity_counts = Counter(str(finding.get("severity")) for finding in all_findings)
    disposition_counts = Counter(str(finding.get("disposition")) for finding in all_findings)
    risk_counts = Counter(str(finding.get("risk_family")) for finding in all_findings)
    actionable_findings = [finding for finding in all_findings if finding.get("actionable")]
    blocking_sources = [
        source.get("source_id")
        for source in source_results
        if source.get("decision") == "block_until_removed"
    ]
    held_sources = [
        source.get("source_id")
        for source in source_results
        if source.get("decision") == "hold_for_context_review"
    ]

    return {
        "decision_contract": profile.get("decision_contract", {}),
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "failures": validation_failures,
        "findings": sorted(
            all_findings,
            key=lambda finding: (
                str(finding.get("source_id")),
                str(finding.get("path")),
                int(finding.get("line") or 0),
                str(finding.get("rule_id")),
            ),
        ),
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "guard_summary": {
            "actionable_finding_count": len(actionable_findings),
            "blocking_source_count": len(blocking_sources),
            "blocking_sources": sorted([str(item) for item in blocking_sources]),
            "byte_count": byte_count,
            "decision_counts": dict(sorted(decision_counts.items())),
            "disposition_counts": dict(sorted(disposition_counts.items())),
            "failure_count": len(validation_failures),
            "file_count": file_count,
            "finding_count": len(all_findings),
            "held_source_count": len(held_sources),
            "held_sources": sorted([str(item) for item in held_sources]),
            "risk_family_counts": dict(sorted(risk_counts.items())),
            "severity_counts": dict(sorted(severity_counts.items())),
            "source_count": len(source_results),
        },
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "prevention_controls": [
            "Demote retrieved text to evidence before model use.",
            "Label documented attack payloads as adversarial examples.",
            "Hold normal guidance for review when it contains instruction-override, approval-bypass, or exfiltration markers.",
            "Block critical actionable findings from MCP retrieval until source owners remove or explicitly recertify them.",
            "Regenerate the pack before secure context trust-pack generation so source hashes include the current scan result."
        ],
        "schema_version": PACK_SCHEMA_VERSION,
        "scanner_rules": profile.get("scanner_rules", []),
        "source_artifacts": {
            "context_poisoning_guard_profile": {
                "path": normalize_path(profile_ref),
                "sha256": sha256_file(profile_path),
            },
            "secure_context_registry": {
                "path": normalize_path(registry_ref),
                "sha256": sha256_file(registry_path),
            }
        },
        "source_results": sorted(source_results, key=lambda source: str(source.get("source_id"))),
        "standards_alignment": profile.get("standards_alignment", []),
    }


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in context poisoning guard pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    profile_path = resolve(repo_root, args.profile)
    registry_path = resolve(repo_root, args.registry)
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(profile_path)
        registry = load_json(registry_path)
        failures = validate_inputs(profile, registry)
        pack = build_pack(
            profile=profile,
            registry=registry,
            profile_path=profile_path,
            registry_path=registry_path,
            profile_ref=args.profile,
            registry_ref=args.registry,
            output_path=output_path,
            repo_root=repo_root,
            generated_at=args.generated_at,
            validation_failures=failures,
        )
    except ContextPoisoningGuardError as exc:
        print(f"context poisoning guard pack generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)

    if args.check:
        if failures:
            print("context poisoning guard pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run this script without --check", file=sys.stderr)
            return 1
        if current_text != next_text:
            print(
                f"{output_path} is stale; run scripts/generate_context_poisoning_guard_pack.py",
                file=sys.stderr,
            )
            return 1
        print(f"Validated context poisoning guard pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")

    if failures:
        print("Generated context poisoning guard pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated context poisoning guard pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
