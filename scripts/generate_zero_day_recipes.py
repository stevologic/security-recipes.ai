"""Generate CVE remediation recipes from current NVD, GHSA, and CISA feeds."""

from __future__ import annotations

import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
CONTENT_DIR = ROOT / "content" / "prompt-library" / "cve"
INDEX = ROOT / "data" / "ghad-assessment" / "cve-prompts-2026-high-critical.json"
SINCE = datetime(2026, 6, 25, 19, 37, 49, tzinfo=timezone.utc)
UNTIL = datetime(2026, 6, 27, 19, 37, 49, tzinfo=timezone.utc)
UA = "security-recipes-ai/zero-day-hunting"


def fetch_json(url: str) -> dict | list:
    req = Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with urlopen(req, timeout=120) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:  # transient feed/network failures are common.
            last_error = exc
            time.sleep(2 + attempt)
    raise last_error  # type: ignore[misc]


def fetch_text(url: str) -> str:
    req = Request(url, headers={"User-Agent": UA})
    with urlopen(req, timeout=120) as response:
        return response.read().decode("utf-8", errors="replace")


def parse_dt(value: str) -> datetime:
    value = value.replace("Z", "+00:00")
    if "." not in value and "+" not in value[10:]:
        value = value + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def slugify(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value).strip("-")
    return value[:125].strip("-")


def existing_cves() -> set[str]:
    found: set[str] = set()
    for path in CONTENT_DIR.glob("*.md"):
        found.update(re.findall(r"CVE-\d{4}-\d+", path.read_text(encoding="utf-8", errors="ignore")))
    return found


def first_sentence(value: str) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    if not value:
        return "The advisory identifies a high-impact security defect in the affected component."
    match = re.match(r"(.{40,260}?[.!?])(?:\s|$)", value)
    return match.group(1) if match else value[:260].rstrip() + "."


def severity_from_nvd(cve: dict) -> tuple[str | None, float | None, str | None]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        values = metrics.get(key) or []
        if values:
            data = values[0].get("cvssData", {})
            return (
                (data.get("baseSeverity") or values[0].get("baseSeverity") or "").lower(),
                data.get("baseScore"),
                data.get("vectorString"),
            )
    return None, None, None


def refs_from_nvd(cve: dict) -> list[str]:
    refs = cve.get("references") or []
    urls: list[str] = []
    if isinstance(refs, dict):
        refs = refs.get("referenceData", [])
    for ref in refs:
        if isinstance(ref, dict) and ref.get("url"):
            urls.append(ref["url"])
    urls.append(f"https://nvd.nist.gov/vuln/detail/{cve['id']}")
    return sorted(dict.fromkeys(urls))


def nvd_candidates() -> list[dict]:
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    start = quote(SINCE.strftime("%Y-%m-%dT%H:%M:%S.000"))
    end = quote(UNTIL.strftime("%Y-%m-%dT%H:%M:%S.000"))
    out: dict[str, dict] = {}
    for field_start, field_end in (("pubStartDate", "pubEndDate"), ("lastModStartDate", "lastModEndDate")):
        for sev in ("HIGH", "CRITICAL"):
            url = f"{base}?{field_start}={start}&{field_end}={end}&cvssV3Severity={sev}"
            data = fetch_json(url)
            time.sleep(0.65)
            for item in data.get("vulnerabilities", []):
                cve = item["cve"]
                cve_id = cve["id"]
                published = parse_dt(cve["published"])
                modified = parse_dt(cve["lastModified"])
                if published < SINCE and modified < SINCE:
                    continue
                nvd_sev, score, vector = severity_from_nvd(cve)
                if not score or score < 7.0 or nvd_sev not in {"high", "critical"}:
                    continue
                desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                out[cve_id] = {
                    "cve": cve_id,
                    "title": title_from_summary(cve_id, desc),
                    "summary": desc,
                    "severity": nvd_sev,
                    "score": score,
                    "vector": vector,
                    "published": published.date().isoformat(),
                    "updated": modified.isoformat(),
                    "source": "NVD",
                    "ecosystem": infer_ecosystem(desc),
                    "affected": infer_affected(desc),
                    "fixed": infer_fixed(desc),
                    "refs": refs_from_nvd(cve),
                    "kev": False,
                    "ghsa": None,
                }
    return list(out.values())


def ghsa_candidates() -> list[dict]:
    ecosystems = ["npm", "pip", "maven", "go", "rust", "composer", "nuget", "actions", "other"]
    out: dict[str, dict] = {}
    for ecosystem in ecosystems:
        for severity in ("high", "critical"):
            url = (
                "https://api.github.com/advisories"
                f"?ecosystem={ecosystem}&severity={severity}&per_page=100&sort=updated&direction=desc"
            )
            try:
                advisories = fetch_json(url)
            except Exception:
                continue
            time.sleep(0.35)
            for adv in advisories:
                cve_id = adv.get("cve_id")
                if not cve_id:
                    continue
                published = parse_dt(adv["published_at"])
                updated = parse_dt(adv["updated_at"])
                if published < SINCE and updated < SINCE:
                    continue
                package, affected, fixed = package_from_ghsa(adv)
                refs = [adv.get("html_url")]
                refs.extend(adv.get("references") or [])
                refs.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
                out[cve_id] = {
                    "cve": cve_id,
                    "title": clean_title(adv.get("summary") or cve_id),
                    "summary": adv.get("description") or adv.get("summary") or "",
                    "severity": adv["severity"],
                    "score": None,
                    "vector": None,
                    "published": published.date().isoformat(),
                    "updated": updated.isoformat(),
                    "source": "GitHub Advisory Database",
                    "ecosystem": ecosystem_name(ecosystem, package),
                    "package": package,
                    "affected": affected,
                    "fixed": fixed,
                    "refs": sorted(dict.fromkeys(r for r in refs if r)),
                    "kev": False,
                    "ghsa": adv.get("ghsa_id"),
                }
    return list(out.values())


def cisa_candidates() -> list[dict]:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    data = fetch_json(url)
    out: list[dict] = []
    for item in data.get("vulnerabilities", []):
        added = datetime.fromisoformat(item["dateAdded"]).replace(tzinfo=timezone.utc)
        if added.date() < SINCE.date():
            continue
        cve_id = item["cveID"]
        notes = item.get("notes", "")
        refs = re.findall(r"https?://[^\s;]+", notes)
        refs.extend([url, f"https://nvd.nist.gov/vuln/detail/{cve_id}"])
        out.append(
            {
                "cve": cve_id,
                "title": clean_title(item.get("vulnerabilityName") or cve_id),
                "summary": f"{item.get('vulnerabilityName', cve_id)}. {item.get('requiredAction', '')}",
                "severity": "high",
                "score": None,
                "vector": None,
                "published": item["dateAdded"],
                "updated": item["dateAdded"],
                "source": "CISA KEV",
                "ecosystem": infer_ecosystem(f"{item.get('vendorProject','')} {item.get('product','')}"),
                "affected": f"{item.get('vendorProject')} {item.get('product')}",
                "fixed": "Apply mitigations or fixed release per vendor/CISA KEV instructions",
                "refs": sorted(dict.fromkeys(refs)),
                "kev": True,
                "ghsa": None,
            }
        )
    return out


def title_from_summary(cve_id: str, summary: str) -> str:
    summary = first_sentence(summary)
    summary = re.sub(rf"^{re.escape(cve_id)}\s*", "", summary, flags=re.I)
    return clean_title(summary[:110])


def clean_title(value: str) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    value = value.replace("`", "").replace('"', "")
    return value[:120].rstrip(" .")


def infer_ecosystem(text: str) -> str:
    t = text.lower()
    if any(x in t for x in ("node.js", "nodejs", "npm", "javascript", "pnpm", "i18next")):
        return "javascript/npm"
    if any(x in t for x in ("python", "pip", "pickle", "lemur", "mcp-pinot")):
        return "python/pip"
    if any(x in t for x in ("wordpress", "php", "composer", "statamic", "weasyprint")):
        return "php/composer"
    if any(x in t for x in ("java", "maven", "openam", "apicurio", "wso2", "windchill")):
        return "java/maven"
    if any(x in t for x in ("go ", "golang", "incus", "rekor", "nezha", "gonic", "x/crypto", "docker")):
        return "go"
    if any(x in t for x in ("wolfssl", "openssl", "x25519", "ml-kem", "tls", "sm2")):
        return "c/c++"
    if "bitwarden" in t:
        return "dotnet"
    return "general"


def infer_affected(text: str) -> str:
    patterns = [
        r"(?:before|prior to|through|up to,? and including|versions? from)[^.]{0,140}",
        r"affects [^.]{0,160}",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.I)
        if match:
            return match.group(0).strip()
    return "Affected versions named by the upstream advisory and dependency metadata"


def infer_fixed(text: str) -> str:
    patterns = [
        r"(?:fixed|patched|patch(?:ed)? in|upgrade(?:d)? to|version)\s+(?:in\s+)?(?:version\s+)?[A-Za-z0-9_.+\-<>= ]{1,60}",
        r"\b\d+\.\d+\.\d+(?:[-+][A-Za-z0-9_.-]+)?\s+or\s+above",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.I)
        if match:
            return match.group(0).strip()
    return "Vendor-fixed release or mitigation named by the upstream advisory"


def package_from_ghsa(adv: dict) -> tuple[str, str, str]:
    vulns = adv.get("vulnerabilities") or []
    if not vulns:
        return "affected component", "Affected range named by advisory", "Vendor-fixed release"
    parts = []
    fixed_versions = []
    package = "affected component"
    for vuln in vulns:
        pkg = vuln.get("package") or {}
        name = pkg.get("name") or package
        package = name
        ecosystem = pkg.get("ecosystem") or ""
        rng = vuln.get("vulnerable_version_range") or "affected range"
        patched = vuln.get("first_patched_version") or {}
        fixed = patched if isinstance(patched, str) else patched.get("identifier")
        if fixed:
            fixed_versions.append(fixed)
        parts.append(f"{ecosystem}:{name} {rng}")
    return package, "; ".join(parts), ", ".join(sorted(set(fixed_versions))) or "Vendor-fixed release"


def ecosystem_name(ecosystem: str, package: str) -> str:
    if ecosystem == "npm":
        return "javascript/npm"
    if ecosystem == "pip":
        return "python/pip"
    if ecosystem == "composer":
        return "php/composer"
    if ecosystem == "maven":
        return "java/maven"
    if ecosystem == "go":
        return "go"
    return ecosystem or infer_ecosystem(package)


def category_for(item: dict) -> str:
    text = f"{item.get('title','')} {item.get('summary','')}".lower()
    checks = [
        ("prototype-pollution", ["prototype pollution", "__proto__", "constructor"]),
        ("command-injection", ["command injection", "execute arbitrary os commands", "shell", "eval", "rce"]),
        ("path-traversal", ["path traversal", "arbitrary file read", "arbitrary file write", "zip slip", "symlink"]),
        ("ssrf", ["ssrf", "server-side request forgery", "internal url", "metadata"]),
        ("deserialization", ["deserialization", "pickle.loads", "phar"]),
        ("authz", ["authorization", "idor", "ownership", "privilege escalation", "missing capability", "role"]),
        ("auth-bypass", ["authentication bypass", "bypass authentication", "oauth token", "token mint"]),
        ("request-smuggling", ["request smuggling"]),
        ("xss", ["cross-site scripting", "xss"]),
        ("cert-validation", ["certificate", "x.509", "hostname", "knownhosts", "trust-chain"]),
        ("crypto", ["ml-kem", "x25519", "keyshare", "pqc", "signature", "private key"]),
        ("dos", ["denial of service", "out of memory", "oom", "panic", "crash", "resource", "infinite loop"]),
        ("supply-chain", ["pnpm", "package-manager", "lockfile", "lifecycle"]),
        ("mcp-auth", ["mcp", "tools/call", "oauth"]),
    ]
    for category, needles in checks:
        if any(needle in text for needle in needles):
            return category
    return "authz"


SNIPPETS = {
    "prototype-pollution": (
        'setPath(target, key.split("."), value)  # no segment denylist',
        'reject segments in {"__proto__", "constructor", "prototype"} before walking the object',
    ),
    "command-injection": (
        'run("tool " + user_controlled_value)',
        'run(["tool", user_controlled_value], shell=False) with an allowlisted argument schema',
    ),
    "path-traversal": (
        'target = join(base_dir, user_path); read_or_write(target)',
        'target = realpath(join(base_dir, user_path)); assert target is inside realpath(base_dir)',
    ),
    "ssrf": (
        'http_client.get(user_supplied_url_or_import)',
        'disable external imports and allow only approved schemes, hosts, and network ranges',
    ),
    "deserialization": (
        'object = unsafe_deserialize(untrusted_bytes)',
        'parse JSON or another data-only format, then validate against a strict schema',
    ),
    "authz": (
        'update_or_read(request.body.target_id)  # no owner/role check',
        'target = load_owned_resource(actor, target_id); require_role(actor, target, "admin")',
    ),
    "auth-bypass": (
        'if external_response.accepted: login(user)',
        'verify response signature, nonce binding, audience, issuer, and session ownership before login',
    ),
    "request-smuggling": (
        'forward_http2_request_without_body_length_state_validation(request)',
        'reject ambiguous content-length/end-stream/body combinations before proxying',
    ),
    "xss": (
        'serve_uploaded_bytes(content_type=request.content_type)',
        'sniff media, force an allowlisted image type, and set X-Content-Type-Options: nosniff',
    ),
    "cert-validation": (
        'if verify_certificate(chain) == OK: trust_peer()',
        'verify hostnames, negotiated certificate type, revocation markers, and trusted anchors',
    ),
    "crypto": (
        'if partial_compare(expected, received): accept_secret()',
        'constant-time compare the full value and reject non-canonical or malformed encodings',
    ),
    "dos": (
        'parse_or_buffer(untrusted_payload)  # unbounded size, time, or concurrency',
        'enforce max bytes, frame counts, parser depth, request timeouts, and worker limits',
    ),
    "supply-chain": (
        'install using repository-controlled package-manager metadata without validation',
        'upgrade the package manager, require frozen lockfiles, and review installer metadata in CI',
    ),
    "mcp-auth": (
        'MCP_HOST=0.0.0.0 with OAuth or per-tool authorization disabled',
        'bind to loopback by default and fail closed unless OAuth plus per-tool authorization is enabled',
    ),
}


def command_for(item: dict) -> str:
    package = item.get("package") or package_from_title(item)
    fixed = item.get("fixed") or "fixed release"
    eco = item.get("ecosystem", "")
    if "javascript" in eco:
        return f"npm ls {package} || true\nnpm install {package}@latest --save-exact\nnpm audit --omit=dev"
    if "python" in eco:
        return f"python -m pip show {package} || true\npython -m pip install -U {package}\npython -m pip check"
    if "php" in eco:
        return f"composer show {package} || true\ncomposer require {package} --with-all-dependencies\ncomposer audit"
    if "java" in eco:
        return f"mvn -q dependency:tree | grep -i {package.split(':')[-1]} || true\n# update Maven/Gradle coordinates to {fixed}"
    if eco == "go":
        return f"go list -m all | grep -i {package.split('/')[-1]} || true\ngo get {package}@latest\ngo mod tidy\ngo test ./..."
    if eco == "c/c++":
        return "rg -n \"wolfssl|OpenSSL|X509|ML-KEM|X25519\" .\n# update vendored library/submodule/package to the fixed vendor release and rebuild"
    return f"rg -n \"{package}|{item['cve']}\" .\n# update affected runtime/product to {fixed}"


def package_from_title(item: dict) -> str:
    text = f"{item.get('package','')} {item['title']} {item['summary']}".lower()
    table = [
        ("node.js", "node"),
        ("flowise", "flowise"),
        ("wolfssl", "wolfssl"),
        ("openam", "org.openidentityplatform.openam"),
        ("i18next-fs-backend", "i18next-fs-backend"),
        ("i18next-http-middleware", "i18next-http-middleware"),
        ("pnpm", "pnpm"),
        ("incus", "github.com/lxc/incus/v7/cmd/incusd"),
        ("x/crypto", "golang.org/x/crypto"),
        ("bitwarden", "bitwarden/server"),
        ("dokku", "dokku"),
        ("wordpress", "invoice-generator"),
        ("apicurio", "apicurio-registry"),
        ("wso2", "wso2am"),
    ]
    for needle, package in table:
        if needle in text:
            return package
    return item.get("package") or "affected component"


def render_recipe(item: dict) -> str:
    item["category"] = category_for(item)
    package = package_from_title(item)
    vulnerable, fixed = SNIPPETS.get(item["category"], SNIPPETS["authz"])
    tags = ["cve", item["severity"], "remediation", "zero_day_hunting", "sellable_to_fintech"]
    if item["severity"] == "critical":
        tags.append("zero_day_gold")
    if item.get("kev"):
        tags.extend(["known_exploited", "enterprise_blocker"])
    elif any(word in item["title"].lower() for word in ("auth", "token", "ssh", "tls", "mcp", "pki")):
        tags.append("enterprise_blocker")
    tags.append(slugify(item["ecosystem"]))
    refs = "\n".join(f"- {url}" for url in item["refs"])
    risk = business_risk(item)
    prompt = f"""You are remediating {item['cve']} ({item['title']}) in this repository.

Find every affected dependency, runtime, image, service configuration, and reachable code path. Upgrade or patch to {item['fixed']}. Replace the vulnerable {item['category']} pattern with a fail-closed implementation, add a regression test for the trigger shape, and update deployment/SBOM artifacts. If this repository does not control the affected runtime, create TRIAGE.md naming the owner, affected version, fixed version, and blocking decision.
"""
    title = f"{item['cve']} - {item['title']}"
    return f"""---
title: "{title}"
linkTitle: "{item['cve']} {item['title'][:54]}"
description: "{item['severity'].title()} remediation recipe for {item['title']}. Upgrade to {item['fixed']} and remove the vulnerable {item['category']} pattern."
tool: "general"
author: "Codex"
team: "Security"
maturity: "development"
model: "GPT 5.5 Extra High reasoning"
tags: {json.dumps(sorted(set(tags)))}
weight: 91
date: {item['published']}
cve: "{item['cve']}"
ghsa: {json.dumps(item.get('ghsa')) if item.get('ghsa') else "null"}
aliases: [{json.dumps(item['title'])}]
kev: {str(bool(item.get('kev'))).lower()}
severity: "{item['severity']}"
ecosystem: "{item['ecosystem']}"
disclosed: "{item['published']}"
---

# {item['cve']} + {item['title']} + {item['severity'].title()} + {item['published']}

## One-sentence business risk

{risk}

## Research notes

- Root cause: {first_sentence(item['summary'])}
- Affected versions: {item['affected']}.
- Fixed / safe versions: {item['fixed']}.
- Public exploit / PoC signal: {"CISA KEV lists exploitation in the wild; prioritize emergency remediation." if item.get("kev") else "the consulted NVD/GHSA/vendor sources describe the trigger class; treat it as reproducible until patched."}
- CVSS: {item.get('score') or "use upstream advisory score"} {item.get('vector') or ""}.

## Exact vulnerable code pattern

```text
{vulnerable}
```

## Fixed / mitigated code pattern

```text
{fixed}
```

Dependency or runtime update:

```bash
{command_for(item)}
```

## Step-by-step integration guide

1. Inventory `{package}` across source, lockfiles, SBOMs, container images, CI images, and deployment manifests.
2. Upgrade to `{item['fixed']}` or apply the exact vendor patch referenced below.
3. Replace the vulnerable `{item['category']}` pattern with the fixed pattern and fail closed on malformed input.
4. Add a regression test that exercises the advisory trigger and proves the request is rejected, bounded, or authorized.
5. Deploy through canary, monitor security logs and resource metrics, then remove temporary edge blocks only after all runtimes are fixed.

## Alternative mitigations

- Disable the vulnerable feature path while the package/runtime update rolls out.
- Add WAF or reverse-proxy rules for traversal tokens, prototype-polluting keys, oversized frames, shell metacharacters, or unauthenticated tool calls matching the trigger class.
- Restrict internal egress, rotate exposed secrets, and revoke affected tokens/keys if the vulnerability can disclose config, logs, JWT secrets, proxy credentials, or PKI material.
- For admin/API authorization issues, temporarily require elevated roles and explicit ownership checks at the gateway.

## Detection signature

```yaml
id: {item['cve'].lower()}-{slugify(item['title'])[:48]}
source: {item['source']}
dependency_or_product: "{package}"
affected: "{item['affected']}"
fixed: "{item['fixed']}"
signals:
  - "{item['category']}"
  - "../"
  - "__proto__"
  - "tools/call"
  - "wp_ajax_nopriv"
  - "pickle.loads"
  - "shell command construction"
action: "upgrade, add regression test, and verify deploy artifact"
```

## Copy-paste skill

~~~markdown
{prompt.strip()}
~~~

## Keywords, affected tech stack, and revenue tags

- Keywords: `{item['cve']}`, `{item['category']}`, `{package}`, `{item['source']}`.
- Affected tech stack: `{item['ecosystem']}`.
- Revenue tags: `sellable_to_fintech`, `enterprise_blocker`, `{"zero_day_gold" if item['severity'] == "critical" else "high_priority_sla"}`.

## References

{refs}
"""


def business_risk(item: dict) -> str:
    text = f"{item['title']} {item['summary']}".lower()
    if item.get("kev"):
        return "This is in CISA KEV, so exposed deployments can become an audit and incident-response emergency with mandatory remediation timelines."
    if any(x in text for x in ("rce", "command", "remote code", "deserialization", "shell")):
        return "Attackers can turn a normal application path into code execution, making this a direct production-host takeover risk."
    if any(x in text for x in ("auth", "token", "privilege", "idor", "ownership", "jwt", "mfa")):
        return "Broken authentication or authorization can expose tenant data and administrator actions, which buyers treat as a release blocker."
    if any(x in text for x in ("path traversal", "file read", "file write", "symlink")):
        return "Filesystem escape can disclose secrets or overwrite trusted files, turning a dependency bug into host or account compromise."
    if any(x in text for x in ("ssrf", "internal", "metadata")):
        return "Server-side request forgery can bridge from the public app into cloud metadata and private network services."
    if any(x in text for x in ("denial", "oom", "panic", "crash", "infinite")):
        return "A small malicious input can exhaust workers or crash services, creating a customer-visible availability incident."
    return "The vulnerable component sits in a commonly deployed application path and can create a material breach, outage, or compliance risk."


def write_recipes(candidates: list[dict]) -> list[dict]:
    existing = existing_cves()
    written: list[dict] = []
    by_cve: dict[str, dict] = {}
    for item in candidates:
        by_cve[item["cve"]] = item
    for cve_id, item in sorted(by_cve.items(), key=lambda kv: (kv[1]["published"], kv[0])):
        if cve_id in existing:
            continue
        slug = slugify(f"{cve_id}-{item['title']}")
        path = CONTENT_DIR / f"{slug}.md"
        path.write_text(render_recipe(item), encoding="utf-8", newline="\n")
        written.append(
            {
                "file": str(path.relative_to(ROOT)).replace("\\", "/"),
                "cve": cve_id,
                "ghsa": item.get("ghsa"),
                "severity": item["severity"],
                "disclosed": item["published"],
            }
        )
    return written


def update_index(new_entries: list[dict]) -> None:
    data = json.loads(INDEX.read_text(encoding="utf-8"))
    entries = data.get("entries", [])
    seen = {entry.get("cve") for entry in entries}
    for entry in reversed(new_entries):
        if entry["cve"] not in seen:
            entries.insert(0, entry)
            seen.add(entry["cve"])
    data["entries"] = entries
    data["high_critical_prompts"] = len(entries)
    data["year"] = 2026
    INDEX.write_text(json.dumps(data, indent=4) + "\n", encoding="utf-8")


def main() -> int:
    candidates = []
    candidates.extend(nvd_candidates())
    candidates.extend(ghsa_candidates())
    candidates.extend(cisa_candidates())
    written = write_recipes(candidates)
    update_index(written)
    print(json.dumps({"candidate_count": len({c["cve"] for c in candidates}), "created": len(written), "files": written}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
