---
title: MCP and Agentic Skills Risk Coverage
linkTitle: MCP Risk Coverage
weight: 18
toc: true
description: >
  Generated OWASP MCP Top 10 and OWASP Agentic Skills Top 10 coverage
  map for SecurityRecipes controls, evidence packs, MCP tools, and
  hosted product wedges.
---

{{< callout type="info" >}}
**What this is.** This pack turns fresh MCP and agent-skill risk
language into a buyer-readable coverage artifact. It shows which
SecurityRecipes evidence paths and MCP tools answer each OWASP MCP Top
10 and OWASP Agentic Skills Top 10 risk.
{{< /callout >}}

SecurityRecipes is positioned as **The Secure Context Layer for Agentic
AI**. That claim needs to cover both sides of the emerging control
plane:

- **MCP and tools:** how an agent discovers, authorizes, describes,
  invokes, and audits external tools.
- **Agentic skills:** the behavior packages, rules, hooks, extensions,
  and workflow instructions that tell agents how to combine tools into
  real actions.

The **MCP and Agentic Skills Risk Coverage Pack** maps those two layers
to existing SecurityRecipes artifacts. It is designed for platform teams,
procurement reviewers, GRC, investors, and acquirers who need to know
whether the project tracks the newest risks without reading the whole
site.

## Generated artifact

- Source model:
  `data/assurance/mcp-risk-coverage-profile.json`
- Generator:
  `scripts/generate_mcp_risk_coverage_pack.py`
- Evidence pack:
  `data/evidence/mcp-risk-coverage-pack.json`
- MCP tool:
  `recipes_mcp_risk_coverage_pack`

Regenerate and validate the pack:

```bash
python3 scripts/generate_mcp_risk_coverage_pack.py
python3 scripts/generate_mcp_risk_coverage_pack.py --check
```

## Why this matters

MCP gives agents a common way to reach tools and context. Skills give
agents reusable workflows for using those tools. Enterprise failure
modes now cross both layers: a safe-looking tool can be poisoned, a safe
looking skill can over-request authority, and a well-scoped context
package can become unsafe when it is handed to a different agent, model,
or runtime.

This pack makes that coverage explicit:

| Risk surface | SecurityRecipes evidence |
| --- | --- |
| MCP token, scope, and authorization failures | MCP Authorization Conformance, Gateway Policy, Agent Identity Ledger, Entitlement Review |
| Tool poisoning and drift | MCP Tool Risk Contract, MCP Tool Surface Drift Sentinel, Connector Intake, Context Poisoning Guard |
| Local server and command execution | MCP STDIO Launch Boundary, Agent Skill Supply Chain, Action Runtime Pack |
| Shadow MCP servers | Connector Intake, Connector Trust, STDIO Launch Boundary, Agentic System BOM |
| Context injection and over-sharing | Secure Context Trust Pack, Context Poisoning Guard, Context Egress Boundary, Memory Boundary, Handoff Boundary |
| Malicious or over-privileged skills | Agent Skill Supply Chain, Gateway Policy, Identity Ledger, Entitlement Review, Action Runtime Pack |
| Skill isolation, scanning, and update drift | Browser Agent Boundary, Measurement Probes, Red-Team Drills, Tool Surface Drift |
| Governance and acquisition evidence | Enterprise Trust Center Export, Agentic System BOM, Telemetry Contract, Run Receipts |

## MCP examples

Get the full coverage summary:

```json
{}
```

Inspect one risk:

```json
{
  "risk_id": "MCP03"
}
```

Inspect one standard:

```json
{
  "standard_id": "owasp-agentic-skills-top-10-2026"
}
```

Find every risk covered by one capability:

```json
{
  "capability_id": "agent-skill-supply-chain-pack"
}
```

Filter for critical risks:

```json
{
  "risk_tier": "critical"
}
```

## Product wedge

The open pack proves that SecurityRecipes understands the current MCP and
skills risk landscape. The commercial layer is the natural hosted
version of those controls:

- live MCP connector discovery and admission,
- tool-surface and annotation drift monitoring,
- skill registry scanning and permission review,
- endpoint launch policy for local MCP servers,
- hosted action firewall APIs,
- signed run and approval receipts,
- telemetry redaction validation,
- customer-private trust-center exports.

That is the path from useful public knowledge to a production control
plane a frontier lab, AI coding platform, cloud provider, or security
vendor could buy.

## Source anchors

Review and regenerate the pack when these sources change:

- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/)
- [Model Context Protocol Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [CISA Secure by Design](https://www.cisa.gov/securebydesign)

## See also

- [Agentic Standards Crosswalk]({{< relref "/security-remediation/agentic-standards-crosswalk" >}})
- [Enterprise Trust Center Export]({{< relref "/security-remediation/enterprise-trust-center-export" >}})
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
- [MCP Tool Surface Drift Sentinel]({{< relref "/security-remediation/mcp-tool-surface-drift-sentinel" >}})
- [Agent Skill Supply Chain]({{< relref "/security-remediation/agent-skill-supply-chain" >}})
- [Agentic Action Runtime Pack]({{< relref "/security-remediation/agentic-action-runtime" >}})
