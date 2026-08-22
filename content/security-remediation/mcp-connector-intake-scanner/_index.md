---
title: MCP Connector Intake Scanner
linkTitle: Connector Intake Scanner
weight: 7
date: 2026-05-02
lastmod: 2026-08-21
sidebar:
  exclude: true
description: >
  Score authentication, token, network, schema, data, write, approval,
  evidence, and red-team risk before promoting a new or changed MCP connector.
breadcrumb_parent: /agentic-security/
---

{{< callout type="info" >}}
**Why this page exists.** MCP connector adoption is outrunning manual
security review. The intake scanner turns a proposed MCP server into a
reviewable admission decision before it becomes a trusted enterprise
connector.
{{< /callout >}}

## The product bet

SecurityRecipes should not only document safe connectors after approval.
It should own the **pre-approval gate**: the repeatable review that says
whether a new MCP server is safe to pilot, must be held for missing
controls, or should be denied until redesigned.

That is a high-value enterprise surface because the reviewer's hard
question is no longer "can an agent call a tool?" It is:

- Which MCP servers are entering the environment?
- Which tokens, scopes, networks, data classes, and write operations do
  they expose?
- Which tool descriptions and schemas can drift after approval?
- Which server should be held before an agent can see it?
- Which evidence proves the intake decision was not a chat-based guess?

The MCP Connector Intake Scanner answers those questions with a
source-controlled candidate registry, deterministic scoring, generated
promotion plans, and an MCP-readable evidence pack.

{{< playbook-workflow >}}

## What was added

- `data/mcp/connector-intake-candidates.json` - source-controlled
  intake examples and the review contract for candidate MCP servers.
- `data/evidence/mcp-connector-intake-pack.json` - generated intake
  decisions, risk findings, control gaps, registry patch previews, and
  red-team drills.
- `recipes_mcp_connector_intake_pack` - MCP tool for retrieving the pack
  by candidate ID, namespace, decision, or full summary.

Run it locally from the repo root:

```bash
python3 scripts/generate_mcp_connector_intake_pack.py
python3 scripts/generate_mcp_connector_intake_pack.py --check
```

## Intake decisions

| Decision | Meaning |
| --- | --- |
| `approve_for_registry_candidate` | Candidate has the required controls for its trust tier and can be proposed for registry addition. |
| `pilot_with_gateway_controls` | Candidate can enter a guarded pilot after declared gaps are closed or enforced by the gateway. |
| `hold_for_controls` | Candidate has critical or high-risk gaps that block pilot use. |
| `deny_until_redesigned` | Candidate requests prohibited data or unsafe high-impact authority that must be split or removed. |

The scanner recommends the target trust tier, then compares the
candidate's declared controls to the minimum controls for that tier.
It treats secrets, raw access tokens, production credentials, signing
material, and unrestricted bulk personal data as prohibited context.

## What the scanner checks

| Area | Examples |
| --- | --- |
| Authorization | Resource indicators, audience validation, PKCE, short-lived identity, token-passthrough denial. |
| Network | Private ranges, cloud metadata endpoints, redirect behavior, external host allowlists. |
| Tool surface | Mutating tools, destructive operations, tool descriptions, input schema pins, output schema pins. |
| Data classes | Source code, internal findings, untrusted web content, production credentials, signing material. |
| Evidence | Gateway audit, owner records, review events, package provenance, approval records. |
| Promotion | Registry patch preview, red-team drills, owner and escalation requirements. |

The output is intentionally plain JSON. A gateway, CI job, procurement
review, or AI platform service can consume it without depending on a
model to interpret the policy.

## Current sample decisions

The initial candidates model three realistic enterprise intake outcomes:

- **GitHub Remediation Branch Writer**: a scoped-write connector that is
  close to pilot-ready because it declares OAuth audience validation,
  short-lived workload identity, branch scope enforcement, review gates,
  schema pins, and tool-call audit.
- **Local Browser Research STDIO Server**: held because local process
  launch, broad network egress, redirects, missing schema pins, and
  untrusted web content make it unsafe until hardened.
- **Container Registry Publisher**: denied until redesigned because
  registry publishing, tag deletion, token passthrough, private network
  reachability, and production credential exposure belong behind a
  separate approval-only or hard-denied surface.

## Industry alignment

This feature follows current primary guidance:

- [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
  requires resource-aware authorization and strict token handling for
  HTTP-based transports.
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)
  calls out confused deputy risk, forbidden token passthrough, SSRF,
  session safety, local server compromise, and scope minimization.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)
  elevates tool misuse, identity abuse, supply-chain exposure, cascading
  failures, and rogue agent behavior.
- [OWASP Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)
  now includes third-party MCP server guidance, secure MCP server
  development, and an Agentic AI security landscape.
- [OWASP GenAI Exploit Round-up Q1 2026](https://genai.owasp.org/2026/04/14/owasp-genai-exploit-round-up-report-q1-2026/)
  shows the shift from theoretical model risk toward identities,
  orchestration layers, permissions, validation controls, and supply
  chains.
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
  keeps the governance frame: map the system, measure risk, manage
  controls, and maintain evidence over time.

## How a gateway uses it

1. Ingest a proposed MCP server card, package record, or tool manifest
   into the candidate registry.
2. Run the generator and review `intake_decision`, `risk_findings`, and
   `control_gaps`.
3. If the decision is `pilot_with_gateway_controls`, enforce the missing
   controls in the MCP gateway before exposing the namespace.
4. If the decision is `hold_for_controls`, block agent access until the
   owner closes the listed gaps.
5. If the decision is `deny_until_redesigned`, split the connector into a
   safer read-only surface or keep the operation hard-denied.
6. After approval, copy the `registry_patch_preview` into the
   [Connector Trust Registry]({{< relref "/security-remediation/mcp-connector-trust-registry" >}})
   and run connector drift drills before production promotion.

## CI contract

The generator fails if:

- The candidate registry is malformed.
- A candidate has no owner, auth strategy, tool surface, data classes,
  declared controls, or evidence.
- A namespace is duplicated, wildcarded, or malformed.
- A tool lacks required booleans for mutation, destructive impact, or
  untrusted content handling.
- A generated intake decision falls outside the allowed decision set.
- The checked-in pack is stale in `--check` mode.

That gives SecurityRecipes a credible path from open knowledge to hosted-ready
MCP governance: public intake logic, private hosted discovery, schema
diffing, continuous connector recertification, and trust-center export.

## See also

- [MCP Connector Trust Registry]({{< relref "/security-remediation/mcp-connector-trust-registry" >}})
  - production connector contracts after intake.
- [MCP Gateway Policy Pack]({{< relref "/security-remediation/mcp-gateway-policy" >}})
  - runtime allow, hold, deny, and kill-session decisions.
- [Agentic Threat Radar]({{< relref "/security-remediation/agentic-threat-radar" >}})
  - source-backed market and threat signals that made this feature the
  next implementation target.
- [Agentic Red-Team Drill Pack]({{< relref "/security-remediation/agentic-red-team-drills" >}})
  - the replay suite connectors must survive before promotion.
