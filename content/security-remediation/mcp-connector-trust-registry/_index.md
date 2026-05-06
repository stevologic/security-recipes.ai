---
title: MCP Connector Trust Registry
linkTitle: Connector Trust Registry
weight: 8
sidebar:
  open: true
description: >
  A generated MCP connector trust pack that inventories every workflow
  namespace, trust tier, access mode, control requirement, evidence
  record, promotion criterion, and runtime kill signal.
---

{{< callout type="info" >}}
**Why this page exists.** MCP makes tool access easy. Enterprise rollout
requires the missing trust layer: which connectors are approved, which
are read-only, which can write, which require approval, and which
evidence proves the connector stayed inside scope.
{{< /callout >}}

## The product bet

SecurityRecipes is positioning itself as the secure context layer for
agentic remediation. That cannot stop at recipes, prompts, or even
gateway policy. A serious AI platform team will ask:

- Which MCP connector namespaces are actually approved for production?
- Which connector can read findings, write branches, write tickets, or
  stage high-impact operations?
- Which auth, consent, network, result-inspection, and audit controls are
  required before an agent may call the connector?
- Which evidence records prove the connector stayed inside its contract?

The MCP Connector Trust Registry is the answer. It turns the connector
catalog from prose into an inventory a gateway, agent host, auditor, or
buyer can consume directly.

## What was added

The registry layer has three artifacts and one MCP tool:

- `data/mcp/connector-trust-registry.json` - the source-controlled
  connector inventory and trust-tier model.
- `scripts/generate_mcp_connector_trust_pack.py` - a dependency-free
  generator and validator with `--check` mode for CI drift detection.
- `data/evidence/mcp-connector-trust-pack.json` - the generated trust
  pack that joins the registry, workflow manifest, and gateway policy.
- `recipes_mcp_connector_trust_pack` - an MCP tool that exposes the pack
  by connector ID, namespace, workflow ID, or full summary.

Run it locally from the repo root:

```bash
python3 scripts/generate_mcp_connector_trust_pack.py
python3 scripts/generate_mcp_connector_trust_pack.py --check
```

GitHub Actions runs the check before the Hugo build, so a workflow cannot
add an MCP namespace without adding the connector trust contract.

## Trust tiers

| Tier | Meaning | Typical connector |
| --- | --- | --- |
| `tier_0_public_context` | Read-only public context with no enterprise data exposure. | SecurityRecipes public recipes. |
| `tier_1_internal_read` | Read-only enterprise context such as findings, SBOMs, CI results, or simulation output. | Advisory feeds, scanner findings, CI run readers. |
| `tier_2_scoped_write` | Bounded write access with branch, ticket, and review controls. | Repository branch writer, security ticket workspace. |
| `tier_3_approval_required` | High-impact staged operations requiring a typed human approval record. | Registry quarantine controller. |
| `tier_4_prohibited` | Direct access to secrets, signers, production deploy, registry publish, or live funds movement. | Must remain hard-denied. |

Every tier declares minimum controls. For example, `tier_2_scoped_write`
requires short-lived workload identity, token-passthrough denial, pinned
tool descriptions, tool-result inspection, private-network egress
denial, tool-call audit, session binding, write-scope enforcement, and
human review before merge.

## What is inside the generated pack

| Section | Purpose |
| --- | --- |
| `connector_trust_summary` | Connector counts, trust-tier coverage, access-mode counts, production/pilot split, and workflow namespace coverage. |
| `connectors` | One trust contract per MCP namespace: owner, data classes, allowed operations, forbidden operations, controls, evidence, promotion criteria, and kill signals. |
| `workflow_connector_map` | Per-workflow mapping from MCP namespace to connector ID, access mode, gateway decision, status, and trust tier. |
| `policy_alignment` | Gateway default decision, policy ID, namespace coverage, policy decisions, and manifest hash alignment. |
| `enterprise_adoption_packet` | Buyer questions answered, first-use guidance, and sales motion for hosted gateway and evidence exports. |
| `source_artifacts` | Hashes for the registry, workflow manifest, and gateway policy pack. |

The initial registry covers all workflow MCP namespaces currently used by
the control plane: findings, repository writes, tickets, advisories,
SBOM inventory, CI reads, image catalogs, artifact inventory, registry
quarantine, incident notes, approved recipes, payment simulation, and
protocol simulation.

## Industry alignment

This feature follows current primary guidance rather than inventing a
private taxonomy:

- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
  names MCP-specific risks such as confused deputy, token passthrough,
  SSRF, session hijacking, local server compromise, and scope
  minimization.
- [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  frames restricted MCP server access around authorization and resource
  owner consent.
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)
  elevates tool misuse, identity and privilege abuse, agentic supply
  chain, cascading failures, and rogue agents.
- [OWASP MCP Tool Poisoning](https://owasp.org/www-community/attacks/MCP_Tool_Poisoning)
  describes the runtime trust gap where tool responses become
  prompt-layer input.
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
  and the [NIST Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  push organizations toward governed, measured, and managed AI system
  risk.

The registry converts those ideas into operating data: connector
inventory, access modes, evidence, and runtime stop conditions.

## How gateways use it

An MCP gateway should load this pack alongside the
[MCP Gateway Policy Pack]({{< relref "/security-remediation/mcp-gateway-policy" >}})
and the
[Agent Identity & Delegation Ledger]({{< relref "/security-remediation/agent-identity-ledger" >}}):

1. Match the tool call to `namespace`.
2. Confirm the namespace exists in the connector trust pack.
3. Confirm the connector access mode permits the requested operation.
4. Confirm the workflow policy allows that namespace and access mode.
5. Apply tier controls before execution.
6. Inspect tool results before returning them to the agent.
7. Record evidence and kill the session if a connector kill signal fires.

This keeps the model out of the policy business. The agent asks for a
tool; the gateway makes the trust decision.

## CI contract

The generator fails if:

- A connector is missing required owner, evidence, promotion, kill, data,
  or operation fields.
- A connector namespace is duplicated, wildcarded, or malformed.
- A workflow MCP namespace is missing from the registry.
- A workflow access mode is not allowed by the registry connector.
- A write connector lacks write-scope enforcement.
- An approval-required connector lacks typed approval and two-key review.
- The gateway policy hash no longer matches the workflow manifest.
- The generated pack is stale in `--check` mode.

That turns MCP trust from a review meeting into a build contract.

## See also

- [Production MCP Server]({{< relref "/mcp-servers" >}})
  - the connector and gateway vision this registry operationalizes.
- [MCP Gateway Policy Pack]({{< relref "/security-remediation/mcp-gateway-policy" >}})
  - the runtime decision contract.
- [Agent Identity & Delegation Ledger]({{< relref "/security-remediation/agent-identity-ledger" >}})
  - the non-human identity view of the same scope.
- [Runtime Controls]({{< relref "/security-remediation/runtime-controls" >}})
  - inline action proxies, result inspection, and session disablement.
- [Agentic Assurance Pack]({{< relref "/security-remediation/agentic-assurance-pack" >}})
  - the broader buyer and auditor evidence export.
