---
title: "AI Agent Security: How to Secure AI Agent Systems"
linkTitle: Agentic Security
page_kind: collection
weight: 4
lastmod: 2026-07-23
toc: true
sidebar:
  open: false
description: >
  Secure AI agent systems against prompt injection, tool abuse, excessive
  permissions, unsafe memory, connector risk, and weak incident response.
---

AI agent security is the work of protecting a system in which a model can
interpret instructions, retrieve context, use credentials, call tools, retain
memory, communicate with other agents, and produce consequential output. The
security boundary therefore includes more than the model: it includes the
agent host, identities, MCP or A2A connections, browser sessions, data stores,
approval flows, telemetry, and recovery controls.

This page is about **securing the AI-agent system itself**. If your goal is to
use an AI coding agent to fix a conventional dependency, CVE, container, SAST,
secret, or repository-configuration finding, use
[How to Remediate Vulnerabilities with AI Agents](/security-remediation/).
Those are related workstreams, but they answer different questions and require
different evidence.

**Last updated July 23, 2026.** [Stephen M Abbott](/about/#stephen-m-abbott)
maintains this guide with Security Recipes contributors in the public
[source and revision history](https://github.com/stevologic/security-recipes.ai/blob/main/content/agentic-security/_index.md).
See the [review methodology](/about/#editorial-principles) and
[corrections policy](/about/#corrections). The source framework below separates
voluntary risk guidance, protocol requirements, community threat guidance, and
deployment-specific decisions instead of presenting them as one compliance
checklist.

## Choose the right security intent

| Intent | System being secured | Typical finding | Expected output |
| --- | --- | --- | --- |
| [AI vulnerability remediation](/security-remediation/) | Traditional software, dependencies, containers, source, and repository configuration | A CVE, SCA alert, SAST result, exposed secret, or vulnerable artifact | A bounded patch or triage note with tests, source evidence, rollback, and human review |
| **AI agent security** | The agent, model boundary, tools, connectors, identities, memory, context, browser, and control plane | Prompt or context injection, excessive authority, unsafe tool use, cross-agent trust, data egress, or missing recovery evidence | A threat model, control change, policy, evaluation, evidence pack, or incident action with an accountable owner |

Do not close an AI-agent security finding merely because the application code
passed unit tests. The evidence must exercise the relevant trust boundary: for
example, a denied tool call, a rejected token audience, a contained browser
session, a poisoned-context fixture, a revoked delegation, or a replayed
incident scenario.

## Threat-model the whole agent system

Start with a concrete deployment and trace data and authority across it. A
generic list of AI risks is not a substitute for knowing which component can
act, what identity it uses, and what happens when untrusted content influences
the run.

| Boundary | Questions to answer | Minimum evidence |
| --- | --- | --- |
| Instructions and retrieved context | Which text is trusted policy, user input, repository content, web content, tool output, or memory? Can lower-trust text change tool behavior? | Source labels, precedence rules, context filtering, and adversarial fixtures |
| Identity and delegation | Which human, workload, agent, or connector identity is acting? What was delegated, for how long, and by whom? | Identity inventory, scoped grant, expiry or revocation path, and approval receipt |
| Tools and connectors | Which operation can read, write, execute, deploy, send, purchase, or expose data? Does authorization bind the token to the intended resource? | Tool inventory, allowed operation set, token audience validation, and denied-action tests |
| Runtime and browser | Where does code execute, what network and filesystem access exists, and can authenticated state cross workspaces or tenants? | Isolation configuration, egress policy, session boundary, and escape or exfiltration tests |
| Memory and handoffs | What persists across runs, and what claims are trusted when one agent delegates to another? | Retention policy, provenance, handoff contract, and stale-state deletion or revocation test |
| Human control | Which actions require approval, and can a request be confused with approval? | Named approver, action-specific receipt, separation of duties, and fail-closed behavior |
| Telemetry and recovery | Can responders reconstruct the input, identity, tool call, decision, output, and resulting state without logging secrets? | Integrity-bound events, incident playbook, containment action, and recovery rehearsal |

## Establish a production baseline

Apply controls in an order that produces verifiable boundaries rather than a
large policy document with no enforcement:

1. **Inventory the system.** Record models, agent hosts, tools, connectors,
   identities, memory stores, data classes, providers, and owners.
2. **Reduce standing authority.** Start read-only, bind credentials to the
   intended resource, separate human and workload identities, and add
   short-lived escalation only for a named action.
3. **Separate context from commands.** Preserve provenance and trust labels;
   do not let retrieved text silently become executable policy.
4. **Contain execution and egress.** Isolate filesystem, browser, network, and
   secret access according to the run's actual needs.
5. **Evaluate the boundary.** Replay hostile context, denied actions, expired
   grants, protocol errors, handoff failures, and recovery paths with versioned
   fixtures and explicit pass criteria.
6. **Prepare to revoke and recover.** Name the owner, containment action,
   evidence source, rollback or restore path, communication route, and
   condition for returning the agent to service.

The correct control depends on the action and deployment. A read-only research
agent does not need the same gate as an agent that can change production,
operate an authenticated browser, or delegate work across organizations.

## Start with the scenario you operate

- **A new agentic application:** begin with the
  [agentic application intake gate](/security-remediation/agentic-app-intake-gate/),
  [agentic posture snapshot](/security-remediation/agentic-posture-snapshot/),
  and [control-plane blueprint](/security-remediation/agentic-control-plane-blueprint/).
- **An MCP-connected agent:** use the
  [MCP connector trust registry](/security-remediation/mcp-connector-trust-registry/),
  [MCP risk coverage](/security-remediation/mcp-risk-coverage/), and
  [secure-context firewall](/security-remediation/secure-context-firewall/).
- **A browser agent:** establish the
  [browser-agent boundary](/security-remediation/browser-agent-boundary/),
  [context-poisoning guard](/security-remediation/context-poisoning-guard/),
  and [secure-context evaluations](/security-remediation/secure-context-evals/).
- **A multi-agent or remote-agent workflow:** validate
  [A2A Agent Cards](/security-remediation/a2a-agent-card-trust/), constrain the
  [handoff boundary](/security-remediation/agent-handoff-boundary/), and record
  the [identity ledger](/security-remediation/agent-identity-ledger/).
- **A production agent with consequential actions:** add
  [entitlement review](/security-remediation/agentic-entitlement-review/),
  [approval receipts](/security-remediation/agentic-approval-receipts/),
  [measurement probes](/security-remediation/agentic-measurement-probes/), and
  an [incident-response pack](/security-remediation/agentic-incident-response-pack/).

## Control directory for securing AI agent systems

Use this directory after the system and its owners are known. Each control page
defines a narrower artifact or decision; it does not grant authority to deploy,
rotate credentials, change production, or accept residual risk.

### Agent identity, delegated authority, and trust

- [Govern the agent skill supply chain](/security-remediation/agent-skill-supply-chain/) across rules files, hooks, extensions, permissions, provenance, and runtime loading.
- [Validate A2A Agent Cards](/security-remediation/a2a-agent-card-trust/) before trusting a remote agent's declared identity or capabilities.
- [Inventory agent capabilities and risk](/security-remediation/agent-capability-risk-register/) so each tool and action has an accountable owner.
- [Constrain agent-to-agent handoffs](/security-remediation/agent-handoff-boundary/) when work crosses identities, scopes, or execution environments.
- [Record identity and delegation chains](/security-remediation/agent-identity-ledger/) for reviewer-visible authority and provenance.
- [Bound persistent agent memory](/security-remediation/agent-memory-boundary/) so later runs cannot silently inherit unsafe state.
- [Build an agent trust fabric](/security-remediation/agent-trust-fabric/) that joins identity, policy, evidence, and revocation signals.

### Governance, posture, and risk routing

- [Gate new agentic applications](/security-remediation/agentic-app-intake-gate/) before they receive repository or production-adjacent access.
- [Design an agentic control plane](/security-remediation/agentic-control-plane-blueprint/) for admission, authorization, telemetry, and stop controls.
- [Measure current agentic posture](/security-remediation/agentic-posture-snapshot/) with a reproducible inventory of controls and gaps.
- [Score deployment readiness](/security-remediation/agentic-readiness-scorecard/) before an agent receives broader data, tool, or production authority.
- [Crosswalk agentic standards](/security-remediation/agentic-standards-crosswalk/) without presenting voluntary guidance or draft protocols as binding requirements.
- [Track the agentic threat radar](/security-remediation/agentic-threat-radar/) so new threat evidence reaches owned controls and evaluations.
- [Operate the workflow control plane](/security-remediation/control-plane/) across admission, execution, review, and release gates.
- [Score agentic risk with AIVSS](/security-remediation/agentic-aivss-risk-scoring/) when an AI-system finding needs consistent prioritization evidence.
- [Route model-provider traffic safely](/security-remediation/model-provider-routing-gate/) when data sensitivity or jurisdiction changes the allowed provider.
- [Assemble an agentic assurance pack](/security-remediation/agentic-assurance-pack/) for architecture, security, and risk review.
- [Bound a design-partner pilot](/security-remediation/design-partner-pilot-pack/) with named owners, success criteria, stop signals, and recovery evidence.
- [Prepare hosted MCP readiness evidence](/security-remediation/hosted-mcp-readiness-pack/) before exposing a managed connector service.
- [Export enterprise trust-center evidence](/security-remediation/enterprise-trust-center-export/) without overstating unverified control claims.
- [Prepare a buyer diligence brief](/security-remediation/secure-context-buyer-diligence-brief/) and [customer proof pack](/security-remediation/secure-context-customer-proof-pack/) from reviewable evidence rather than marketing assertions.

### Authorization, exposure, and runtime boundaries

- [Review agent entitlements](/security-remediation/agentic-entitlement-review/) to find excessive, stale, or unowned permissions.
- [Map agentic exposure paths](/security-remediation/agentic-exposure-graph/) from untrusted input through tools, identities, and consequential actions.
- [Constrain the agentic action runtime](/security-remediation/agentic-action-runtime/) so consequential operations bind identity, policy, approval, evidence, and stop behavior.
- [Isolate browser-agent workspaces](/security-remediation/browser-agent-boundary/) before an agent handles authenticated sessions or downloaded content.
- [Guard against context poisoning](/security-remediation/context-poisoning-guard/) when retrieved text can influence privileged tool use.
- [Enforce a context-egress boundary](/security-remediation/context-egress-boundary/) before retrieved data, memory, or tool output can leave its approved trust zone.
- [Enforce a secure-context firewall](/security-remediation/secure-context-firewall/) between untrusted evidence and executable instructions.

### Protocols, connectors, and system inventory

- [Test agent protocol conformance](/security-remediation/agentic-protocol-conformance/) for deterministic identity, error, and authorization behavior.
- [Maintain an MCP connector trust registry](/security-remediation/mcp-connector-trust-registry/) with ownership, provenance, and review state.
- [Test MCP authorization conformance](/security-remediation/mcp-authorization-conformance/) for token audience, resource binding, delegation, and failure behavior.
- [Scan new MCP connector intake](/security-remediation/mcp-connector-intake-scanner/) before a server, tool, or credential enters the approved registry.
- [Constrain MCP elicitation](/security-remediation/mcp-elicitation-boundary/) so a server cannot turn a data request into hidden approval or secret collection.
- [Apply an MCP gateway policy](/security-remediation/mcp-gateway-policy/) for admission, routing, authentication, authorization, telemetry, and revocation.
- [Evaluate MCP runtime decisions](/security-remediation/mcp-runtime-decision-evaluator/) against versioned allow, deny, approval, and stop fixtures.
- [Secure the MCP stdio launch boundary](/security-remediation/mcp-stdio-launch-boundary/) around executable provenance, arguments, environment, and inherited privileges.
- [Publish an MCP tool risk contract](/security-remediation/mcp-tool-risk-contract/) for the data, side effects, authority, and evidence of every operation.
- [Detect MCP tool-surface drift](/security-remediation/mcp-tool-surface-drift-sentinel/) before changed schemas or capabilities silently bypass review.
- [Measure MCP and agent-skill risk coverage](/security-remediation/mcp-risk-coverage/) against the tool and connector surface actually in use.
- [Generate an agentic system BOM](/security-remediation/agentic-system-bom/) for models, agents, tools, connectors, identities, and data stores.
- [Watch authoritative sources for drift](/security-remediation/agentic-source-freshness-watch/) before stale guidance reaches an agent.

### Evidence, evaluation, and incident readiness

- [Prepare an agentic incident-response pack](/security-remediation/agentic-incident-response-pack/) with containment, evidence, and recovery procedures.
- [Run agentic measurement probes](/security-remediation/agentic-measurement-probes/) against the controls that should stop or constrain a run.
- [Run agentic red-team drills](/security-remediation/agentic-red-team-drills/) with owned scenarios, safe boundaries, findings, and retest evidence.
- [Replay adversarial agent scenarios](/security-remediation/agentic-red-team-replay-harness/) to prove fixes remain effective after policy or model changes.
- [Evaluate secure-context behavior](/security-remediation/secure-context-evals/) with versioned fixtures and reviewable pass criteria.
- [Capture approval receipts](/security-remediation/agentic-approval-receipts/) for high-impact actions that require explicit human authorization.
- [Capture agentic run receipts](/security-remediation/agentic-run-receipts/) that bind inputs, identity, policy, tools, approvals, outputs, and resulting state.
- [Define an agentic telemetry contract](/security-remediation/agentic-telemetry-contract/) for reconstructing consequential runs without logging secrets.
- [Build an agentic SOC detection pack](/security-remediation/agentic-soc-detection-pack/) around observable misuse, escalation, egress, and containment signals.
- [Publish a secure-context evidence contract](/security-remediation/secure-context-evidence-contract/) so reviewers know which claims and artifacts are required.

### Secure-context provenance and enterprise assurance

- [Model catastrophic agentic risk](/security-remediation/agentic-catastrophic-risk-annex/) for low-frequency, high-impact failure paths.
- [Attest secure-context controls](/security-remediation/secure-context-attestation/) with integrity-bound evidence rather than self-reported claims.
- [Trace secure-context lineage](/security-remediation/secure-context-lineage-ledger/) from source acquisition through transformation and agent use.
- [Assemble a secure-context trust pack](/security-remediation/secure-context-trust-pack/) for security, procurement, and architecture review.
- [Quantify secure-context value](/security-remediation/secure-context-value-model/) using measurable risk and operating outcomes.
- [Apply a critical-infrastructure profile](/security-remediation/critical-infrastructure-secure-context/) where safety, availability, and regulatory evidence raise the bar.

## Evidence required before calling the system secure

A control description is not proof that a deployed agent obeys it. Preserve a
reviewable evidence set that includes:

- the deployed system inventory and versioned configuration;
- the identity, delegation, allowed-tool, and data-access boundaries;
- the source and trust classification of instructions, context, and memory;
- negative tests that prove prohibited actions fail closed;
- integrity-bound tool, approval, handoff, and egress events;
- adversarial evaluations tied to the deployed model, policy, and connector
  versions;
- incident containment, credential revocation, rollback, and restore evidence;
- named owners for the system, each consequential action, and residual risk.

Separate observed evidence from operator assertions and analyst inference. If
the test environment, identity provider, connector implementation, or model
version differs from production, record that gap instead of treating the test
as production proof.

## Primary sources and interpretation boundaries

Use the source that is authoritative for the claim being made:

- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
  is a voluntary risk-management framework. NIST notes that AI RMF 1.0 is being
  revised; preserve the version used in every assessment.
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  adapts the AI RMF to generative-AI risks. It is not a product configuration
  guide or automatic certification.
- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
  tracks emerging work on agent standards, protocols, identity, security, and
  evaluation. Its initiatives, RFIs, concept papers, and drafts must be labeled
  by publication status rather than presented as final requirements.
- [OWASP Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)
  provides community threat and control work for agentic systems. Validate its
  guidance against the deployed product and current source material.
- [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  and [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
  govern MCP-specific boundaries such as authorization, token audience, and
  confused-deputy risks; they do not secure the rest of the agent application.
- [A2A Protocol Specification](https://a2a-protocol.org/latest/specification/)
  and [enterprise guidance](https://a2a-protocol.org/latest/topics/enterprise-ready/)
  define protocol and implementation considerations for agent-to-agent
  communication. Pin the version evaluated because the protocol can evolve.
- [MITRE ATLAS](https://atlas.mitre.org/) is a knowledge base for adversary
  tactics and techniques involving AI-enabled systems. Use it to structure
  scenarios, not as evidence that a control is operating.
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
  supplies general incident-response guidance; the agent-specific containment
  and evidence plan still has to be designed and exercised for the deployment.

No single source above proves that an AI agent system is secure. Product
documentation is authoritative for supported configuration, protocol
specifications are authoritative only within their protocol boundary, and the
deployment's own tests and evidence must prove the controls that operators
rely on.

## Related paths

- [Compare AI coding agents for vulnerability remediation](/agents/)
- [How to remediate traditional software vulnerabilities with AI agents](/security-remediation/)
- [Connect scoped context through MCP](/mcp-servers/)
- [Integrate recipes and security context into an existing agent](/docs/agent-integration/)
