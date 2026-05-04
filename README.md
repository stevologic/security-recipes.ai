# security-recipes.ai

A Hugo docs site (built with the [Hextra](https://imfing.github.io/hextra/)
theme) — published as **[security-recipes.ai](https://security-recipes.ai/)** —
positioning SecurityRecipes as **the trusted secure context layer for agentic AI and MCP servers**.

It combines:
- **Open knowledge (MIT Licensed):** community recipes, docs, and prompt playbooks.
- **Production MCP path:** free and premium MCP access, including premium-only
  features delivered through MCP for enterprise operations.

## Vision

The agentic landscape is moving faster than any single team's internal
documentation can keep up with. New models ship monthly, new agent
platforms launch quarterly, MCP connectors proliferate across every
SaaS an engineering org touches, and the guardrails that kept a pilot
safe last quarter may not cover the capabilities shipping next quarter.

SecurityRecipes is designed to become a high-trust foundation for agentic security operations in 2026 and beyond.

This project exists for two reasons:

1. **A working reference for agentic security remediation.** A
   tool-agnostic, reviewer-gated, measurable shape of workflow that
   any security engineering team can adopt, adapt, and fork — rather
   than starting from a blank page every time a new capability lands.
2. **A common language for agentic enablement inside companies
   embracing this transformational moment.** Engineering leaders,
   security teams, platform teams, and compliance counterparts need
   a shared vocabulary and a shared mental model to have the same
   conversation. This site is designed to be that shared artifact —
   something a team can point at internally ("this is the shape we're
   adopting, this is the maturity stage we're in, this is the
   evidence we're producing") instead of re-explaining first
   principles in every meeting.

The recipes, prompts, reference workflows, metrics, reviewer
playbook, rollout model, compliance mapping, and threat model are
all written to be **industry-generic**: rename the labels, swap the
tools, bring your own policy — the shape travels. As the landscape
evolves, so does this site. Forks are encouraged; contributions back
are the whole point.

## Standards alignment

SecurityRecipes content is designed to align with established security references:

- **OWASP Top 10** for common application security failure modes.
- **NIST AI Risk Management Framework (AI RMF 1.0)** for governable AI system lifecycle controls.
- **Least-privilege + auditable control design** reflected in MCP guidance and reviewer-gated workflows.

## What's in the site

The site is a polished landing page backed by a full docs experience,
and ships with:

- **Visual Guide** - four GPT Image-2 walkthrough panels that show how
  to explore the repo, run a first agent PR, operate workflows, and
  scale through MCP.
- **Fundamentals** — plain-English primer on agents, prompts, MCP,
  and the vocabulary the rest of the site assumes.
- **Agents** — five per-tool recipe pages with install / configure /
  dispatch / guardrail sections.
- **Prompt Library** — tool-agnostic and per-tool prompts, including
  full OWASP Top 10 (2026) audit and remediation playbooks.
- **MCP Servers** — connector catalog, onboarding checklist, and a
  write-up on MCP gateways (when and why to put one in front of your
  connectors).
- **Agentic Security Remediation** — reference workflows a security
  team can operate on engineering's behalf: Sensitive Data Element
  and Vulnerable Dependency remediation.
- **MCP Connector Trust Registry** - generated connector trust evidence
  for every workflow MCP namespace: tiers, access modes, required
  controls, evidence, promotion criteria, and kill signals.
- **MCP Runtime Decision Evaluator** - deterministic allow, hold, deny,
  and kill-session decisions for each agent tool call before it reaches
  enterprise systems.
- **Agentic Assurance Pack** — generated enterprise evidence that maps
  workflows, MCP policy, control objectives, and AI/Agent BOM seed data
  to current agentic AI security expectations.
- **Agentic Red-Team Drill Pack** - generated adversarial eval drills
  that replay prompt injection, goal hijack, approval bypass, token
  passthrough, connector drift, runaway-loop, and evidence-integrity
  failure modes across approved workflows.
- **Agentic Readiness Scorecard** - generated scale, pilot, gate, and
  block decisions for approved workflows using control-plane, MCP
  policy, connector trust, identity, assurance, and red-team evidence.
- **Agent Identity & Delegation Ledger** - generated non-human identity
  contracts for approved agents, delegated MCP scopes, explicit denies,
  review ownership, runtime revocation, and audit evidence.
- **Agentic System BOM** - generated Agent/AI Bill of Materials for
  workflows, agent classes, identities, MCP connectors, policy
  components, evidence artifacts, knowledge sources, eval drills, and
  drift triggers.
- **Agentic Run Receipts** - generated proof templates for every governed
  agent run: identity issuance, secure-context retrieval, poisoning scan,
  MCP tool decisions, context egress, human approvals, verifier output,
  evidence retention, run closure, and identity revocation.
- **Agentic Measurement Probes** - generated traceability probes for
  context integrity, MCP authorization, identity, memory, egress,
  red-team replay, readiness, run receipts, and threat alignment.
- **Agentic Exposure Graph** - generated relationship graph and
  risk-ranked paths across secure context, agent identities, MCP
  namespaces, authorization decisions, egress policy, readiness,
  capability risk, and run receipts.
- **Agentic App Intake Gate** - generated launch-review evidence and
  runtime decisions for agentic apps, agent hosts, and production MCP
  rollouts across autonomy, data, tools, memory, handoffs, guardrails,
  telemetry, and approval proof.
- **Model Provider Routing Gate** - generated provider/model route
  decisions before secure context crosses a frontier, private, local, or
  unsanctioned model boundary.
- **Secure Context Trust Pack** - generated provenance, source-hash,
  trust-tier, retrieval-policy, and workflow context-package evidence for
  the secure context layer agents consume through MCP.
- **Secure Context Lineage Ledger** - generated source-to-run lineage
  for context hashes, attestations, poisoning scans, retrieval decisions,
  model routes, egress, handoffs, telemetry, run receipts, and reuse.
- **Secure Context Evals** - generated scenario-backed evals for
  retrieval correctness, attestation holds, context-poisoning resilience,
  egress safety, runtime answer contracts, and agent-to-agent handoff
  boundaries.
- **Secure Context Release Gate** - generated release manifests for
  open-reference, production MCP, and trust-center context channels with
  source hashes, signature requirements, poisoning/eval blockers, and
  rollback signals.
- **Agent Handoff Boundary** - generated protocol trust evidence and
  deterministic runtime decisions for MCP, A2A, provider-native
  subagents, and human approval bridges before context crosses an agent
  boundary.
- **A2A Agent Card Trust Profile** - generated remote-agent intake
  evidence and deterministic allow, pilot, hold, deny, or kill decisions
  for A2A Agent Cards before secure context crosses into opaque agents.
- **Context Poisoning Guard** - generated pre-retrieval scan evidence for
  prompt-injection, tool-poisoning, approval-bypass, hidden-instruction,
  encoded-payload, and exfiltration markers across registered context
  roots.
- **Secure Context Firewall** - deterministic allow, hold, deny, and
  kill-session decisions before MCP-backed context is returned to an
  agent.
- **Context Egress Boundary** - generated data-class, destination-class,
  tenant-boundary, DPA, zero-data-retention, residency, and secret-egress
  decisions before retrieved context leaves a model, MCP, telemetry,
  public-corpus, or tenant boundary.
- **Agentic Threat Radar** - generated source-backed threat signals,
  buyer triggers, mapped controls, and product roadmap priorities for
  agentic AI and MCP security.
- **Agentic Standards Crosswalk** - generated OWASP, NIST, MCP,
  OpenAI, and Anthropic standards-to-evidence map for buyer diligence,
  AI platform architecture review, and MCP-native control review.
- **MCP and Agentic Skills Risk Coverage** - generated OWASP MCP Top 10
  and OWASP Agentic Skills Top 10 coverage map across evidence packs,
  MCP tools, and hosted product wedges.
- **Agentic Protocol Conformance Pack** - generated MCP and A2A protocol
  conformance evidence with deterministic runtime decisions for
  authorization metadata, tool annotations, tool-surface drift, Agent
  Cards, identity, handoff, and prompt-injection boundaries.
- **Agentic Control Plane Blueprint** - generated architecture, buyer
  diligence map, MCP evidence surface, and commercialization path for
  the secure context layer.
- **Agentic Incident Response Pack** - generated incident classes,
  containment phases, forensic evidence bindings, replay gates, tabletop
  cases, and deterministic runtime response decisions for secure-context
  and MCP failures.
- **Agentic Approval Receipt Pack** - generated scope-bound approval
  profiles, expiry, reviewer-role, separation-of-duties, risk-acceptance,
  and runtime receipt decisions before privileged agent actions execute.
- **MCP Connector Intake Scanner** - generated admission decisions,
  control gaps, registry patch previews, and red-team drills for new or
  changed MCP servers before connector promotion.
- **MCP Authorization Conformance** - generated resource, audience,
  PKCE, token-passthrough, session-binding, and scope-drift decisions
  before MCP tool calls execute.
- **MCP Tool Risk Contract** - generated annotation-trust, workflow-scope,
  and session-combination decisions before MCP tools are invoked.
- **Automation, not agentic** — what deterministic tooling still does
  best, and where agents should *not* replace it.
- **Contribute** — fork-and-PR guide for adding recipes, prompts, or
  workflows.

It's designed to be hosted on **GitHub Pages** with zero manual deploy
steps: pushing to `main` rebuilds and publishes. The Repository and
Contribute links resolve **dynamically** to whichever repo hosts the
site — no find-and-replace required before forking.

---

## Visual guide: how to use this repo

This repo is easiest to use as a path, not a pile of pages. The
visual guide below shows the intended reading order and the operational
loop the site is designed to support.

### 1. Start with the map

![Visual map of the security-recipes.ai docs showing Start, Search, Pick, and Read across Quick Start, Agents, Prompt Library, MCP Servers, and Security Remediation.](static/images/how-to-use/visual-site-map.png)

Begin with **Quick Start** when you want a five-minute path, use search
when you already know the problem, then pick the section that matches
your job: agent setup, prompt reuse, MCP access, or security-operated
remediation workflows.

### 2. Run one safe agent PR

![Workflow showing Pick Agent, Add Rules, Draft PR, and Review for a first reviewer-gated remediation pull request.](static/images/how-to-use/first-agent-pr.png)

Pick one agent your team already uses, add the matching house-rules
file from the recipe or prompt library, let the agent draft a branch
and pull request, and review it like any other human-authored change.

### 3. Operate remediation as a security workflow

![Security operations workflow showing Intake, Gate, Sandbox, Evidence, and Review.](static/images/how-to-use/security-workflow-ops.png)

For scale, treat agentic remediation as a security-owned workflow:
findings enter a queue, eligibility gates decide what can run, the
agent works in a bounded sandbox, evidence is produced, and humans keep
the merge decision.

### 4. Use MCP as the context layer

![Architecture view showing Agents, Recipes, MCP Server, Policy, Audit, and Scoped Tools.](static/images/how-to-use/mcp-context-layer.png)

The production shape is MCP-backed: agents retrieve recipe context,
policy narrows tool access, scoped connectors reach enterprise systems,
and audit records make the whole run reviewable.

The same walkthrough is available in the Hugo site on the
[Visual Guide page](content/how-to-use/_index.md).

---

## Quick start

### Prerequisites

- [Hugo extended](https://gohugo.io/installation/) `>= 0.139`
- [Go](https://go.dev/dl/) `>= 1.21` (Hextra is loaded as a Hugo Module)
- Git

### Run locally

Run from the repository root, the directory that contains `hugo.yaml`.
The current layout does not use a nested site directory.

```bash
hugo mod get -u           # fetch the Hextra theme
hugo server -D            # http://localhost:1313
```

### Run in Docker

A multi-stage `Dockerfile` builds the site with Hugo extended and
serves it from `nginx:alpine`:

```bash
# from the repository root
docker build -t security-recipes .
docker run --rm -p 8080:80 security-recipes
# open http://localhost:8080
```

### Add a recipe for a new agent

```bash
hugo new content <agent_name>/_index.md
```

Then edit the file. The archetype (`archetypes/default.md`) gives you a
ready-made skeleton with the four required sections (Install →
Configure → Dispatch → Guardrails).

### Contribute a prompt

Drop a new Markdown file under `content/prompt-library/<tool>/` (or
under `content/prompt-library/general/` for tool-agnostic prompts).
Every entry carries frontmatter with `author`, `team`, `maturity`, and
the `model` it was validated against. See any existing prompt — for
example, `content/prompt-library/general/owasp-top-10-2026-audit.md` —
as a template.


### Generate CVE recipe drafts from GitHub Advisory Database

If you have a local checkout of `github/advisory-database`, you can
bulk-generate draft CVE recipe pages (High/Critical entries with CVE IDs
and a fixed version event) using:

```bash
python scripts/generate_cve_recipes_from_ghad.py \
  --advisory-root /path/to/advisory-database/advisories/github-reviewed \
  --output-root content/prompt-library/cve/generated \
  --report-path data/ghad-assessment/latest.json \
  --published-year 2026
```

The generator assesses **all High/Critical advisories** in the input
path (optionally filtered by `--published-year`) and records one decision per advisory in the JSON report
(`generated`, `skipped_no_cve`, `skipped_no_fix`, `skipped_no_ranges`).
Generated pages are intentionally marked **draft** so maintainers can
review wording and add CVE-specific nuances before publishing. After
generation, iterate through each `generated` result in the assessment
report and either (a) promote to a curated file in
`content/prompt-library/cve/` or (b) discard if no real remediation path
exists.

---

### Generate the agentic assurance pack

The assurance pack joins the workflow control plane, MCP gateway policy,
control map, and validation report into a buyer- and auditor-ready JSON
artifact:

```bash
python3 scripts/generate_agentic_assurance_pack.py
python3 scripts/generate_agentic_assurance_pack.py --check
```

The generated artifact lives at
`data/evidence/agentic-assurance-pack.json` and is exposed through the
MCP server as `recipes_agentic_assurance_pack`.

---

### Generate the agent identity delegation ledger

The identity ledger joins the workflow control plane, MCP gateway
policy, and validation report into a non-human identity contract for
each approved workflow and agent class:

```bash
python3 scripts/generate_agent_identity_ledger.py
python3 scripts/generate_agent_identity_ledger.py --check
```

The generated artifact lives at
`data/evidence/agent-identity-delegation-ledger.json` and is exposed
through the MCP server as `recipes_agent_identity_ledger`.

---

### Generate the agentic entitlement review pack

The entitlement review pack turns agent identity contracts into expiring
permission leases with review cadence, MCP authorization evidence,
step-up approval requirements, and deterministic allow / hold / deny /
kill decisions for each identity, workflow, namespace, and access mode:

```bash
python3 scripts/generate_agentic_entitlement_review_pack.py
python3 scripts/generate_agentic_entitlement_review_pack.py --check
```

The generated artifact lives at
`data/evidence/agentic-entitlement-review-pack.json` and is exposed
through the MCP server as `recipes_agentic_entitlement_review_pack`.
Runtime entitlement decisions are exposed through
`recipes_evaluate_agentic_entitlement_decision`.

---

### Generate the agentic red-team drill pack

The red-team drill pack joins adversarial scenarios, workflow manifests,
gateway policy, connector trust, and agent identity scope into a
machine-readable eval bundle:

```bash
python3 scripts/generate_agentic_red_team_drill_pack.py
python3 scripts/generate_agentic_red_team_drill_pack.py --check
```

The generated artifact lives at
`data/evidence/agentic-red-team-drill-pack.json` and is exposed through
the MCP server as `recipes_agentic_red_team_drill_pack`.

---

### Generate the agentic readiness scorecard

The readiness scorecard joins the workflow manifest, MCP gateway policy,
connector trust pack, identity ledger, red-team drill pack, assurance
pack, and readiness model into a promotion-gate artifact:

```bash
python3 scripts/generate_agentic_readiness_scorecard.py
python3 scripts/generate_agentic_readiness_scorecard.py --check
```

The generated artifact lives at
`data/evidence/agentic-readiness-scorecard.json` and is exposed through
the MCP server as `recipes_agentic_readiness_scorecard`.

---

### Generate the agent capability risk register

The capability risk register joins the workflow manifest, MCP gateway
policy, connector trust pack, red-team drill pack, readiness scorecard,
and capability-risk model into a residual-risk artifact:

```bash
python3 scripts/generate_agent_capability_risk_register.py
python3 scripts/generate_agent_capability_risk_register.py --check
```

The generated artifact lives at
`data/evidence/agent-capability-risk-register.json` and is exposed
through the MCP server as `recipes_agent_capability_risk_register`.

---

### Generate the agent memory boundary pack

The memory boundary pack joins the workflow manifest and memory-boundary
model into a runtime policy for ephemeral scratchpads, append-only run
receipts, read-only policy memory, tenant runtime memory, vector memory,
TTL, provenance, rollback, and prohibited persistence:

```bash
python3 scripts/generate_agent_memory_boundary_pack.py
python3 scripts/generate_agent_memory_boundary_pack.py --check
```

The generated artifact lives at
`data/evidence/agent-memory-boundary-pack.json` and is exposed through
the MCP server as `recipes_agent_memory_boundary_pack` and
`recipes_evaluate_agent_memory_decision`.

---

### Generate the agent skill supply-chain pack

The skill supply-chain pack joins the workflow manifest, secure context
trust pack, memory boundary pack, connector trust pack, and skill model
into a provenance and runtime decision surface for agent skills, rules
files, hooks, extensions, and behavior packages:

```bash
python3 scripts/generate_agent_skill_supply_chain_pack.py
python3 scripts/generate_agent_skill_supply_chain_pack.py --check
```

The generated artifact lives at
`data/evidence/agent-skill-supply-chain-pack.json` and is exposed through
the MCP server as `recipes_agent_skill_supply_chain_pack` and
`recipes_evaluate_agent_skill_decision`.

---

### Generate the Agentic System BOM

The Agentic System Bill of Materials joins the workflow manifest, MCP
gateway policy, connector trust pack, identity ledger, red-team drill
pack, readiness scorecard, assurance pack, and BOM profile into an
inspectable inventory:

```bash
python3 scripts/generate_agentic_system_bom.py
python3 scripts/generate_agentic_system_bom.py --check
```

The generated artifact lives at `data/evidence/agentic-system-bom.json`
and is exposed through the MCP server as `recipes_agentic_system_bom`.

---

### Generate the agentic run receipt pack

The run receipt pack joins the workflow manifest, MCP gateway policy,
agent identity ledger, secure context trust pack, context poisoning
guard, context egress boundary, readiness scorecard, red-team drills,
Agentic System BOM, and assurance pack into a proof template for each
governed agent run:

```bash
python3 scripts/generate_agentic_run_receipt_pack.py
python3 scripts/generate_agentic_run_receipt_pack.py --check
```

The generated artifact lives at
`data/evidence/agentic-run-receipt-pack.json` and is exposed through the
MCP server as `recipes_agentic_run_receipt_pack`.

---

### Generate the agentic telemetry contract

The telemetry contract joins workflow scope, run receipts, measurement
probes, egress boundaries, and incident response into an
OpenTelemetry-aligned trace contract for agent, model, MCP, context,
policy, approval, verifier, and incident events:

```bash
python3 scripts/generate_agentic_telemetry_contract.py
python3 scripts/generate_agentic_telemetry_contract.py --check
```

The generated artifact lives at
`data/evidence/agentic-telemetry-contract.json` and is exposed through
the MCP server as `recipes_agentic_telemetry_contract` and
`recipes_evaluate_agentic_telemetry_event`.

---

### Generate the agentic measurement probe pack

The measurement probe pack joins workflow scope, MCP gateway policy,
authorization conformance, secure context, poisoning scans, egress,
memory boundaries, red-team drills, readiness, capability risk, run
receipts, and threat radar into repeatable traceability checks:

```bash
python3 scripts/generate_agentic_measurement_probe_pack.py
python3 scripts/generate_agentic_measurement_probe_pack.py --check
```

The generated artifact lives at
`data/evidence/agentic-measurement-probe-pack.json` and is exposed
through the MCP server as `recipes_agentic_measurement_probe_pack`.

---

### Generate the agentic exposure graph

The exposure graph joins workflow scope, secure context, MCP gateway
policy, authorization conformance, connector trust, non-human identity,
context egress, readiness, capability risk, and run receipts into
risk-ranked paths a buyer can inspect before agentic AI expands:

```bash
python3 scripts/generate_agentic_exposure_graph.py
python3 scripts/generate_agentic_exposure_graph.py --check
```

The generated artifact lives at
`data/evidence/agentic-exposure-graph.json` and is exposed through the
MCP server as `recipes_agentic_exposure_graph`.

---

### Generate the agentic posture snapshot

The posture snapshot joins secure context, MCP tool risk, authorization,
A2A handoffs, agent skills, identity, telemetry, exposure, readiness,
standards, and trust-center evidence into one buyer-facing posture
decision:

```bash
python3 scripts/generate_agentic_posture_snapshot.py
python3 scripts/generate_agentic_posture_snapshot.py --check
```

The generated artifact lives at
`data/evidence/agentic-posture-snapshot.json` and is exposed through the
MCP server as `recipes_agentic_posture_snapshot` and
`recipes_evaluate_agentic_posture_decision`.

---

### Generate the agentic app intake gate

The app intake gate joins posture, MCP tool-risk, authorization, egress,
eval, telemetry, run receipt, skill, and incident evidence into a
launch-review gate for new agentic applications:

```bash
python3 scripts/generate_agentic_app_intake_pack.py
python3 scripts/generate_agentic_app_intake_pack.py --check
```

The generated artifact lives at
`data/evidence/agentic-app-intake-pack.json` and is exposed through the
MCP server as `recipes_agentic_app_intake_pack` and
`recipes_evaluate_agentic_app_intake_decision`.

---

### Generate the model provider routing gate

The model provider routing gate joins workflow scope, context egress,
telemetry, and run receipt evidence into a provider-neutral decision
surface before secure context is sent to a frontier, private, local, or
unsanctioned model route:

```bash
python3 scripts/generate_model_provider_routing_pack.py
python3 scripts/generate_model_provider_routing_pack.py --check
```

The generated artifact lives at
`data/evidence/model-provider-routing-pack.json` and is exposed through
the MCP server as `recipes_model_provider_routing_pack` and
`recipes_evaluate_model_provider_routing_decision`.

---

### Generate the secure context trust pack

The secure context trust pack turns SecurityRecipes context roots into a
retrieval-ready provenance artifact: approved source roots, owners,
trust tiers, source hashes, instruction-handling rules, poisoning
controls, and per-workflow context package hashes.

```bash
python3 scripts/generate_secure_context_trust_pack.py
python3 scripts/generate_secure_context_trust_pack.py --check
```

The GitHub Pages workflow also refreshes this pack before running the
`--check` gate, so content-only pushes deploy with current source hashes
even when a local commit forgets to regenerate the JSON first.

The generated artifact lives at
`data/evidence/secure-context-trust-pack.json` and is exposed through
the MCP server as `recipes_secure_context_trust_pack`.

---

### Generate the secure context attestation pack

The secure context attestation pack turns the trust pack into an
attestation-shaped evidence artifact: context-source subjects, workflow
context package subjects, source artifact subjects, verification
policy, recertification queue, and production signature-readiness
requirements.

```bash
python3 scripts/generate_secure_context_attestation_pack.py
python3 scripts/generate_secure_context_attestation_pack.py --check
```

The generated artifact lives at
`data/evidence/secure-context-attestation-pack.json` and is exposed
through the MCP server as `recipes_secure_context_attestation_pack`.
Runtime decisions are exposed as
`recipes_evaluate_context_attestation_decision`.

---

### Generate the secure context lineage ledger

The secure context lineage ledger joins trust, attestation, poisoning,
egress, handoff, telemetry, run receipt, and model-routing evidence into
a source-to-run context movement artifact. It answers whether context can
be trusted, reused, handed off, persisted, or routed after an agent has
used it.

```bash
python3 scripts/generate_secure_context_lineage_ledger.py
python3 scripts/generate_secure_context_lineage_ledger.py --check
```

The generated artifact lives at
`data/evidence/secure-context-lineage-ledger.json` and is exposed
through the MCP server as `recipes_secure_context_lineage_ledger`.
Runtime decisions are exposed as
`recipes_evaluate_secure_context_lineage_decision`.

---

### Generate the secure context eval pack

The secure context eval pack joins the trust pack, attestation pack,
context poisoning guard, egress boundary, and threat radar into
scenario-backed evals for retrieval correctness, production holds,
prohibited data classes, answer citations, and agent-to-agent handoff
boundaries.

```bash
python3 scripts/generate_secure_context_eval_pack.py
python3 scripts/generate_secure_context_eval_pack.py --check
```

The generated artifact lives at
`data/evidence/secure-context-eval-pack.json` and is exposed through the
MCP server as `recipes_secure_context_eval_pack`. Runtime answer checks
are exposed as `recipes_evaluate_secure_context_eval_case`.

---

### Generate the agent handoff boundary pack

The handoff boundary pack joins workflow scope, agent identity, secure
context trust, context egress, and threat-radar evidence into protocol
trust decisions for MCP, A2A, provider-native subagents, and human
approval bridges.

```bash
python3 scripts/generate_agent_handoff_boundary_pack.py
python3 scripts/generate_agent_handoff_boundary_pack.py --check
```

The generated artifact lives at
`data/evidence/agent-handoff-boundary-pack.json` and is exposed through
the MCP server as `recipes_agent_handoff_boundary_pack`. Runtime
handoff decisions are exposed as
`recipes_evaluate_agent_handoff_decision`.

---

### Generate the A2A Agent Card trust profile

The A2A Agent Card trust profile evaluates remote-agent discovery
metadata before an opaque agent receives context or delegated authority.

```bash
python3 scripts/generate_a2a_agent_card_trust_profile.py
python3 scripts/generate_a2a_agent_card_trust_profile.py --check
```

The generated artifact lives at
`data/evidence/a2a-agent-card-trust-profile.json` and is exposed
through the MCP server as `recipes_a2a_agent_card_trust_profile`.
Runtime card decisions are exposed as
`recipes_evaluate_a2a_agent_card_trust_decision`.

---

### Generate the context poisoning guard pack

The context poisoning guard pack scans every registered secure-context
source before it is treated as MCP-retrievable context. It detects
prompt-injection, tool-poisoning, approval-bypass, hidden-instruction,
encoded-payload, and secret-exfiltration markers and classifies them as
pass, documented adversarial examples, review holds, or blocks.

```bash
python3 scripts/generate_context_poisoning_guard_pack.py
python3 scripts/generate_context_poisoning_guard_pack.py --check
```

The generated artifact lives at
`data/evidence/context-poisoning-guard-pack.json` and is exposed through
the MCP server as `recipes_context_poisoning_guard_pack`.

---

### Evaluate a secure context retrieval decision

The secure context firewall turns the generated trust pack into a
single pre-retrieval decision an MCP gateway, agent host, CI admission
check, or policy sidecar can log and enforce:

```bash
python3 scripts/evaluate_secure_context_retrieval.py \
  --workflow-id vulnerable-dependency-remediation \
  --source-id prompt-library-recipes \
  --retrieval-mode workflow_prompt_context \
  --requested-path content/prompt-library/general/base-image-bump.md \
  --expect-decision allow_public_context
```

The same decision function is exposed through the MCP server as
`recipes_evaluate_context_retrieval_decision`.

---

### Generate the agentic threat radar

The threat radar turns current agentic AI and MCP security guidance
into a source-backed product artifact: threat signals, buyer triggers,
mapped SecurityRecipes controls, MCP tool surfaces, and recommended
roadmap moves.

```bash
python3 scripts/generate_agentic_threat_radar.py
python3 scripts/generate_agentic_threat_radar.py --check
```

The generated artifact lives at
`data/evidence/agentic-threat-radar.json` and is exposed through the
MCP server as `recipes_agentic_threat_radar`.

---

### Generate the agentic standards crosswalk

The standards crosswalk maps OWASP, NIST, MCP, OpenAI, and Anthropic
agentic security guidance to SecurityRecipes capabilities, generated
evidence, and MCP tools.

```bash
python3 scripts/generate_agentic_standards_crosswalk.py
python3 scripts/generate_agentic_standards_crosswalk.py --check
```

The generated artifact lives at
`data/evidence/agentic-standards-crosswalk.json` and is exposed through
the MCP server as `recipes_agentic_standards_crosswalk`.

---

### Generate the MCP and agentic-skill risk coverage pack

The coverage pack maps the OWASP MCP Top 10 beta and OWASP Agentic
Skills Top 10 to SecurityRecipes controls, generated evidence, MCP
tools, and hosted product wedges.

```bash
python3 scripts/generate_mcp_risk_coverage_pack.py
python3 scripts/generate_mcp_risk_coverage_pack.py --check
```

The generated artifact lives at
`data/evidence/mcp-risk-coverage-pack.json` and is exposed through the
MCP server as `recipes_mcp_risk_coverage_pack`.

---

### Generate the agentic control plane blueprint

The control plane blueprint joins existing generated evidence into an
architecture and buyer-diligence artifact for the secure context layer:
layers, source packs, MCP tools, diligence questions, and
commercialization path.

```bash
python3 scripts/generate_agentic_control_plane_blueprint.py
python3 scripts/generate_agentic_control_plane_blueprint.py --check
```

The generated artifact lives at
`data/evidence/agentic-control-plane-blueprint.json` and is exposed
through the MCP server as `recipes_agentic_control_plane_blueprint`.

---

### Generate the agentic catastrophic-risk annex

The catastrophic-risk annex maps high-impact agent action classes to
severe scenarios, required evidence, default decisions, runtime kill
signals, buyer views, and a deterministic evaluator for allow / hold /
deny / kill decisions before high-impact autonomy proceeds.

```bash
python3 scripts/generate_agentic_catastrophic_risk_annex.py
python3 scripts/generate_agentic_catastrophic_risk_annex.py --check
```

The generated artifact lives at
`data/evidence/agentic-catastrophic-risk-annex.json` and is exposed
through the MCP server as `recipes_agentic_catastrophic_risk_annex`.
Runtime decisions are exposed through
`recipes_evaluate_agentic_catastrophic_risk_decision`.

---

### Generate the agentic incident response pack

The incident response pack maps secure-context and MCP-backed agentic
failures to incident classes, containment phases, forensic evidence,
workflow response decisions, tabletop cases, and a deterministic
evaluator for monitor / triage / hold / contain / kill decisions.

```bash
python3 scripts/generate_agentic_incident_response_pack.py
python3 scripts/generate_agentic_incident_response_pack.py --check
```

The generated artifact lives at
`data/evidence/agentic-incident-response-pack.json` and is exposed
through the MCP server as `recipes_agentic_incident_response_pack`.
Runtime decisions are exposed through
`recipes_evaluate_agentic_incident_response_decision`.

---

### Generate the agentic action runtime pack

The action runtime pack maps secure-context and MCP evidence to
pre-action allow / hold / deny / kill decisions before an agent executes
a side effect such as a branch write, production deploy, identity scope
change, context egress, remote handoff, persistent memory write, skill
install, registry quarantine, or irreversible transaction.

```bash
python3 scripts/generate_agentic_action_runtime_pack.py
python3 scripts/generate_agentic_action_runtime_pack.py --check
```

The generated artifact lives at
`data/evidence/agentic-action-runtime-pack.json` and is exposed through
the MCP server as `recipes_agentic_action_runtime_pack`. Runtime action
decisions are exposed through
`recipes_evaluate_agentic_action_runtime_decision`.

---

### Generate the agentic approval receipt pack

The approval receipt pack turns human approvals into scope-bound,
time-boxed, role-checked, separation-of-duties evidence before privileged
agent actions execute. It validates approver roles, scope hashes, expiry,
risk acceptance, and run-receipt linkage before returning allow / hold /
deny / kill decisions.

```bash
python3 scripts/generate_agentic_approval_receipt_pack.py
python3 scripts/generate_agentic_approval_receipt_pack.py --check
```

The generated artifact lives at
`data/evidence/agentic-approval-receipt-pack.json` and is exposed through
the MCP server as `recipes_agentic_approval_receipt_pack`. Runtime
approval decisions are exposed through
`recipes_evaluate_agentic_approval_receipt_decision`.

---

### Generate the browser-agent workspace boundary pack

The browser-agent boundary pack maps browser workspaces and task profiles
to ambient-authority controls for logged-in sessions, untrusted web
content, local storage, localhost, downloads, forms, admin consoles, and
external sends.

```bash
python3 scripts/generate_browser_agent_boundary_pack.py
python3 scripts/generate_browser_agent_boundary_pack.py --check
```

The generated artifact lives at
`data/evidence/browser-agent-boundary-pack.json` and is exposed through
the MCP server as `recipes_browser_agent_boundary_pack`. Runtime browser
decisions are exposed through
`recipes_evaluate_browser_agent_boundary_decision`.

---

### Generate the agentic entitlement review pack

The entitlement review pack maps agent identities and MCP namespaces to
expiring permission leases, access-review cadence, step-up authorization
rules, approval evidence, and deterministic allow / hold / deny / kill
decisions before an agent uses a scope.

```bash
python3 scripts/generate_agentic_entitlement_review_pack.py
python3 scripts/generate_agentic_entitlement_review_pack.py --check
```

The generated artifact lives at
`data/evidence/agentic-entitlement-review-pack.json` and is exposed
through the MCP server as `recipes_agentic_entitlement_review_pack`.
Runtime entitlement decisions are exposed through
`recipes_evaluate_agentic_entitlement_decision`.

---

### Generate the enterprise trust-center export

The trust-center export bundles the generated secure-context, MCP,
identity, handoff, incident response, eval, readiness, runtime evidence,
and acquisition strategy packs into one buyer-diligence packet.

```bash
python3 scripts/generate_enterprise_trust_center_export.py
python3 scripts/generate_enterprise_trust_center_export.py --check
```

The generated artifact lives at
`data/evidence/enterprise-trust-center-export.json` and is exposed
through the MCP server as `recipes_enterprise_trust_center_export`.

---

### Generate the MCP connector trust pack

The connector trust pack joins the MCP connector registry, workflow
control plane, and gateway policy into a machine-readable inventory of
connector namespaces, trust tiers, access modes, controls, evidence,
promotion criteria, and kill signals:

```bash
python3 scripts/generate_mcp_connector_trust_pack.py
python3 scripts/generate_mcp_connector_trust_pack.py --check
```

The generated artifact lives at
`data/evidence/mcp-connector-trust-pack.json` and is exposed through the
MCP server as `recipes_mcp_connector_trust_pack`.

---

### Generate the MCP connector intake pack

The connector intake pack evaluates proposed or changed MCP servers
before they are promoted into the connector trust registry:

```bash
python3 scripts/generate_mcp_connector_intake_pack.py
python3 scripts/generate_mcp_connector_intake_pack.py --check
```

The generated artifact lives at
`data/evidence/mcp-connector-intake-pack.json` and is exposed through
the MCP server as `recipes_mcp_connector_intake_pack`.

---

### Generate the MCP STDIO launch boundary pack

The STDIO launch boundary pack evaluates local MCP server launches as
subprocess execution requests before an agent host starts them:

```bash
python3 scripts/generate_mcp_stdio_launch_boundary_pack.py
python3 scripts/generate_mcp_stdio_launch_boundary_pack.py --check
```

The generated artifact lives at
`data/evidence/mcp-stdio-launch-boundary-pack.json` and is exposed
through the MCP server as `recipes_mcp_stdio_launch_boundary_pack`.
Runtime decisions are exposed as `recipes_evaluate_mcp_stdio_launch_decision`.

---

### Generate the MCP authorization conformance pack

The authorization conformance pack joins connector trust, connector
intake, workflow policy, and MCP authorization rules into a
machine-readable resource, audience, token, session, and scope-drift
control layer:

```bash
python3 scripts/generate_mcp_authorization_conformance_pack.py
python3 scripts/generate_mcp_authorization_conformance_pack.py --check
```

The generated artifact lives at
`data/evidence/mcp-authorization-conformance-pack.json` and is exposed
through the MCP server as `recipes_mcp_authorization_conformance_pack`.
Runtime decisions are exposed as `recipes_evaluate_mcp_authorization_decision`.

---

### Generate the MCP elicitation boundary pack

The elicitation boundary pack turns MCP form-mode and URL-mode user
prompts into a policy surface for sensitive data, external OAuth,
payment or billing flows, URL safety, consent, and receipt evidence:

```bash
python3 scripts/generate_mcp_elicitation_boundary_pack.py
python3 scripts/generate_mcp_elicitation_boundary_pack.py --check
python3 scripts/evaluate_mcp_elicitation_boundary_decision.py \
  --workflow-id mcp-connector-intake-scanner \
  --agent-id sr-agent::mcp-connector-intake::codex \
  --run-id run-123 \
  --connector-id github \
  --namespace github.oauth \
  --server-id mcp-server::github \
  --elicitation-profile-id profile-third-party-oauth-url \
  --elicitation-id elicit-123 \
  --mode url \
  --url https://github.com/login/oauth/authorize \
  --url-domain github.com \
  --user-id user-123 \
  --session-id session-123 \
  --correlation-id corr-123 \
  --authorization-pack-hash auth-pack-sha256 \
  --client-supports-mode \
  --server-identity-displayed \
  --user-can-decline \
  --user-consent-recorded \
  --completion-notification-bound \
  --https-url \
  --url-allowlisted \
  --expect-decision allow_elicitation_with_receipt
```

The generated artifact lives at
`data/evidence/mcp-elicitation-boundary-pack.json` and is exposed
through the MCP server as `recipes_mcp_elicitation_boundary_pack`.
Runtime decisions are exposed as
`recipes_evaluate_mcp_elicitation_boundary_decision`.

---

### Generate the MCP tool-risk contract

The tool-risk contract joins connector trust, authorization conformance,
workflow policy, MCP tool annotations, and runtime session-combination
risk into a pre-call decision pack:

```bash
python3 scripts/generate_mcp_tool_risk_contract.py
python3 scripts/generate_mcp_tool_risk_contract.py --check
python3 scripts/evaluate_mcp_tool_risk_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --namespace repo.contents \
  --tool-name repo.contents.patch \
  --requested-access-mode write_branch \
  --server-trusted \
  --human-approval-id approval-ci \
  --expect-decision allow_with_confirmation
```

The generated artifact lives at
`data/evidence/mcp-tool-risk-contract.json` and is exposed through the
MCP server as `recipes_mcp_tool_risk_contract`.
Runtime decisions are exposed as `recipes_evaluate_mcp_tool_risk_decision`.

---

### Generate the MCP tool-surface drift pack

The tool-surface drift pack fingerprints approved MCP tool descriptions,
input schemas, output schemas, annotations, and capability flags so a
gateway can detect post-approval drift before an agent trusts a changed
tool:

```bash
python3 scripts/generate_mcp_tool_surface_drift_pack.py
python3 scripts/generate_mcp_tool_surface_drift_pack.py --check
python3 scripts/evaluate_mcp_tool_surface_drift_decision.py \
  --namespace repo.contents \
  --tool-name repo.contents.patch_scoped_branch \
  --workflow-id vulnerable-dependency-remediation \
  --requested-access-mode write_branch \
  --use-baseline-hashes \
  --expect-decision allow_pinned_tool_surface
```

The generated artifact lives at
`data/evidence/mcp-tool-surface-drift-pack.json` and is exposed through
the MCP server as `recipes_mcp_tool_surface_drift_pack`.
Runtime decisions are exposed as
`recipes_evaluate_mcp_tool_surface_drift_decision`.

---

### Evaluate an MCP gateway runtime decision

The runtime evaluator turns the generated MCP gateway policy into a
single pre-call decision an agent host, MCP gateway, CI admission check,
or policy sidecar can log and enforce:

```bash
python3 scripts/evaluate_mcp_gateway_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --agent-id sr-agent::vulnerable-dependency-remediation::codex \
  --run-id run-123 \
  --tool-namespace repo.contents \
  --tool-access-mode write_branch \
  --branch-name sec-auto-remediation/fix-cve \
  --changed-path package.json \
  --changed-path package-lock.json \
  --diff-line-count 120 \
  --gate-phase tool_call
```

The same decision function is exposed through the MCP server as
`recipes_evaluate_mcp_gateway_decision`.

---

## Project layout

The Hugo project lives directly at the repository root. All paths below
are root-relative.

```
.
├── hugo.yaml                       # Site config (menus, params, dynamic repoURL)
├── go.mod                          # Hugo module deps (Hextra)
├── archetypes/default.md           # `hugo new` template
├── assets/css/custom.css           # Hextra overrides — matches landing theme
├── content/
│   ├── _index.md                   # Home page (rendered by custom layout)
│   ├── how-to-use/_index.md         # Visual guide for using the repo/site
│   ├── fundamentals/_index.md      # Primer — agents, prompts, MCP, vocabulary
│   ├── docs/_index.md              # Docs landing — purpose of this site
│   ├── agents/_index.md            # Agents overview / decision tree
│   ├── github_copilot/_index.md    # Per-agent recipe
│   ├── devin/_index.md
│   ├── cursor/_index.md
│   ├── codex/_index.md
│   ├── claude/_index.md
│   ├── prompt-library/
│   │   ├── _index.md               # Library landing
│   │   ├── general/                # Tool-agnostic prompts (OWASP, review, triage)
│   │   ├── claude/                 # Claude skills, slash commands
│   │   ├── cursor/                 # Cursor rules + commands
│   │   ├── codex/                  # Codex CLI prompts
│   │   ├── devin/                  # Devin playbooks + knowledge
│   │   └── github_copilot/         # Copilot instructions + issue templates
│   ├── mcp-servers/_index.md       # Connector catalog + gateway write-up
│   ├── security-remediation/
│   │   ├── _index.md               # Security team workflow overview
│   │   ├── sensitive-data/         # SDE remediation workflow
│   │   └── vulnerable-dependencies/# Dep remediation workflow
│   ├── automation/_index.md        # Automation, not agentic
│   └── contribute/_index.md        # How to submit recipes/prompts
├── data/
│   ├── assurance/                  # Assurance control map
│   ├── control-plane/              # Workflow manifests + schema
│   ├── context/                    # Secure context registry
│   ├── evidence/                   # Generated audit / assurance reports
│   └── policy/                     # Generated MCP gateway policy
├── layouts/
│   ├── index.html                  # Custom landing page (polished hero + cards)
│   ├── partials/footer.html        # Footer override (copyright)
│   ├── partials/custom/head-end.html # Injects custom.css
│   └── shortcodes/prompt-toc.html  # Auto-TOC for prompt-library pages
├── static/
│   ├── .nojekyll                   # Tell GH Pages "this is not Jekyll"
│   └── images/
│       ├── logo.svg
│       ├── how-to-use/              # GPT Image-2 visual walkthrough panels
│       └── covers/                 # Per-tool hero illustrations
├── Dockerfile                      # Multi-stage: Hugo extended → nginx:alpine
└── .github/workflows/hugo.yml      # GH Pages CI/CD + dynamic repoURL injection
```

The repo root also holds `CONTRIBUTING.md` (the fork-and-PR guide that
the top nav's **Contribute** link points at) and `LICENSE`.

---

## Site sections at a glance

| Section | What's in it |
| ------- | ------------ |
| **Visual Guide** | Four GPT Image-2 walkthrough panels that explain how to use the repo as a path: explore, run one PR, operate workflows, and scale through MCP. |
| **Fundamentals** | What an agent is; the five tools; prompts; MCP; MCP gateways; agentic remediation; vocabulary. |
| **Docs** | Orientation for the site — who it's for, how to read a recipe, how to contribute. |
| **Agents** | Per-tool recipes for GitHub Copilot, Claude, Cursor, Codex, Devin — each with Install → Configure → Dispatch → Guardrails, plus General and Enterprise onboarding. |
| **Prompt Library** | Tool-agnostic prompts under `general/` (OWASP Top 10 2026 audit, OWASP Top 10 2026 remediate) plus per-tool prompts for CVE triage, vulnerable deps, and SDE remediation. |
| **MCP Servers** | Why MCP exists; connector catalog (risk, ownership, ticket, knowledge, code, observability); MCP gateway patterns; integration on-ramp. |
| **Security Remediation** | Reference workflows a security team can operate: SDE, vulnerable dependencies, SAST, base images, artifact quarantine, classic vulnerable defaults, crypto payments, and DeFi / blockchain security. Includes the agentic control plane blueprint, exposure graph, threat radar, MCP and agentic-skill risk coverage, workflow control plane, MCP gateway policy pack, runtime decision evaluator, action runtime pack, browser-agent boundary pack, MCP connector intake scanner, MCP connector trust registry, A2A Agent Card trust profile, secure context trust pack, context poisoning guard, secure context firewall, agentic assurance pack, readiness scorecard, capability risk register, red-team drill pack, agent identity ledger, Agentic System BOM, agentic run receipts, agentic telemetry contract, model provider routing gate, program metrics, reviewer playbook, rollout maturity model, and compliance mapping. |
| **Automation** | The "just use a linter" checklist — deterministic automation that earns its keep before an agent ever runs. |
| **Contribute** | How to add a recipe, a prompt, or a new workflow. |

---

## Dynamic repository URL

The "Repository" link on the landing page and repo-backed Contribute
links are resolved from the root-level `hugo.yaml` and site content. CI
runs from the repository root and updates repo-aware values during the
build:

```bash
HUGO_PARAMS_REPOURL="https://github.com/${{ github.repository }}"
CANONICAL_REPOSITORY="stevologic/security-recipes.ai"
sed -i "s|${CANONICAL_REPOSITORY}|${{ github.repository }}|g" hugo.yaml
find content -type f -name "*.md" -exec sed -i \
  "s|${CANONICAL_REPOSITORY}|${{ github.repository }}|g" {} +
```

This means you can fork the repo under any org/user and the links
follow without moving files or adding a subdirectory-specific
`working-directory`.

---

## Deploying to GitHub Pages

The project ships with a GitHub Actions workflow
(`.github/workflows/hugo.yml`) that:

1. Installs Hugo (extended) + Go.
2. Fetches the Hextra theme via Hugo Modules.
3. Validates generated governance packs, refreshes and validates the
   secure context trust pack, then refreshes and validates agentic run
   receipts against the current control artifacts.
4. Runs `hugo --gc --minify` from the repository root with
   `HUGO_PARAMS_REPOURL` wired to the hosting repo.
5. Verifies `public/recipes-index.json` is generated at the root build
   output for MCP
   search/retrieval servers.
6. Pushes the compiled root-level `public/` directory to a dedicated
   **`gh-pages`** branch using `peaceiris/actions-gh-pages`.

### MCP server-friendly content index

This site generates a machine-readable JSON corpus at:

- **`/recipes-index.json`** (for example,
  `https://security-recipes.ai/recipes-index.json`)

The index is emitted by Hugo during the normal build (`hugo --gc --minify`)
using:

- `hugo.yaml` output format: `RECIPESINDEX` (base name: `recipes-index`)
- template: `layouts/index.recipesindex.json`

Each record includes structured fields intended for MCP tools such as
`search_recipes` and `get_recipe`, including:

- `slug`, `title`, `url`, `path`, `section`
- `agent`, `tags`, `severity`
- `last_updated`, `summary`, `content`, `source_file`

In CI, the workflow validates that `public/recipes-index.json` is:

1. Present and non-empty
2. Valid JSON
3. A non-empty array with required fields (`slug`, `title`, `url`, `content`)

This keeps the static site MCP-ready without requiring runtime crawling of
rendered HTML.

### Workflow control plane manifests

Enterprise workflows also have a source-controlled control-plane pack:

- manifest: `data/control-plane/workflow-manifests.json`
- schema: `data/control-plane/workflow-manifest.schema.json`
- validator: `scripts/validate_workflow_control_plane.py`
- report: `data/evidence/workflow-control-plane-report.json`

The manifest declares each workflow's eligible findings, automation-first
tools, MCP context, file scope, gates, evidence, KPIs, and kill signals.
CI runs the validator before the Hugo build so workflow policy cannot drift
silently from the documentation.

### MCP gateway policy pack

The workflow manifest also compiles into an enforcer-friendly gateway
policy pack:

- policy: `data/policy/mcp-gateway-policy.json`
- generator: `scripts/generate_mcp_gateway_policy.py`
- runtime evaluator: `scripts/evaluate_mcp_gateway_decision.py`
- MCP tools: `recipes_mcp_gateway_policy`,
  `recipes_evaluate_mcp_gateway_decision`

The generated pack gives an MCP gateway or agent host a default-deny
decision contract for scoped tool access, remediation branch writes,
ticket writes, approval holds, runtime session kills, and evidence
records. CI runs the generator in `--check` mode so workflow changes must
update the policy artifact.

The runtime evaluator executes the same policy for one tool-call request
and returns `allow`, `allow_scoped_branch`, `allow_scoped_ticket`,
`hold_for_approval`, `deny`, or `kill_session` with matched scope,
violations, approval state, and source manifest hash.

### MCP connector trust pack

The workflow manifest and gateway policy also compile with the MCP
connector registry into a trust pack:

- registry: `data/mcp/connector-trust-registry.json`
- generator: `scripts/generate_mcp_connector_trust_pack.py`
- pack: `data/evidence/mcp-connector-trust-pack.json`
- MCP tool: `recipes_mcp_connector_trust_pack`

The generated pack covers every workflow MCP namespace with connector
owner, status, trust tier, access mode, controls, evidence records,
promotion criteria, and runtime kill signals. CI runs the generator in
`--check` mode so connector trust cannot drift from workflow policy.

### MCP connector intake pack

Proposed and changed MCP servers compile into a pre-promotion intake
pack:

- candidate registry: `data/mcp/connector-intake-candidates.json`
- generator: `scripts/generate_mcp_connector_intake_pack.py`
- pack: `data/evidence/mcp-connector-intake-pack.json`
- MCP tool: `recipes_mcp_connector_intake_pack`

The generated pack scores auth, token, network, schema, data, write,
approval, and evidence risk. It returns an admission decision, control
gaps, registry patch preview, promotion plan, and red-team drills before
a connector can move into the production trust registry.

### MCP STDIO launch boundary pack

Local STDIO MCP server launches compile into a subprocess boundary pack:

- model: `data/assurance/mcp-stdio-launch-boundary-model.json`
- generator: `scripts/generate_mcp_stdio_launch_boundary_pack.py`
- runtime evaluator: `scripts/evaluate_mcp_stdio_launch_decision.py`
- pack: `data/evidence/mcp-stdio-launch-boundary-pack.json`
- MCP tools: `recipes_mcp_stdio_launch_boundary_pack`,
  `recipes_evaluate_mcp_stdio_launch_decision`

The generated pack checks exact command allowlists, package-runner
bootstrap, digest/signature evidence, sandboxing, environment keys,
network egress, filesystem roots, high-impact capabilities, and approval
records before an MCP client spawns a local STDIO server.

### MCP authorization conformance pack

MCP authorization profiles compile into a pre-call conformance pack:

- profile: `data/assurance/mcp-authorization-conformance-profile.json`
- generator: `scripts/generate_mcp_authorization_conformance_pack.py`
- runtime evaluator: `scripts/evaluate_mcp_authorization_decision.py`
- pack: `data/evidence/mcp-authorization-conformance-pack.json`
- MCP tools: `recipes_mcp_authorization_conformance_pack`,
  `recipes_evaluate_mcp_authorization_decision`

The generated pack checks resource indicators, token audience, PKCE,
token-passthrough denial, session binding, consent, audit correlation,
workflow namespace scope, and candidate MCP server auth gaps.

### MCP elicitation boundary pack

MCP form-mode and URL-mode elicitation profiles compile into a user
prompt and sensitive-flow boundary pack:

- profile: `data/assurance/mcp-elicitation-boundary-profile.json`
- generator: `scripts/generate_mcp_elicitation_boundary_pack.py`
- runtime evaluator: `scripts/evaluate_mcp_elicitation_boundary_decision.py`
- pack: `data/evidence/mcp-elicitation-boundary-pack.json`
- MCP tools: `recipes_mcp_elicitation_boundary_pack`,
  `recipes_evaluate_mcp_elicitation_boundary_decision`

The generated pack blocks secrets in form mode, requires URL mode for
sensitive third-party authorization and payment-like flows, checks safe
URL handling, separates external OAuth from MCP authorization, and emits
receipt fields for workflow, agent, run, server, user, session,
correlation, URL, consent, and decision evidence.

### MCP tool-risk contract

MCP tool risk compiles into a pre-call annotation and session-combination
contract:

- profile: `data/assurance/mcp-tool-risk-contract-profile.json`
- generator: `scripts/generate_mcp_tool_risk_contract.py`
- runtime evaluator: `scripts/evaluate_mcp_tool_risk_decision.py`
- contract: `data/evidence/mcp-tool-risk-contract.json`
- MCP tools: `recipes_mcp_tool_risk_contract`,
  `recipes_evaluate_mcp_tool_risk_decision`

The generated pack checks standard MCP tool annotations, whether the
annotation source is trusted, workflow namespace scope, state-changing
and external-communication paths, and the private-data plus
untrusted-content plus exfiltration combination before a tool call runs.

### MCP tool-surface drift pack

MCP tool surfaces compile into a drift sentinel for descriptions,
schemas, annotations, and capability metadata:

- profile: `data/assurance/mcp-tool-surface-drift-profile.json`
- generator: `scripts/generate_mcp_tool_surface_drift_pack.py`
- runtime evaluator: `scripts/evaluate_mcp_tool_surface_drift_decision.py`
- pack: `data/evidence/mcp-tool-surface-drift-pack.json`
- MCP tools: `recipes_mcp_tool_surface_drift_pack`,
  `recipes_evaluate_mcp_tool_surface_drift_decision`

The generated pack checks description hashes, input and output schema
hashes, annotation hashes, workflow binding, access-mode boundaries,
candidate connector quarantine, and high-impact capability expansion
before a changed MCP tool surface is trusted.

### Agentic assurance pack

The manifest, gateway policy, and control map also compile into a
buyer- and auditor-ready assurance pack:

- control map: `data/assurance/agentic-assurance-control-map.json`
- generator: `scripts/generate_agentic_assurance_pack.py`
- pack: `data/evidence/agentic-assurance-pack.json`

The generated pack maps SecurityRecipes controls to AI risk references,
summarizes per-workflow assurance coverage, and seeds AI/Agent BOM
inventory work. CI runs the generator in `--check` mode so the control
story cannot drift from the workflow and policy artifacts.

### Agent identity delegation ledger

Agent identities are generated from the same workflow and policy
sources:

- ledger: `data/evidence/agent-identity-delegation-ledger.json`
- generator: `scripts/generate_agent_identity_ledger.py`
- MCP tool: `recipes_agent_identity_ledger`

The ledger declares one non-human identity contract per workflow and
agent class, including delegated MCP scopes, explicit denied actions,
reviewer pools, runtime kill signals, required evidence, token rules,
and source artifact hashes. CI runs the generator in `--check` mode so
identity scope cannot drift from gateway policy.

### Agentic entitlement review pack

Agent entitlements are generated from the identity ledger, MCP
authorization evidence, connector trust, action runtime, handoff,
telemetry, and run receipt packs:

- profile: `data/assurance/agentic-entitlement-review-profile.json`
- generator: `scripts/generate_agentic_entitlement_review_pack.py`
- evaluator: `scripts/evaluate_agentic_entitlement_decision.py`
- pack: `data/evidence/agentic-entitlement-review-pack.json`
- MCP tools: `recipes_agentic_entitlement_review_pack`, `recipes_evaluate_agentic_entitlement_decision`

The pack declares expiring permission leases and access-review cadence
for each identity, workflow, MCP namespace, and access mode. CI runs the
generator and evaluator so entitlement state cannot drift from gateway
policy, MCP authorization, or runtime action evidence.

### Agentic red-team drill pack

Adversarial eval scenarios are generated from a source-controlled
scenario map and joined to the workflow, policy, connector trust, and
identity artifacts:

- scenario map: `data/assurance/agentic-red-team-scenario-map.json`
- generator: `scripts/generate_agentic_red_team_drill_pack.py`
- pack: `data/evidence/agentic-red-team-drill-pack.json`
- MCP tool: `recipes_agentic_red_team_drill_pack`

The generated pack gives every approved workflow repeatable drills for
tool-result injection, goal hijack, credential access, approval bypass,
token passthrough, connector schema drift, runaway loops, and evidence
integrity failures. CI runs the generator in `--check` mode so red-team
coverage cannot drift from workflow and MCP policy.

### Agentic readiness scorecard

Scale decisions are generated from the workflow manifest, gateway
policy, connector trust pack, identity ledger, red-team drill pack,
assurance pack, and source-controlled readiness model:

- readiness model: `data/assurance/agentic-readiness-model.json`
- generator: `scripts/generate_agentic_readiness_scorecard.py`
- scorecard: `data/evidence/agentic-readiness-scorecard.json`
- MCP tool: `recipes_agentic_readiness_scorecard`

The generated scorecard gives each approved workflow a `scale_ready`,
`pilot_guarded`, `manual_gate`, or `blocked` decision with dimension
scores, blockers, pilot connector dependencies, and next actions. CI
runs the generator in `--check` mode so adoption decisions cannot drift
from the underlying control artifacts.

### Agent capability risk register

Capability risk tiers are generated from the workflow manifest, gateway
policy, connector trust pack, red-team drill pack, readiness scorecard,
and source-controlled capability-risk model:

- model: `data/assurance/agent-capability-risk-model.json`
- generator: `scripts/generate_agent_capability_risk_register.py`
- register: `data/evidence/agent-capability-risk-register.json`
- MCP tool: `recipes_agent_capability_risk_register`

The generated register scores each workflow by system criticality, AI
autonomy, access permissions, and impact radius, then subtracts control
credit for readiness, default-deny policy, connector coverage,
red-team drills, and runtime kill signals. CI runs the generator in
`--check` mode so capability-risk decisions cannot drift from the
underlying control artifacts.

### Agent memory boundary pack

The generated memory boundary pack turns persistent agent state into a
governed control surface:

- model: `data/assurance/agent-memory-boundary-model.json`
- generator: `scripts/generate_agent_memory_boundary_pack.py`
- runtime evaluator: `scripts/evaluate_agent_memory_boundary_decision.py`
- pack: `data/evidence/agent-memory-boundary-pack.json`
- MCP tools: `recipes_agent_memory_boundary_pack`,
  `recipes_evaluate_agent_memory_decision`

The pack defines ephemeral scratchpads, append-only receipt memory,
read-only policy memory, tenant runtime memory, vector memory, TTLs,
provenance, approval, rollback, and prohibited persistence. The runtime
evaluator returns allow, hold, deny, or kill-session decisions before an
agent stores or replays memory.

### Agent skill supply-chain pack

The generated skill supply-chain pack turns agent behavior packages into
governed inventory:

- model: `data/assurance/agent-skill-supply-chain-model.json`
- generator: `scripts/generate_agent_skill_supply_chain_pack.py`
- runtime evaluator:
  `scripts/evaluate_agent_skill_supply_chain_decision.py`
- pack: `data/evidence/agent-skill-supply-chain-pack.json`
- MCP tools: `recipes_agent_skill_supply_chain_pack`,
  `recipes_evaluate_agent_skill_decision`

The pack scores skills, rules files, hooks, and extensions by publisher,
registry, version pinning, package hash, signature status, scan status,
filesystem access, network egress, shell access, memory writes, identity
file writes, and MCP permissions. The runtime evaluator returns allow,
hold, deny, or kill-session decisions before install, update, enable, or
run.

### Agent handoff boundary pack

The generated handoff boundary pack turns MCP, A2A, provider-native
subagents, and human approval bridges into a governed protocol trust
surface:

- model: `data/assurance/agent-handoff-boundary-model.json`
- generator: `scripts/generate_agent_handoff_boundary_pack.py`
- runtime evaluator:
  `scripts/evaluate_agent_handoff_boundary_decision.py`
- pack: `data/evidence/agent-handoff-boundary-pack.json`
- MCP tools: `recipes_agent_handoff_boundary_pack`,
  `recipes_evaluate_agent_handoff_decision`

The pack defines metadata-only, cited-evidence, approval-gated, and
prohibited handoff profiles. The runtime evaluator returns allow, hold,
deny, or kill-session decisions before context crosses an agent,
protocol, tenant, or organization boundary.

### A2A Agent Card trust profile

The generated A2A Agent Card trust profile turns remote-agent discovery
into an enterprise intake decision before secure context or authority is
shared:

- profile: `data/assurance/a2a-agent-card-trust-profile.json`
- generator: `scripts/generate_a2a_agent_card_trust_profile.py`
- runtime evaluator:
  `scripts/evaluate_a2a_agent_card_trust_decision.py`
- pack: `data/evidence/a2a-agent-card-trust-profile.json`
- MCP tools: `recipes_a2a_agent_card_trust_profile`,
  `recipes_evaluate_a2a_agent_card_trust_decision`

The profile evaluates required Agent Card fields, HTTPS interfaces,
provider identity, security schemes, security requirements, signatures,
extended-card behavior, high-impact skills, and prohibited secret or
prompt-injection markers. Runtime decisions are allow, restricted pilot,
hold, deny, or kill-session.

### Agentic System BOM

The generated Agentic System Bill of Materials turns the same control
artifacts into an inspectable inventory:

- BOM profile: `data/assurance/agentic-system-bom-profile.json`
- generator: `scripts/generate_agentic_system_bom.py`
- BOM: `data/evidence/agentic-system-bom.json`
- MCP tool: `recipes_agentic_system_bom`

The BOM inventories workflows, agent classes, non-human identities, MCP
connectors, policy components, evidence artifacts, knowledge sources,
evaluation drills, source hashes, readiness decisions, and update
triggers. CI runs the generator in `--check` mode so the agentic system
inventory cannot drift from the governed source artifacts.

### Agentic run receipt pack

The generated run receipt pack turns the same control artifacts into a
portable proof template for every governed agent run:

- receipt profile: `data/assurance/agentic-run-receipt-profile.json`
- generator: `scripts/generate_agentic_run_receipt_pack.py`
- pack: `data/evidence/agentic-run-receipt-pack.json`
- MCP tool: `recipes_agentic_run_receipt_pack`

The pack requires identity issuance, context retrieval decisions,
context poisoning inspection, MCP tool decisions, context egress
decisions, human approval, verifier output, evidence attachment, run
closure, and identity revocation before a run is trusted.

### Agentic telemetry contract

The generated telemetry contract turns run receipts, measurement probes,
egress boundaries, and incident response evidence into a vendor-neutral
trace contract:

- profile: `data/assurance/agentic-telemetry-contract-profile.json`
- generator: `scripts/generate_agentic_telemetry_contract.py`
- evaluator: `scripts/evaluate_agentic_telemetry_event.py`
- pack: `data/evidence/agentic-telemetry-contract.json`
- MCP tools: `recipes_agentic_telemetry_contract`,
  `recipes_evaluate_agentic_telemetry_event`

The contract defines required OpenTelemetry-shaped fields for agent,
model, MCP, context, policy, egress, approval, verifier, and incident
events while making raw prompts, outputs, tool arguments, and tool
results opt-in only.

### Agentic measurement probe pack

The generated measurement probe pack turns the same control artifacts
into repeatable traceability checks for agentic workflow expansion:

- profile: `data/assurance/agentic-measurement-probe-profile.json`
- generator: `scripts/generate_agentic_measurement_probe_pack.py`
- pack: `data/evidence/agentic-measurement-probe-pack.json`
- MCP tool: `recipes_agentic_measurement_probe_pack`

The pack verifies context integrity, MCP authorization, non-human
identity, context egress, memory boundaries, red-team replay, run
receipt reconstruction, readiness decisions, and current threat-radar
alignment before a workflow is treated as measurement-ready.

### Agentic exposure graph

The generated exposure graph turns the same control artifacts into a
relationship map of workflows, context sources, non-human identities,
MCP namespaces, authorization decisions, egress policies, readiness,
capability risk, and run receipts:

- profile: `data/assurance/agentic-exposure-graph-profile.json`
- generator: `scripts/generate_agentic_exposure_graph.py`
- graph: `data/evidence/agentic-exposure-graph.json`
- MCP tool: `recipes_agentic_exposure_graph`

The graph ranks paths by access mode, connector state, residual risk,
workflow maturity, egress sensitivity, and readiness evidence so AI
platform and acquisition reviewers can see which agentic paths need
standard monitoring, guarded rollout, owner review, or architecture
review before scale.

### Agentic posture snapshot

The generated posture snapshot turns the control artifacts into an
enterprise posture-management surface:

- profile: `data/assurance/agentic-posture-model.json`
- generator: `scripts/generate_agentic_posture_snapshot.py`
- runtime evaluator: `scripts/evaluate_agentic_posture_decision.py`
- snapshot: `data/evidence/agentic-posture-snapshot.json`
- MCP tools: `recipes_agentic_posture_snapshot`,
  `recipes_evaluate_agentic_posture_decision`

The snapshot reports posture score, workflow posture decisions, XPIA and
session-exfiltration risk factors, high-exposure paths, pilot connector
rollups, actionable context-poisoning signals, source hashes, and buyer
views for AI platform review, procurement security, and acquisition
diligence.

### Agentic app intake gate

The generated app intake gate turns new agentic applications into
launch-review evidence:

- profile: `data/assurance/agentic-app-intake-profile.json`
- generator: `scripts/generate_agentic_app_intake_pack.py`
- runtime evaluator: `scripts/evaluate_agentic_app_intake_decision.py`
- pack: `data/evidence/agentic-app-intake-pack.json`
- MCP tools: `recipes_agentic_app_intake_pack`,
  `recipes_evaluate_agentic_app_intake_decision`

The gate scores autonomy, data classes, MCP access, remote tools,
indirect prompt injection exposure, external writes, production writes,
memory, A2A handoffs, guardrail evals, telemetry, run receipts, egress
controls, authorization binding, skill governance, incident response,
and approval evidence before launch or production expansion.

### Model provider routing gate

The generated model provider routing gate turns provider/model choice
into a governed secure-context boundary:

- profile: `data/assurance/model-provider-routing-profile.json`
- generator: `scripts/generate_model_provider_routing_pack.py`
- runtime evaluator:
  `scripts/evaluate_model_provider_routing_decision.py`
- pack: `data/evidence/model-provider-routing-pack.json`
- MCP tools: `recipes_model_provider_routing_pack`,
  `recipes_evaluate_model_provider_routing_decision`

The pack maps approved frontier-provider, private-runtime, local-model,
and unsanctioned-provider routes to workflow, data-class, autonomy,
retention, training exclusion, residency, DPA, guardrail, telemetry,
run-receipt, egress, and human-approval evidence. Runtime decisions are
allow approved route, allow guarded route, hold for provider review,
deny unapproved route, or kill session on provider signal.

### Secure context trust pack

The generated secure context trust pack defines which context roots are
approved for agent retrieval and how retrieved text is handled:

- registry: `data/context/secure-context-registry.json`
- generator: `scripts/generate_secure_context_trust_pack.py`
- runtime evaluator: `scripts/evaluate_secure_context_retrieval.py`
- pack: `data/evidence/secure-context-trust-pack.json`
- MCP tools: `recipes_secure_context_trust_pack`,
  `recipes_evaluate_context_retrieval_decision`

The pack records source owners, trust tiers, source hashes, retrieval
decisions, poisoning controls, citation requirements, and per-workflow
context package hashes. CI runs the generator in `--check` mode so the
secure context layer cannot drift silently from source-controlled docs,
policy, evidence, or MCP runtime code. The runtime evaluator uses that
pack as a default-deny context firewall: unregistered context is denied,
workflow-unapproved context is denied, hash drift holds for
recertification, and prohibited data classes kill the session.

### Secure context attestation pack

The generated secure context attestation pack turns the trust pack into a
verifiable context-subject inventory:

- profile: `data/assurance/secure-context-attestation-profile.json`
- generator: `scripts/generate_secure_context_attestation_pack.py`
- runtime evaluator: `scripts/evaluate_context_attestation_decision.py`
- pack: `data/evidence/secure-context-attestation-pack.json`
- MCP tools: `recipes_secure_context_attestation_pack`,
  `recipes_evaluate_context_attestation_decision`

The pack creates an in-toto-shaped statement seed for context sources,
workflow context packages, and source artifacts. Open-reference and CI
environments can verify hashes immediately; production MCP,
trust-center, and diligence environments hold until a keyless signature
bundle and transparency-log proof are present.

### Secure context lineage ledger

The generated secure context lineage ledger turns context movement into
a buyer- and runtime-readable evidence surface:

- profile: `data/assurance/secure-context-lineage-profile.json`
- generator: `scripts/generate_secure_context_lineage_ledger.py`
- runtime evaluator: `scripts/evaluate_secure_context_lineage_decision.py`
- ledger: `data/evidence/secure-context-lineage-ledger.json`
- MCP tools: `recipes_secure_context_lineage_ledger`,
  `recipes_evaluate_secure_context_lineage_decision`

The ledger joins context source hashes, attestation state, poisoning
scan state, retrieval decisions, model-provider routes, egress
boundaries, handoff boundaries, telemetry requirements, run receipts,
and reuse policy. It is designed for MCP gateway enforcement, AI
platform review, incident replay, trust-center export, and acquisition
diligence. The runtime evaluator returns allow, hold, deny, or
kill-session decisions before context is reused, handed off, routed,
persisted, or trusted after an agent run.

### Secure context eval pack

The generated secure context eval pack turns the secure context layer
into scenario-backed product evidence:

- profile: `data/assurance/secure-context-eval-scenarios.json`
- generator: `scripts/generate_secure_context_eval_pack.py`
- runtime evaluator: `scripts/evaluate_secure_context_eval_case.py`
- pack: `data/evidence/secure-context-eval-pack.json`
- MCP tools: `recipes_secure_context_eval_pack`,
  `recipes_evaluate_secure_context_eval_case`

The pack checks retrieval correctness, production attestation holds,
context-poisoning scan status, egress decisions, answer citation
contracts, and agent-to-agent handoff boundaries. It is designed for CI,
MCP gateways, trust-center exports, and acquisition diligence.

### Secure context release gate

The generated secure context release gate promotes trusted context into
explicit open-reference, production MCP, and trust-center release
channels instead of letting agents consume unversioned docs:

- profile: `data/context/secure-context-release-profile.json`
- generator: `scripts/generate_secure_context_release_pack.py`
- runtime evaluator: `scripts/evaluate_secure_context_release_decision.py`
- pack: `data/context/secure-context-release-pack.json`
- docs: `content/docs/secure-context-release/_index.md`

```bash
python3 scripts/generate_secure_context_release_pack.py
python3 scripts/generate_secure_context_release_pack.py --check

python3 scripts/evaluate_secure_context_release_decision.py \
  --release-id production-policy-context-release \
  --channel-id production-mcp \
  --environment production_mcp \
  --expect-decision hold_for_signature
```

The release gate joins the trust pack, attestation pack, poisoning guard,
secure-context evals, egress boundary, and threat radar into a
source-hash manifest. Open-reference releases can ship unsigned with
citations and scans; production MCP and trust-center releases hold until
signature and transparency-log evidence are present; high-risk assurance
sources hold for poisoning review.

### Context poisoning guard pack

The generated context poisoning guard pack adds deterministic inspection
to the secure context layer:

- profile: `data/assurance/context-poisoning-guard-profile.json`
- generator: `scripts/generate_context_poisoning_guard_pack.py`
- pack: `data/evidence/context-poisoning-guard-pack.json`
- MCP tool: `recipes_context_poisoning_guard_pack`

The pack scans registered context roots for direct instruction override,
secret exfiltration, approval bypass, hidden HTML instruction, external
callback, encoded payload, and zero-width control markers. It separates
documented adversarial examples from actionable poisoning risk so MCP
clients can hold or block unsafe context without removing red-team
training material from the knowledge base.

### Agentic threat radar

The generated agentic threat radar maps current external guidance to
SecurityRecipes product capabilities and roadmap priorities:

- source registry: `data/intelligence/agentic-threat-radar-sources.json`
- generator: `scripts/generate_agentic_threat_radar.py`
- radar: `data/evidence/agentic-threat-radar.json`
- MCP tool: `recipes_agentic_threat_radar`

The radar records source-backed signals, priority, horizon, confidence,
buyer triggers, mapped capabilities, source URLs, and recommended
roadmap actions. CI runs the generator in `--check` mode so market and
threat intelligence cannot drift silently from the generated MCP-facing
artifact.

### Agentic standards crosswalk

The generated standards crosswalk maps current OWASP, NIST, MCP,
OpenAI, and Anthropic agentic security guidance to SecurityRecipes
capabilities, generated evidence, and MCP tools:

- profile: `data/assurance/agentic-standards-crosswalk.json`
- generator: `scripts/generate_agentic_standards_crosswalk.py`
- crosswalk: `data/evidence/agentic-standards-crosswalk.json`
- MCP tool: `recipes_agentic_standards_crosswalk`

The pack answers procurement, AI platform, and acquisition diligence
questions by linking standards controls to evidence paths, runtime
evaluators, MCP tools, and commercialization hooks. CI runs the generator
in `--check` mode so standards coverage cannot drift silently from the
generated MCP-facing artifact.

### MCP and agentic skills risk coverage

The generated risk coverage pack maps OWASP MCP Top 10 and OWASP
Agentic Skills Top 10 risks to SecurityRecipes capabilities, generated
evidence, MCP tools, and hosted product wedges:

- profile: `data/assurance/mcp-risk-coverage-profile.json`
- generator: `scripts/generate_mcp_risk_coverage_pack.py`
- pack: `data/evidence/mcp-risk-coverage-pack.json`
- MCP tool: `recipes_mcp_risk_coverage_pack`

The pack answers buyer questions about token exposure, scope creep, tool
poisoning, shadow MCP servers, context over-sharing, malicious skills,
over-privileged skills, weak isolation, update drift, and skill
governance with evidence paths rather than claims.

### Agentic control plane blueprint

The generated agentic control plane blueprint turns the existing packs
into one architecture and buyer-diligence artifact:

- profile: `data/assurance/agentic-control-plane-blueprint.json`
- generator: `scripts/generate_agentic_control_plane_blueprint.py`
- blueprint: `data/evidence/agentic-control-plane-blueprint.json`
- MCP tool: `recipes_agentic_control_plane_blueprint`

The blueprint maps architecture layers to source packs, MCP tools,
buyer questions, commercialization path, and acquisition-readiness
signals. It is designed for AI platform architecture review, MCP server
intake, procurement security, GRC, and acquisition diligence.

### Agentic catastrophic-risk annex

The generated catastrophic-risk annex turns high-impact autonomy into
explicit severe-risk scenarios, default decisions, evidence gates, kill
signals, and buyer views:

- profile: `data/assurance/agentic-catastrophic-risk-annex.json`
- generator: `scripts/generate_agentic_catastrophic_risk_annex.py`
- evaluator: `scripts/evaluate_agentic_catastrophic_risk_decision.py`
- annex: `data/evidence/agentic-catastrophic-risk-annex.json`
- MCP tools: `recipes_agentic_catastrophic_risk_annex`, `recipes_evaluate_agentic_catastrophic_risk_decision`

The annex is designed for board AI risk review, high-impact MCP tool
approval, procurement security, and acquisition diligence. CI runs the
generator in `--check` mode so severe-risk evidence cannot drift from
the generated source packs.

### Agentic incident response pack

The generated incident response pack turns secure-context and MCP-backed
agent failures into an enterprise response model:

- profile: `data/assurance/agentic-incident-response-profile.json`
- generator: `scripts/generate_agentic_incident_response_pack.py`
- evaluator: `scripts/evaluate_agentic_incident_response_decision.py`
- pack: `data/evidence/agentic-incident-response-pack.json`
- MCP tools: `recipes_agentic_incident_response_pack`, `recipes_evaluate_agentic_incident_response_decision`

The pack covers context poisoning, MCP tool misuse, identity scope abuse,
authorization confused-deputy events, token passthrough, agent handoff
leakage, memory or skill compromise, high-impact autonomy near misses,
and evidence integrity gaps. It is designed for AI platform incident
response, SOC tabletop exercises, trust-center readouts, customer
disclosure evidence, and acquisition diligence.

### Agentic action runtime pack

The generated action runtime pack turns secure-context and MCP evidence
into pre-action allow, hold, deny, or kill decisions:

- profile: `data/assurance/agentic-action-runtime-profile.json`
- generator: `scripts/generate_agentic_action_runtime_pack.py`
- evaluator: `scripts/evaluate_agentic_action_runtime_decision.py`
- pack: `data/evidence/agentic-action-runtime-pack.json`
- MCP tools: `recipes_agentic_action_runtime_pack`, `recipes_evaluate_agentic_action_runtime_decision`

The pack covers branch writes, production deploys, identity and scope
changes, credential access, external context egress, remote agent
handoffs, persistent memory writes, skill or tool installs, registry
quarantine, and irreversible transactions. It is designed for MCP
gateways, agent hosts, high-impact action inventory, platform readiness
reviews, and buyer diligence.

### Agentic approval receipt pack

The generated approval receipt pack turns human approvals into scoped,
time-boxed, replayable evidence:

- profile: `data/assurance/agentic-approval-receipt-profile.json`
- generator: `scripts/generate_agentic_approval_receipt_pack.py`
- evaluator: `scripts/evaluate_agentic_approval_receipt_decision.py`
- pack: `data/evidence/agentic-approval-receipt-pack.json`
- MCP tools: `recipes_agentic_approval_receipt_pack`, `recipes_evaluate_agentic_approval_receipt_decision`

The pack covers bounded remediation, privileged tool step-up, identity
scope changes, production releases, secret and data boundaries,
irreversible actions, and incident containment. It is designed for
approval-source integrations, signed receipt validation, buyer diligence,
and hosted MCP enforcement before high-impact agent actions execute.

### Browser-agent workspace boundary pack

The generated browser-agent boundary pack turns browser and desktop agent
authority into deterministic allow, hold, deny, or kill decisions:

- profile: `data/assurance/browser-agent-boundary-profile.json`
- generator: `scripts/generate_browser_agent_boundary_pack.py`
- evaluator: `scripts/evaluate_browser_agent_boundary_decision.py`
- pack: `data/evidence/browser-agent-boundary-pack.json`
- MCP tools: `recipes_browser_agent_boundary_pack`, `recipes_evaluate_browser_agent_boundary_decision`

The pack covers logged-out research browsers, the SecurityRecipes
browser planner, isolated enterprise browser workspaces, email/document
agents, personal browser profiles, localhost developer tooling, and
payment or admin consoles. It is designed for AI browser procurement,
browser-agent launch reviews, desktop agent workspace design, prompt
injection tabletops, and buyer diligence.

### Agentic entitlement review pack

The generated entitlement review pack turns agent identities and MCP
scopes into expiring access-review evidence:

- profile: `data/assurance/agentic-entitlement-review-profile.json`
- generator: `scripts/generate_agentic_entitlement_review_pack.py`
- evaluator: `scripts/evaluate_agentic_entitlement_decision.py`
- pack: `data/evidence/agentic-entitlement-review-pack.json`
- MCP tools: `recipes_agentic_entitlement_review_pack`, `recipes_evaluate_agentic_entitlement_decision`

The pack covers permission leases, review cadence, step-up
authorization, approval evidence, token-passthrough denial, revocation
signals, and deterministic allow, hold, deny, or kill decisions. It is
designed for MCP gateways, IAM access reviews, AI platform intake,
quarterly recertification, and buyer diligence.

### Enterprise trust-center export

The generated enterprise trust-center export bundles the product's
secure-context, MCP, identity, entitlement review, handoff, incident
response, eval, readiness, and runtime evidence into one buyer-diligence
packet:

- profile: `data/assurance/enterprise-trust-center-profile.json`
- generator: `scripts/generate_enterprise_trust_center_export.py`
- export: `data/evidence/enterprise-trust-center-export.json`
- MCP tool: `recipes_enterprise_trust_center_export`

The export indexes required evidence packs, hashes, categories, MCP
tools, trust-center sections, and diligence questions. It is designed
for procurement review, AI platform intake, trust-center export, and
acquisition diligence.

### Standalone MCP server (Python + Docker)

This repo also includes a standalone MCP server implementation that reads
`recipes-index.json` directly from GitHub Pages (or any forked host):

- Script: `mcp_server.py`
- Config template: `mcp-server.toml.example`
- Docker image recipe: `Dockerfile.mcp-server`
- Python deps: `requirements-mcp-server.txt`

#### Local run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-mcp-server.txt
cp mcp-server.toml.example mcp-server.toml
python mcp_server.py
# MCP endpoint: http://localhost:8000/mcp
```

#### Docker run

```bash
docker build -f Dockerfile.mcp-server -t mcp.server .
docker run --rm -it \
  -p 8123:80 \
  mcp.server
# MCP endpoint: http://localhost:8123/mcp
```

See `README.mcp-localhost.md` for client configuration examples and
localhost troubleshooting.

#### Re-pointing for forks / custom domains

Edit `mcp-server.toml`:

- `source_index_url` → where your fork publishes `recipes-index.json`
- `allowed_source_hosts` → strict allow-list for that index hostname
- `server_public_base_url` → your MCP server's own hostname (metadata)
- `control_plane_manifest_path` -> local workflow-control-plane manifest
  exposed through the `recipes_workflow_control_plane` MCP tool
- `gateway_policy_path` -> generated policy pack exposed through the
  `recipes_mcp_gateway_policy` and
  `recipes_evaluate_mcp_gateway_decision` MCP tools
- `assurance_pack_path` -> generated assurance pack exposed through the
  `recipes_agentic_assurance_pack` MCP tool
- `identity_ledger_path` -> generated agent identity ledger exposed
  through the `recipes_agent_identity_ledger` MCP tool
- `entitlement_review_pack_path` -> generated agentic entitlement
  review pack exposed through `recipes_agentic_entitlement_review_pack`
  and `recipes_evaluate_agentic_entitlement_decision` MCP tools
- `approval_receipt_pack_path` -> generated scope-bound approval
  receipt pack exposed through `recipes_agentic_approval_receipt_pack`
  and `recipes_evaluate_agentic_approval_receipt_decision` MCP tools
- `connector_trust_pack_path` -> generated MCP connector trust pack
  exposed through the `recipes_mcp_connector_trust_pack` MCP tool
- `connector_intake_pack_path` -> generated MCP connector intake pack
  exposed through the `recipes_mcp_connector_intake_pack` MCP tool
- `mcp_stdio_launch_boundary_pack_path` -> generated MCP STDIO launch
  boundary pack exposed through `recipes_mcp_stdio_launch_boundary_pack`
  and `recipes_evaluate_mcp_stdio_launch_decision`
- `authorization_conformance_pack_path` -> generated MCP authorization
  conformance pack exposed through
  `recipes_mcp_authorization_conformance_pack` and
  `recipes_evaluate_mcp_authorization_decision`
- `elicitation_boundary_pack_path` -> generated MCP elicitation
  boundary pack exposed through `recipes_mcp_elicitation_boundary_pack`
  and `recipes_evaluate_mcp_elicitation_boundary_decision`
- `tool_risk_contract_path` -> generated MCP tool-risk contract exposed
  through `recipes_mcp_tool_risk_contract` and
  `recipes_evaluate_mcp_tool_risk_decision`
- `tool_surface_drift_pack_path` -> generated MCP tool-surface drift
  pack exposed through `recipes_mcp_tool_surface_drift_pack` and
  `recipes_evaluate_mcp_tool_surface_drift_decision`
- `red_team_drill_pack_path` -> generated agentic red-team drill pack
  exposed through the `recipes_agentic_red_team_drill_pack` MCP tool
- `readiness_scorecard_path` -> generated agentic readiness scorecard
  exposed through the `recipes_agentic_readiness_scorecard` MCP tool
- `capability_risk_register_path` -> generated capability risk register
  exposed through the `recipes_agent_capability_risk_register` MCP tool
- `agent_memory_boundary_pack_path` -> generated agent memory boundary
  pack exposed through the `recipes_agent_memory_boundary_pack` and
  `recipes_evaluate_agent_memory_decision` MCP tools
- `agent_skill_supply_chain_pack_path` -> generated agent skill
  supply-chain pack exposed through the
  `recipes_agent_skill_supply_chain_pack` and
  `recipes_evaluate_agent_skill_decision` MCP tools
- `agent_handoff_boundary_pack_path` -> generated agent handoff boundary
  pack exposed through `recipes_agent_handoff_boundary_pack` and
  `recipes_evaluate_agent_handoff_decision` MCP tools
- `a2a_agent_card_trust_profile_path` -> generated A2A Agent Card trust
  profile exposed through `recipes_a2a_agent_card_trust_profile` and
  `recipes_evaluate_a2a_agent_card_trust_decision` MCP tools
- `agentic_system_bom_path` -> generated Agentic System BOM exposed
  through the `recipes_agentic_system_bom` MCP tool
- `agentic_run_receipt_pack_path` -> generated run receipt pack exposed
  through the `recipes_agentic_run_receipt_pack` MCP tool
- `secure_context_trust_pack_path` -> generated secure context trust pack
  exposed through the `recipes_secure_context_trust_pack` and
  `recipes_evaluate_context_retrieval_decision` MCP tools
- `secure_context_attestation_pack_path` -> generated secure context
  attestation pack exposed through
  `recipes_secure_context_attestation_pack` and
  `recipes_evaluate_context_attestation_decision` MCP tools
- `secure_context_lineage_ledger_path` -> generated secure context
  lineage ledger exposed through `recipes_secure_context_lineage_ledger`
  and `recipes_evaluate_secure_context_lineage_decision` MCP tools
- `secure_context_eval_pack_path` -> generated secure context eval pack
  exposed through `recipes_secure_context_eval_pack` and
  `recipes_evaluate_secure_context_eval_case` MCP tools
- `context_poisoning_guard_pack_path` -> generated context poisoning
  guard pack exposed through the `recipes_context_poisoning_guard_pack`
  MCP tool
- `context_egress_boundary_pack_path` -> generated context egress
  boundary pack exposed through `recipes_context_egress_boundary_pack`
  and `recipes_evaluate_context_egress_decision` MCP tools
- `threat_radar_path` -> generated agentic threat radar exposed through
  the `recipes_agentic_threat_radar` MCP tool
- `standards_crosswalk_path` -> generated agentic standards crosswalk
  exposed through the `recipes_agentic_standards_crosswalk` MCP tool
- `mcp_risk_coverage_pack_path` -> generated OWASP MCP and agentic-skill
  risk coverage exposed through the `recipes_mcp_risk_coverage_pack`
  MCP tool
- `control_plane_blueprint_path` -> generated control plane blueprint
  exposed through the `recipes_agentic_control_plane_blueprint` MCP tool
- `exposure_graph_path` -> generated agentic exposure graph exposed
  through the `recipes_agentic_exposure_graph` MCP tool
- `posture_snapshot_path` -> generated agentic posture snapshot exposed
  through `recipes_agentic_posture_snapshot` and
  `recipes_evaluate_agentic_posture_decision` MCP tools
- `app_intake_pack_path` -> generated agentic app intake pack exposed
  through `recipes_agentic_app_intake_pack` and
  `recipes_evaluate_agentic_app_intake_decision` MCP tools
- `model_provider_routing_pack_path` -> generated model provider routing
  pack exposed through `recipes_model_provider_routing_pack` and
  `recipes_evaluate_model_provider_routing_decision` MCP tools
- `incident_response_pack_path` -> generated agentic incident response
  pack exposed through `recipes_agentic_incident_response_pack` and
  `recipes_evaluate_agentic_incident_response_decision` MCP tools
- `action_runtime_pack_path` -> generated agentic action runtime pack
  exposed through `recipes_agentic_action_runtime_pack` and
  `recipes_evaluate_agentic_action_runtime_decision` MCP tools
- `browser_agent_boundary_pack_path` -> generated browser-agent
  workspace boundary pack exposed through
  `recipes_browser_agent_boundary_pack` and
  `recipes_evaluate_browser_agent_boundary_decision` MCP tools
- `measurement_probe_pack_path` -> generated measurement probe pack
  exposed through the `recipes_agentic_measurement_probe_pack` MCP tool
- `telemetry_contract_path` -> generated agentic telemetry contract
  exposed through `recipes_agentic_telemetry_contract` and
  `recipes_evaluate_agentic_telemetry_event` MCP tools
- `enterprise_trust_center_export_path` -> generated trust-center export
  exposed through the `recipes_enterprise_trust_center_export` MCP tool

This lets teams host the Hugo site and MCP server under different domains
without changing code.

### One-time setup

1. **Push this repo to GitHub.**
   The Hugo project lives at the repository root. Keep `hugo.yaml`,
   `content/`, `layouts/`, `assets/`, `static/`, `data/`, and
   `.github/workflows/hugo.yml` together at the top level.

2. **Choose your Pages URL.**
   For normal GitHub Pages hosting, no path edits are required:
   the workflow computes the correct `baseURL` for either
   `https://<user>.github.io/` or `https://<user>.github.io/<repo>/`
   and patches the root `hugo.yaml` during CI. For a custom domain,
   keep `static/CNAME` at the repo root's `static/` directory. For
   non-GitHub-Actions builds, set `baseURL` in `hugo.yaml` to the
   URL where the compiled site will be served.

3. **Push to `main`.**
   The workflow runs, creates the `gh-pages` branch on first deploy,
   and every subsequent push force-updates that branch with the
   latest build (`force_orphan: true` keeps the branch small).

4. **Point GitHub Pages at `gh-pages`.**
   In the repo's **Settings → Pages**:
   - **Source:** Deploy from a branch
   - **Branch:** `gh-pages`  /  `(root)`

   Save. A minute later your site is live at
   `https://<user>.github.io/<repo>/`.

> **Custom domain?** Add a `static/CNAME` file containing your domain
> (it ends up at the root of `gh-pages`, which is what makes the
> custom-domain binding survive `force_orphan: true` deploys). The
> workflow detects the CNAME and uses `https://<your-domain>/` as the
> baseURL automatically — no `hugo.yaml` edit required, and the
> GitHub-Pages-subpath rewrites (asset URLs, card links) are skipped
> because the site is served from the host root.

> **Token permissions.** The workflow only needs the default
> `GITHUB_TOKEN` with `contents: write` — no PATs required.

---

## Customising

- **Colors / branding** — `assets/css/custom.css` sets the shared
  accent palette and the ambient orbs that carry the landing-page
  aesthetic into the docs.
- **Logo** — replace `static/images/logo.svg`.
- **Per-tool covers** — replace anything in `static/images/covers/`.
- **Landing page** — `layouts/index.html` is a fully custom home.
  Tweak the hero copy, tool tags, or the Prompt Library CTA there.
- **Navbar / footer** — see the `menu` and `params.footer` blocks in
  `hugo.yaml`. The footer template itself is overridden at
  `layouts/partials/footer.html` to guarantee the site-owned copyright
  wins over the theme default.

---

## Forking for an enterprise

The site is designed to be forked and customised without code
changes:

- GitHub Pages forks usually need no path edits: the workflow computes
  `baseURL`, runs Hugo from the repo root, and publishes root `public/`.
- Use `static/CNAME` for a custom GitHub Pages domain, or update
  `baseURL` in `hugo.yaml` only for non-GitHub-Actions hosting.
- `HUGO_PARAMS_REPOURL` overrides Repository link targets via CI.
- Per-agent pages carry an **Enterprise Onboarding** section as a
  placeholder — a forking enterprise fills it with its own
  identity-provider, policy, and deployment specifics while leaving
  the **General Onboarding** section intact.

See each per-agent recipe for the exact shape; the pattern is
consistent across all five.

---

## License

MIT — see `LICENSE`.

---

An open, community-driven playbook for **security engineering teams** ♥
