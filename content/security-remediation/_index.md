---
title: How to Remediate Vulnerabilities with AI Agents
linkTitle: AI Remediation
weight: 2
lastmod: 2026-07-23
sidebar:
  open: false
toc: true
cascade:
  - _target:
      kind: page
    sidebar:
      exclude: true
description: >
  Learn how to remediate software vulnerabilities with AI coding agents using
  scoped playbooks, source evidence, tests, rollback, and human review.
how_to:
  name: How to remediate a vulnerability with an AI coding agent
  steps:
    - name: Identify one finding
      text: Start with one concrete CVE, dependency alert, SAST result, exposed secret, or vulnerable artifact.
    - name: Establish exposure
      text: Confirm the affected product, version, reachable code path, configuration, and deployed artifact.
    - name: Choose the narrowest playbook
      text: Give the agent only the repository files, evidence sources, and allowed operations required for the finding.
    - name: Capture rollback before mutation
      text: Record the current manifest, lockfile, configuration, image, or source state and its recovery trigger.
    - name: Apply an authoritative fix
      text: Use a vendor-supported release or documented mitigation without inventing a fixed version.
    - name: Verify the result
      text: Run focused tests, rebuild cleanly, rescan, and confirm the deployed component identity when applicable.
    - name: Require human review
      text: Return evidence, diff, tests, residual risk, and rollback; stop for triage when ownership or safety is unclear.
---

AI vulnerability remediation uses a coding agent to investigate one confirmed
security finding, make the smallest justified change, run the relevant tests,
and return a pull request or triage note for human review. The agent accelerates
repository work; it does not decide risk acceptance, invent fixed versions, or
gain permission to change production.

Here, **agentic vulnerability remediation** means AI agents fixing traditional
software, dependency, container, and repository-configuration vulnerabilities.
It does not mean finding flaws in AI models or AI systems, and it is distinct
from endpoint agents that only recommend actions for an operator to perform.

**Last updated July 23, 2026.** [Stephen M Abbott](/about/#stephen-m-abbott)
maintains this guide with Security Recipes contributors in the public
[source and revision history](https://github.com/stevologic/security-recipes.ai/blob/main/content/security-remediation/_index.md).
See the [review methodology](/about/#editorial-principles) and
[corrections policy](/about/#corrections). The method follows evidence and
change-control principles from the
[NIST Secure Software Development Framework](https://csrc.nist.gov/pubs/sp/800/218/final),
while product and vulnerability facts remain anchored to the affected vendor,
CVE record, NVD, and CISA evidence.

These playbooks are reusable, bounded instructions for that workflow. Each one
should tell an AI agent:

- what kind of finding it can handle,
- what context it needs,
- what files it should avoid,
- what tests or checks matter,
- when to stop and write a triage note,
- what a reviewer should see in the output.

The goal is not to automate every security task. The goal is to make safe,
bounded fixes easier to delegate while keeping source authority, change
approval, and final review with people.

## How to remediate a vulnerability with an AI agent

Before granting write access, require a named finding, proven affectedness, an
authoritative fix or mitigation, repository ownership, an allowed path set, a
protected test or scan, a rollback state, and a required reviewer. Dependency,
SAST, container, and repository-configuration findings can usually enter this
workflow. Endpoint patching, firmware, secret rotation, production-only
infrastructure, end-of-life products, and unclear ownership should stop for
operator-led triage unless separate authority and evidence are supplied.

1. **Identify one finding.** Start with a CVE, dependency alert, SAST result,
   exposed secret, vulnerable container layer, or similarly concrete signal.
2. **Establish exposure.** Confirm the affected product, version, code path,
   configuration, and deployed artifact before changing anything.
3. **Choose the narrowest playbook.** Give the agent only the repository files,
   evidence sources, and allowed operations needed for this finding.
4. **Capture rollback before mutation.** Record the current manifest, lockfile,
   configuration, image, or source state and the trigger that would restore it.
5. **Apply an authoritative fix.** Prefer a vendor-supported release or a
   documented mitigation. Never infer a fixed version from absence of evidence.
6. **Verify the result.** Run focused regression tests, rebuild from a clean
   state, rescan, and confirm the deployed component identity where applicable.
7. **Require human review.** Return the evidence, diff, tests, residual risk,
   and rollback path. Stop with `TRIAGE.md` when ownership or safe remediation
   cannot be proved.

<figure class="sr-guide-figure">
  <img src="/images/how-to-use/cve-to-agent-plan.webp"
       alt="A CVE record flows through affectedness checks, a bounded AI agent plan, verification, rollback evidence, and human review"
       width="2048" height="1152" loading="lazy" decoding="async">
  <figcaption>A CVE is an evidence input, not permission to patch. The agent receives a bounded plan only after affectedness and ownership are established.</figcaption>
</figure>

Start with the [CVE Database](/cve-database/) for an exact vulnerability, the
[Quick Start](/quickstart/) for a first agent-assisted fix, or the playbooks
below for a specific finding class.

## CVE-specific remediation guides

Use a CVE-specific recipe only when its product and affected-version evidence
match the finding you are investigating:

- [CVE-2026-45321: TanStack npm supply-chain compromise](/cve/CVE-2026-45321/)
- [CVE-2026-39987: Marimo pre-auth terminal RCE](/cve/CVE-2026-39987/)
- [CVE-2026-14956: Bricksforge Pro Forms privilege escalation](/cve/CVE-2026-14956/)
- [CVE-2025-48384: Git submodule code execution](/cve/CVE-2025-48384/)
- [CVE-2025-11953: Metro4Shell React Native CLI RCE](/cve/CVE-2025-11953/)
- [CVE-2025-3248: Langflow unauthenticated RCE](/cve/CVE-2025-3248/)
- [CVE-2024-23897: Jenkins CLI arbitrary file read](/cve/CVE-2024-23897/)
- [CVE-2024-37079: VMware vCenter Server heap-overflow RCE](/cve/CVE-2024-37079/)
- [CVE-2024-6387: OpenSSH regreSSHion race-condition RCE](/cve/CVE-2024-6387/)
- [CVE-2021-44228: Log4Shell in Apache Log4j](/cve/CVE-2021-44228/)
- [CVE-2024-3094: xz-utils supply-chain backdoor](/cve/CVE-2024-3094/)
- [CVE-2021-35395: Realtek AP-Router SDK buffer overflow](/cve/CVE-2021-35395/)
- [CVE-2014-0160: Heartbleed in OpenSSL](/recipes/cve/cve-2014-0160-heartbleed/)

## What an AI remediation agent should and should not do

An AI coding agent is most useful as a bounded repository operator. It can
trace dependency resolution, locate a vulnerable call site, prepare a narrow
patch, update tests, and assemble review evidence. It should not be treated as
the authority for affected versions, exploitability, business risk, or release
approval.

| The agent may do | Keep human-owned |
| --- | --- |
| Read the named alert, advisory, manifests, lockfiles, source, and tests | Decide whether the finding is accepted, deferred, or remediated |
| Prove which package, image, configuration, or code path is present | Confirm production ownership, exposure, and maintenance windows |
| Apply a vendor-supported upgrade or a documented mitigation | Approve breaking changes, compensating controls, and residual risk |
| Run focused tests, rebuild, rescan, and record command output | Review the diff and authorize merge or deployment |
| Stop with a precise triage note when evidence is missing | Supply credentials, secrets, production access, or broader authority |

OWASP's [Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)
tracks risks such as tool misuse, identity and privilege abuse, and goal
manipulation in autonomous workflows. In practice, give a remediation agent a
read-only starting posture, an explicit file boundary, the smallest necessary
write capability, and no production credentials.

## Choose an AI agent for vulnerability remediation

Use the agent your team already governs. Start with
[AI agents for vulnerability remediation](/agents/) to compare supported tools
and their native instruction surfaces. Each guide maps the same evidence, scope,
verification, rollback, and human-review contract onto that agent.

| Agent guide | Focused remediation recipe |
| --- | --- |
| [Remediate vulnerabilities with Codex](/codex/) | [Codex vulnerable dependency remediation prompt](/recipes/codex/vulnerable-dep-remediation/) |
| [Remediate CVEs with Claude Code](/claude/) | [Claude Code CVE remediation skill](/recipes/claude/cve-triage-skill/) |
| [Remediate vulnerable dependencies with Cursor](/cursor/) | [Cursor vulnerable dependency remediation](/recipes/cursor/vulnerable-dep-remediation/) |
| [Remediate vulnerabilities with GitHub Copilot](/github_copilot/) | [GitHub Copilot vulnerability remediation template](/recipes/github_copilot/vulnerable-dep-remediation/) |
| [Run scheduled vulnerability remediation with Devin](/devin/) | [Devin scheduled vulnerability remediation](/recipes/devin/scheduled-vulnerability-remediation/) |

## Hypothetical workflow: remediate a dependency CVE with an AI agent

Suppose a dependency alert reports a CVE in a transitive package. A weak
instruction such as “fix all vulnerabilities” invites unrelated upgrades and
gives the reviewer no proof that the reported component was removed. A bounded
run starts with the alert, the authoritative advisory, the repository's
manifest and lockfile, and the exact tests permitted for the affected area.

### Agent prompt template

```text
Remediate one finding: <CVE-ID> in <package or component>.

Allowed scope:
- Read <alert/advisory>, <manifest>, <lockfile>, affected source, and named tests.
- Change only files required for the smallest vendor-supported remediation.
- Do not deploy, rotate secrets, change permissions, or update unrelated packages.

Required evidence before editing:
1. Show the resolved vulnerable version and dependency path.
2. Cite the vendor-supported fixed version or documented mitigation.
3. State whether the affected code path or configuration is present.
4. Record the current lockfile or artifact state for rollback.

Verification:
- Preserve the original alert, reproducer, or scan result and its checksum
  before editing.
- Do not weaken, delete, skip, or reconfigure the scanner, CI gate, or original
  regression that proves the finding.
- Run <focused tests>.
- Rebuild from a clean dependency state.
- Show that the vulnerable version is absent from the resolved graph.
- Run the protected reproducer or an independently owned verifier after the
  patch.
- Report residual risk and the exact rollback command or revert path.

If affectedness, ownership, or a supported fix cannot be proved, stop and
write TRIAGE.md. Do not guess a version or broaden the change.
```

### Evidence a reviewer should receive

A reviewer-ready result contains the finding identity and source URL, the
before-and-after dependency path, a small diff, test and build output, a
rescan or equivalent absence check, rollback instructions, and remaining
uncertainty. “The tests passed” is not sufficient if the old package still
exists in another workspace, container layer, generated artifact, or deployed
image.

The correct result may be a triage note rather than a patch. For example, stop
when the only fixed release requires an unowned platform migration, when the
alert refers to a package that is not in the shipped artifact, or when a vendor
has not published a supported remediation. Those outcomes require a human risk
decision, not a more confident prompt.

## Real repository case study: CVE-2026-13149 in brace-expansion

On July 21, 2026, this repository's Dependabot alert 9 identified
[CVE-2026-13149 / GHSA-3jxr-9vmj-r5cp](https://github.com/advisories/GHSA-3jxr-9vmj-r5cp)
in the transitive development dependency `brace-expansion`. The lockfile
resolved `minimatch` to `brace-expansion` 1.1.15; the advisory marks the 1.x
line below 1.1.16 as vulnerable to exponential CPU consumption from a short
brace-pattern input.

A bounded, agent-assisted task produced the dependency portion of
[pull request 89](https://github.com/stevologic/security-recipes.ai/pull/89),
which was reviewed and merged the same day. That pull request also fixed a
separate Fail2Ban deployment bootstrap problem. The evidence below therefore
describes only the dependency slice; it does not present the entire pull
request as a one-finding change.

| Contract item | Recorded evidence |
| --- | --- |
| Finding | One high-severity advisory affecting transitive `brace-expansion` 1.1.15; the supported first patched 1.x release was 1.1.16. |
| Scope | `package-lock.json` and the dependency regression in `tests/test_dependabot_config.js`; no application API or unrelated package upgrade was required. |
| Change | The lockfile moved 1.1.15 to 1.1.16 and updated its registry artifact integrity. |
| Verification | The regression pins 1.1.16, the advisory proof input completed in about 1 ms, `npm audit` reported zero vulnerabilities, and the repository build, performance budget, and test suites passed. |
| Review and recovery | The public PR preserves the diff and validation trail. Reverting that dependency slice would restore the vulnerable version, so an operational rollback would need another supported patched release rather than 1.1.15. |

The durable proof is the
[version regression](https://github.com/stevologic/security-recipes.ai/blob/main/tests/test_dependabot_config.js)
and the public pull-request record, not the agent's summary. This example shows
the useful boundary: an agent can trace a transitive package, prepare a narrow
lockfile update, run the protected check, and assemble evidence. A person still
accepts the advisory, reviews the combined pull-request scope, and authorizes
the merge. It does not prove that every dependency alert, production asset, or
breaking upgrade is safe to delegate.

## Prioritize evidence before asking the agent to patch

Severity is an input, not a complete remediation decision. FIRST's
[CVSS v4 specification](https://www.first.org/cvss/v4.0/specification-document)
separates intrinsic base characteristics from threat and environment-specific
metrics. Combine that signal with actual deployment exposure, reachability,
asset importance, compensating controls, and evidence of exploitation.

Use this source order for a CVE-driven run:

1. The affected vendor's advisory and fixed-release notes for product-specific
   affected ranges, patches, and mitigations.
2. The CVE record and NVD entry for identity, normalized descriptions, CWE,
   CVSS observations, and source references.
3. The [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
   as an explicit prioritization input when exploitation is known in the wild.
4. The repository and deployed artifact for proof that the affected component
   and path actually exist in your environment.

Never let a model-generated summary outrank a newer vendor advisory. When two
sources disagree, preserve both claims, their dates, and the unresolved gap;
route the finding to a person who owns the affected system.

## Exact scope

Exact scope means a recipe is allowed to handle one concrete finding, not a
general backlog theme. The recipe should be narrow enough that a reviewer can
tell whether the agent stayed inside the boundary without reconstructing the
whole system.

A scoped recipe names:

- the finding identity, such as a CVE, scanner rule, SARIF alert, package,
  endpoint, or source/sink pair;
- the files, manifests, tests, and configuration the agent may inspect or
  change;
- the files and actions that are explicitly out of scope;
- the evidence that must be returned before review starts;
- the stop conditions that turn the run into a triage note instead of a patch.

The boundary is useful because it makes failure legible. If an agent needs to
touch unrelated ownership areas, change deployment topology, migrate data, edit
secrets, broaden permissions, or fix several findings at once, the recipe should
stop and ask for a human-owned plan. That is not a failed automation run; it is
the guardrail working.

Use [Recipe Recommender]({{< relref "/security-remediation/recipe-recommender" >}})
to choose the single safest recipe before work starts, and use
[Reviewer Playbook]({{< relref "/security-remediation/reviewer-playbook" >}})
to reject PRs that drift outside the declared scope.

## Python remediation suite

{{< cards >}}
  {{< card link="/security-remediation/remediation-suite/" title="Python Remediation Suite" subtitle="Run any of the 75 playbooks with bounded workspace inspection, agent-ready plans, integrity-hashed evidence, and deterministic verification." >}}
{{< /cards >}}

## Core remediation recipes

{{< cards >}}
  {{< card link="/security-remediation/vulnerable-dependencies/" title="Vulnerable Dependencies" subtitle="Bump direct and transitive dependencies, update lockfiles, and prove the affected package is no longer present." >}}
  {{< card link="/security-remediation/sast-findings/" title="SAST Findings" subtitle="Use for local, testable SAST fixes where the rule, source, sink, and safe pattern are clear." >}}
  {{< card link="/security-remediation/sensitive-data/" title="Sensitive Data" subtitle="Clean up exposed secrets, PII, or sensitive fields in logs, configs, fixtures, and schemas." >}}
  {{< card link="/security-remediation/base-images/" title="Base Images and Containers" subtitle="Update image tags, OS packages, and Dockerfile patterns without broad deployment changes." >}}
  {{< card link="/security-remediation/classic-vulnerable-defaults/" title="Classic Vulnerable Defaults" subtitle="Fix repeat offenders such as unsafe YAML, pickle, XXE, weak JWT settings, and dangerous defaults." >}}
  {{< card link="/security-remediation/artifact-cache-purge/" title="Artifact Cache Purge" subtitle="Quarantine compromised artifacts from mirrors, registries, and CI caches." >}}
{{< /cards >}}

## Specialized domains

{{< cards >}}
  {{< card link="/security-remediation/crypto-payments/" title="Crypto Payments" subtitle="Protect irreversible payment, wallet, address, and settlement workflows." >}}
  {{< card link="/security-remediation/defi-blockchain/" title="DeFi and Blockchain" subtitle="Remediation patterns for smart contracts, bridges, oracle usage, and governance workflows." >}}
{{< /cards >}}

## Operating the recipe loop

{{< cards >}}
  {{< card link="/security-remediation/recipe-recommender/" title="Recipe Recommender" subtitle="Classify one finding and pick the single safest downstream recipe before an agent starts remediation." >}}
  {{< card link="/security-remediation/reviewer-playbook/" title="Reviewer Playbook" subtitle="Questions reviewers should ask before merging an agent-authored security PR." >}}
  {{< card link="/security-remediation/gatekeeping/" title="Gatekeeping Patterns" subtitle="Admission, mid-run, pre-merge, and post-merge gates for agent-assisted work." >}}
  {{< card link="/security-remediation/runtime-controls/" title="Runtime Controls" subtitle="How to keep agent tool use scoped while a remediation run is active." >}}
  {{< card link="/security-remediation/maturity/" title="Rollout Model" subtitle="Crawl, walk, run adoption with promotion criteria and stop signals." >}}
  {{< card link="/security-remediation/metrics/" title="Metrics" subtitle="MTTR, reviewer burden, merge quality, false positives, and where automation is earning its keep." >}}
  {{< card link="/security-remediation/compliance/" title="Compliance and Audit" subtitle="Evidence patterns for SOC 2, ISO 27001, PCI DSS, NIST SSDF, and internal review." >}}
  {{< card link="/security-remediation/evidence-bundles/" title="Evidence Bundles" subtitle="Export run receipts as normalized events, manifests, control gaps, hashes, and readable audit reports." >}}
{{< /cards >}}

## Production guardrails for AI remediation agents

After the finding-specific workflow is working, use the control groups below
to choose the next production safeguard. They connect agent identity, runtime
authority, evidence, and incident response without treating every control as a
requirement for every remediation run.

### Agent identity, delegated authority, and trust

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
- [Operate the workflow control plane](/security-remediation/control-plane/) across admission, execution, review, and release gates.
- [Score agentic risk with AIVSS](/security-remediation/agentic-aivss-risk-scoring/) when an AI-system finding needs consistent prioritization evidence.
- [Route model-provider traffic safely](/security-remediation/model-provider-routing-gate/) when data sensitivity or jurisdiction changes the allowed provider.

### Authorization, exposure, and runtime boundaries

- [Review agent entitlements](/security-remediation/agentic-entitlement-review/) to find excessive, stale, or unowned permissions.
- [Map agentic exposure paths](/security-remediation/agentic-exposure-graph/) from untrusted input through tools, identities, and consequential actions.
- [Isolate browser-agent workspaces](/security-remediation/browser-agent-boundary/) before an agent handles authenticated sessions or downloaded content.
- [Guard against context poisoning](/security-remediation/context-poisoning-guard/) when retrieved text can influence privileged tool use.
- [Enforce a secure-context firewall](/security-remediation/secure-context-firewall/) between untrusted evidence and executable instructions.

### Protocols, connectors, and system inventory

- [Test agent protocol conformance](/security-remediation/agentic-protocol-conformance/) for deterministic identity, error, and authorization behavior.
- [Maintain an MCP connector trust registry](/security-remediation/mcp-connector-trust-registry/) with ownership, provenance, and review state.
- [Measure MCP and agent-skill risk coverage](/security-remediation/mcp-risk-coverage/) against the tool and connector surface actually in use.
- [Generate an agentic system BOM](/security-remediation/agentic-system-bom/) for models, agents, tools, connectors, identities, and data stores.
- [Watch authoritative sources for drift](/security-remediation/agentic-source-freshness-watch/) before stale guidance reaches a remediation agent.

### Evidence, evaluation, and incident readiness

- [Prepare an agentic incident-response pack](/security-remediation/agentic-incident-response-pack/) with containment, evidence, and recovery procedures.
- [Run agentic measurement probes](/security-remediation/agentic-measurement-probes/) against the controls that should stop or constrain a run.
- [Replay adversarial agent scenarios](/security-remediation/agentic-red-team-replay-harness/) to prove fixes remain effective after policy or model changes.
- [Evaluate secure-context behavior](/security-remediation/secure-context-evals/) with versioned fixtures and reviewable pass criteria.
- [Capture approval receipts](/security-remediation/agentic-approval-receipts/) for high-impact actions that require explicit human authorization.
- [Publish a secure-context evidence contract](/security-remediation/secure-context-evidence-contract/) so reviewers know which claims and artifacts are required.

### Secure-context provenance and enterprise assurance

- [Model catastrophic agentic risk](/security-remediation/agentic-catastrophic-risk-annex/) for low-frequency, high-impact failure paths.
- [Attest secure-context controls](/security-remediation/secure-context-attestation/) with integrity-bound evidence rather than self-reported claims.
- [Trace secure-context lineage](/security-remediation/secure-context-lineage-ledger/) from source acquisition through transformation and agent use.
- [Assemble a secure-context trust pack](/security-remediation/secure-context-trust-pack/) for security, procurement, and architecture review.
- [Quantify secure-context value](/security-remediation/secure-context-value-model/) using measurable risk and operating outcomes.
- [Apply a critical-infrastructure profile](/security-remediation/critical-infrastructure-secure-context/) where safety, availability, and regulatory evidence raise the bar.

## Recipe run contract

```text
One finding.
One matching recipe.
One agent run.
One PR or triage note.
Human review before merge.
```

That contract keeps agentic remediation useful. If a finding requires broad
architecture work, production infrastructure changes, unclear ownership, or a
high-risk data migration, the correct output is a triage note rather than a
heroic patch.

## MCP context for recipes

Most recipes get better when the agent can read structured evidence:

- advisory and package data,
- code scanning alerts,
- SBOM or SARIF output,
- repository ownership,
- CI status,
- internal runbooks.

Use [MCP Integration]({{< relref "/mcp-servers" >}}) to connect those sources
as scoped context. Start read-only; add write access only after a separate
review.

## Common questions about AI vulnerability remediation

### Can an AI agent automatically patch every CVE?

No. It can safely handle a subset of findings where affectedness, repository
ownership, an authoritative remediation, focused verification, and rollback
are all available. Kernel, firmware, infrastructure, data migration,
production-only, end-of-life, or ownership-ambiguous findings usually require
triage and a human-owned change plan.

### Which coding agents can use these playbooks?

The method is tool-independent. Use the setup guides for [Codex](/codex/),
[Claude Code](/claude/), [Cursor](/cursor/), [GitHub Copilot](/github_copilot/),
or [Devin](/devin/) to translate the same scope, evidence, stop, and review
contract into the agent you already operate.

### Should the agent use CVSS to choose what to fix first?

Not by itself. CVSS communicates vulnerability characteristics; it does not
prove that your deployed asset is exposed or that a vulnerability is being
exploited. Combine it with vendor urgency, CISA KEV status, reachable attack
paths, asset criticality, and the cost and safety of the remediation.

### What should happen when the agent cannot prove a safe fix?

It should stop without editing and return a triage note naming the missing
evidence, affected owner, attempted checks, temporary containment options, and
the decision required. A bounded stop is a successful control outcome; an
unsupported upgrade is not.

## Add or improve a recipe

Good recipes are specific. They name what is in scope, what is out of scope,
what evidence is required, and what a safe stop looks like. See
[Contribute]({{< relref "/contribute" >}}) when you have a working recipe or
prompt to share.
