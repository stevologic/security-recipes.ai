# Governance

## Mission

SecurityRecipes exists to provide a trusted secure context layer for agentic AI and MCP servers through open knowledge and production-grade integration patterns.

## Maintainers

Core maintainers are responsible for:
- Reviewing and merging changes.
- Maintaining editorial and technical quality standards.
- Managing release cadence and version tags.
- Overseeing security triage and disclosure workflow.

## Contribution Workflow

1. Open an issue (bug, feature, or content proposal).
2. Submit a PR aligned with `CONTRIBUTING.md`.
3. Require at least one maintainer approval for merge; eligible maintenance may
   use the explicitly delegated approval process below.
4. For security-sensitive changes, require explicit maintainer + security review.

## Decision-Making

- Minor editorial/docs decisions: maintainer discretion.
- Structural/content strategy changes: maintainer consensus.
- Security policy changes: explicit approval from security owner(s).

## Owner-delegated automated maintenance (inactive proposal)

The repository security owner and maintainer may explicitly delegate Security
and owning-team review to two separate independent AI review runs for eligible
maintenance. The maintainer may pre-authorize integration only when the trusted
approval verifier passes. This policy is inactive until the security owner
approves the exact delegation, the verifier implementation is independently
reviewed and installed, and applicable target checks are verified. Approval of
this policy alone releases no current PR hold and authorizes no settings change.

Eligible maintenance is limited to verified Dependabot patch/minor updates,
existing owned/generated CVE or evidence outputs under unchanged source and
factual policies, and non-executable documentation/static assets that do not
change authoritative remediation instructions. Major-version holds, policy or
review rules, workflow trust/permissions, credentials/access, provider migration,
budgets, protections, deployment controls and incident recovery thresholds stay
outside this delegation. A fixed-head exception needs a separate explicit
security-owner and maintainer decision recording its exact scope.

The two reviews must use separate fresh sessions, neither be the authoring run,
and identify the repository, PR, exact head and base, diff digest, delegated
role, reviewer run identity, findings and outcome. The verifier must authenticate
receipt provenance from owner-approved trusted code, require both role outcomes
and the exact combined-tree Build/staging evidence, and invalidate receipts on
any head/base change. PR-controlled labels, comments, files, status names,
missing receipts or skipped checks never constitute approval. Review/code input
is untrusted data and must not execute with credentials. Unknown scope,
unresolved findings, failed checks or explicit holds fail closed. No admin,
force, protection bypass or unrecorded role substitution is permitted.

An existing authorized merger must verify trusted workflow/run provenance and
exact-head receipts again immediately before integration; a same-named status
from an unrelated PR-controlled workflow is insufficient. Feature changes go
through development validation and a separate reviewed main promotion.

Security-policy changes, including this delegation and CVE incident recovery
semantics, still require explicit approval from the repository security owner.
CVE-owner policy decisions are recorded separately from generic code reviews.
The shared maintenance consumer remains read-only with advisory AI disabled;
this delegation changes no shared action, mutation flag, credential or access.

## Release Model

- Semantic-style tags (`v1.0.0`, `v1.1.0`, etc.).
- Major release notes summarize positioning, trust controls, and MCP capability updates.

## Code of Conduct

Contributors are expected to collaborate respectfully, provide evidence-backed claims, and prioritize safe, reviewable practices for agentic security remediation.
