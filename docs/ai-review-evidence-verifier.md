# Held review-evidence verifier

This draft supplies a read-only verifier component for the inactive two-file
AI-role delegation proposal. It is not a role approval, required status publisher,
model runner, merger or deployment controller. It has no workflow caller and no
activation option. Settings, access, credentials, budgets, provider/model wiring,
the BF1.1.1 shared consumer and PR holds are unchanged. #385's CVE-policy decision
is not approved by this work.

The shipped registry has `delegation_active=false`, all trusted publisher lists
empty, and explicit holds for #361, #382, #383, #384 and #385. Draft PRs and protected policy/control
paths cannot qualify. No workflow/run/actor/model identity is invented as an
approved production reviewer. Registered fixture identities used in tests are
offline examples only.

## Preview use and authority

Run `python scripts/verify_ai_review_evidence.py --self-check` to validate the
inactive registry without a credential, network call or model request. It exits
**3** and reports both approval and merge authority false. Invalid evidence
exits 1; configuration/read failures exit 2. The CLI never exits successfully as
an approval check, and even complete authenticated evidence remains held.

A future preview can supply a PR number and four GitHub run IDs using `--pr`,
`--security-run`, `--owning-team-run`, `--build-run` and `--staging-run`, with the
existing `GITHUB_TOKEN` available for read-only API requests. The CLI has no
arbitrary repository, URL, saved-metadata bundle, policy override, write or
activation option. Do not install its exit code as the required
`ai-approval-policy` check. Activation needs a new, independently reviewed
implementation and explicit owner authorization.

## Trust boundary

The reader calls only narrowly allowed GET endpoints at `api.github.com` for
this repository. It never follows authenticated API redirects. Artifact storage
receives a new credential-free request only for an HTTPS Azure Blob redirect;
another redirect is refused. Download and JSON/ZIP sizes are bounded. Raw server
errors, response bodies and token values are not emitted as diagnostics.

PR files/comments/labels or model JSON cannot assert their own provenance. The
verifier independently reads PR/head/base/combined-parent metadata, nontruncated
Git tree inventories and changed-file inventories. It binds every receipt to
the repository, PR, head/target repositories and branch refs, exact
head/base/combined commit/tree and a canonical digest
of changed paths, old/new blobs and file modes. Changes to executable modes,
forks, unregistered targets and incomplete inventories are held. A fresh final
snapshot detects head/base/ref changes during verification.

Each evidence role needs a distinct owner-approved workflow ID, immutable
definition commit, exact workflow path/default branch, permitted initial and
current-attempt triggering actor identities,
successful completed run and expected non-skipped job. GitHub artifact metadata
must identify that run and definition. The downloaded ZIP SHA-256 must match the
authenticated metadata; exactly one bounded `receipt.json` is read without
extracting paths. Duplicate, expired, missing, stale-attempt, ambiguous or
malformed artifacts are held. ZIP compression is restricted to stored or
deflated members; JSON rejects nonfinite numbers and excessive nesting.
An unrelated same-named check from GitHub Actions
is insufficient. After the final PR snapshot, run/job/artifact metadata is read
again and must remain identical and successful, including the current attempt,
actors and artifact digest. GitHub GETs do not provide an atomic snapshot; a
future authorized operator must still independently recheck immediately before
its exact-head action. This preview cannot eliminate changes after its last GET.

The two review receipts require distinct fresh session identities, consistent
authenticated authoring-session provenance, no reuse of an evidence/authoring
run, exact scope, pass outcomes, no unresolved findings and explicit assertions
that excluded security semantics did not change. Dependency metadata must attest
verified patch/minor classification with no maintainer changes. Generated
outputs require source/ownership validation under unchanged factual policy.
The generated-path registry is empty until its ownership scope is reviewed.
Build evidence must cover all native check families; staging evidence must
identify development and the exact combined revision.

These assertions are accepted only inside receipts from the registered trusted
publisher code. **Raw AI output is not the receipt.** The future publisher must
independently construct controlled identity/context/metadata fields, authenticate
the authoring record, start fresh read-only review sessions and preserve genuine
model findings. This receiver cannot prove model-session independence from an
untrusted self-description. The registry therefore remains empty until those
publisher definitions and their receipt contract are concretely reviewed.

## Deliberate limits and rollout blockers

This component checks a conservative scope subset: registered documentation and
image assets; selected dependency manifests from the authenticated Dependabot
identity; explicitly registered generated paths. Scope assertions remain AI
review judgments, not a mathematical proof that security prose is harmless.
Correlated review errors and prompt injection remain risks for the owner to
assess before activating any delegated process.

Actual trusted Security/owning-team publishers and Build/staging receipt
publishers are not registered or installed by this draft. Current native Build
success alone is not a combined-tree/staging receipt. No artifact or sign-off is
fabricated to fill that gap. Review freshness is invalidated by a head/base/diff
change or a registered publisher-definition change; the component does not
purchase repeated reviews just because a unchanged receipt has aged.

The existing signed-commit compatibility and unread classic branch protections
remain separate rollout blockers. No ruleset is enabled, review count changed,
signature requirement removed or setting bypassed. Future integration must
verify the approved runtime/verifier registry from trusted code again immediately
before any separately authorized action. The shared maintenance action remains
read-only and owns none of this custom approval pipeline.

Tests use an offline authenticated-API contract fixture, deterministic ZIPs and
mock openers. They exercise provenance, context/digest/modes, preserved holds,
scope, stale/duplicate receipts, both review sessions, native/staging evidence,
head/base races, sanitized GET-only transport and credential-free redirects.
Fixtures are not production role approvals or authenticated model availability.
