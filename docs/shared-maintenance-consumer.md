# Shared maintenance consumer draft

This consumer pins contract 1.1.0 at
[`1e6e9a9c4dc9f766c49a421ea268f247d1113287`](https://github.com/stevologic/oss-deps-explorer/blob/1e6e9a9c4dc9f766c49a421ea268f247d1113287/actions/maintenance/README.md).
Its policy belongs to this repository. The caller passes only the existing
read-only GitHub token; all mutation flags and advisory AI are false. No model
key, model selection, provider migration, access grant or operations caller is
added. Existing xAI custom jobs retain their configuration. Daybreak access
verification remains a separate CVE task.

The proposed schedule is Monday **8:07 a.m. America/Phoenix**. Monthly tooling
review and quarterly major-version/support review appear in the first weekly
report of the corresponding month. This does not change native Dependabot,
security-update cadence, or any custom workflow. Policy changes also receive a
PR/push preview; reports expire after seven days. The weekly schedule becomes
active only after reviewed integration and promotion to the default branch.

## Review and ownership boundaries

The pinned inventory uses GET requests, does not execute `validation_commands`,
and emits proposals with merge/delete/close authority explicitly false. It does
not reproduce this repository's full Build or judge the Security/owning-team
roles required by [CONTRIBUTING.md](../CONTRIBUTING.md#review-expectations) and
[GOVERNANCE.md](../GOVERNANCE.md#contribution-workflow). Those gates remain
mandatory. The configured `build` check is the existing job context.

PRs 361, 382 and 383 are reserved in this initial policy because their documented
review/integration requirements are pending. These reservations affect this
read-only report only. An owner-reviewed policy update can remove each after its
required reviews and actual integration validation are complete. All open PR
heads are additionally preserved by inventory, along with default/development,
release, Pages and `automation/*` branches. The custom job list reserves every
existing pipeline, including CVE/content delivery, factual validation, issue
ownership, watchdog recovery, DNS and deployment. No shared job takes ownership
of them.

`supported_image_tracks` records the repository's current Docker/Compose tracks
for review; it does not establish vendor support or endorse floating tags/root
runtime. Release/EOL evidence and the full Build image checks are required for
future changes. Existing supply-chain findings remain tracked in the automation
audit.

## Integration and operator constraints

Keep this consumer as a separate draft stacked on the repair follow-up, so its
review diff contains only this policy, caller, documentation and boundary tests.
After the preceding drafts integrate with history preserved, retarget it to
`development`, run the full final-tree Build and staging validation, obtain the
required role-specific approvals, then prepare a separate reviewed main PR.

The separate shared operations action is not installed or enabled. Development's
existing protection is disabled and owner-enforced strict target checks have not
been verified. The contract's merge operator fails closed in that situation;
this draft changes no protection or access setting. A future operator proposal
needs its own explicit owner approval, exact digest/head, repeated evidence and
all local review/security gates. Inventory success authorizes no mutation.
