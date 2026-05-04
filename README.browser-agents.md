# Browser AI Remediation Agents

The SecurityRecipes chatbot includes a beta browser-side agent planner.
It is not a background worker. It is a thin local orchestrator that:

- stores provider, GitHub, and delivery credentials in the current
  browser profile with `localStorage`
- gathers selected site, recipe, GitHub, and deps.dev context
- asks the selected provider, OpenAI, Grok, or Claude, for a focused
  remediation output
- delivers that output only through the route the user selected

No credential is stored in the site database because the static site has
no database.

## Context Sources

| Source | Data Collected | Auth |
|--------|----------------|------|
| Page context | Current page text, headings, and snippets relevant to the question. | None |
| Recipe index | Local generated `recipes-index.json` entries. | None |
| GitHub repository | README, SECURITY, CONTRIBUTING, license, manifests, open issues, and open pull requests. | Public repos need none; private repos and higher limits need a GitHub PAT or OAuth token. |
| Dependency intelligence | GitHub Dependency Graph SBOM packages checked against deps.dev package-version advisories. | Public dependency graph can work without auth; private graph needs GitHub auth. |

The Docker nginx runtime exposes `/github-api/` as a same-origin relay to
`https://api.github.com/`. If the browser has a GitHub token saved, the
relay forwards the `Authorization` header for that request.

## Agent Outputs

| Output | Behavior |
|--------|----------|
| Draft PR packet | Copies a PR-ready packet to the clipboard. |
| GitHub issue | Creates an issue via the GitHub API using saved GitHub auth. |
| Slack message | Posts to a saved incoming webhook URL. |
| Email handoff | Opens `mailto:` or posts JSON to a saved CORS-enabled relay URL. |
| Jira ticket | Creates a Jira task using saved base URL, project, email, and token. |
| Runbook receipt | Copies the reviewed receipt to the clipboard. |
| Server runbook | Copies command, validation, stop condition, and rollback steps. |

Browser CORS still applies. Production Slack, Jira, and SMTP paths are
usually better behind a same-origin relay that can log delivery and
redact credentials.

## Scheduling

The current scheduler is local draft state:

1. Add one precise action to the queue.
2. Generate a plan with the selected LLM provider.
3. Run the selected output route.
4. Save a schedule draft if the action should recur later.

Saved drafts record status, next run time, approval gate, context pack,
and output route. They do not wake up unattended. A production scheduler
needs durable job storage, a worker identity, audit logs, retry policy,
credential revocation, and a human approval gate before any external
change is made.

The generated browser-agent boundary pack now captures this contract in
machine-readable form:

```bash
python3 scripts/generate_browser_agent_boundary_pack.py
python3 scripts/evaluate_browser_agent_boundary_decision.py \
  --workspace-class-id security-recipes-browser-planner \
  --task-profile-id draft-remediation-handoff
```

Use that evaluator before promoting the beta planner into a recurring
worker, a shared browser profile, or an external delivery path.

## Security Notes

- Provider and GitHub credentials stay in browser `localStorage`.
- Tokens are visible to JavaScript on this origin, so do not use this on
  an untrusted or shared browser profile.
- Use short-lived or least-privilege tokens where possible.
- Keep output routes draft-first unless a reviewed backend controls the
  write path.
- Treat personal browser profiles, localhost access, admin consoles,
  downloads, payments, and raw token exposure as hold / deny / kill
  conditions, not convenience features.
