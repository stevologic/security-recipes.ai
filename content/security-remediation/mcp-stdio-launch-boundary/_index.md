---
title: MCP STDIO Launch Boundary
linkTitle: MCP STDIO Launch Boundary
weight: 8
sidebar:
  open: true
description: >
  A deterministic launch gate for local STDIO MCP servers that treats
  MCP client configuration as executable supply-chain surface before an
  agent host starts a subprocess.
---

{{< callout type="info" >}}
**Why this page exists.** A STDIO MCP server is a local process. If an
agent host accepts a command from config, marketplace metadata, or a
one-click install link, it is accepting code execution. The launch
boundary gives that moment the same policy discipline as remote MCP
authorization.
{{< /callout >}}

## The product bet

SecurityRecipes is positioned as the secure context layer for agentic AI.
That claim is stronger when it governs both sides of MCP adoption:
remote tools that need authorization and local tools that need launch
control.

The MCP transport spec says the STDIO client launches the server as a
subprocess, and the latest MCP security guidance calls out local MCP
server compromise, malicious startup commands, sandboxing, consent,
filesystem control, and network control. That makes STDIO launch review a
natural enterprise product surface: before the agent sees a local tool,
the platform can ask for a machine-readable launch decision.

The high-value buyer questions are straightforward:

- Which local MCP server commands are approved to run?
- Can the launch install a package, execute a shell, or reach the
  private network?
- Which environment variables and filesystem roots can the subprocess
  see?
- Which launch changes require owner approval or full connector intake?
- Which decision should an MCP client enforce before spawning?

## What was added

- `data/assurance/mcp-stdio-launch-boundary-model.json` - source model
  for approved STDIO profiles, launch examples, decisions, red-team
  drills, and standards alignment.
- `scripts/generate_mcp_stdio_launch_boundary_pack.py` - dependency-free
  generator and validator with `--check` mode.
- `data/evidence/mcp-stdio-launch-boundary-pack.json` - generated launch
  boundaries, risk findings, source hashes, and buyer evidence.
- `scripts/evaluate_mcp_stdio_launch_decision.py` - deterministic runtime
  evaluator for an MCP client, endpoint agent, or CI gate.
- `recipes_mcp_stdio_launch_boundary_pack` and
  `recipes_evaluate_mcp_stdio_launch_decision` - MCP tools that expose
  the pack and runtime decision surface.

Run it locally from the repo root:

```bash
python3 scripts/generate_mcp_stdio_launch_boundary_pack.py
python3 scripts/generate_mcp_stdio_launch_boundary_pack.py --check
```

Evaluate the repo-shipped local server launch:

```bash
python3 scripts/evaluate_mcp_stdio_launch_decision.py \
  --launch-id security-recipes-local-stdio \
  --command python \
  --arg mcp_server.py \
  --sandboxed \
  --network-egress allowlist \
  --env-key RECIPES_MCP_TRANSPORT \
  --expect-decision allow_pinned_sandboxed_stdio_launch
```

## Launch decisions

| Decision | Meaning |
| --- | --- |
| `allow_pinned_sandboxed_stdio_launch` | The command, args, package, sandbox, environment, network, filesystem, and evidence all match the registered boundary. |
| `hold_for_owner_review` | The launch is known, but missing sandbox, approval, network, environment, or profile evidence. |
| `deny_unregistered_stdio_launch` | The launch ID or profile is unknown. Run intake before allowing it. |
| `deny_untrusted_package_launch` | The launch uses package-runner bootstrap, floating versions, unverified publisher state, or missing digest/signature evidence. |
| `deny_shell_or_network_bootstrap` | The launch uses shell wrappers, command chaining, broad network bootstrap, private-network reachability, or command drift. |
| `kill_session_on_secret_or_privilege_request` | The launch attempts to pass secrets, inherited credentials, root privileges, private keys, tokens, or prohibited data to the subprocess. |

## What the evaluator checks

| Boundary | Examples |
| --- | --- |
| Command identity | Exact executable and argument list must match the registered launch. |
| Package provenance | Package runners such as `npx`, `uvx`, `pipx`, or `bunx` need digest, signature, and verified publisher evidence before they can move to a safer profile. |
| Environment | Secret-like keys such as tokens, API keys, passwords, SSH agent sockets, and private-key material kill the session unless explicitly allowed. |
| Network | Wildcard, unrestricted, private-network, or metadata-endpoint reachability is denied for local launches. |
| Filesystem | Declared roots and modes become the policy surface for endpoint or sandbox enforcement. |
| Approval | Browser automation, source-control write, registry publish, credential access, broad network, and subprocess-spawn capabilities require typed approval. |

## Current sample boundaries

- **SecurityRecipes Local Read-Only MCP Server**: allowed when launched
  from the source-controlled repo with exact command, sandbox evidence,
  narrow environment, and allowlisted public index access.
- **Browser Research Package Runner Candidate**: denied because `npx -y`
  package resolution at launch time, wildcard egress, and private-network
  reachability are too much trust for local research.
- **Containerized Registry Publisher STDIO Candidate**: denied until the
  connector is redesigned because registry publish authority,
  private-network reachability, and the source intake decision make it too
  risky for local STDIO launch.
- **Untrusted One-Click Shell STDIO Install**: denied because shell
  chaining, network download, broad filesystem write, and unowned package
  execution are not acceptable MCP client defaults.

## Industry alignment

This feature follows current primary guidance:

- [MCP Transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
  defines STDIO as a client-launched subprocess and warns local HTTP
  transports to avoid DNS rebinding exposure.
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
  covers local MCP server compromise, malicious startup commands,
  sandboxing, consent, filesystem control, network control, and scope
  minimization.
- [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  says HTTP authorization guidance does not apply to STDIO; local
  credentials come from the environment, so environment policy matters.
- [OpenAI Agents SDK MCP](https://openai.github.io/openai-agents-js/guides/mcp/)
  supports hosted, Streamable HTTP, and STDIO MCP servers, which means
  enterprise governance needs to cover all transport modes.
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)
  highlights tool misuse, identity abuse, agentic supply chain,
  unexpected code execution, cascading failures, and rogue agents.
- [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/)
  treats agent skills as an execution layer and recommends verified
  publishers, pinned versions, isolated runtime, network restrictions,
  monitoring, audit logging, and approval workflows.
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
  provides the governance frame for mapping, measuring, and managing AI
  system risks.
- [Google SAIF](https://safety.google/safety/saif/) reinforces secure
  defaults, platform-level controls, adaptive mitigations, and business
  context for AI system risk.

## How an MCP client uses it

1. Register every approved local STDIO server in the launch model with
   owner, command, args, package provenance, environment policy,
   filesystem roots, network policy, and evidence.
2. Generate the launch boundary pack and publish it to the internal MCP
   client, endpoint policy agent, or platform control plane.
3. Before spawning a STDIO server, call the evaluator with the actual
   command, args, environment keys, network posture, sandbox state, and
   approval record.
4. Spawn only on `allow_pinned_sandboxed_stdio_launch`.
5. Treat `hold_for_owner_review`, `deny_*`, and `kill_*` as enforceable
   outcomes with audit records.

## CI contract

The generator fails if:

- The model has malformed standards, profiles, launches, decisions, or
  red-team drills.
- A launch uses an unknown profile or non-STDIO transport.
- Required command, owner, evidence, environment, filesystem, or control
  fields are missing.
- The connector intake pack cannot be loaded.
- The checked-in evidence pack is stale in `--check` mode.

That gives SecurityRecipes a credible next product surface: local MCP
client posture management, launch receipts, endpoint policy export, and
continuous recertification for every subprocess an agent host can start.

## See also

- [MCP Connector Intake Scanner]({{< relref "/security-remediation/mcp-connector-intake-scanner" >}})
  - pre-approval review for new or changed MCP servers.
- [MCP Authorization Conformance]({{< relref "/security-remediation/mcp-authorization-conformance" >}})
  - remote MCP resource, audience, token, and scope control.
- [MCP Gateway Policy Pack]({{< relref "/security-remediation/mcp-gateway-policy" >}})
  - runtime allow, hold, deny, and kill-session decisions.
- [Agent Skill Supply Chain]({{< relref "/security-remediation/agent-skill-supply-chain" >}})
  - skill provenance, permission, isolation, and package decisions.
- [Agentic Threat Radar]({{< relref "/security-remediation/agentic-threat-radar" >}})
  - source-backed signals that make local tool governance urgent.
