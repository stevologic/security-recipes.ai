---
title: Reputable Prompt Sources
linkTitle: Prompt Sources
page_kind: collection
weight: 10
toc: true
sidebar:
  open: false
description: >
  A curated catalog of external, reputable sources for
  pre-engineered security prompts, red-team probes, guardrail
  templates, and eval packs. Start here before writing a prompt
  from scratch.
---

{{< callout type="info" >}}
**Before you write a prompt from scratch, look here.** Most
of the prompts a security program needs — triage, red-team,
remediation, guardrail — already exist in reviewed, maintained
libraries published by vendors, standards bodies, or academic
groups. This page is the shortlist of where to start.
{{< /callout >}}

The Recipes section on this site is **internal to the
community-driven recipes** — production-shaped prompts teams have
shared back. Alongside that, any healthy program draws on
**external sources** of pre-engineered prompts and probes:
standards bodies publishing attack taxonomies, model providers
publishing example prompts, eval frameworks shipping red-team
packs, and community-maintained awesome-lists that aggregate the
rest.

This page catalogs the ones we consider reputable enough to
recommend as starting points. Recency and maintenance status
change; always check when a source was last updated before
leaning on it.

## How to use this page

- **Pick sources that match the job.** OWASP and MITRE are
  authoritative for *taxonomies and threat models*; Anthropic,
  OpenAI, and Google publish *prompting practice*; Promptfoo,
  Garak, and PyRIT ship *executable red-team packs*; community
  awesome-lists aggregate *everything* — but curation quality
  varies.
- **Verify before running.** Copying a prompt from any external
  source and pointing it at a production target without reading
  it is how programs get burned. Every prompt runs under the
  same guardrails as an internal one.
- **Attribute upstream.** When you adapt a prompt from one of
  these sources into this repo's Recipes section, keep the
  upstream attribution in the `source:` frontmatter field.

---

## Standards and threat taxonomies

The authoritative sources for *what to test for* and *how to
name what you find*. Use these as scaffolding for remediation and
red-team prompts — then fill in the specifics with the
implementation-oriented sources further down.

### OWASP GenAI Security Project

- **What's there.** The OWASP Top 10 for Large Language Model
  Applications / GenAI Top 10, plus deeper guidance on prompt
  injection, insecure output handling, training data poisoning,
  model DoS, supply-chain risks, sensitive information
  disclosure, insecure plugin design, excessive agency,
  overreliance, and model theft.
- **Why it's useful for prompts.** Every entry in the GenAI Top
  10 maps to a class of audit or red-team prompt you can write.
  The project also publishes cheat-sheets and sample checklists
  that translate directly into instructions for an agent.
- **Where.** `genai.owasp.org` and the OWASP
  GitHub organisation — look for `www-project-top-10-for-large-language-model-applications`
  and related repos.
- **Caveat.** Top 10 lists shift year over year and differ by
  domain. Always reference the year and project in any audit prompt
  that cites them (for example, "OWASP Top 10 for LLM Applications
  2025"), and keep your prompt's taxonomy references current.

### MITRE ATLAS

- **What's there.** ATLAS (Adversarial Threat Landscape for
  Artificial-Intelligence Systems) is MITRE's ATT&CK-shaped
  knowledge base of adversarial techniques *against* AI and ML
  systems — reconnaissance, resource development, initial
  access, ML model access, execution, persistence, defense
  evasion, credential access, discovery, collection, ML attack
  staging, exfiltration, and impact.
- **Why it's useful for prompts.** Red-team and threat-model
  prompts benefit enormously from pinning each probe to an ATLAS
  technique ID (e.g. `AML.T0051.000 LLM Prompt Injection: Direct`).
  It gives reviewers a shared vocabulary and makes coverage
  gaps visible at a glance.
- **Where.** `atlas.mitre.org`.

### NIST AI Risk Management Framework + AI 600-1

- **What's there.** The NIST AI RMF is a voluntary framework for
  managing AI risk across govern / map / measure / manage.
  **NIST AI 600-1** is the Generative AI Profile that overlays
  the RMF with GenAI-specific risks and mitigations.
- **Why it's useful for prompts.** The AI 600-1 risk list
  (confabulation, harmful bias, data privacy, information
  integrity, information security, etc.) is a clean source of
  categories to audit a model or agent against. Compliance
  audits increasingly cite these documents, so aligning your
  audit prompts to their vocabulary pays off downstream.
- **Where.** `nist.gov/itl/ai-risk-management-framework` and the
  NIST AI Resource Center.

### Cloud Security Alliance AI Safety Initiative

- **What's there.** Working-group publications on AI controls,
  prompt security, model supply-chain risk, and shared
  responsibility models for GenAI in cloud environments.
- **Why it's useful for prompts.** CSA publications are vendor-
  neutral and written for security engineers, so they translate
  into audit and reviewer prompts more directly than some of the
  academic literature.
- **Where.** `cloudsecurityalliance.org/ai-safety-initiative`.

### Google Secure AI Framework (SAIF)

- **What's there.** A high-level framework plus a
  self-assessment tool that asks concrete questions across data,
  model, application, infrastructure, and governance layers. The
  risk catalog behind SAIF is published.
- **Why it's useful for prompts.** The self-assessment question
  bank is a ready-made source of review prompts ("does the
  agent have least-privilege access to downstream systems?
  describe the control").
- **Where.** `safety.google/security-ai-framework/` and the SAIF
  Risk Map.

---

## Model provider prompt libraries

These are where to look when you want a starting point prompt
*shaped for a specific model*. The security-relevant ones are
noted explicitly.

### Anthropic prompt examples and Cookbook

- **Prompt examples.** Anthropic's public prompt examples include
  ready-to-run prompts including code review, threat modeling,
  and security analysis entries. The structure (system /
  user / examples) makes them easy to fork for in-house use.
- **Cookbook.** `anthropic-cookbook` on GitHub has end-to-end
  examples for agent patterns, tool use, and evaluation — useful
  when you're writing prompts that will run as part of a larger
  Claude agent rather than a one-shot.
- **Skills.** Anthropic's published skills (`anthropics/skills`
  on GitHub) are longer-form, heavier-weight prompts packaged
  with scripts — a good reference for skill-shaped contributions
  to this site's Recipes section.
- **Prompting guide.** `docs.claude.com/en/docs/build-with-claude/prompt-engineering`
  is the up-to-date canonical reference for Claude prompting
  patterns (XML tags, chain-of-thought, prompt chaining).
- **Where.** `claude.com/recipes`,
  `github.com/anthropics/anthropic-cookbook`,
  `github.com/anthropics/skills`, `docs.claude.com`.

### OpenAI Prompt Engineering Guide and Cookbook

- **Prompt Engineering Guide.** OpenAI's canonical prompting
  reference — structure, instruction following, few-shot,
  chain-of-thought, and safety messaging patterns.
- **Cookbook.** `openai-cookbook` on GitHub is a large collection
  of notebooks including evaluation patterns, function-calling
  examples, and agent patterns. Individual notebooks touch on
  security topics (moderation, input validation).
- **Where.** `platform.openai.com/docs/guides/prompt-engineering`
  and `github.com/openai/openai-cookbook`.

### Model Spec and safety messaging (cross-provider)

- Most major model providers publish a **model spec** or
  equivalent document describing what the model is and isn't
  supposed to do. These are useful source material for a
  reviewer prompt that asks "does the agent's behaviour comply
  with the provider's stated policy?"
- **Where.** `model-spec.openai.com` (OpenAI),
  Anthropic's usage policy + model card,
  Google's model cards for each Gemini release.

---

## Red-team and eval frameworks (executable packs)

Where the previous section gives you *text*, these give you
*runnable red-team batteries*. All are open source.

### Garak (NVIDIA)

- **What it is.** `garak` is a command-line LLM vulnerability
  scanner — think `nmap` for language models. It ships probes
  for prompt injection, data leakage, jailbreak-style attacks,
  toxicity, hallucination, and more, plus a scoring harness.
- **Why it's useful.** Each probe is a concrete prompt (or
  family of prompts) with a detector that decides whether the
  model failed. You can pull probe text directly or use `garak`
  to run the full battery against a target.
- **Where.** `github.com/NVIDIA/garak` (formerly
  `leondz/garak`).

### Microsoft PyRIT

- **What it is.** **Py**thon **R**isk **I**dentification **T**oolkit —
  Microsoft's open-source framework for AI red-teaming. Ships
  orchestrators, converters, and scorer modules that compose
  into automated adversarial campaigns.
- **Why it's useful.** PyRIT's converter library (Base64,
  translation, persona, multi-turn rewrites) is a ready-made
  source of obfuscation prompts — useful for hardening your
  guardrails against paraphrased attack text.
- **Where.** `github.com/Azure/PyRIT`.

### Promptfoo

- **What it is.** An evaluation and red-team framework. Ships
  built-in red-team plugins for prompt injection, PII leakage,
  insecure output handling, excessive agency, and other OWASP
  LLM Top 10 categories, plus custom plugin support.
- **Why it's useful.** Promptfoo's YAML test format is easy to
  fork into your own regression suite. Its red-team pack is
  actively maintained and tracks OWASP category updates.
- **Where.** `promptfoo.dev` and
  `github.com/promptfoo/promptfoo`.

### DeepEval

- **What it is.** An eval framework with built-in metrics
  including hallucination, bias, toxicity, and prompt-injection
  resilience. More evaluation-focused than red-team-focused, but
  the test sets are reusable.
- **Where.** `github.com/confident-ai/deepeval`.

### Braintrust, LangSmith, and peers

- Vendor observability + eval platforms. Their public
  templates and blog content occasionally ship reusable prompt
  and eval patterns. Useful as references; not sources of
  truth on their own.

---

## Community-maintained collections

Curation quality varies — read before trusting. These are the
ones that consistently surface good material.

### Awesome LLM Security

- Curated index of research papers, frameworks, prompts, and
  tooling across the LLM-security space. Updated frequently.
- **Where.** `github.com/corca-ai/awesome-llm-security`. Also
  worth checking: `awesome-ai-security`, `awesome-mlsecops`.

### Awesome Prompt Injection

- Focused collection of prompt-injection papers, demos, and
  defences. A good reading list when you're writing new
  reviewer prompts for injection-risk PRs.
- **Where.** Search GitHub for `awesome-prompt-injection` —
  multiple maintained forks; pick one with a recent commit.

### Simon Willison's blog and tagged archives

- Simon Willison has been one of the most consistently
  thoughtful writers on prompt injection and LLM security in
  practice. His **`prompt-injection`** and **`llms`** tag
  archives are a running, real-time chronicle.
- **Where.** `simonwillison.net/tags/prompt-injection/` and
  `simonwillison.net/tags/llms/`.

### Learn Prompting — Prompt Hacking chapter

- `learnprompting.org` is a free, community-maintained course;
  the **Prompt Hacking** chapter is a clean teaching resource
  for prompt injection, jailbreaks, and defences. Useful when
  onboarding reviewers who are new to the topic.
- **Where.** `learnprompting.org/docs/prompt_hacking/`.

### HackAPrompt dataset

- The largest publicly released dataset of prompt-injection
  attempts, gathered through a public competition. Useful as a
  regression corpus for a prompt-hardening eval.
- **Where.** `huggingface.co/datasets/hackaprompt` (search the
  Hugging Face hub for the latest release).

---

## Agent-specific prompt sources

When the target isn't just an LLM but a coding or remediation
agent, a few sources publish prompts specifically shaped for
agent behaviour.

### GitHub Copilot Coding Agent — prompt and instruction examples

- Microsoft publishes sample `copilot-instructions.md` files in
  docs and example repos. Mine these for structural patterns,
  not for your actual instructions — your instructions should
  be yours.
- **Where.** `docs.github.com/en/copilot/customizing-copilot`.

### Cursor rules examples

- The Cursor team maintains a growing gallery of example
  `.cursor/rules/*.mdc` files, and the community repo
  `cursor.directory` aggregates submissions from users.
- **Where.** `docs.cursor.com` and `cursor.directory`.

### Devin playbooks and knowledge

- Cognition publishes example playbooks and knowledge entries
  in their docs. These are workflow-shaped, which maps neatly
  onto agentic remediation runbooks.
- **Where.** `docs.devin.ai`.

### Codex / Agents.md

- The Codex ecosystem uses `AGENTS.md` as a standard
  repo-level prompt file. The `agents.md` site and a handful of
  high-quality example repos on GitHub show working patterns.
- **Where.** `agents.md` and the OpenAI Codex docs.

---

## How to evaluate a new source

Before leaning on a prompt source you haven't used before:

- **Check the last commit / last updated date.** Anything in AI
  security that hasn't been touched in 9+ months is probably
  stale.
- **Follow one prompt end to end.** If it runs cleanly, the
  source is probably worth a broader look. If it's full of
  placeholder text or doesn't run, move on.
- **Read the license.** Some academic or vendor prompt
  collections carry restrictive licenses. If you plan to fork
  into this repo's Recipes section, the source license has to be
  compatible (MIT-equivalent or clearly permissive).
- **Attribute.** When a prompt here was adapted from an external
  source, the entry's frontmatter should carry a `source:` field
  pointing at the upstream.

## Contributing back

If you find a reputable source that's missing from this list —
especially one with a durable maintainer and a clear license —
open a PR. See
[Contribute]({{< relref "/contribute" >}}) for the full
workflow. Entries here should carry a one-paragraph "what's
there / why it's useful / where" block so future readers can
judge fit in under thirty seconds.

## See also

- [Recipes]({{< relref "/recipes" >}}) — internal, community-curated prompts
- [Fundamentals]({{< relref "/fundamentals" >}}) — plain-English primer on prompts, agents, and MCP
- [Fundamentals → Emerging Patterns]({{< relref "/fundamentals/emerging-patterns" >}}) — what else is maturing in the agentic remediation space
- [Automation]({{< relref "/automation" >}}) — deterministic tools that pair with these prompts
