---
title: "Code Hygiene Recipes"
linkTitle: "Code Hygiene"
description: "Bounded audit and remediation recipes for code correctness, maintainability, lifecycle safety, and diagnostic debt across major ecosystems."
weight: 22
sidebar:
  open: false
---

Use the narrowest ecosystem recipe that matches the repository. Cross-language recipes are intended for polyglot or language-independent work. Each recipe starts read-only and requires explicit authorization before edits.

{{< callout type="warning" >}}
Code hygiene is not a substitute for vulnerability triage. Named CVEs, scanner findings, authorization, injection, secrets, and compliance-evidence work should use their focused recipes.
{{< /callout >}}

## Ecosystem families

{{< prompt-toc >}}
