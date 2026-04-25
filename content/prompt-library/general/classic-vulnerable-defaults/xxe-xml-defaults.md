---
title: "XML external entities (XXE) — parser defaults"
linkTitle: "XML external entities (XXE)"
description: "Per-language parser hardening: defusedxml for Python, factory feature flags for Java, libxml entity-loading off in PHP."
tool: "general"
author: "Stephen M Abbott"
team: "Security"
maturity: "development"
model: "Opus 4.7"
tags: ["xml", "xxe", "uplift", "mitigate", "defusedxml"]
weight: 24
date: 2026-04-25
---

XML parsers in most languages historically defaulted to
*resolving external entities*. A single XML payload can read
local files, exfiltrate data over DNS, hang the parser on a
billion-laughs payload, or pivot through SSRF. Most parsers
have safer modes; few default to them. The fix is to set the
right flags everywhere — every parser, every library, every
vendored XML toolkit.

## Pattern

- **Python.** `xml.etree.ElementTree.parse`,
  `xml.dom.minidom.parse`, `xml.sax.parse`, `lxml.etree.parse`
  with default options.
- **Java.** `DocumentBuilderFactory`, `SAXParserFactory`,
  `XMLInputFactory`, `TransformerFactory`, `SchemaFactory` —
  all entity-resolving by default.
- **PHP.** `simplexml_load_string`, `DOMDocument::loadXML` with
  default options; `libxml_disable_entity_loader` global flag
  was the historical mitigation but its semantics changed in
  PHP 8.
- **.NET.** `XmlDocument`, `XmlReader` defaults pre-4.5.2
  resolved entities; current defaults are safer but
  application code often re-enables them.
- **Ruby.** `Nokogiri::XML(input)` with default options —
  `noent: true` is the dangerous flag.
- **Go.** `encoding/xml` does not resolve entities (good); but
  third-party XML libraries vary.

## Why it matters

The classic XXE payload reads a local file:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<foo>&x;</foo>
```

…and your parser returns the contents in the response body, or
in an error message, or via a side-channel DNS lookup. There is
no patch coming for "the XML spec allows this" — the fix is to
configure the parser to refuse.

## Mitigation — disable entity resolution and DTD loading

Per language, the right flags:

**Python (uplift to `defusedxml`).**

```python
# Replace
# import xml.etree.ElementTree as ET
import defusedxml.ElementTree as ET
# All ET.* calls now refuse external entities, DTDs, and
# entity-expansion attacks.
```

`defusedxml` has wrappers for `ElementTree`, `minidom`, `sax`,
`lxml`, `pulldom`, and `xmlrpc`. Replacing the import is the
fix.

**Java.**

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

Equivalent flag-sets exist for `SAXParserFactory`,
`XMLInputFactory` (`IS_SUPPORTING_EXTERNAL_ENTITIES`,
`SUPPORT_DTD`), and `TransformerFactory`
(`XMLConstants.ACCESS_EXTERNAL_DTD`,
`ACCESS_EXTERNAL_STYLESHEET`).

**PHP.**

```php
$dom = new DOMDocument();
$dom->loadXML(
    $input,
    LIBXML_NONET | LIBXML_NOENT
        ? 0  // default safe in PHP 8+; verify with phpunit
        : 0  // explicitly no LIBXML_NOENT, no LIBXML_DTDLOAD
);
```

PHP 8 changed `libxml_disable_entity_loader` semantics; the
correct shape is now flag-based at the load call.

**.NET.**

```csharp
var settings = new XmlReaderSettings {
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null,
};
using var reader = XmlReader.Create(input, settings);
```

Never use `XmlDocument.Load(stream)` directly without setting
`XmlResolver = null` and `DtdProcessing = Prohibit`.

**Ruby.**

```ruby
doc = Nokogiri::XML(input) do |config|
  config.strict.nonet  # no network, no DTD loading
end
```

## Uplift — replace XML where possible

For new APIs and config files, prefer JSON, YAML (with
`safe_load`), or protobuf. XML's parser-level vulnerabilities
are not a fixable category; the only real fix is to stop
parsing XML where the format isn't required.

## Inputs

- **Call sites** — every XML-parser instantiation in the repo.
- **Languages and parsers** in scope.

## The prompt

~~~markdown
You are remediating XML-parser defaults across this repo.
Output a PR or a TRIAGE.md.

## Step 0 — Inventory

1. List every XML-parser instantiation: `ElementTree.parse`,
   `DocumentBuilderFactory.newInstance`, `XmlDocument`,
   `Nokogiri::XML`, `simplexml_load_string`, etc.
2. For each, identify whether the input is untrusted (request
   body, uploaded file, partner data feed) or trusted (a
   bundled config file).
3. Flag any code path that returns parsed XML content in an
   HTTP response (XXE exfiltration surface) and any path that
   logs parsed content.

## Step 1 — Mitigate per language

Apply the language-specific configuration from the recipe
body:

- **Python:** swap imports to `defusedxml`.
- **Java:** set the `disallow-doctype-decl`,
  `external-general-entities`, `external-parameter-entities`,
  `load-external-dtd` features to safe values on every parser
  factory, plus `setXIncludeAware(false)` and
  `setExpandEntityReferences(false)`.
- **PHP:** pass safe libxml flags to every parser; remove
  `LIBXML_NOENT` and `LIBXML_DTDLOAD` everywhere.
- **.NET:** set `DtdProcessing = Prohibit` and
  `XmlResolver = null` on every reader.
- **Ruby:** use `nonet`, `noent: false`.

## Step 2 — Uplift the API surface (when applicable)

If a public API takes XML and the agent has authority to
introduce a JSON endpoint side-by-side, do it. Mark XML
endpoints deprecated; keep them serving (with the mitigated
parser) until clients migrate.

## Step 3 — Tests

For every language touched, add a test:

1. The classic XXE payload (referencing
   `file:///etc/passwd` or a local DTD) is rejected without
   resolving the entity.
2. A billion-laughs / quadratic-blowup payload is rejected
   without exhausting memory.
3. A normal XML payload still parses correctly (behaviour
   preservation).

## Step 4 — Open the PR

- Branch: `remediate/xxe-<module-slug>`.
- Title: `[Security][XXE] harden XML parsers in <module>`.
- Body: per-language summary, call-site list, test additions,
  any deprecation notices.
- Label: `sec-auto-remediation`.

## Stop conditions

- A parser configuration option changes the schema-validation
  semantics in a way that breaks legitimate inputs.
- Tests fail in unrelated code that depends on XInclude or
  DTD resolution for a real reason. Triage.
- A vendored XML library has no exposed safe-mode flag. Flag
  and triage; consider replacing the library.

## Scope

- Do not change XML schemas (XSDs). The fix is parser
  configuration, not schema content.
- Do not bundle unrelated refactors.
- Do not silently re-enable any flag the recipe disables.
~~~

## Watch for

- **DTD-using legitimate inputs.** Some partner integrations
  ship inline DTDs. The mitigation breaks them. Identify
  before deploying; allowlist the partner-DTD path explicitly
  rather than globally re-enabling DTDs.
- **Logging the parsed payload.** Even with entities disabled,
  logging unparsed XML can leak data via log-injection. Log
  the payload's hash, not its content.
- **Dependency-injected parsers.** A framework that injects a
  parser bean (Spring, Symfony, Rails) needs the parser bean
  reconfigured at construction. Find and fix the bean
  definition, not just the call sites.
- **Schema validation feature-flags re-enabling DTDs.** Some
  XSD validators re-resolve external schemas; double-check
  `SchemaFactory` settings.

## Related

- [Classic Vulnerable Defaults]({{< relref "/security-remediation/classic-vulnerable-defaults" >}})
  — workflow context.
- [Java ObjectInputStream]({{< relref "/prompt-library/general/classic-vulnerable-defaults/java-deserialization" >}})
  — sibling Java deserialization pattern.
