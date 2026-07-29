// Security Recipes health check action.
//
// Runs the checks this site advises as LLM evaluations grounded in
// security-recipes.ai recipe context, fetched from the hosted MCP server
// with a static-feed fallback. Zero runtime dependencies: Node's built-in
// fetch and fs only, so the action needs no install step in any repository.

import { appendFileSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, sep } from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const SITE = 'https://security-recipes.ai';
const MCP_PROTOCOL_VERSION = '2025-06-18';
const EVIDENCE_FILE_LIMIT = 6 * 1024;
const EVIDENCE_TOTAL_LIMIT = 64 * 1024;
const RECIPE_CONTEXT_LIMIT = 9 * 1024;
const MAX_FINDINGS = 8;

// Every check maps to guidance this site publishes; the recipe query feeds
// the MCP search and the page anchors the human-readable reference.
export const CHECKS = [
  {
    key: 'dependencies',
    input: 'check-dependencies',
    label: 'Vulnerable dependencies',
    defaultEnabled: true,
    recipeQuery: 'vulnerable dependency remediation',
    page: `${SITE}/security-remediation/vulnerable-dependencies/`,
    evidence: 'manifests',
  },
  {
    key: 'secrets',
    input: 'check-secrets',
    label: 'Secrets and data exposure',
    defaultEnabled: true,
    recipeQuery: 'source code secrets data exposure audit',
    page: `${SITE}/recipes/general/source-code-secrets-data-exposure-audit/`,
    evidence: 'source',
  },
  {
    key: 'injection',
    input: 'check-injection',
    label: 'Injection sinks',
    defaultEnabled: true,
    recipeQuery: 'source code injection sink audit',
    page: `${SITE}/recipes/general/source-code-injection-sink-audit/`,
    evidence: 'source',
  },
  {
    key: 'supply-chain',
    input: 'check-supply-chain',
    label: 'Supply chain and build integrity',
    defaultEnabled: true,
    recipeQuery: 'supply chain build integrity audit',
    page: `${SITE}/recipes/general/source-code-supply-chain-build-integrity-audit/`,
    evidence: 'pipeline',
  },
  {
    key: 'authz',
    input: 'check-authz',
    label: 'Authorization and tenant boundaries',
    defaultEnabled: false,
    recipeQuery: 'authorization tenant boundary audit',
    page: `${SITE}/recipes/general/source-code-authz-tenant-boundary-audit/`,
    evidence: 'source',
  },
  {
    key: 'containers',
    input: 'check-containers',
    label: 'Container and base image hygiene',
    defaultEnabled: false,
    recipeQuery: 'base image bump container hygiene',
    page: `${SITE}/recipes/general/base-image-bump/`,
    evidence: 'containers',
  },
  {
    key: 'owasp',
    input: 'check-owasp',
    label: 'OWASP Top 10 audit',
    defaultEnabled: false,
    recipeQuery: 'OWASP top 10 2026 audit',
    page: `${SITE}/recipes/general/owasp-top-10-2026-audit/`,
    evidence: 'source',
  },
  {
    key: 'cve-exposure',
    input: 'check-cve-exposure',
    label: 'CVE intelligence intake',
    defaultEnabled: false,
    recipeQuery: 'cve intelligence intake gate',
    page: `${SITE}/recipes/general/cve-intelligence-intake-gate/`,
    evidence: 'manifests',
  },
  {
    key: 'compliance',
    input: 'check-compliance',
    label: 'Compliance standards',
    defaultEnabled: false,
    recipeQuery: 'compliance standards remediation',
    page: `${SITE}/recipes/general/compliance-standards/`,
    evidence: 'pipeline',
  },
];

const STATIC_FALLBACK_MODELS = {
  anthropic: 'claude-haiku-4-5',
  openai: 'gpt-5-mini',
  xai: 'grok-3-mini',
  ollama: '',
};

const SKIP_DIRS = new Set([
  '.git', 'node_modules', 'vendor', 'dist', 'build', 'public', 'out',
  'target', 'coverage', '.next', '.venv', 'venv', '__pycache__',
]);

export function readInput(name, fallback = '') {
  // The GitHub runner exports inputs as INPUT_<NAME> with spaces converted
  // to underscores but dashes preserved (INPUT_API-KEY), so probe the
  // runner spelling first and the underscore variant second.
  const variants = [
    `INPUT_${name.replace(/ /g, '_').toUpperCase()}`,
    `INPUT_${name.replace(/[ -]/g, '_').toUpperCase()}`,
  ];
  for (const env of variants) {
    const value = process.env[env];
    if (value !== undefined && value !== '') return value.trim();
  }
  return fallback;
}

export function readBoolInput(name, fallback) {
  const raw = readInput(name, '');
  if (raw === '') return fallback;
  return ['true', '1', 'yes', 'on'].includes(raw.toLowerCase());
}

// "Lowest available" model selection: rank a provider's model list by name,
// preferring the smallest tier, and among equals prefer the newest-sorting
// identifier. Non-chat models never qualify.
export function pickLowestModel(ids) {
  const unusable = /(embed|whisper|tts|audio|image|dall|moderation|realtime|rerank|guard|vision-preview|transcribe|search)/i;
  const tiers = [/nano/i, /(mini|haiku|lite)/i, /(small|flash|tiny)/i];
  const usable = ids.filter((id) => typeof id === 'string' && id && !unusable.test(id));
  if (!usable.length) return '';
  for (const tier of tiers) {
    const matches = usable.filter((id) => tier.test(id));
    if (matches.length) return matches.sort().reverse()[0];
  }
  return usable.sort().reverse()[0];
}

async function fetchJson(url, options = {}, timeoutMs = 20000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    if (!response.ok) throw new Error(`${url} responded ${response.status}`);
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

export async function resolveModel(provider, { apiKey, baseUrl }) {
  const requested = readInput('model', '');
  if (requested) return { model: requested, autoSelected: false };
  try {
    if (provider === 'ollama') {
      const payload = await fetchJson(`${baseUrl}/api/tags`);
      const models = (payload.models || [])
        .filter((entry) => entry && entry.name)
        .sort((a, b) => (a.size || 0) - (b.size || 0));
      if (models.length) return { model: models[0].name, autoSelected: true };
    } else if (provider === 'anthropic') {
      const payload = await fetchJson('https://api.anthropic.com/v1/models?limit=100', {
        headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
      });
      const picked = pickLowestModel((payload.data || []).map((m) => m.id));
      if (picked) return { model: picked, autoSelected: true };
    } else {
      const payload = await fetchJson(`${baseUrl}/v1/models`, {
        headers: { authorization: `Bearer ${apiKey}` },
      });
      const picked = pickLowestModel((payload.data || []).map((m) => m.id));
      if (picked) return { model: picked, autoSelected: true };
    }
  } catch (error) {
    console.log(`Model listing unavailable (${error.message}); using the static fallback.`);
  }
  return { model: STATIC_FALLBACK_MODELS[provider] || '', autoSelected: true };
}

export function providerBaseUrl(provider, override) {
  if (override) return override.replace(/\/+$/, '');
  if (provider === 'openai') return 'https://api.openai.com';
  if (provider === 'xai') return 'https://api.x.ai';
  if (provider === 'ollama') return 'http://localhost:11434';
  return '';
}

async function chat(provider, { apiKey, baseUrl, model, system, user }) {
  if (provider === 'anthropic') {
    const payload = await fetchJson('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model,
        max_tokens: 3000,
        system,
        messages: [{ role: 'user', content: user }],
      }),
    }, 180000);
    return (payload.content || [])
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join('\n');
  }

  const headers = { 'content-type': 'application/json' };
  if (provider !== 'ollama' || apiKey) headers.authorization = `Bearer ${apiKey}`;
  const payload = await fetchJson(`${baseUrl}/v1/chat/completions`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user },
      ],
    }),
  }, 180000);
  return payload.choices?.[0]?.message?.content || '';
}

// --- MCP client (streamable HTTP, JSON or SSE responses) -------------------

function parseMcpBody(text, contentType) {
  if (contentType.includes('text/event-stream') || text.startsWith('event:') || text.startsWith('data:')) {
    const events = text.split('\n')
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).trim())
      .filter(Boolean);
    for (const event of events.reverse()) {
      try {
        const parsed = JSON.parse(event);
        if (parsed && (parsed.result !== undefined || parsed.error !== undefined)) return parsed;
      } catch { /* keep scanning */ }
    }
    throw new Error('No JSON-RPC payload in the MCP event stream');
  }
  return JSON.parse(text);
}

export function createMcpClient(url) {
  let sessionId = '';
  let nextId = 1;

  async function post(body, timeoutMs = 25000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const headers = {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
      };
      if (sessionId) headers['mcp-session-id'] = sessionId;
      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      const newSession = response.headers.get('mcp-session-id');
      if (newSession) sessionId = newSession;
      if (response.status === 202) return null;
      const text = await response.text();
      if (!response.ok) throw new Error(`MCP responded ${response.status}`);
      const parsed = parseMcpBody(text, response.headers.get('content-type') || '');
      if (parsed.error) throw new Error(parsed.error.message || 'MCP error');
      return parsed.result;
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    async initialize() {
      const result = await post({
        jsonrpc: '2.0',
        id: nextId++,
        method: 'initialize',
        params: {
          protocolVersion: MCP_PROTOCOL_VERSION,
          capabilities: {},
          clientInfo: { name: 'security-health-action', version: '1.0.0' },
        },
      });
      await post({ jsonrpc: '2.0', method: 'notifications/initialized' });
      return result;
    },
    async callTool(name, args) {
      const result = await post({
        jsonrpc: '2.0',
        id: nextId++,
        method: 'tools/call',
        params: { name, arguments: args },
      });
      const text = (result?.content || [])
        .filter((block) => block.type === 'text')
        .map((block) => block.text)
        .join('\n');
      // FastMCP reports tool failures as content with isError set; a payload
      // like that must never masquerade as recipe context.
      if (result?.isError || /^Error calling tool/u.test(text)) {
        throw new Error(text.slice(0, 200) || `Tool ${name} reported an error`);
      }
      return text;
    },
  };
}

export async function loadRecipeContext(mcpUrl, checks) {
  const context = { source: 'none', serverName: '', recipes: new Map() };
  try {
    const client = createMcpClient(mcpUrl);
    const info = await client.initialize();
    context.serverName = info?.serverInfo?.name || 'security-recipes-mcp';
    for (const check of checks) {
      try {
        const text = await client.callTool('recipes_search', { query: check.recipeQuery });
        if (text) context.recipes.set(check.key, text.slice(0, RECIPE_CONTEXT_LIMIT));
      } catch (error) {
        console.log(`MCP recipes_search failed for ${check.key}: ${error.message}`);
      }
    }
    if (context.recipes.size) {
      context.source = 'mcp';
      return context;
    }
  } catch (error) {
    console.log(`MCP unavailable (${error.message}); falling back to the recipes feed.`);
  }

  try {
    const feed = await fetchJson(`${SITE}/api/recipes.json`, {}, 30000);
    const records = Array.isArray(feed.recipes) ? feed.recipes
      : Array.isArray(feed.items) ? feed.items
        : Array.isArray(feed) ? feed : [];
    for (const check of checks) {
      const words = check.recipeQuery.toLowerCase().split(/\s+/);
      const scored = records
        .map((record) => {
          const haystack = JSON.stringify(record).toLowerCase();
          const score = words.reduce((sum, word) => sum + (haystack.includes(word) ? 1 : 0), 0);
          return { record, score };
        })
        .filter((entry) => entry.score >= Math.min(2, words.length))
        .sort((a, b) => b.score - a.score)
        .slice(0, 2);
      if (scored.length) {
        context.recipes.set(
          check.key,
          JSON.stringify(scored.map((entry) => entry.record)).slice(0, RECIPE_CONTEXT_LIMIT),
        );
      }
    }
    if (context.recipes.size) context.source = 'feed';
  } catch (error) {
    console.log(`Recipes feed unavailable (${error.message}); checks run with page references only.`);
  }
  return context;
}

// --- Evidence collection ---------------------------------------------------

function walkFiles(root, matcher, limit) {
  const found = [];
  const queue = ['.'];
  while (queue.length && found.length < limit) {
    const current = queue.shift();
    let entries;
    try {
      entries = readdirSync(join(root, current), { withFileTypes: true });
    } catch { continue; }
    entries.sort((a, b) => a.name.localeCompare(b.name, 'en'));
    for (const entry of entries) {
      if (found.length >= limit) break;
      const relPath = current === '.' ? entry.name : `${current}/${entry.name}`;
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.cache')) queue.push(relPath);
      } else if (matcher(relPath, entry.name)) {
        found.push(relPath);
      }
    }
  }
  return found;
}

export function collectEvidence(kind, root) {
  const matchers = {
    manifests: (_, name) => /^(package\.json|requirements[^/]*\.txt|pyproject\.toml|go\.mod|Cargo\.toml|Gemfile(\.lock)?|pom\.xml|composer\.json|.*\.csproj|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|uv\.lock|poetry\.lock)$/.test(name),
    pipeline: (rel, name) => rel.startsWith('.github/') && /\.(ya?ml)$/.test(name),
    containers: (_, name) => /^(Dockerfile.*|docker-compose.*\.ya?ml|.*\.dockerfile|Containerfile)$/i.test(name),
    source: (_, name) => /\.(js|mjs|cjs|ts|tsx|jsx|py|go|rb|java|php|cs|rs|c|cc|cpp|h|sh|sql|env\.example)$/.test(name),
  };
  const files = walkFiles(root, matchers[kind] || matchers.source, kind === 'source' ? 14 : 24);
  const sections = [];
  let total = 0;
  for (const file of files) {
    if (total >= EVIDENCE_TOTAL_LIMIT) break;
    let text;
    try {
      const size = statSync(join(root, file)).size;
      if (size > 512 * 1024) continue;
      text = readFileSync(join(root, file), 'utf8');
    } catch { continue; }
    const slice = text.slice(0, EVIDENCE_FILE_LIMIT);
    total += slice.length;
    sections.push(`--- ${file.split(sep).join('/')} ---\n${slice}`);
  }
  return sections.join('\n\n');
}

// --- Verdicts --------------------------------------------------------------

export function parseVerdict(text) {
  const candidates = [];
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenced) candidates.push(fenced[1]);
  const brace = text.indexOf('{');
  if (brace !== -1) candidates.push(text.slice(brace, text.lastIndexOf('}') + 1));
  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate);
      const status = ['pass', 'warn', 'fail'].includes(parsed.status) ? parsed.status : 'warn';
      const findings = (Array.isArray(parsed.findings) ? parsed.findings : [])
        .slice(0, MAX_FINDINGS)
        .map((finding) => ({
          severity: String(finding.severity || 'medium'),
          title: String(finding.title || 'Unlabeled finding').slice(0, 160),
          recommendation: String(finding.recommendation || '').slice(0, 400),
        }));
      return { status, summary: String(parsed.summary || '').slice(0, 500), findings };
    } catch { /* try the next candidate */ }
  }
  return {
    status: 'warn',
    summary: `The model reply was not valid JSON: ${text.slice(0, 200)}`,
    findings: [],
  };
}

function checkPrompt(check, recipeContext) {
  return [
    'You are a strict, evidence-bound application security auditor running in CI.',
    `You are evaluating exactly one control: ${check.label}.`,
    'Grounding guidance from security-recipes.ai (authoritative for method and stop conditions):',
    recipeContext || `No machine context was retrievable; follow the published recipe at ${check.page}.`,
    `Human-readable recipe: ${check.page}`,
    '',
    'Rules:',
    '- Judge only from the evidence excerpts provided. Never invent files, packages, versions, or lines.',
    '- Report a finding only when the evidence shown supports it.',
    '- If the evidence is insufficient to decide, use status "warn" and say what is missing.',
    '- Placeholder or example credentials (test fixtures, *.example files, obvious dummies) are not findings.',
    '- Respond with ONLY a JSON object: {"status":"pass|warn|fail","summary":"...","findings":[{"severity":"low|medium|high|critical","title":"...","recommendation":"..."}]}',
    `- At most ${MAX_FINDINGS} findings, ordered most severe first.`,
  ].join('\n');
}

// --- Reporting -------------------------------------------------------------

const STATUS_ICON = { pass: '✅ pass', warn: '⚠️ warn', fail: '❌ fail', skipped: '⏭️ off', error: '💥 error' };

export function renderSummary(results, meta) {
  const lines = [
    '## Security Recipes health check',
    '',
    `- Context: ${meta.contextSource === 'mcp'
      ? `connected to the hosted [security-recipes.ai MCP server](${SITE}/mcp-servers/)`
      : meta.contextSource === 'feed'
        ? `[security-recipes.ai recipes feed](${SITE}/api/recipes.json) (MCP fallback)`
        : 'recipe page references only (network context unavailable)'}`,
    `- Model: \`${meta.model}\` via ${meta.provider}${meta.autoSelected ? ' (auto-selected lowest available)' : ''}`,
    '',
    '| Check | Status | Detail |',
    '| --- | --- | --- |',
  ];
  for (const result of results) {
    if (result.status === 'skipped') {
      lines.push(`| ${result.label} | ${STATUS_ICON.skipped} | Not enabled — set \`${result.input}: true\` to run it. [Recipe](${result.page}) |`);
    } else {
      const detail = result.summary
        ? result.summary.replace(/\|/g, '\\|').replace(/\n/g, ' ')
        : '';
      const findings = result.findings.length ? ` ${result.findings.length} finding(s).` : '';
      lines.push(`| [${result.label}](${result.page}) | ${STATUS_ICON[result.status]} | ${detail}${findings} |`);
    }
  }
  const disabled = results.filter((result) => result.status === 'skipped');
  if (disabled.length) {
    lines.push('', `**${disabled.length} check(s) are not enabled.** Enable them with the boolean inputs above for complete coverage.`);
  }
  for (const result of results) {
    if (!result.findings?.length) continue;
    lines.push('', `### ${result.label}`);
    for (const finding of result.findings) {
      lines.push(`- **${finding.severity}** — ${finding.title}${finding.recommendation ? `: ${finding.recommendation}` : ''}`);
    }
  }
  return lines.join('\n');
}

function writeOutput(name, value) {
  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
  }
}

// --- Entry -----------------------------------------------------------------

export async function run() {
  const provider = readInput('provider', 'openai').toLowerCase();
  if (!['anthropic', 'openai', 'xai', 'ollama'].includes(provider)) {
    throw new Error(`Unsupported provider "${provider}". Use anthropic, openai, xai, or ollama.`);
  }
  const apiKey = readInput('api-key', '');
  if (!apiKey && provider !== 'ollama') {
    throw new Error(`The ${provider} provider requires the api-key input.`);
  }
  const baseUrl = providerBaseUrl(provider, readInput('base-url', ''));
  const mcpUrl = readInput('mcp-url', `${SITE}/mcp`);
  const failOn = readInput('fail-on', 'fail');
  const root = readInput('working-directory', process.cwd());

  const enabledChecks = CHECKS.filter((check) => readBoolInput(check.input, check.defaultEnabled));
  const { model, autoSelected } = await resolveModel(provider, { apiKey, baseUrl });
  if (!model) throw new Error('No model could be resolved for the selected provider.');
  console.log(`Provider ${provider}, model ${model}${autoSelected ? ' (lowest available)' : ''}.`);

  const context = await loadRecipeContext(mcpUrl, enabledChecks);
  console.log(`Recipe context source: ${context.source}.`);

  const results = [];
  for (const check of CHECKS) {
    if (!enabledChecks.includes(check)) {
      results.push({ ...check, status: 'skipped', findings: [], summary: '' });
      continue;
    }
    const evidence = collectEvidence(check.evidence, root);
    if (!evidence) {
      results.push({ ...check, status: 'pass', findings: [], summary: 'No matching evidence files exist in this repository.' });
      continue;
    }
    try {
      const reply = await chat(provider, {
        apiKey,
        baseUrl,
        model,
        system: checkPrompt(check, context.recipes.get(check.key)),
        user: `Repository evidence excerpts:\n\n${evidence}`,
      });
      const verdict = parseVerdict(reply);
      results.push({ ...check, ...verdict });
      console.log(`${check.label}: ${verdict.status} (${verdict.findings.length} findings)`);
      for (const finding of verdict.findings) {
        const level = verdict.status === 'fail' ? 'error' : 'warning';
        console.log(`::${level} title=${check.label}::[${finding.severity}] ${finding.title}`);
      }
    } catch (error) {
      results.push({ ...check, status: 'error', findings: [], summary: `Check failed to run: ${error.message}` });
      console.log(`::error title=${check.label}::${error.message}`);
    }
  }

  const summary = renderSummary(results, {
    provider, model, autoSelected, contextSource: context.source,
  });
  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${summary}\n`);
  }
  console.log(summary);

  let overall = 'pass';
  for (const result of results) {
    if (result.status === 'skipped') continue;
    writeOutput(result.key, result.status);
    if (['fail', 'error'].includes(result.status)) overall = 'fail';
    else if (result.status === 'warn' && overall === 'pass') overall = 'warn';
  }
  writeOutput('result', overall);

  const failing = overall === 'fail' || (failOn === 'warn' && overall === 'warn');
  if (failOn !== 'never' && failing) {
    throw new Error(`Security health concluded ${overall}; see the job summary for findings.`);
  }
}

const invokedDirectly = process.argv[1] &&
  pathToFileURL(process.argv[1]).href === import.meta.url;
if (invokedDirectly) {
  run().catch((error) => {
    console.log(`::error::${error.message}`);
    process.exitCode = 1;
  });
}
