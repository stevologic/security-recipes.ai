/*
 * SecurityRecipes AI chatbot.
 * Runs in the browser: provider credentials are stored client-side and
 * requests use the same-origin provider relay when the site runtime exposes it.
 */
(function () {
  'use strict';

  if (window.__SECURITY_RECIPES_AI_CHATBOT__) return;
  window.__SECURITY_RECIPES_AI_CHATBOT__ = true;

  var PROVIDERS = {
    openai: {
      label: 'OpenAI',
      tokenLabel: 'OpenAI token',
      defaultModel: 'gpt-5.5',
      models: ['gpt-5.5', 'gpt-5.4', 'gpt-5.4-mini', 'gpt-5.3-codex', 'gpt-5.3-codex-spark'],
      endpoint: 'https://api.openai.com/v1/responses',
      proxyPath: '/ai-provider-proxy/openai/v1/responses'
    },
    grok: {
      label: 'Grok',
      tokenLabel: 'xAI token',
      defaultModel: 'grok-4.3',
      models: ['grok-4.3', 'grok-4.2', 'grok-4', 'grok-3'],
      endpoint: 'https://api.x.ai/v1/chat/completions',
      proxyPath: '/ai-provider-proxy/xai/v1/chat/completions'
    },
    claude: {
      label: 'Claude',
      tokenLabel: 'Anthropic token',
      defaultModel: 'claude-sonnet-4-5',
      models: ['claude-sonnet-4-5', 'claude-opus-4-5', 'claude-haiku-4-5', 'claude-sonnet-4-0'],
      endpoint: 'https://api.anthropic.com/v1/messages',
      proxyPath: '/ai-provider-proxy/anthropic/v1/messages'
    }
  };

  var STORE = {
    provider: 'securityRecipes.ai.provider',
    agentProvider: 'securityRecipes.ai.agent.provider',
    agentRecipe: 'securityRecipes.ai.agent.recipe',
    agentActions: 'securityRecipes.ai.agent.actions',
    agentInputChannels: 'securityRecipes.ai.agent.inputChannels',
    agentWorkflowTemplate: 'securityRecipes.ai.agent.workflowTemplate',
    agentReportProfile: 'securityRecipes.ai.agent.reportProfile',
    agentOutputChannel: 'securityRecipes.ai.agent.outputChannel',
    settingsOpen: 'securityRecipes.ai.settingsOpen',
    chatHistory: 'securityRecipes.ai.chatHistory',
    credentialMode: 'securityRecipes.ai.credentialMode.',
    token: 'securityRecipes.ai.token.',
    model: 'securityRecipes.ai.model.',
    oauthClientId: 'securityRecipes.ai.oauth.clientId.',
    oauthAuthUrl: 'securityRecipes.ai.oauth.authUrl.',
    oauthTokenUrl: 'securityRecipes.ai.oauth.tokenUrl.',
    oauthScope: 'securityRecipes.ai.oauth.scope.',
    oauthPending: 'securityRecipes.ai.oauth.pending',
    context: 'securityRecipes.ai.includeContext',
    related: 'securityRecipes.ai.includeRelated',
    githubContext: 'securityRecipes.ai.includeGitHubContext',
    githubRepoUrl: 'securityRecipes.ai.github.publicRepo',
    githubAuthMode: 'securityRecipes.ai.github.authMode',
    githubToken: 'securityRecipes.ai.github.token.',
    githubOAuthClientId: 'securityRecipes.ai.github.oauth.clientId',
    githubOAuthAuthUrl: 'securityRecipes.ai.github.oauth.authUrl',
    githubOAuthTokenUrl: 'securityRecipes.ai.github.oauth.tokenUrl',
    githubOAuthScope: 'securityRecipes.ai.github.oauth.scope',
    githubOAuthPending: 'securityRecipes.ai.github.oauth.pending',
    slackWebhook: 'securityRecipes.ai.integrations.slackWebhook',
    emailRecipient: 'securityRecipes.ai.integrations.emailRecipient',
    smtpRelayUrl: 'securityRecipes.ai.integrations.smtpRelayUrl',
    jiraBaseUrl: 'securityRecipes.ai.integrations.jiraBaseUrl',
    jiraEmail: 'securityRecipes.ai.integrations.jiraEmail',
    jiraToken: 'securityRecipes.ai.integrations.jiraToken',
    jiraProject: 'securityRecipes.ai.integrations.jiraProject',
    teamsWebhook: 'securityRecipes.ai.integrations.teamsWebhook',
    serviceNowBaseUrl: 'securityRecipes.ai.integrations.serviceNowBaseUrl',
    serviceNowTable: 'securityRecipes.ai.integrations.serviceNowTable',
    serviceNowToken: 'securityRecipes.ai.integrations.serviceNowToken',
    linearApiKey: 'securityRecipes.ai.integrations.linearApiKey',
    linearTeamId: 'securityRecipes.ai.integrations.linearTeamId',
    splunkHecUrl: 'securityRecipes.ai.integrations.splunkHecUrl',
    splunkHecToken: 'securityRecipes.ai.integrations.splunkHecToken',
    splunkIndex: 'securityRecipes.ai.integrations.splunkIndex',
    splunkSourceType: 'securityRecipes.ai.integrations.splunkSourceType',
    elasticBaseUrl: 'securityRecipes.ai.integrations.elasticBaseUrl',
    elasticApiKey: 'securityRecipes.ai.integrations.elasticApiKey',
    elasticSpaceId: 'securityRecipes.ai.integrations.elasticSpaceId',
    elasticOwner: 'securityRecipes.ai.integrations.elasticOwner',
    genericWebhookUrl: 'securityRecipes.ai.integrations.genericWebhookUrl',
    genericWebhookMethod: 'securityRecipes.ai.integrations.genericWebhookMethod',
    genericWebhookAuthHeader: 'securityRecipes.ai.integrations.genericWebhookAuthHeader',
    genericWebhookHeaders: 'securityRecipes.ai.integrations.genericWebhookHeaders',
    depsDevContext: 'securityRecipes.ai.includeDepsDevContext',
    sarifContext: 'securityRecipes.ai.includeSarifContext',
    sbomContext: 'securityRecipes.ai.includeSbomContext',
    sarifUpload: 'securityRecipes.ai.upload.sarif',
    sbomUpload: 'securityRecipes.ai.upload.sbom'
  };

  var CHAT_HISTORY_COOKIE = 'securityRecipesAiChatHistory';
  var CHAT_HISTORY_COUNT_COOKIE = CHAT_HISTORY_COOKIE + 'Count';
  var CHAT_HISTORY_MAX_MESSAGES = 100;
  var CHAT_HISTORY_MAX_STORAGE_CHARS = 450000;
  var CHAT_HISTORY_MAX_CHUNKS = 12;
  var GITHUB_CONTEXT_MAX_FILES = 18;
  var GITHUB_CONTEXT_MAX_FILE_CHARS = 1600;
  var GITHUB_CONTEXT_MAX_TOTAL_CHARS = 12000;
  var GITHUB_CONTEXT_MAX_ISSUES = 6;
  var GITHUB_CONTEXT_MAX_PRS = 6;
  var GITHUB_CONTEXT_MAX_ITEM_CHARS = 750;
  var DEPS_DEV_MAX_PACKAGES = 40;
  var DEPS_DEV_MAX_ADVISORIES = 12;
  var DEPS_DEV_MAX_CONTEXT_CHARS = 9000;
  var IMPORTED_CONTEXT_MAX_CHARS = 9000;
  var SARIF_SAMPLE_FINDINGS = 12;
  var SARIF_TOP_ITEMS = 8;
  var SBOM_SAMPLE_COMPONENTS = 12;
  var SBOM_TOP_ITEMS = 8;
  var CONNECTIVITY_CHECK_INTERVAL_MS = 60000;
  var GITHUB_MANIFEST_PATHS = [
    'README.md',
    'README',
    'SECURITY.md',
    'CONTRIBUTING.md',
    'CONTRIBUTING',
    'LICENSE',
    'LICENSE.md',
    '.github/CODEOWNERS',
    'CODEOWNERS',
    'AGENTS.md',
    'CLAUDE.md',
    'package.json',
    'package-lock.json',
    'pnpm-lock.yaml',
    'yarn.lock',
    'pyproject.toml',
    'requirements.txt',
    'poetry.lock',
    'go.mod',
    'go.sum',
    'pom.xml',
    'build.gradle',
    'settings.gradle',
    'Cargo.toml',
    'Gemfile',
    'composer.json',
    'Dockerfile',
    'docker-compose.yml',
    'compose.yaml',
    '.github/dependabot.yml'
  ];
  var AGENT_WORKFLOWS = [
    { value: 'dependency', label: 'Dependency fix', prompt: 'Vulnerable dependency remediation', description: 'Bump the narrowest package set and hold for review.' },
    { value: 'sast', label: 'SAST triage', prompt: 'SAST finding triage', description: 'Group findings, remove false positives, and draft fixes.' },
    { value: 'sensitive-data', label: 'Sensitive data', prompt: 'Sensitive data remediation', description: 'Quarantine exposure, route rotation, and preserve evidence.' },
    { value: 'mcp-guardrail', label: 'MCP guardrail', prompt: 'MCP connector guardrail review', description: 'Check connector egress, auth, and runtime policy.' },
    { value: 'base-image', label: 'Base image', prompt: 'Base image update', description: 'Select a patched base and prove compatibility.' },
    { value: 'recipe-runbook', label: 'Apply recipe', prompt: 'Apply SecurityRecipes runbook', description: 'Turn a recipe into commands, checks, and rollback for a target.' }
  ];
  var AGENT_OUTPUT_ROUTES = [
    { value: 'draft-pr', label: 'Draft PR packet', requirement: 'No GitHub write required. Produces branch name, PR body, tests, rollback, and reviewer checklist.' },
    { value: 'github-issue', label: 'GitHub issue', requirement: 'Requires GitHub PAT or OAuth token with issues write access.' },
    { value: 'slack', label: 'Slack message', requirement: 'Requires an incoming Slack webhook URL.' },
    { value: 'email', label: 'Email handoff', requirement: 'Uses a local mailto draft, or a configured CORS-enabled email relay URL.' },
    { value: 'jira', label: 'Jira ticket', requirement: 'Requires Jira base URL, account email, API token, and project key.' },
    { value: 'runbook', label: 'Runbook receipt', requirement: 'No external auth required. Produces copyable steps and evidence.' },
    { value: 'server-runbook', label: 'Server runbook', requirement: 'No automatic server changes. Produces commands for a human-run maintenance window.' }
  ];

  var state = {
    provider: localStorage.getItem(STORE.provider) || 'openai',
    messages: loadChatHistoryStorage(),
    docs: [],
    docsLoading: null,
    includeContext: localStorage.getItem(STORE.context) !== 'false',
    includeRelated: localStorage.getItem(STORE.related) !== 'false',
    includeGitHub: localStorage.getItem(STORE.githubContext) === 'true',
    includeDepsDev: localStorage.getItem(STORE.depsDevContext) === 'true',
    includeSarif: localStorage.getItem(STORE.sarifContext) === 'true',
    includeSbom: localStorage.getItem(STORE.sbomContext) === 'true',
    githubRepoUrl: localStorage.getItem(STORE.githubRepoUrl) || '',
    githubLastStatusDetail: '',
    githubContextText: '',
    githubContextLoadedAt: '',
    depsDevContextText: '',
    depsDevContextLoadedAt: '',
    sarifContextText: '',
    sarifContextLoadedAt: '',
    sarifContextMeta: null,
    sbomContextText: '',
    sbomContextLoadedAt: '',
    sbomContextMeta: null,
    settingsOpen: localStorage.getItem(STORE.settingsOpen) === 'true',
    agentRecipePath: localStorage.getItem(STORE.agentRecipe) || '',
    agentActions: loadStoredJson(STORE.agentActions, []),
    agentRecipeResults: [],
    agentRecipeActive: -1,
    sending: false,
    agentRunning: false,
    agentLastOutput: '',
    agentLastConfig: null,
    connectivity: {},
    connectivityTimer: null,
    persistentNavigationEnabled: false,
    siteNavigating: false
  };
  if (!Array.isArray(state.agentActions)) state.agentActions = [];
  hydrateImportedContextState('sarif');
  hydrateImportedContextState('sbom');

  var els = {};
  var mermaidLoader = null;
  var mermaidRenderTimer = null;
  var mermaidRenderSeq = 0;

  function html(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function loadStoredJson(key, fallback) {
    try {
      var raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (e) {
      localStorage.removeItem(key);
      return fallback;
    }
  }

  function saveStoredJson(key, value) {
    localStorage.setItem(key, JSON.stringify(value));
  }

  function importedContextStateMap(kind) {
    if (kind === 'sarif') {
      return {
        include: 'includeSarif',
        text: 'sarifContextText',
        loadedAt: 'sarifContextLoadedAt',
        meta: 'sarifContextMeta'
      };
    }
    return {
      include: 'includeSbom',
      text: 'sbomContextText',
      loadedAt: 'sbomContextLoadedAt',
      meta: 'sbomContextMeta'
    };
  }

  function importedContextToggleStoreKey(kind) {
    return kind === 'sarif' ? STORE.sarifContext : STORE.sbomContext;
  }

  function importedContextDataStoreKey(kind) {
    return kind === 'sarif' ? STORE.sarifUpload : STORE.sbomUpload;
  }

  function importedContextChannelId(kind) {
    return kind === 'sarif' ? 'sarif-manual-import' : 'sbom-manual-import';
  }

  function importedContextLabel(kind) {
    return kind === 'sarif' ? 'SARIF' : 'SBOM';
  }

  function hydrateImportedContextState(kind) {
    var stored = loadStoredJson(importedContextDataStoreKey(kind), null);
    var map = importedContextStateMap(kind);
    if (!stored || typeof stored !== 'object') return;
    state[map.text] = typeof stored.text === 'string' ? stored.text : '';
    state[map.loadedAt] = typeof stored.loadedAt === 'string' ? stored.loadedAt : '';
    state[map.meta] = stored.meta && typeof stored.meta === 'object' ? stored.meta : null;
  }

  function importedContextBundle(kind) {
    var map = importedContextStateMap(kind);
    return {
      enabled: !!state[map.include],
      text: state[map.text] || '',
      loadedAt: state[map.loadedAt] || '',
      meta: state[map.meta] || null
    };
  }

  function importedChannelBundle(channelId) {
    if (channelId === importedContextChannelId('sarif')) return importedContextBundle('sarif');
    if (channelId === importedContextChannelId('sbom')) return importedContextBundle('sbom');
    return null;
  }

  function setImportedContextBundle(kind, payload) {
    var map = importedContextStateMap(kind);
    state[map.text] = payload && typeof payload.text === 'string' ? payload.text : '';
    state[map.loadedAt] = payload && typeof payload.loadedAt === 'string' ? payload.loadedAt : '';
    state[map.meta] = payload && payload.meta && typeof payload.meta === 'object' ? payload.meta : null;
    if (state[map.text]) {
      saveStoredJson(importedContextDataStoreKey(kind), {
        text: state[map.text],
        loadedAt: state[map.loadedAt],
        meta: state[map.meta]
      });
    } else {
      localStorage.removeItem(importedContextDataStoreKey(kind));
    }
  }

  function marketplacePayload() {
    return window.__SECURITY_RECIPES_MARKETPLACE || {};
  }

  function fallbackInputChannels() {
    return [
      {
        id: 'page-context',
        label: 'Current page context',
        category: 'Local browser context',
        status: 'native',
        runtime_support: 'live',
        description: 'Attach the current page title, headings, and bounded page text.',
        auth_modes: ['none'],
        config: { type: 'page_context' }
      },
      {
        id: 'recipe-index',
        label: 'SecurityRecipes search index',
        category: 'Local browser context',
        status: 'native',
        runtime_support: 'live',
        description: 'Attach top matching SecurityRecipes docs, prompts, and workflows.',
        auth_modes: ['none'],
        config: { type: 'recipes_index' }
      },
      {
        id: 'github-repository',
        label: 'GitHub repository context',
        category: 'Code and findings sources',
        status: 'native',
        runtime_support: 'live',
        description: 'Load bounded public or authenticated GitHub repository context.',
        auth_modes: ['public', 'pat', 'oauth'],
        config: { type: 'github_repository' }
      },
      {
        id: 'deps-dev-advisories',
        label: 'deps.dev advisory context',
        category: 'Code and findings sources',
        status: 'native',
        runtime_support: 'live',
        description: 'Check GitHub dependency graph packages against deps.dev advisories.',
        auth_modes: ['public', 'pat', 'oauth'],
        config: { type: 'deps_dev_lookup' }
      }
    ];
  }

  function inputChannels() {
    var data = marketplacePayload().inputChannels;
    return data && Array.isArray(data.channels) && data.channels.length
      ? data.channels.slice()
      : fallbackInputChannels();
  }

  function normalizeOutputChannel(channel) {
    var out = {};
    var key;
    for (key in channel) out[key] = channel[key];
    if (!out.id) out.id = out.value || out.driver || 'output-channel';
    if (!out.label) out.label = out.id;
    if (!out.value) out.value = out.driver || out.id;
    if (!out.driver) out.driver = out.value;
    if (!out.requirement) out.requirement = out.description || 'Review the output before sending it downstream.';
    if (!out.runtime_support) out.runtime_support = 'copy_only';
    return out;
  }

  function outputChannels() {
    var data = marketplacePayload().outputChannels;
    var channels = data && Array.isArray(data.channels) && data.channels.length
      ? data.channels
      : AGENT_OUTPUT_ROUTES.map(function (route) {
          return {
            id: route.value,
            label: route.label,
            value: route.value,
            driver: route.value,
            category: 'Operational handoff',
            status: 'native',
            runtime_support: 'copy_only',
            browser_delivery: true,
            requirement: route.requirement,
            description: route.requirement,
            config: { type: route.value }
          };
        });
    return channels.map(normalizeOutputChannel);
  }

  function reportProfiles() {
    var data = marketplacePayload().reportProfiles;
    return data && Array.isArray(data.profiles) ? data.profiles.slice() : [];
  }

  function workflowTemplates() {
    var data = marketplacePayload().workflowTemplates;
    return data && Array.isArray(data.templates) ? data.templates.slice() : [];
  }

  function inputChannelById(id) {
    return inputChannels().find(function (channel) { return channel.id === id; }) || null;
  }

  function outputChannelById(id) {
    return outputChannels().find(function (channel) {
      return channel.id === id || channel.value === id;
    }) || outputChannels()[0] || normalizeOutputChannel(AGENT_OUTPUT_ROUTES[0]);
  }

  function reportProfileById(id) {
    return reportProfiles().find(function (profile) { return profile.id === id; }) || reportProfiles()[0] || null;
  }

  function workflowTemplateById(id) {
    return workflowTemplates().find(function (template) { return template.id === id; }) || null;
  }

  function defaultInputChannelIds() {
    var ids = [];
    if (localStorage.getItem(STORE.context) !== 'false') ids.push('page-context');
    if (localStorage.getItem(STORE.related) !== 'false') ids.push('recipe-index');
    if (localStorage.getItem(STORE.githubContext) === 'true') ids.push('github-repository');
    if (localStorage.getItem(STORE.depsDevContext) === 'true') ids.push('deps-dev-advisories');
    if (localStorage.getItem(STORE.sarifContext) === 'true') ids.push(importedContextChannelId('sarif'));
    if (localStorage.getItem(STORE.sbomContext) === 'true') ids.push(importedContextChannelId('sbom'));
    return ids.length ? ids : ['page-context', 'recipe-index'];
  }

  function storedInputChannelIds() {
    var raw = loadStoredJson(STORE.agentInputChannels, defaultInputChannelIds());
    return Array.isArray(raw) ? raw.filter(Boolean) : defaultInputChannelIds();
  }

  function selectByText(select, label) {
    if (!select || !label) return;
    var target = collapseText(label).toLowerCase();
    for (var i = 0; i < select.options.length; i++) {
      var option = select.options[i];
      if (collapseText(option.textContent).toLowerCase() === target || collapseText(option.value).toLowerCase() === target) {
        select.selectedIndex = i;
        return;
      }
    }
  }

  function selectValues(select) {
    if (!select || !select.options) return [];
    return Array.prototype.slice.call(select.options)
      .filter(function (option) { return option.selected; })
      .map(function (option) { return option.value; })
      .filter(Boolean);
  }

  function setSelectValues(select, values) {
    if (!select || !select.options) return;
    var wanted = {};
    (Array.isArray(values) ? values : [values]).filter(Boolean).forEach(function (value) {
      wanted[String(value)] = true;
    });
    Array.prototype.forEach.call(select.options, function (option) {
      option.selected = !!wanted[option.value];
    });
  }

  function persistedAgentOutputChannel() {
    return localStorage.getItem(STORE.agentOutputChannel) || '';
  }

  function persistedWorkflowTemplate() {
    return localStorage.getItem(STORE.agentWorkflowTemplate) || '';
  }

  function persistedReportProfile() {
    return localStorage.getItem(STORE.agentReportProfile) || '';
  }

  function fallbackCopyText(text) {
    return new Promise(function (resolve, reject) {
      var textarea = document.createElement('textarea');
      var activeElement = document.activeElement;
      var selection = window.getSelection ? window.getSelection() : null;
      var ranges = [];
      if (selection) {
        for (var i = 0; i < selection.rangeCount; i += 1) {
          ranges.push(selection.getRangeAt(i));
        }
      }
      textarea.value = text;
      textarea.setAttribute('readonly', '');
      textarea.style.position = 'fixed';
      textarea.style.top = '0';
      textarea.style.left = '0';
      textarea.style.width = '1px';
      textarea.style.height = '1px';
      textarea.style.padding = '0';
      textarea.style.border = '0';
      textarea.style.opacity = '0';
      textarea.style.pointerEvents = 'none';
      document.body.appendChild(textarea);
      try {
        textarea.focus({ preventScroll: true });
      } catch (e) {
        textarea.focus();
      }
      textarea.select();
      textarea.setSelectionRange(0, textarea.value.length);
      try {
        document.execCommand('copy') ? resolve() : reject(new Error('Copy command failed.'));
      } catch (error) {
        reject(error);
      } finally {
        textarea.remove();
        if (selection) {
          selection.removeAllRanges();
          ranges.forEach(function (range) {
            selection.addRange(range);
          });
        }
        if (activeElement && typeof activeElement.focus === 'function') {
          try {
            activeElement.focus({ preventScroll: true });
          } catch (e) {
            activeElement.focus();
          }
        }
      }
    });
  }

  function copyText(text) {
    var value = String(text || '');
    if (!value) return Promise.reject(new Error('Nothing to copy.'));
    if (navigator.clipboard && window.isSecureContext && typeof navigator.clipboard.writeText === 'function') {
      return navigator.clipboard.writeText(value).catch(function () {
        return fallbackCopyText(value);
      });
    }
    return fallbackCopyText(value);
  }

  function downloadJsonFile(fileName, payload) {
    var data = JSON.stringify(payload || {}, null, 2);
    var blob = new Blob([data], { type: 'application/json;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var link = document.createElement('a');
    link.href = url;
    link.download = fileName || 'securityrecipes-report.json';
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(function () {
      URL.revokeObjectURL(url);
    }, 0);
  }

  function safeMarkdownUrl(value, kind) {
    var raw = String(value || '').trim().replace(/^<|>$/g, '');
    if (!raw || /[\u0000-\u001f\s]/.test(raw)) return '';
    if (kind === 'image' && /^data:image\/(?:png|jpe?g|gif|webp);base64,/i.test(raw)) return raw;
    try {
      var parsed = new URL(raw, window.location.href);
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') return parsed.href;
    } catch (e) {
      return '';
    }
    return '';
  }

  function inlineMarkdown(source) {
    var tokens = [];
    var text = String(source || '');

    function stash(markup) {
      var key = '@@AICBTOKEN' + tokens.length + '@@';
      tokens.push({ key: key, markup: markup });
      return key;
    }

    text = text.replace(/`([^`\n]+)`/g, function (_match, code) {
      return stash('<code>' + html(code) + '</code>');
    });

    text = text.replace(/!\[([^\]]*)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g, function (match, alt, url) {
      var safe = safeMarkdownUrl(url, 'image');
      if (!safe) return match;
      return stash('<img src="' + html(safe) + '" alt="' + html(alt) + '" loading="lazy" referrerpolicy="no-referrer">');
    });

    text = text.replace(/(^|[^!])\[([^\]]+)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g, function (_match, prefix, label, url) {
      var safe = safeMarkdownUrl(url, 'link');
      if (!safe) return _match;
      return prefix + stash('<a href="' + html(safe) + '" target="_blank" rel="noopener noreferrer">' + html(label) + '</a>');
    });

    text = text.replace(/(^|[\s([{>])((?:https?:\/\/)[^\s<>"']+)/g, function (_match, prefix, url) {
      var link = url;
      var suffix = '';
      while (/[),.;:!?]$/.test(link)) {
        if (link.charAt(link.length - 1) === ')' && (link.match(/\(/g) || []).length >= (link.match(/\)/g) || []).length) break;
        suffix = link.charAt(link.length - 1) + suffix;
        link = link.slice(0, -1);
      }
      var safe = safeMarkdownUrl(link, 'link');
      if (!safe) return _match;
      return prefix + stash('<a href="' + html(safe) + '" target="_blank" rel="noopener noreferrer">' + html(link) + '</a>') + suffix;
    });

    text = html(text)
      .replace(/~~(.+?)~~/g, '<del>$1</del>')
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/__(.+?)__/g, '<strong>$1</strong>')
      .replace(/(^|[^\*])\*([^*\n]+)\*/g, '$1<em>$2</em>')
      .replace(/(^|[^_])_([^_\n]+)_/g, '$1<em>$2</em>');
    text = allowSafeInlineHtml(text);

    tokens.forEach(function (token) {
      text = text.split(token.key).join(token.markup);
    });

    return text;
  }

  function allowSafeInlineHtml(rendered) {
    return String(rendered || '').replace(/&lt;(\/?)(br|hr|p|ul|ol|li|blockquote|strong|em|b|i|u|s|del|code|kbd|sub|sup|pre|table|thead|tbody|tr|th|td|h1|h2|h3|h4)\s*\/?&gt;/gi, function (_match, close, tag) {
      tag = String(tag || '').toLowerCase();
      if (tag === 'br' || tag === 'hr') return '<' + tag + '>';
      return '<' + close + tag + '>';
    });
  }

  function renderCodeBlock(language, code) {
    var lang = String(language || '').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
    var body = String(code || '').replace(/^\n+|\n+$/g, '');
    if (lang === 'mermaid') {
      return '<div class="ai-chatbot-mermaid" data-mermaid-source="' + html(body) + '">' +
        '<div class="ai-chatbot-mermaid-toolbar">' +
          '<span>Mermaid diagram</span>' +
          '<button class="ai-chatbot-mermaid-copy" type="button" data-copy-mermaid title="Copy Mermaid source">Copy source</button>' +
        '</div>' +
        '<pre><code>' + html(body) + '</code></pre>' +
      '</div>';
    }
    return '<pre><code' + (lang ? ' class="language-' + html(lang) + '"' : '') + '>' + html(body) + '</code></pre>';
  }

  function splitMarkdownTableRow(line) {
    var trimmed = String(line || '').trim();
    if (trimmed.indexOf('|') === -1) return null;
    if (trimmed.charAt(0) === '|') trimmed = trimmed.slice(1);
    if (trimmed.charAt(trimmed.length - 1) === '|') trimmed = trimmed.slice(0, -1);
    var cells = trimmed.split('|').map(function (cell) { return cell.trim(); });
    return cells.length > 1 ? cells : null;
  }

  function markdownTableAlignment(line) {
    var cells = splitMarkdownTableRow(line);
    if (!cells || !cells.every(function (cell) { return /^:?-{3,}:?$/.test(cell); })) return null;
    return cells.map(function (cell) {
      var left = cell.charAt(0) === ':';
      var right = cell.charAt(cell.length - 1) === ':';
      if (left && right) return 'center';
      if (right) return 'right';
      return 'left';
    });
  }

  function renderMarkdownTable(headers, aligns, rows) {
    function styleFor(index) {
      return aligns[index] && aligns[index] !== 'left' ? ' style="text-align:' + aligns[index] + '"' : '';
    }
    var head = '<thead><tr>' + headers.map(function (cell, index) {
      return '<th' + styleFor(index) + '>' + inlineMarkdown(cell) + '</th>';
    }).join('') + '</tr></thead>';
    var body = '<tbody>' + rows.map(function (row) {
      return '<tr>' + headers.map(function (_cell, index) {
        return '<td' + styleFor(index) + '>' + inlineMarkdown(row[index] || '') + '</td>';
      }).join('') + '</tr>';
    }).join('') + '</tbody>';
    return '<div class="ai-chatbot-table-wrap"><table>' + head + body + '</table></div>';
  }

  function normalizeLooseMarkdownTables(source) {
    var text = String(source || '');
    var guard = 0;
    var previous;
    do {
      previous = text;
      text = text
        .replace(/(\|[^\n|]+(?:\|[^\n|]+){2,}\|)\s+(\|:?-{3,}:?(?:\|:?-{3,}:?){2,}\|)/g, '$1\n$2')
        .replace(/(\|:?-{3,}:?(?:\|:?-{3,}:?){2,}\|)\s+(\|[^\n|]+(?:\|[^\n|]+){2,}\|)/g, '$1\n$2')
        .replace(/(\|[^\n|]+(?:\|[^\n|]+){2,}\|)\s+(\|[^\n|]+(?:\|[^\n|]+){2,}\|)(?=\s*(?:\n|$))/g, '$1\n$2');
      guard += 1;
    } while (text !== previous && guard < 6);
    return text;
  }

  function renderMarkdownText(source) {
    var lines = normalizeLooseMarkdownTables(source).replace(/\n{3,}/g, '\n\n').split('\n');
    var output = [];
    var paragraph = [];
    var quote = [];
    var listItems = [];
    var listType = '';

    function flushParagraph() {
      if (!paragraph.length) return;
      output.push('<p>' + inlineMarkdown(paragraph.join('\n')).replace(/\n/g, '<br>') + '</p>');
      paragraph = [];
    }

    function flushQuote() {
      if (!quote.length) return;
      output.push('<blockquote>' + inlineMarkdown(quote.join('\n')).replace(/\n/g, '<br>') + '</blockquote>');
      quote = [];
    }

    function flushList() {
      if (!listItems.length) return;
      output.push('<' + listType + '>' + listItems.map(function (item) {
        return '<li>' + inlineMarkdown(item) + '</li>';
      }).join('') + '</' + listType + '>');
      listItems = [];
      listType = '';
    }

    for (var lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      var line = lines[lineIndex];
      var trimmed = line.trim();
      var heading = /^(#{1,4})\s+(.+)$/.exec(trimmed);
      var unordered = /^\s*[-*]\s+(.+)$/.exec(line);
      var ordered = /^\s*\d+[.)]\s+(.+)$/.exec(line);
      var blockquote = /^\s*>\s?(.*)$/.exec(line);
      var nextListType = ordered ? 'ol' : (unordered ? 'ul' : '');

      if (!trimmed) {
        flushParagraph();
        flushQuote();
        flushList();
        continue;
      }

      if (/^(?:-{3,}|\*{3,})$/.test(trimmed)) {
        flushParagraph();
        flushQuote();
        flushList();
        output.push('<hr>');
        continue;
      }

      var tableHeaders = splitMarkdownTableRow(line);
      var tableAligns = lineIndex + 1 < lines.length ? markdownTableAlignment(lines[lineIndex + 1]) : null;
      if (tableHeaders && tableAligns && tableAligns.length === tableHeaders.length) {
        flushParagraph();
        flushQuote();
        flushList();
        var tableRows = [];
        lineIndex += 2;
        while (lineIndex < lines.length) {
          var tableRow = splitMarkdownTableRow(lines[lineIndex]);
          if (!tableRow || !lines[lineIndex].trim()) {
            lineIndex--;
            break;
          }
          tableRows.push(tableRow);
          lineIndex++;
        }
        output.push(renderMarkdownTable(tableHeaders, tableAligns, tableRows));
        continue;
      }

      if (heading) {
        flushParagraph();
        flushQuote();
        flushList();
        var level = Math.min(4, heading[1].length);
        output.push('<h' + level + '>' + inlineMarkdown(heading[2]) + '</h' + level + '>');
        continue;
      }

      if (blockquote) {
        flushParagraph();
        flushList();
        quote.push(blockquote[1]);
        continue;
      }

      if (nextListType) {
        flushParagraph();
        flushQuote();
        if (listType && listType !== nextListType) flushList();
        listType = nextListType;
        listItems.push((ordered || unordered)[1]);
        continue;
      }

      flushQuote();
      flushList();
      paragraph.push(line);
    }

    flushParagraph();
    flushQuote();
    flushList();
    return output.join('');
  }

  function renderMarkdown(source) {
    var text = String(source || '').replace(/\r\n?/g, '\n');
    if (!text.trim()) return '';
    var output = [];
    var fencePattern = /```([A-Za-z0-9_-]*)[^\n]*\n([\s\S]*?)(?:\n```|$)/g;
    var lastIndex = 0;
    var match;
    while ((match = fencePattern.exec(text))) {
      output.push(renderMarkdownText(text.slice(lastIndex, match.index)));
      output.push(renderCodeBlock(match[1], match[2]));
      lastIndex = fencePattern.lastIndex;
    }
    output.push(renderMarkdownText(text.slice(lastIndex)));
    return output.join('');
  }

  function initMermaid(mermaid) {
    if (!mermaid || mermaid.__securityRecipesInitialized) return;
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: 'strict',
      theme: 'dark',
      themeVariables: {
        darkMode: true,
        background: '#070b12',
        mainBkg: '#111827',
        primaryColor: '#102a32',
        primaryTextColor: '#e5edf7',
        primaryBorderColor: '#14b8a6',
        secondaryColor: '#1e293b',
        secondaryTextColor: '#e5edf7',
        secondaryBorderColor: '#64748b',
        tertiaryColor: '#18181b',
        tertiaryTextColor: '#e5edf7',
        tertiaryBorderColor: '#a78bfa',
        nodeTextColor: '#e5edf7',
        lineColor: '#94a3b8',
        textColor: '#e5edf7',
        edgeLabelBackground: '#0f172a',
        clusterBkg: '#0b1220',
        clusterBorder: '#334155'
      },
      fontFamily: 'inherit',
      flowchart: {
        htmlLabels: true,
        useMaxWidth: true
      }
    });
    mermaid.__securityRecipesInitialized = true;
  }

  function ensureMermaid() {
    if (window.mermaid) {
      initMermaid(window.mermaid);
      return Promise.resolve(window.mermaid);
    }
    if (mermaidLoader) return mermaidLoader;
    mermaidLoader = new Promise(function (resolve, reject) {
      var script = document.createElement('script');
      script.src = 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js';
      script.async = true;
      script.onload = function () {
        initMermaid(window.mermaid);
        resolve(window.mermaid);
      };
      script.onerror = function () {
        reject(new Error('Mermaid renderer could not load.'));
      };
      document.head.appendChild(script);
    });
    return mermaidLoader;
  }

  function renderMermaidBlocks() {
    if (!els.panel) return;
    var blocks = Array.prototype.slice.call(els.panel.querySelectorAll('.ai-chatbot-mermaid:not([data-rendered])'));
    if (!blocks.length) return;

    ensureMermaid().then(function (mermaid) {
      blocks.forEach(function (block) {
        var source = block.getAttribute('data-mermaid-source') || '';
        if (!source.trim() || block.hasAttribute('data-rendered')) return;
        block.setAttribute('data-rendered', 'pending');
        var id = 'ai-chatbot-mermaid-' + (++mermaidRenderSeq);
        Promise.resolve(mermaid.render(id, source)).then(function (result) {
          var svg = typeof result === 'string' ? result : (result && result.svg ? result.svg : '');
          if (!svg) throw new Error('Mermaid renderer returned no SVG.');
          block.innerHTML =
            '<div class="ai-chatbot-mermaid-toolbar">' +
              '<span>Mermaid diagram</span>' +
              '<button class="ai-chatbot-mermaid-copy" type="button" data-copy-mermaid title="Copy Mermaid source">Copy source</button>' +
            '</div>' +
            '<div class="ai-chatbot-mermaid-rendered">' + svg + '</div>';
          block.setAttribute('data-rendered', 'true');
          block.removeAttribute('data-error');
          if (result && typeof result.bindFunctions === 'function') result.bindFunctions(block);
        }).catch(function () {
          block.removeAttribute('data-rendered');
          block.setAttribute('data-error', 'true');
        });
      });
    }).catch(function () {
      blocks.forEach(function (block) {
        block.setAttribute('data-error', 'true');
      });
    });
  }

  function queueMermaidRender() {
    if (!els.panel) return;
    if (mermaidRenderTimer) window.clearTimeout(mermaidRenderTimer);
    mermaidRenderTimer = window.setTimeout(function () {
      mermaidRenderTimer = null;
      renderMermaidBlocks();
    }, 0);
  }

  function handleMessageClick(event) {
    var copyButton = event.target.closest('[data-copy-mermaid]');
    if (!copyButton || !els.panel.contains(copyButton)) return;
    var block = copyButton.closest('.ai-chatbot-mermaid');
    var source = block ? block.getAttribute('data-mermaid-source') || '' : '';
    if (!source) return;
    copyText(source).then(function () {
      copyButton.textContent = 'Copied';
      window.setTimeout(function () {
        copyButton.textContent = 'Copy source';
      }, 1400);
    }).catch(function () {
      copyButton.textContent = 'Copy failed';
      window.setTimeout(function () {
        copyButton.textContent = 'Copy source';
      }, 1800);
    });
  }

  function collapseText(s) {
    return String(s || '').replace(/\s+/g, ' ').trim();
  }

  function nowIso() {
    return new Date().toISOString();
  }

  function formatTimestamp(value) {
    var date = value ? new Date(value) : new Date();
    if (Number.isNaN(date.getTime())) date = new Date();
    return new Intl.DateTimeFormat(undefined, {
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit'
    }).format(date);
  }

  function icon(name) {
    var icons = {
      bot: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="5" y="7" width="14" height="11" rx="3" stroke="currentColor" stroke-width="1.8"/><path d="M12 7V4M9 12h.01M15 12h.01M8.5 18 7 21M15.5 18 17 21" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
      close: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
      expand: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M9 4H4v5M15 4h5v5M20 15v5h-5M4 15v5h5M4 9l6-5M14 4l6 5M20 15l-6 5M10 20l-6-5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
      collapse: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M10 4v6H4M14 4v6h6M20 14h-6v6M4 14h6v6M10 10 4 4M14 10l6-6M14 14l6 6M10 14l-6 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
      chevron: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m8 10 4 4 4-4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
      send: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m4 12 16-8-5 16-3-7-8-1z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>',
      save: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M5 4h12l2 2v14H5V4zM8 4v6h8V4M8 17h8" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>',
      reset: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4 5v6h6M20 19v-6h-6M6.5 9A7 7 0 0 1 18 7.5M17.5 15A7 7 0 0 1 6 16.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>'
    };
    return icons[name] || '';
  }

  function providerConfig(provider) {
    return PROVIDERS[provider || state.provider] || PROVIDERS.openai;
  }

  function providerEndpoint(provider) {
    var cfg = providerFor(provider);
    if (cfg.proxyPath) return new URL(cfg.proxyPath, window.location.origin).toString();
    return cfg.endpoint;
  }

  function credentialModeKey(provider) {
    return STORE.credentialMode + provider;
  }

  function getCredentialMode(provider) {
    var mode = localStorage.getItem(credentialModeKey(provider || state.provider));
    return mode === 'oauth' ? 'oauth' : 'api_key';
  }

  function setCredentialMode(provider, mode) {
    localStorage.setItem(credentialModeKey(provider), mode === 'oauth' ? 'oauth' : 'api_key');
  }

  function credentialModeLabel(provider, mode) {
    var resolved = mode || getCredentialMode(provider || state.provider);
    return resolved === 'oauth' ? 'OAuth bearer' : 'API key';
  }

  function tokenKey(provider, mode) {
    return STORE.token + provider + '.' + (mode || getCredentialMode(provider));
  }

  function legacyTokenKey(provider) {
    return STORE.token + provider;
  }

  function modelKey(provider) {
    return STORE.model + provider;
  }

  function getToken(provider, mode) {
    var resolvedProvider = provider || state.provider;
    var resolvedMode = mode || getCredentialMode(resolvedProvider);
    return localStorage.getItem(tokenKey(resolvedProvider, resolvedMode)) ||
      (resolvedMode === 'api_key' ? localStorage.getItem(legacyTokenKey(resolvedProvider)) || '' : '');
  }

  function tokenLabel(provider, mode) {
    var cfg = providerFor(provider || state.provider);
    return (mode || getCredentialMode(provider || state.provider)) === 'oauth'
      ? cfg.label + ' OAuth bearer'
      : cfg.tokenLabel;
  }

  function oauthFieldKey(provider, field) {
    var prefix = {
      clientId: STORE.oauthClientId,
      authUrl: STORE.oauthAuthUrl,
      tokenUrl: STORE.oauthTokenUrl,
      scope: STORE.oauthScope
    }[field];
    return prefix ? prefix + provider : '';
  }

  function getOAuthField(provider, field) {
    var key = oauthFieldKey(provider || state.provider, field);
    return key ? localStorage.getItem(key) || '' : '';
  }

  function setOAuthField(provider, field, value) {
    var key = oauthFieldKey(provider, field);
    if (!key) return;
    var clean = collapseText(value || '');
    if (clean) localStorage.setItem(key, clean);
    else localStorage.removeItem(key);
  }

  function githubAuthMode() {
    return localStorage.getItem(STORE.githubAuthMode) === 'oauth' ? 'oauth' : 'pat';
  }

  function setGitHubAuthMode(mode) {
    localStorage.setItem(STORE.githubAuthMode, mode === 'oauth' ? 'oauth' : 'pat');
  }

  function githubTokenKey(mode) {
    return STORE.githubToken + (mode || githubAuthMode());
  }

  function getGitHubToken(mode) {
    return localStorage.getItem(githubTokenKey(mode || githubAuthMode())) || '';
  }

  function githubCredentialLabel(mode) {
    return (mode || githubAuthMode()) === 'oauth' ? 'OAuth token' : 'PAT';
  }

  function githubOAuthFieldKey(field) {
    var map = {
      clientId: STORE.githubOAuthClientId,
      authUrl: STORE.githubOAuthAuthUrl,
      tokenUrl: STORE.githubOAuthTokenUrl,
      scope: STORE.githubOAuthScope
    };
    return map[field] || '';
  }

  function getGitHubOAuthField(field) {
    var key = githubOAuthFieldKey(field);
    if (!key) return '';
    var value = localStorage.getItem(key) || '';
    if (value) return value;
    if (field === 'authUrl') return 'https://github.com/login/oauth/authorize';
    if (field === 'tokenUrl') return 'https://github.com/login/oauth/access_token';
    if (field === 'scope') return 'repo read:org workflow';
    return '';
  }

  function setGitHubOAuthField(field, value) {
    var key = githubOAuthFieldKey(field);
    if (!key) return;
    var clean = collapseText(value || '');
    if (clean) localStorage.setItem(key, clean);
    else localStorage.removeItem(key);
  }

  function integrationFieldKey(name) {
    return {
      slackWebhook: STORE.slackWebhook,
      emailRecipient: STORE.emailRecipient,
      smtpRelayUrl: STORE.smtpRelayUrl,
      jiraBaseUrl: STORE.jiraBaseUrl,
      jiraEmail: STORE.jiraEmail,
      jiraToken: STORE.jiraToken,
      jiraProject: STORE.jiraProject,
      teamsWebhook: STORE.teamsWebhook,
      serviceNowBaseUrl: STORE.serviceNowBaseUrl,
      serviceNowTable: STORE.serviceNowTable,
      serviceNowToken: STORE.serviceNowToken,
      linearApiKey: STORE.linearApiKey,
      linearTeamId: STORE.linearTeamId,
      splunkHecUrl: STORE.splunkHecUrl,
      splunkHecToken: STORE.splunkHecToken,
      splunkIndex: STORE.splunkIndex,
      splunkSourceType: STORE.splunkSourceType,
      elasticBaseUrl: STORE.elasticBaseUrl,
      elasticApiKey: STORE.elasticApiKey,
      elasticSpaceId: STORE.elasticSpaceId,
      elasticOwner: STORE.elasticOwner,
      genericWebhookUrl: STORE.genericWebhookUrl,
      genericWebhookMethod: STORE.genericWebhookMethod,
      genericWebhookAuthHeader: STORE.genericWebhookAuthHeader,
      genericWebhookHeaders: STORE.genericWebhookHeaders
    }[name] || '';
  }

  function getIntegrationField(name) {
    var key = integrationFieldKey(name);
    return key ? localStorage.getItem(key) || '' : '';
  }

  function setIntegrationField(name, value) {
    var key = integrationFieldKey(name);
    if (!key) return;
    var clean = collapseText(value || '');
    if (clean) localStorage.setItem(key, clean);
    else localStorage.removeItem(key);
  }

  function trimText(value) {
    return String(value || '').replace(/\r\n/g, '\n').trim();
  }

  function parseJsonObjectInput(text, label) {
    var raw = trimText(text);
    if (!raw) return {};
    var parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new Error((label || 'JSON input') + ' must be valid JSON.');
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error((label || 'JSON input') + ' must be a JSON object.');
    }
    return parsed;
  }

  async function postJson(url, options) {
    var response = await fetch(url, {
      method: (options && options.method) || 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, (options && options.headers) || {}),
      body: JSON.stringify((options && options.body) || {})
    });
    var bodyText = await response.text();
    var data = null;
    if (bodyText) {
      try {
        data = JSON.parse(bodyText);
      } catch (_error) {
        data = null;
      }
    }
    return {
      response: response,
      data: data,
      text: bodyText
    };
  }

  function oauthRedirectUri() {
    return window.location.origin + window.location.pathname;
  }

  function base64UrlFromBytes(bytes) {
    var binary = '';
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  function randomBase64Url(byteLength) {
    if (!window.crypto || !window.crypto.getRandomValues) {
      throw new Error('This browser does not expose crypto.getRandomValues for OAuth state. Paste an OAuth bearer token manually instead.');
    }
    var bytes = new Uint8Array(byteLength || 32);
    window.crypto.getRandomValues(bytes);
    return base64UrlFromBytes(bytes);
  }

  async function pkceChallenge(verifier) {
    if (!window.crypto || !window.crypto.subtle || !window.TextEncoder) {
      throw new Error('This browser does not support PKCE crypto for OAuth. Paste an OAuth bearer token manually instead.');
    }
    var bytes = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    return base64UrlFromBytes(new Uint8Array(bytes));
  }

  function oauthCallbackParams() {
    var query = new URLSearchParams(window.location.search || '');
    var hash = new URLSearchParams((window.location.hash || '').replace(/^#/, ''));
    return {
      code: query.get('code') || hash.get('code') || '',
      accessToken: query.get('access_token') || hash.get('access_token') || '',
      state: query.get('state') || hash.get('state') || '',
      error: query.get('error') || hash.get('error') || '',
      errorDescription: query.get('error_description') || hash.get('error_description') || ''
    };
  }

  function clearOAuthCallbackUrl() {
    if (!window.history || !window.history.replaceState) return;
    window.history.replaceState({}, document.title, window.location.origin + window.location.pathname);
  }

  function readPendingOAuth() {
    try {
      var raw = localStorage.getItem(STORE.oauthPending);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      localStorage.removeItem(STORE.oauthPending);
      return null;
    }
  }

  function saveOAuthToken(provider, token) {
    setCredentialMode(provider, 'oauth');
    localStorage.setItem(tokenKey(provider, 'oauth'), token);
    state.provider = provider;
    localStorage.setItem(STORE.provider, provider);
  }

  async function exchangeOAuthCode(pending, code) {
    var body = new URLSearchParams();
    body.set('grant_type', 'authorization_code');
    body.set('code', code);
    body.set('redirect_uri', pending.redirectUri);
    body.set('client_id', pending.clientId);
    body.set('code_verifier', pending.codeVerifier);

    var response = await fetch(pending.tokenUrl, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body.toString()
    });
    if (!response.ok) throw new Error('OAuth token exchange returned ' + statusLine(response.status, response.statusText) + '. If this provider blocks browser token exchange, paste the OAuth bearer token manually.');
    var data = await response.json();
    if (!data || !data.access_token) throw new Error('OAuth token exchange did not return an access_token.');
    return data.access_token;
  }

  async function startOAuthBrowserFlow() {
    var provider = state.provider;
    var cfg = providerFor(provider);
    var clientId = getOAuthField(provider, 'clientId');
    var authUrl = getOAuthField(provider, 'authUrl');
    var tokenUrl = getOAuthField(provider, 'tokenUrl');
    var scope = getOAuthField(provider, 'scope');
    if (!clientId || !authUrl || !tokenUrl) {
      setStatus('Save OAuth client ID, authorization URL, and token URL first.', 'error');
      return;
    }

    var stateValue = randomBase64Url(24);
    var verifier = randomBase64Url(64);
    var challenge = await pkceChallenge(verifier);
    var redirectUri = oauthRedirectUri();
    var pending = {
      provider: provider,
      clientId: clientId,
      tokenUrl: tokenUrl,
      redirectUri: redirectUri,
      codeVerifier: verifier,
      state: stateValue,
      createdAt: nowIso()
    };
    localStorage.setItem(STORE.oauthPending, JSON.stringify(pending));

    var url = new URL(authUrl);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('state', stateValue);
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');
    if (scope) url.searchParams.set('scope', scope);

    setStatus('Opening ' + cfg.label + ' OAuth authorization in this browser...', '');
    window.location.assign(url.toString());
  }

  function readPendingGitHubOAuth() {
    try {
      var raw = localStorage.getItem(STORE.githubOAuthPending);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      localStorage.removeItem(STORE.githubOAuthPending);
      return null;
    }
  }

  function saveGitHubOAuthToken(token) {
    setGitHubAuthMode('oauth');
    localStorage.setItem(githubTokenKey('oauth'), token);
  }

  async function startGitHubOAuthBrowserFlow() {
    var clientId = collapseText(els.githubOAuthClientId && els.githubOAuthClientId.value) || getGitHubOAuthField('clientId');
    var authUrl = collapseText(els.githubOAuthAuthUrl && els.githubOAuthAuthUrl.value) || getGitHubOAuthField('authUrl');
    var tokenUrl = collapseText(els.githubOAuthTokenUrl && els.githubOAuthTokenUrl.value) || getGitHubOAuthField('tokenUrl');
    var scope = collapseText(els.githubOAuthScope && els.githubOAuthScope.value) || getGitHubOAuthField('scope');
    if (!clientId || !authUrl || !tokenUrl) {
      setGitHubStatus('Save GitHub OAuth client ID, authorization URL, and token URL first.', 'error');
      return;
    }

    var stateValue = randomBase64Url(24);
    var verifier = randomBase64Url(64);
    var challenge = await pkceChallenge(verifier);
    var redirectUri = oauthRedirectUri();
    localStorage.setItem(STORE.githubOAuthPending, JSON.stringify({
      clientId: clientId,
      tokenUrl: tokenUrl,
      redirectUri: redirectUri,
      codeVerifier: verifier,
      state: stateValue,
      createdAt: nowIso()
    }));

    var url = new URL(authUrl);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('state', stateValue);
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');
    if (scope) url.searchParams.set('scope', scope);

    setGitHubStatus('Opening GitHub OAuth authorization in this browser...', '');
    window.location.assign(url.toString());
  }

  async function handleOAuthCallback() {
    var params = oauthCallbackParams();
    if (!params.code && !params.accessToken && !params.error) return;
    if (els.panel) openPanel('chat');
    var githubPending = readPendingGitHubOAuth();
    if (githubPending && params.state === githubPending.state) {
      try {
        if (params.error) throw new Error(params.errorDescription || params.error);
        var githubToken = params.accessToken || await exchangeOAuthCode(githubPending, params.code);
        saveGitHubOAuthToken(githubToken);
        localStorage.removeItem(STORE.githubOAuthPending);
        clearOAuthCallbackUrl();
        updateGitHubAuthUI();
        setGitHubStatus('GitHub OAuth token saved locally: ' + maskToken(githubToken), 'ok');
      } catch (error) {
        clearOAuthCallbackUrl();
        updateGitHubAuthUI();
        setGitHubStatus('GitHub OAuth failed: ' + (error && error.message ? error.message : 'token exchange failed'), 'error');
      }
      return;
    }
    var pending = readPendingOAuth();
    if (params.error) {
      localStorage.removeItem(STORE.oauthPending);
      clearOAuthCallbackUrl();
      setStatus('OAuth authorization failed: ' + (params.errorDescription || params.error), 'error');
      return;
    }
    if (!pending || !pending.provider || params.state !== pending.state) {
      clearOAuthCallbackUrl();
      setStatus('OAuth callback was ignored because the saved browser state did not match.', 'error');
      return;
    }
    try {
      var token = params.accessToken || await exchangeOAuthCode(pending, params.code);
      saveOAuthToken(pending.provider, token);
      localStorage.removeItem(STORE.oauthPending);
      clearOAuthCallbackUrl();
      updateProviderUI();
      setSettingsOpen(false);
      setStatus(providerConfig(pending.provider).label + ' OAuth bearer saved locally: ' + maskToken(token), 'ok');
    } catch (error) {
      clearOAuthCallbackUrl();
      setSettingsOpen(true);
      setStatus(error && error.message ? error.message : 'OAuth token exchange failed.', 'error');
      updateProviderUI();
    }
  }

  function getModel(provider) {
    provider = provider || state.provider;
    return localStorage.getItem(modelKey(provider)) || PROVIDERS[provider].defaultModel;
  }

  function maskToken(token) {
    if (!token) return 'No token saved';
    if (token.length <= 8) return 'Token saved';
    return 'Saved locally: ' + token.slice(0, 4) + '...' + token.slice(-4);
  }

  function setOAuthStatus(text, kind) {
    if (!els.oauthStatus) return;
    els.oauthStatus.textContent = text || '';
    if (kind) els.oauthStatus.setAttribute('data-kind', kind);
    else els.oauthStatus.removeAttribute('data-kind');
  }

  function setGitHubStatus(text, kind, detail) {
    if (!els.githubStatus) return;
    els.githubStatus.textContent = text || '';
    state.githubLastStatusDetail = detail || text || '';
    if (state.githubLastStatusDetail) {
      els.githubStatus.title = state.githubLastStatusDetail;
      els.githubStatus.setAttribute('aria-label', state.githubLastStatusDetail);
    } else {
      els.githubStatus.removeAttribute('title');
      els.githubStatus.removeAttribute('aria-label');
    }
    if (kind) els.githubStatus.setAttribute('data-kind', kind);
    else els.githubStatus.removeAttribute('data-kind');
  }

  function setDepsDevStatus(text, kind, detail) {
    if (!els.depsDevStatus) return;
    els.depsDevStatus.textContent = text || '';
    var statusDetail = detail || text || '';
    if (statusDetail) {
      els.depsDevStatus.title = statusDetail;
      els.depsDevStatus.setAttribute('aria-label', statusDetail);
    } else {
      els.depsDevStatus.removeAttribute('title');
      els.depsDevStatus.removeAttribute('aria-label');
    }
    if (kind) els.depsDevStatus.setAttribute('data-kind', kind);
    else els.depsDevStatus.removeAttribute('data-kind');
  }

  function setElementStatus(element, text, kind, detail) {
    if (!element) return;
    element.textContent = text || '';
    var statusDetail = detail || text || '';
    if (statusDetail) {
      element.title = statusDetail;
      element.setAttribute('aria-label', statusDetail);
    } else {
      element.removeAttribute('title');
      element.removeAttribute('aria-label');
    }
    if (kind) element.setAttribute('data-kind', kind);
    else element.removeAttribute('data-kind');
  }

  function setSarifStatus(text, kind, detail) {
    setElementStatus(els.sarifStatus, text, kind, detail);
  }

  function setSbomStatus(text, kind, detail) {
    setElementStatus(els.sbomStatus, text, kind, detail);
  }

  function cleanupLegacyGitHubAuth() {
    var legacyToken = localStorage.getItem('securityRecipes.ai.github.token');
    if (legacyToken && !getGitHubToken('pat')) localStorage.setItem(githubTokenKey('pat'), legacyToken);
    localStorage.removeItem('securityRecipes.ai.github.token');
    localStorage.removeItem('securityRecipes.ai.github.repos');
    localStorage.removeItem('securityRecipes.ai.github.selectedRepos');
  }

  function expireCookie(name) {
    document.cookie = name + '=; Path=/; Max-Age=0; SameSite=Lax';
  }

  function getCookie(name) {
    var prefix = name + '=';
    var cookies = document.cookie ? document.cookie.split('; ') : [];
    for (var i = 0; i < cookies.length; i++) {
      if (cookies[i].indexOf(prefix) === 0) {
        try {
          return decodeURIComponent(cookies[i].slice(prefix.length));
        } catch (e) {
          return '';
        }
      }
    }
    return '';
  }

  function normalizeMessages(messages) {
    if (!Array.isArray(messages)) return [];
    return messages
      .map(function (m) {
        if (!m || (m.role !== 'user' && m.role !== 'assistant')) return null;
        var content = String(m.content || '');
        if (!content.trim()) return null;
        return {
          role: m.role,
          content: content,
          error: !!m.error,
          createdAt: m.createdAt || nowIso()
        };
      })
      .filter(Boolean)
      .slice(-CHAT_HISTORY_MAX_MESSAGES);
  }

  function clearChatHistoryCookies() {
    var count = parseInt(getCookie(CHAT_HISTORY_COUNT_COOKIE), 10) || 0;
    var limit = Math.max(count, CHAT_HISTORY_MAX_CHUNKS);
    expireCookie(CHAT_HISTORY_COUNT_COOKIE);
    expireCookie(CHAT_HISTORY_COOKIE);
    for (var i = 0; i < limit; i++) {
      expireCookie(CHAT_HISTORY_COOKIE + '.' + i);
    }
  }

  function loadLegacyChatHistoryCookie() {
    try {
      var count = parseInt(getCookie(CHAT_HISTORY_COUNT_COOKIE), 10) || 0;
      var raw = '';
      if (count > 0) {
        for (var i = 0; i < count; i++) raw += getCookie(CHAT_HISTORY_COOKIE + '.' + i);
      } else {
        raw = getCookie(CHAT_HISTORY_COOKIE);
      }
      if (!raw) return [];
      return normalizeMessages(JSON.parse(raw));
    } catch (e) {
      return [];
    }
  }

  function loadChatHistoryStorage() {
    try {
      var raw = localStorage.getItem(STORE.chatHistory);
      if (raw) return normalizeMessages(JSON.parse(raw));
    } catch (e) {
      localStorage.removeItem(STORE.chatHistory);
    }

    return loadLegacyChatHistoryCookie();
  }

  function saveChatHistoryStorage() {
    var messages = normalizeMessages(state.messages);
    var raw = JSON.stringify(messages);
    while (messages.length && raw.length > CHAT_HISTORY_MAX_STORAGE_CHARS) {
      messages = messages.slice(1);
      raw = JSON.stringify(messages);
    }

    state.messages = messages;
    clearChatHistoryCookies();
    if (!messages.length) {
      localStorage.removeItem(STORE.chatHistory);
      return;
    }

    localStorage.setItem(STORE.chatHistory, raw);
  }

  function clearChatHistoryStorage() {
    localStorage.removeItem(STORE.chatHistory);
    clearChatHistoryCookies();
  }

  function providerFor(provider) {
    return PROVIDERS[provider] || PROVIDERS.openai;
  }

  function providerModelOptions(provider) {
    var cfg = providerFor(provider);
    var models = (cfg.models || []).slice();
    if (models.indexOf(cfg.defaultModel) === -1) models.unshift(cfg.defaultModel);
    return models;
  }

  function populateModelSelect(select, provider) {
    if (!select) return;
    var current = getModel(provider);
    var models = providerModelOptions(provider);
    if (current && models.indexOf(current) === -1) models.unshift(current);
    select.innerHTML = models.map(function (model) {
      return '<option value="' + html(model) + '">' + html(model) + '</option>';
    }).join('');
    select.value = current || providerFor(provider).defaultModel;
  }

  function statusLine(statusCode, statusText) {
    if (statusCode === null || typeof statusCode === 'undefined') return 'n/a (no HTTP response)';
    return String(statusCode) + (statusText ? ' ' + statusText : '');
  }

  function apiKeyStatusFor(response) {
    if (response.ok) return 'accepted';
    if (response.status === 401 || response.status === 403) return 'rejected';
    return 'not confirmed by this response';
  }

  function recordConnectivity(provider, result) {
    state.connectivity[provider] = {
      provider: provider,
      checkedAt: nowIso(),
      endpoint: result.endpoint || providerFor(provider).endpoint,
      connected: result.connected,
      apiKeyStatus: result.apiKeyStatus,
      statusCode: result.statusCode,
      statusText: result.statusText || '',
      detail: result.detail || ''
    };
    updateProviderBadge();
  }

  function providerTooltip(provider) {
    var cfg = providerFor(provider);
    var token = getToken(provider);
    var last = state.connectivity[provider];
    if (!last) {
      return cfg.label + ' connectivity: not checked yet. API key validation: ' +
        (token ? 'send a message to validate the saved token.' : 'no token saved.') +
        ' Status code: n/a.';
    }
    if (last.checking) {
      return cfg.label + ' connectivity: checking now. API key validation: pending. Status code: n/a.';
    }

    return cfg.label + ' connectivity: ' + (last.connected ? 'HTTP response received' : 'failed before HTTP response') + '. ' +
      'API key validation: ' + last.apiKeyStatus + '. ' +
      'Status code: ' + statusLine(last.statusCode, last.statusText) + '. ' +
      'Checked: ' + formatTimestamp(last.checkedAt) + '. ' +
      'Endpoint: ' + last.endpoint + (last.detail ? '. Detail: ' + last.detail : '');
  }

  function updateProviderBadge() {
    if (!els.providerBadge) return;
    var cfg = providerConfig();
    var last = state.connectivity[state.provider];
    els.providerBadge.textContent = cfg.label;
    els.providerBadge.title = providerTooltip(state.provider);
    els.providerBadge.setAttribute('aria-label', els.providerBadge.title);
    els.providerBadge.setAttribute('data-connectivity', last ? (last.checking ? 'checking' : (last.connected ? 'ok' : 'error')) : 'unknown');
  }

  function headerOffset() {
    var selectors = ['body > header', '.nav-container', '.hextra-navbar', 'nav'];
    for (var i = 0; i < selectors.length; i++) {
      var el = document.querySelector(selectors[i]);
      if (!el) continue;
      var rect = el.getBoundingClientRect();
      if (rect.width >= window.innerWidth * 0.5 && rect.height >= 40 && rect.top <= 8 && rect.bottom > 40 && rect.bottom < window.innerHeight) {
        return Math.round(rect.bottom);
      }
    }
    return 64;
  }

  function updatePanelOffset() {
    if (!els.panel) return;
    els.panel.style.setProperty('--ai-chat-top-offset', String(headerOffset()) + 'px');
  }

  function basePrefix() {
    var raw = (window.__SITE_BASE_PREFIX || '/').toString();
    if (!raw.startsWith('/')) raw = '/' + raw;
    if (!raw.endsWith('/')) raw += '/';
    return raw;
  }

  function siteHref(path) {
    return basePrefix() + String(path || '').replace(/^\/+/, '');
  }

  function isProbablyHtmlPath(pathname) {
    var last = String(pathname || '').split('/').pop() || '';
    if (!last || last.indexOf('.') === -1) return true;
    return /\.html?$/i.test(last);
  }

  function persistentNavigationUrl(link) {
    if (!link || !link.href || link.hasAttribute('download')) return null;

    var target = (link.getAttribute('target') || '').toLowerCase();
    if (target && target !== '_self') return null;

    var raw = link.getAttribute('href') || '';
    if (!raw || raw.charAt(0) === '#') return null;
    if (/^(mailto:|tel:|javascript:)/i.test(raw)) return null;

    var url;
    try {
      url = new URL(raw, window.location.href);
    } catch (error) {
      return null;
    }

    var localHost = /^(localhost|127\.0\.0\.1|\[::1\]|::1)$/.test(window.location.hostname);
    if (url.origin !== window.location.origin) {
      if (localHost && url.hostname === 'security-recipes.ai') {
        url = new URL(url.pathname + url.search + url.hash, window.location.origin);
      } else {
        return null;
      }
    }

    if (!isProbablyHtmlPath(url.pathname)) return null;
    if (url.pathname === window.location.pathname && url.search === window.location.search && url.hash) return null;

    return url;
  }

  function syncHeadForNavigation(nextDoc) {
    if (!nextDoc) return;
    document.title = nextDoc.title || document.title;

    [
      'meta[name="description"]',
      'meta[name="keywords"]',
      'meta[property="og:title"]',
      'meta[property="og:description"]',
      'meta[property="og:url"]',
      'meta[name="twitter:title"]',
      'meta[name="twitter:description"]',
      'link[rel="canonical"]'
    ].forEach(function (selector) {
      var next = nextDoc.head.querySelector(selector);
      var current = document.head.querySelector(selector);
      if (!next || !current) {
        if (next && !current) document.head.appendChild(document.importNode(next, true));
        return;
      }
      if (current.tagName.toLowerCase() === 'meta') {
        current.setAttribute('content', next.getAttribute('content') || '');
      } else {
        current.setAttribute('href', next.getAttribute('href') || '');
      }
    });
  }

  function applyDocumentAttributes(nextDoc) {
    if (!nextDoc || !nextDoc.body) return;

    document.body.className = nextDoc.body.className || '';
    Array.prototype.slice.call(document.body.attributes).forEach(function (attr) {
      if (attr.name !== 'class') document.body.removeAttribute(attr.name);
    });
    Array.prototype.slice.call(nextDoc.body.attributes).forEach(function (attr) {
      if (attr.name !== 'class') document.body.setAttribute(attr.name, attr.value);
    });

    if (nextDoc.documentElement.className) {
      document.documentElement.className = nextDoc.documentElement.className;
    }
  }

  function replaceBodyKeepingChatbot(nextDoc) {
    var keep = Array.prototype.slice.call(document.querySelectorAll('.ai-chatbot-shell, .docs-search-shell'));

    applyDocumentAttributes(nextDoc);

    Array.prototype.slice.call(document.body.childNodes).forEach(function (node) {
      if (keep.indexOf(node) === -1) node.remove();
    });

    Array.prototype.slice.call(nextDoc.body.childNodes).forEach(function (node) {
      if (node.nodeType === 1 && node.matches('script, .ai-chatbot-shell, .docs-search-shell')) return;
      document.body.appendChild(document.importNode(node, true));
    });

    keep.forEach(function (node) {
      document.body.appendChild(node);
    });
  }

  function executeInlinePageScripts(nextDoc) {
    Array.prototype.slice.call(nextDoc.body.querySelectorAll('script:not([src])')).forEach(function (oldScript) {
      var text = oldScript.textContent || '';
      if (!text.trim()) return;
      var script = document.createElement('script');
      script.text = text;
      document.body.appendChild(script);
      script.remove();
    });
  }

  function executePageEnhancementScripts(nextDoc) {
    var enhancers = ['nav-enhance', 'sidebar-collapse', 'cve-hub-collapse'];
    Array.prototype.slice.call(nextDoc.head.querySelectorAll('script[src]')).forEach(function (oldScript) {
      var src = oldScript.getAttribute('src') || '';
      if (!enhancers.some(function (name) { return src.indexOf('/js/' + name) !== -1; })) return;
      var script = document.createElement('script');
      script.src = oldScript.src;
      script.async = false;
      if (oldScript.integrity) script.integrity = oldScript.integrity;
      if (oldScript.crossOrigin) script.crossOrigin = oldScript.crossOrigin;
      document.head.appendChild(script);
      script.addEventListener('load', function () {
        script.remove();
      });
    });
  }

  function namedNavigationTarget(name) {
    if (!document.getElementsByName) return null;
    var matches = document.getElementsByName(name);
    return matches && matches.length ? matches[0] : null;
  }

  function scrollToNavigationTarget(url) {
    if (url && url.hash) {
      var id = url.hash.slice(1);
      try {
        id = decodeURIComponent(id);
      } catch (error) {
        // Keep the raw hash when decoding fails.
      }

      var target = document.getElementById(id) || namedNavigationTarget(id);
      if (target && target.scrollIntoView) {
        target.scrollIntoView({ block: 'start', behavior: 'auto' });
        return;
      }
    }

    window.scrollTo({ top: 0, left: 0, behavior: 'auto' });
  }

  async function navigateSite(url, push) {
    if (state.siteNavigating) return;
    state.siteNavigating = true;
    document.documentElement.setAttribute('data-site-navigating', 'true');
    if (els.providerBadge) els.providerBadge.setAttribute('aria-busy', 'true');

    try {
      var response = await fetch(url.toString(), {
        credentials: 'same-origin',
        headers: { 'X-SecurityRecipes-Navigation': '1' }
      });
      if (!response.ok) throw new Error('page returned ' + response.status + ' ' + (response.statusText || '').trim());

      var contentType = response.headers.get('content-type') || '';
      if (contentType && contentType.indexOf('text/html') === -1) {
        throw new Error('target did not return HTML');
      }

      var text = await response.text();
      var nextDoc = new DOMParser().parseFromString(text, 'text/html');

      syncHeadForNavigation(nextDoc);
      replaceBodyKeepingChatbot(nextDoc);
      executeInlinePageScripts(nextDoc);
      executePageEnhancementScripts(nextDoc);

      if (push) {
        history.pushState({ securityRecipesPersistentNavigation: true }, '', url.toString());
      }

      scrollToNavigationTarget(url);
      updatePanelOffset();
      updateProviderBadge();
      window.dispatchEvent(new CustomEvent('securityRecipes:pageNavigated', { detail: { url: url.toString() } }));
    } catch (error) {
      setStatus('Page navigation failed: ' + (error && error.message ? error.message : 'unknown error'), 'error');
    } finally {
      state.siteNavigating = false;
      document.documentElement.removeAttribute('data-site-navigating');
      if (els.providerBadge) els.providerBadge.removeAttribute('aria-busy');
    }
  }

  function handlePersistentNavigationClick(event) {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;

    var link = event.target && event.target.closest ? event.target.closest('a[href]') : null;
    var url = persistentNavigationUrl(link);
    if (!url) return;

    event.preventDefault();
    navigateSite(url, true);
  }

  function enablePersistentSiteNavigation() {
    if (state.persistentNavigationEnabled) return;
    state.persistentNavigationEnabled = true;

    try {
      if (!history.state || !history.state.securityRecipesPersistentNavigation) {
        history.replaceState({ securityRecipesPersistentNavigation: true }, '', window.location.href);
      }
      if ('scrollRestoration' in history) history.scrollRestoration = 'manual';
    } catch (error) {
      // Browsers can block history mutations on unusual URLs; navigation still works normally.
    }

    document.addEventListener('click', handlePersistentNavigationClick);
    window.addEventListener('popstate', function () {
      navigateSite(new URL(window.location.href), false);
    });
  }

  function indexCandidates() {
    var origin = window.location.origin;
    var prefix = basePrefix();
    return [
      new URL(prefix + 'recipes-index.json', origin).toString(),
      new URL('recipes-index.json', origin).toString()
    ];
  }

  function ensureDocsIndex() {
    if (state.docsLoading) return state.docsLoading;
    state.docsLoading = (async function () {
      var urls = indexCandidates();
      for (var i = 0; i < urls.length; i++) {
        try {
          var r = await fetch(urls[i], { credentials: 'same-origin' });
          if (!r.ok) throw new Error('index-unavailable');
          var data = await r.json();
          state.docs = Array.isArray(data) ? data : [];
          if (state.docs.length) return state.docs;
        } catch (e) {
          state.docs = [];
        }
      }
      return state.docs;
    })();
    return state.docsLoading;
  }

  function githubApiUrl(path, direct) {
    var safePath = String(path || '');
    if (!safePath.startsWith('/')) safePath = '/' + safePath;
    return direct
      ? 'https://api.github.com' + safePath
      : new URL('/github-api' + safePath, window.location.origin).toString();
  }

  function depsDevApiUrl(path) {
    var safePath = String(path || '');
    if (!safePath.startsWith('/')) safePath = '/' + safePath;
    return 'https://api.deps.dev' + safePath;
  }

  function githubHeaders() {
    var headers = {
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28'
    };
    var token = getGitHubToken();
    if (token) headers.Authorization = 'Bearer ' + token;
    return headers;
  }

  async function githubFetch(path, requestOptions) {
    requestOptions = requestOptions || {};
    var headers = Object.assign({}, githubHeaders(), requestOptions.headers || {});
    var options = {
      method: requestOptions.method || 'GET',
      credentials: 'omit',
      cache: 'no-store',
      headers: headers
    };
    if (typeof requestOptions.body !== 'undefined') options.body = requestOptions.body;
    var response;
    try {
      response = await fetch(githubApiUrl(path, false), options);
      var contentType = response.headers.get('content-type') || '';
      if (!(response.status === 404 && contentType.indexOf('text/html') !== -1)) return response;
    } catch (e) {
      response = null;
    }
    return fetch(githubApiUrl(path, true), options);
  }

  async function githubError(response) {
    var detail = response.statusText || 'GitHub request failed';
    try {
      var text = await response.text();
      var data = JSON.parse(text);
      detail = data.message || text || detail;
    } catch (e) {
      // Keep the generic status detail.
    }
    return new Error('GitHub API returned ' + statusLine(response.status, response.statusText) + ': ' + detail);
  }

  async function githubJson(path, allowMissing) {
    var response = await githubFetch(path);
    if (allowMissing && response.status === 404) return null;
    if (!response.ok) throw await githubError(response);
    return response.json();
  }

  async function githubWriteJson(path, body) {
    var response = await githubFetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {})
    });
    if (!response.ok) throw await githubError(response);
    return response.json();
  }

  async function depsDevFetch(path) {
    var options = {
      method: 'GET',
      credentials: 'omit',
      cache: 'no-store',
      headers: { 'Accept': 'application/json' }
    };
    return fetch(depsDevApiUrl(path), options);
  }

  async function depsDevJson(path, allowMissing) {
    var response = await depsDevFetch(path);
    if (allowMissing && response.status === 404) return null;
    if (!response.ok) {
      var detail = response.statusText || 'deps.dev request failed';
      try {
        var text = await response.text();
        var data = JSON.parse(text);
        detail = data.error || data.message || text || detail;
      } catch (e) {
        // Keep the generic status detail.
      }
      throw new Error('deps.dev API returned ' + statusLine(response.status, response.statusText) + ': ' + detail);
    }
    return response.json();
  }

  function parseGitHubRepository(value) {
    var raw = collapseText(value || '').replace(/^git@github\.com:/i, 'https://github.com/').replace(/\.git$/i, '');
    if (!raw) return null;
    if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(raw)) {
      var direct = raw.split('/');
      return { owner: direct[0], repo: direct[1], fullName: direct[0] + '/' + direct[1] };
    }
    try {
      var url = new URL(raw.indexOf('://') === -1 ? 'https://' + raw : raw);
      if (!/^(www\.)?github\.com$/i.test(url.hostname)) return null;
      var parts = url.pathname.split('/').filter(Boolean);
      if (parts.length < 2) return null;
      return { owner: parts[0], repo: parts[1].replace(/\.git$/i, ''), fullName: parts[0] + '/' + parts[1].replace(/\.git$/i, '') };
    } catch (e) {
      return null;
    }
  }

  function currentGitHubRepositoryInput() {
    return collapseText((els.githubRepoInput && els.githubRepoInput.value) || state.githubRepoUrl || '');
  }

  function repoApiPath(fullName) {
    var parsed = parseGitHubRepository(fullName);
    if (!parsed) return '';
    return encodeURIComponent(parsed.owner) + '/' + encodeURIComponent(parsed.repo);
  }

  function repoContentPath(fullName, filePath, ref) {
    var repo = repoApiPath(fullName);
    if (!repo) return '';
    var encodedPath = String(filePath || '').split('/').map(encodeURIComponent).join('/');
    var out = '/repos/' + repo + '/contents/' + encodedPath;
    if (ref) out += '?ref=' + encodeURIComponent(ref);
    return out;
  }

  function decodeGitHubContent(content) {
    var clean = String(content || '').replace(/\s/g, '');
    if (!clean) return '';
    var binary = window.atob(clean);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder('utf-8').decode(bytes);
  }

  function redactRepositoryContext(text) {
    return String(text || '').split('\n').map(function (line) {
      if (/-----BEGIN [A-Z ]*(PRIVATE KEY|SECRET)[A-Z ]*-----/i.test(line)) return '[redacted possible private key material]';
      if (/(authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|secret)\s*[:=]/i.test(line)) {
        return '[redacted possible secret line]';
      }
      return line;
    }).join('\n');
  }

  function normalizeGitHubRepo(repo) {
    return {
      full_name: repo.full_name || '',
      name: repo.name || '',
      owner: repo.owner && repo.owner.login ? repo.owner.login : '',
      private: !!repo.private,
      fork: !!repo.fork,
      archived: !!repo.archived,
      description: collapseText(repo.description || ''),
      language: repo.language || '',
      default_branch: repo.default_branch || 'main',
      updated_at: repo.updated_at || '',
      html_url: repo.html_url || ''
    };
  }

  function usefulRepositoryPath(path) {
    var lower = String(path || '').toLowerCase();
    if (!lower || /(^|\/)(node_modules|vendor|dist|build|target|coverage|\.git)\//.test(lower)) return false;
    if (GITHUB_MANIFEST_PATHS.map(function (p) { return p.toLowerCase(); }).indexOf(lower) !== -1) return true;
    if (/^\.github\/workflows\/[^/]+\.(ya?ml)$/.test(lower)) return true;
    if (/(^|\/)(readme|security|contributing|license|copying|notice|codeowners|agents|claude)(\.[a-z0-9_-]+)?$/.test(lower)) return true;
    return /(^|\/)(package\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb|pyproject\.toml|requirements[^/]*\.txt|poetry\.lock|go\.mod|go\.sum|pom\.xml|build\.gradle|settings\.gradle|cargo\.toml|gemfile|composer\.json|dockerfile|docker-compose\.ya?ml|compose\.ya?ml|makefile)$/.test(lower);
  }

  function repositoryFilePriority(path) {
    var lower = String(path || '').toLowerCase();
    var exact = GITHUB_MANIFEST_PATHS.map(function (p) { return p.toLowerCase(); }).indexOf(lower);
    if (exact !== -1) return exact;
    if (/(^|\/)readme(\.[a-z0-9_-]+)?$/.test(lower)) return 40;
    if (/(^|\/)(security|contributing|license|codeowners)(\.[a-z0-9_-]+)?$/.test(lower)) return 50;
    if (/^\.github\/workflows\//.test(lower) || lower === '.github/dependabot.yml') return 70;
    return 100;
  }

  async function fetchGitHubFile(fullName, filePath, ref) {
    var path = repoContentPath(fullName, filePath, ref);
    if (!path) return null;
    var data = await githubJson(path, true);
    if (!data || Array.isArray(data) || data.type !== 'file' || data.encoding !== 'base64' || !data.content) return null;
    if (data.size && data.size > 250000) return { path: filePath, text: '[skipped: file is too large for bounded browser context]' };
    var text = redactRepositoryContext(decodeGitHubContent(data.content));
    return {
      path: filePath,
      text: collapseText(text).slice(0, GITHUB_CONTEXT_MAX_FILE_CHARS)
    };
  }

  async function fetchGitHubTreeFiles(repo, ref) {
    var data = await githubJson('/repos/' + repoApiPath(repo.full_name) + '/git/trees/' + encodeURIComponent(ref) + '?recursive=1', true);
    if (!data || !Array.isArray(data.tree)) return GITHUB_MANIFEST_PATHS.slice();
    var paths = data.tree
      .filter(function (item) { return item && item.type === 'blob' && usefulRepositoryPath(item.path); })
      .sort(function (a, b) {
        var priority = repositoryFilePriority(a.path) - repositoryFilePriority(b.path);
        return priority || String(a.path).localeCompare(String(b.path));
      })
      .map(function (item) { return item.path; });
    GITHUB_MANIFEST_PATHS.forEach(function (path) {
      if (paths.indexOf(path) === -1) paths.push(path);
    });
    return paths.slice(0, GITHUB_CONTEXT_MAX_FILES);
  }

  function formatGitHubIssue(item) {
    var labels = Array.isArray(item.labels) ? item.labels.map(function (label) {
      return label && label.name ? label.name : '';
    }).filter(Boolean).join(', ') : '';
    return [
      '#' + item.number + ' ' + collapseText(item.title || ''),
      labels ? 'labels=' + labels : '',
      item.state ? 'state=' + item.state : '',
      item.html_url ? 'url=' + item.html_url : '',
      item.body ? 'body=' + collapseText(item.body).slice(0, GITHUB_CONTEXT_MAX_ITEM_CHARS) : ''
    ].filter(Boolean).join(' | ');
  }

  function depsDevSystemForPurl(type) {
    var map = {
      npm: 'NPM',
      maven: 'MAVEN',
      pypi: 'PYPI',
      cargo: 'CARGO',
      golang: 'GO',
      go: 'GO',
      gem: 'RUBYGEMS',
      rubygems: 'RUBYGEMS',
      nuget: 'NUGET'
    };
    return map[String(type || '').toLowerCase()] || '';
  }

  function parsePackageUrl(purl) {
    var raw = String(purl || '').trim();
    if (!raw || raw.indexOf('pkg:') !== 0) return null;
    var withoutPrefix = raw.slice(4).split('#')[0].split('?')[0];
    var atIndex = withoutPrefix.lastIndexOf('@');
    if (atIndex <= 0) return null;
    var namePart = withoutPrefix.slice(0, atIndex);
    var version = decodeURIComponent(withoutPrefix.slice(atIndex + 1));
    var slash = namePart.indexOf('/');
    if (slash <= 0 || !version) return null;
    var type = decodeURIComponent(namePart.slice(0, slash)).toLowerCase();
    var path = namePart.slice(slash + 1).split('/').map(decodeURIComponent);
    var system = depsDevSystemForPurl(type);
    if (!system) return null;
    var name = '';
    if (type === 'maven' && path.length >= 2) {
      name = path.slice(0, -1).join('.') + ':' + path[path.length - 1];
    } else if (type === 'golang' || type === 'go') {
      name = path.join('/');
    } else if (type === 'npm' && path.length >= 2 && path[0].charAt(0) === '@') {
      name = path[0] + '/' + path[1];
    } else {
      name = path.join('/');
    }
    if (!name) return null;
    return {
      system: system,
      name: name,
      version: version,
      purl: raw
    };
  }

  function dedupePackages(packages) {
    var seen = {};
    return packages.filter(function (pkg) {
      if (!pkg || !pkg.system || !pkg.name || !pkg.version) return false;
      var key = pkg.system + '|' + pkg.name + '|' + pkg.version;
      if (seen[key]) return false;
      seen[key] = true;
      return true;
    });
  }

  async function fetchGitHubSbomPackages(fullName) {
    var path = '/repos/' + repoApiPath(fullName) + '/dependency-graph/sbom';
    var response = await githubFetch(path);
    if (!response.ok) throw await githubError(response);
    var data = await response.json();
    var packages = data && data.sbom && Array.isArray(data.sbom.packages) ? data.sbom.packages : [];
    return dedupePackages(packages.map(function (pkg) {
      var refs = Array.isArray(pkg.externalRefs) ? pkg.externalRefs : [];
      var ref = refs.find(function (item) {
        return item && item.referenceType === 'purl' && item.referenceLocator;
      });
      return ref ? parsePackageUrl(ref.referenceLocator) : null;
    }));
  }

  function depsDevVersionPath(pkg) {
    return '/v3/systems/' + encodeURIComponent(pkg.system) +
      '/packages/' + encodeURIComponent(pkg.name) +
      '/versions/' + encodeURIComponent(pkg.version);
  }

  function depsDevAdvisoryPath(id) {
    return '/v3/advisories/' + encodeURIComponent(id);
  }

  function advisoryKeyId(key) {
    if (!key) return '';
    if (typeof key === 'string') return key;
    return key.id || key.advisoryId || key.url || '';
  }

  function advisoryAliases(advisory) {
    if (!advisory || !Array.isArray(advisory.aliases)) return '';
    return advisory.aliases.filter(Boolean).slice(0, 5).join(', ');
  }

  function advisorySeverity(advisory) {
    if (!advisory) return '';
    if (advisory.cvss3Score) return 'CVSS ' + advisory.cvss3Score;
    if (advisory.cvss4Score) return 'CVSS ' + advisory.cvss4Score;
    if (advisory.severity) return advisory.severity;
    return '';
  }

  async function fetchDepsDevVulnerabilityContext(fullName) {
    var sbomPackages = [];
    var sbomError = '';
    try {
      sbomPackages = await fetchGitHubSbomPackages(fullName);
    } catch (error) {
      sbomError = error && error.message ? error.message : 'Dependency graph SBOM request failed.';
    }

    var packages = sbomPackages.slice(0, DEPS_DEV_MAX_PACKAGES);
    var vulnerable = [];
    var checked = [];
    var advisoryIds = [];
    var advisoryDetails = {};
    var depsDevErrors = [];

    for (var i = 0; i < packages.length; i++) {
      var pkg = packages[i];
      try {
        var versionData = await depsDevJson(depsDevVersionPath(pkg), true);
        var keys = versionData && Array.isArray(versionData.advisoryKeys) ? versionData.advisoryKeys : [];
        var ids = keys.map(advisoryKeyId).filter(Boolean);
        checked.push(pkg.system + ':' + pkg.name + '@' + pkg.version);
        if (ids.length) {
          vulnerable.push({ pkg: pkg, advisoryIds: ids.slice(0, 6) });
          ids.forEach(function (id) {
            if (advisoryIds.indexOf(id) === -1 && advisoryIds.length < DEPS_DEV_MAX_ADVISORIES) advisoryIds.push(id);
          });
        }
      } catch (error) {
        if (depsDevErrors.length < 3) depsDevErrors.push(pkg.system + ':' + pkg.name + '@' + pkg.version + ' -> ' + (error && error.message ? error.message : 'deps.dev lookup failed'));
      }
    }

    for (var j = 0; j < advisoryIds.length; j++) {
      try {
        advisoryDetails[advisoryIds[j]] = await depsDevJson(depsDevAdvisoryPath(advisoryIds[j]), true);
      } catch (error) {
        advisoryDetails[advisoryIds[j]] = null;
      }
    }

    var lines = [
      'Dependency intelligence context for public GitHub repository: ' + fullName,
      'Sources: GitHub Dependency Graph SBOM when accessible; deps.dev v3 package-version advisory data.',
      'Limitations: missing SBOM, disabled dependency graph, private repos without GitHub auth, rate limits, unsupported ecosystems, and version ranges can make results partial.'
    ];

    if (sbomError) lines.push('GitHub dependency graph SBOM was unavailable: ' + sbomError);
    else lines.push('GitHub dependency graph SBOM packages returned: ' + sbomPackages.length + '. deps.dev package versions checked: ' + checked.length + '.');

    if (depsDevErrors.length) {
      lines.push('deps.dev lookup notes:');
      depsDevErrors.forEach(function (item) { lines.push('- ' + item); });
    }

    lines.push('Package versions sampled:');
    if (checked.length) checked.slice(0, 12).forEach(function (item) { lines.push('- ' + item); });
    else lines.push('- none; no package versions were available for deps.dev checks.');

    lines.push('deps.dev advisories found for sampled package versions:');
    if (vulnerable.length) {
      vulnerable.forEach(function (hit) {
        var details = hit.advisoryIds.map(function (id) {
          var detail = advisoryDetails[id];
          var title = detail && detail.title ? collapseText(detail.title) : '';
          var aliases = advisoryAliases(detail);
          var severity = advisorySeverity(detail);
          return [id, title, aliases ? 'aliases=' + aliases : '', severity].filter(Boolean).join(' | ');
        });
        lines.push('- ' + hit.pkg.system + ':' + hit.pkg.name + '@' + hit.pkg.version + ' -> ' + details.join('; '));
      });
    } else {
      lines.push('- none returned for the sampled package versions.');
    }

    return lines.join('\n').slice(0, DEPS_DEV_MAX_CONTEXT_CHARS);
  }

  async function fetchGitHubRepoContext(fullName) {
    var repo = normalizeGitHubRepo(await githubJson('/repos/' + repoApiPath(fullName), false));
    if (repo.private && !getGitHubToken()) throw new Error('Repository is private. Add a GitHub PAT or OAuth token with repo read access, then load context again.');
    var ref = repo.default_branch || 'main';
    var treePaths = await fetchGitHubTreeFiles(repo, ref);
    var files = [];
    for (var i = 0; i < treePaths.length && files.length < GITHUB_CONTEXT_MAX_FILES; i++) {
      try {
        var file = await fetchGitHubFile(repo.full_name, treePaths[i], ref);
        if (file && file.text) files.push(file);
      } catch (e) {
        // Missing or binary files are skipped; metadata, issues, and PRs still carry context.
      }
    }

    var issuesData = await githubJson('/repos/' + repoApiPath(repo.full_name) + '/issues?state=open&sort=updated&per_page=20', true);
    var issues = Array.isArray(issuesData) ? issuesData.filter(function (item) { return !item.pull_request; }).slice(0, GITHUB_CONTEXT_MAX_ISSUES) : [];
    var prsData = await githubJson('/repos/' + repoApiPath(repo.full_name) + '/pulls?state=open&sort=updated&per_page=' + GITHUB_CONTEXT_MAX_PRS, true);
    var prs = Array.isArray(prsData) ? prsData.slice(0, GITHUB_CONTEXT_MAX_PRS) : [];

    var lines = [
      (repo.private ? 'Authenticated GitHub repository: ' : 'Public GitHub repository: ') + repo.full_name,
      'Default branch: ' + ref,
      repo.language ? 'Primary language: ' + repo.language : '',
      repo.description ? 'Description: ' + repo.description : '',
      repo.html_url ? 'URL: ' + repo.html_url : '',
      repo.fork ? 'Repository note: fork' : '',
      repo.archived ? 'Repository note: archived' : ''
    ].filter(Boolean);

    lines.push('Repository files loaded for bounded remediation context:');
    if (files.length) {
      files.forEach(function (file) {
        lines.push('- ' + file.path + ': ' + file.text);
      });
    } else {
      lines.push('- none found in README/security/contributing/license/manifest/workflow candidates.');
    }

    lines.push('Recent open GitHub issues:');
    if (issues.length) issues.forEach(function (issue) { lines.push('- ' + formatGitHubIssue(issue)); });
    else lines.push('- none returned by the public issues API.');

    lines.push('Recent open GitHub pull requests:');
    if (prs.length) prs.forEach(function (pr) { lines.push('- ' + formatGitHubIssue(pr)); });
    else lines.push('- none returned by the public pull request API.');

    return {
      text: lines.join('\n').slice(0, GITHUB_CONTEXT_MAX_TOTAL_CHARS),
      fileCount: files.length,
      issueCount: issues.length,
      prCount: prs.length,
      repo: repo
    };
  }

  function updateGitHubUI() {
    if (els.includeGitHub) els.includeGitHub.checked = state.includeGitHub;
    if (els.githubRepoInput && els.githubRepoInput.value !== state.githubRepoUrl) els.githubRepoInput.value = state.githubRepoUrl;
    updateGitHubAuthUI();
    updateSettingsSummary();
    if (state.githubContextLoadedAt && state.githubContextText) {
      setGitHubStatus('GitHub context ready for ' + state.githubRepoUrl + '. Checked ' + formatTimestamp(state.githubContextLoadedAt) + '.', 'ok');
    } else if (state.githubRepoUrl) {
      setGitHubStatus('Repository set: ' + state.githubRepoUrl + '. Load context or send a message to fetch it.', '');
    } else {
      setGitHubStatus('Paste a GitHub repository URL or owner/repo. Public repos work without auth; private repos need GitHub auth.', '');
    }
  }

  function updateGitHubAuthUI() {
    var mode = githubAuthMode();
    if (els.githubAuthModeButtons) {
      Array.prototype.forEach.call(els.githubAuthModeButtons, function (button) {
        button.setAttribute('aria-pressed', button.getAttribute('data-github-auth-mode') === mode ? 'true' : 'false');
      });
    }
    if (els.githubTokenLabel) els.githubTokenLabel.textContent = 'GitHub ' + githubCredentialLabel(mode);
    if (els.githubTokenInput) els.githubTokenInput.value = '';
    if (els.githubOAuthDetails) {
      els.githubOAuthDetails.hidden = mode !== 'oauth';
      if (mode === 'oauth' && !getGitHubToken('oauth')) els.githubOAuthDetails.open = true;
    }
    if (els.githubOAuthClientId) els.githubOAuthClientId.value = getGitHubOAuthField('clientId');
    if (els.githubOAuthScope) els.githubOAuthScope.value = getGitHubOAuthField('scope');
    if (els.githubOAuthAuthUrl) els.githubOAuthAuthUrl.value = getGitHubOAuthField('authUrl');
    if (els.githubOAuthTokenUrl) els.githubOAuthTokenUrl.value = getGitHubOAuthField('tokenUrl');
  }

  function updateDepsDevUI() {
    if (els.includeDepsDev) els.includeDepsDev.checked = state.includeDepsDev;
    updateSettingsSummary();
    if (state.depsDevContextLoadedAt && state.depsDevContextText) {
      setDepsDevStatus('deps.dev dependency intelligence ready for ' + state.githubRepoUrl + '. Checked ' + formatTimestamp(state.depsDevContextLoadedAt) + '.', 'ok');
    } else if (state.includeDepsDev && state.githubRepoUrl) {
      setDepsDevStatus('deps.dev enabled. Use Check dependencies or send a message to fetch GitHub SBOM + deps.dev advisory context.', '');
    } else if (state.includeDepsDev) {
      setDepsDevStatus('deps.dev enabled. Paste a public GitHub repository URL or owner/repo first.', '');
    } else {
      setDepsDevStatus('Optional: check public GitHub Dependency Graph SBOM package versions against deps.dev advisories.', '');
    }
  }

  function importedContextSummaryLine(kind, bundle) {
    var meta = bundle && bundle.meta;
    if (!meta) return importedContextLabel(kind) + ' summary is cached locally.';
    if (kind === 'sarif') {
      return [
        meta.file_name || 'local.sarif.json',
        String(meta.finding_count || 0) + ' findings',
        meta.tool_names && meta.tool_names.length ? meta.tool_names.slice(0, 2).join(', ') : ''
      ].filter(Boolean).join(' · ');
    }
    var count = meta.component_count;
    if (typeof count !== 'number') count = meta.package_count || 0;
    return [
      meta.file_name || 'local.bom.json',
      (meta.format || 'SBOM') + (meta.spec_version ? ' ' + meta.spec_version : ''),
      String(count) + ' items'
    ].filter(Boolean).join(' · ');
  }

  function recommendedWorkflowValues(hints) {
    var out = [];
    if (hints && hints['dependency']) out.push('dependency');
    if (hints && hints['sensitive-data']) out.push('sensitive-data');
    if (hints && hints['sast']) out.push('sast');
    if (hints && hints['mcp-guardrail']) out.push('mcp-guardrail');
    return out.slice(0, 3);
  }

  function sortCountEntries(counts, limit) {
    return Object.keys(counts || {})
      .map(function (key) {
        return { key: key, count: counts[key] };
      })
      .sort(function (a, b) {
        if (b.count !== a.count) return b.count - a.count;
        return a.key < b.key ? -1 : (a.key > b.key ? 1 : 0);
      })
      .slice(0, limit || SARIF_TOP_ITEMS);
  }

  function severityCountText(counts) {
    var order = ['critical', 'high', 'medium', 'low', 'info'];
    return order
      .filter(function (key) { return counts && counts[key]; })
      .map(function (key) { return key + ' ' + counts[key]; })
      .join(', ') || 'none';
  }

  function sarifNumericSeverity(result) {
    var props = result && result.properties;
    var raw = props && (
      props['security-severity'] ||
      props.securitySeverity ||
      props['security_severity']
    );
    if (raw === null || raw === undefined || raw === '') return null;
    var value = Number(raw);
    return isFinite(value) ? value : null;
  }

  function normalizeSarifSeverity(result) {
    var numeric = sarifNumericSeverity(result);
    if (numeric !== null) {
      if (numeric >= 9) return 'critical';
      if (numeric >= 7) return 'high';
      if (numeric >= 4) return 'medium';
      if (numeric > 0) return 'low';
    }
    var level = collapseText(result && result.level).toLowerCase();
    if (level === 'error') return 'high';
    if (level === 'warning') return 'medium';
    if (level === 'note') return 'low';
    return 'info';
  }

  function sarifResultMessage(result) {
    if (!result || !result.message) return '';
    return collapseText(result.message.text || result.message.markdown || '').slice(0, 260);
  }

  function sarifResultLocation(result) {
    var locations = result && Array.isArray(result.locations) ? result.locations : [];
    var physical = locations.length ? locations[0].physicalLocation : null;
    var artifact = physical && physical.artifactLocation ? physical.artifactLocation : null;
    var region = physical && physical.region ? physical.region : null;
    return {
      file: collapseText(artifact && (artifact.uri || artifact.uriBaseId) || '').slice(0, 180),
      line: region && (region.startLine || region.endLine) ? String(region.startLine || region.endLine) : ''
    };
  }

  function summarizeSarifDocument(doc, fileName) {
    var runs = doc && Array.isArray(doc.runs) ? doc.runs : [];
    if (!runs.length) throw new Error('SARIF upload must include runs[].');

    var toolNames = {};
    var severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    var ruleCounts = {};
    var fileCounts = {};
    var sampleFindings = [];
    var workflowHints = {};
    var totalResults = 0;

    runs.forEach(function (run) {
      var tool = run && run.tool && run.tool.driver ? run.tool.driver : {};
      var toolName = collapseText(tool.name || tool.fullName || 'Unknown tool');
      if (toolName) toolNames[toolName] = true;
      var results = Array.isArray(run && run.results) ? run.results : [];
      totalResults += results.length;
      results.forEach(function (result) {
        var severity = normalizeSarifSeverity(result);
        severityCounts[severity] += 1;

        var ruleId = collapseText(result && (result.ruleId || (result.rule && result.rule.id) || 'unmapped-rule')).slice(0, 120) || 'unmapped-rule';
        ruleCounts[ruleId] = (ruleCounts[ruleId] || 0) + 1;

        var location = sarifResultLocation(result);
        if (location.file) fileCounts[location.file] = (fileCounts[location.file] || 0) + 1;

        if (sampleFindings.length < SARIF_SAMPLE_FINDINGS) {
          sampleFindings.push({
            severity: severity,
            rule_id: ruleId,
            message: sarifResultMessage(result) || 'No message provided.',
            file: location.file,
            line: location.line
          });
        }

        var hintText = (ruleId + ' ' + (sarifResultMessage(result) || '')).toLowerCase();
        if (/secret|password|token|credential|api[-_ ]?key|private[-_ ]?key|hardcod/i.test(hintText)) {
          workflowHints['sensitive-data'] = true;
        } else if (/depend|package|library|module|artifact|container|sbom|cve|vuln/i.test(hintText)) {
          workflowHints['dependency'] = true;
        } else {
          workflowHints['sast'] = true;
        }
      });
    });

    var topRules = sortCountEntries(ruleCounts, SARIF_TOP_ITEMS);
    var topFiles = sortCountEntries(fileCounts, SARIF_TOP_ITEMS);
    var tools = Object.keys(toolNames);
    var recommended = recommendedWorkflowValues(workflowHints);
    if (!recommended.length) recommended = ['sast'];

    var meta = {
      type: 'sarif',
      format: 'SARIF',
      file_name: fileName || 'local.sarif.json',
      version: collapseText(doc && doc.version || ''),
      run_count: runs.length,
      finding_count: totalResults,
      tool_names: tools,
      severity_counts: severityCounts,
      top_rules: topRules.map(function (entry) {
        return { rule_id: entry.key, finding_count: entry.count };
      }),
      top_files: topFiles.map(function (entry) {
        return { path: entry.key, finding_count: entry.count };
      }),
      sample_findings: sampleFindings,
      recommended_workflows: recommended
    };

    var lines = [
      'Local SARIF upload: ' + meta.file_name,
      'Format: SARIF' + (meta.version ? ' ' + meta.version : '') + '. Runs: ' + runs.length + '. Findings: ' + totalResults + '.',
      tools.length ? 'Scanner tools: ' + tools.join(', ') + '.' : 'Scanner tools: unknown.',
      'Severity counts: ' + severityCountText(severityCounts) + '.',
      'Recommended workflows: ' + recommended.join(', ') + '.'
    ];

    if (topRules.length) {
      lines.push('Top rules:');
      topRules.forEach(function (entry) {
        lines.push('- ' + entry.key + ': ' + entry.count);
      });
    }

    if (topFiles.length) {
      lines.push('Most affected files:');
      topFiles.forEach(function (entry) {
        lines.push('- ' + entry.key + ': ' + entry.count);
      });
    }

    if (sampleFindings.length) {
      lines.push('Sample findings:');
      sampleFindings.forEach(function (finding) {
        var location = finding.file ? ' @ ' + finding.file + (finding.line ? ':' + finding.line : '') : '';
        lines.push('- [' + finding.severity + '] ' + finding.rule_id + location + ' -> ' + finding.message);
      });
    }

    return {
      meta: meta,
      text: lines.join('\n').slice(0, IMPORTED_CONTEXT_MAX_CHARS),
      loadedAt: nowIso()
    };
  }

  function purlEcosystem(value) {
    var match = /^pkg:([^\/@?#]+)/i.exec(String(value || '').trim());
    return match ? match[1].toLowerCase() : '';
  }

  function recordEcosystem(counts, value) {
    var key = collapseText(value || '').toLowerCase() || 'unknown';
    counts[key] = (counts[key] || 0) + 1;
  }

  function summarizeCycloneDxDocument(doc, fileName) {
    var metadataComponent = doc && doc.metadata && doc.metadata.component ? doc.metadata.component : null;
    var components = Array.isArray(doc && doc.components) ? doc.components : [];
    var services = Array.isArray(doc && doc.services) ? doc.services : [];
    var dependencies = Array.isArray(doc && doc.dependencies) ? doc.dependencies : [];
    var vulnerabilities = Array.isArray(doc && doc.vulnerabilities) ? doc.vulnerabilities : [];
    var sampleComponents = [];
    var ecosystemCounts = {};

    if (metadataComponent) {
      recordEcosystem(ecosystemCounts, purlEcosystem(metadataComponent.purl) || metadataComponent.type || 'application');
      sampleComponents.push({
        name: collapseText(metadataComponent.name || metadataComponent['bom-ref'] || 'Application').slice(0, 120),
        version: collapseText(metadataComponent.version || '').slice(0, 80),
        type: collapseText(metadataComponent.type || 'application').slice(0, 80),
        purl: collapseText(metadataComponent.purl || '').slice(0, 160)
      });
    }

    components.forEach(function (component) {
      recordEcosystem(ecosystemCounts, purlEcosystem(component && component.purl) || (component && component.type) || 'unknown');
      if (sampleComponents.length < SBOM_SAMPLE_COMPONENTS) {
        sampleComponents.push({
          name: collapseText(component && (component.name || component['bom-ref']) || 'Unnamed component').slice(0, 120),
          version: collapseText(component && component.version || '').slice(0, 80),
          type: collapseText(component && component.type || '').slice(0, 80),
          purl: collapseText(component && component.purl || '').slice(0, 160)
        });
      }
    });

    var ecosystems = sortCountEntries(ecosystemCounts, SBOM_TOP_ITEMS).map(function (entry) {
      return { ecosystem: entry.key, count: entry.count };
    });
    var vulnerabilityIds = vulnerabilities
      .map(function (item) {
        return collapseText(item && (item.id || item.bomRef || item['bom-ref']) || '').slice(0, 120);
      })
      .filter(Boolean)
      .slice(0, SBOM_TOP_ITEMS);

    var meta = {
      type: 'sbom',
      format: 'CycloneDX',
      spec_version: collapseText(doc && doc.specVersion || ''),
      file_name: fileName || 'local.cdx.json',
      component_count: components.length + (metadataComponent ? 1 : 0),
      service_count: services.length,
      dependency_count: dependencies.length,
      vulnerability_count: vulnerabilities.length,
      ecosystems: ecosystems,
      sample_components: sampleComponents,
      vulnerability_ids: vulnerabilityIds,
      recommended_workflows: ['dependency']
    };

    var lines = [
      'Local SBOM upload: ' + meta.file_name,
      'Format: CycloneDX' + (meta.spec_version ? ' ' + meta.spec_version : '') + '. Components: ' + meta.component_count + '. Services: ' + services.length + '. Dependencies: ' + dependencies.length + '.',
      'Documented vulnerabilities: ' + vulnerabilities.length + '.',
      'Recommended workflows: dependency.'
    ];

    if (ecosystems.length) {
      lines.push('Ecosystems:');
      ecosystems.forEach(function (entry) {
        lines.push('- ' + entry.ecosystem + ': ' + entry.count);
      });
    }

    if (sampleComponents.length) {
      lines.push('Sample components:');
      sampleComponents.forEach(function (component) {
        var detail = [component.type, component.version].filter(Boolean).join(' ');
        lines.push('- ' + component.name + (detail ? ' (' + detail + ')' : '') + (component.purl ? ' ' + component.purl : ''));
      });
    }

    if (vulnerabilityIds.length) {
      lines.push('Sample vulnerability identifiers:');
      vulnerabilityIds.forEach(function (id) {
        lines.push('- ' + id);
      });
    }

    return {
      meta: meta,
      text: lines.join('\n').slice(0, IMPORTED_CONTEXT_MAX_CHARS),
      loadedAt: nowIso()
    };
  }

  function spdxExternalRefs(pkg) {
    return Array.isArray(pkg && pkg.externalRefs) ? pkg.externalRefs : [];
  }

  function spdxPackagePurl(pkg) {
    var refs = spdxExternalRefs(pkg);
    for (var i = 0; i < refs.length; i += 1) {
      var type = collapseText(refs[i] && (refs[i].referenceType || refs[i].referenceLocatorType || '')).toLowerCase();
      if (type === 'purl') return collapseText(refs[i].referenceLocator || '').slice(0, 160);
    }
    return '';
  }

  function spdxSecurityReferenceCount(pkg) {
    return spdxExternalRefs(pkg).filter(function (ref) {
      return collapseText(ref && ref.referenceCategory || '').toLowerCase() === 'security';
    }).length;
  }

  function summarizeSpdxDocument(doc, fileName) {
    var packages = Array.isArray(doc && doc.packages) ? doc.packages : [];
    var relationships = Array.isArray(doc && doc.relationships) ? doc.relationships : [];
    var files = Array.isArray(doc && doc.files) ? doc.files : [];
    var samplePackages = [];
    var ecosystemCounts = {};
    var securityReferenceCount = 0;

    packages.forEach(function (pkg) {
      var purl = spdxPackagePurl(pkg);
      recordEcosystem(ecosystemCounts, purlEcosystem(purl) || (pkg && pkg.primaryPackagePurpose) || 'unknown');
      securityReferenceCount += spdxSecurityReferenceCount(pkg);
      if (samplePackages.length < SBOM_SAMPLE_COMPONENTS) {
        samplePackages.push({
          name: collapseText(pkg && pkg.name || 'Unnamed package').slice(0, 120),
          version: collapseText(pkg && pkg.versionInfo || '').slice(0, 80),
          purpose: collapseText(pkg && pkg.primaryPackagePurpose || '').slice(0, 80),
          purl: purl
        });
      }
    });

    var ecosystems = sortCountEntries(ecosystemCounts, SBOM_TOP_ITEMS).map(function (entry) {
      return { ecosystem: entry.key, count: entry.count };
    });
    var meta = {
      type: 'sbom',
      format: 'SPDX',
      spec_version: collapseText(doc && doc.spdxVersion || ''),
      file_name: fileName || 'local.spdx.json',
      package_count: packages.length,
      relationship_count: relationships.length,
      file_count: files.length,
      ecosystems: ecosystems,
      sample_components: samplePackages,
      security_reference_count: securityReferenceCount,
      recommended_workflows: ['dependency']
    };

    var lines = [
      'Local SBOM upload: ' + meta.file_name,
      'Format: SPDX' + (meta.spec_version ? ' ' + meta.spec_version : '') + '. Packages: ' + packages.length + '. Relationships: ' + relationships.length + '. Files: ' + files.length + '.',
      'Package security references: ' + securityReferenceCount + '.',
      'Recommended workflows: dependency.'
    ];

    if (ecosystems.length) {
      lines.push('Ecosystems:');
      ecosystems.forEach(function (entry) {
        lines.push('- ' + entry.ecosystem + ': ' + entry.count);
      });
    }

    if (samplePackages.length) {
      lines.push('Sample packages:');
      samplePackages.forEach(function (pkg) {
        var detail = [pkg.purpose, pkg.version].filter(Boolean).join(' ');
        lines.push('- ' + pkg.name + (detail ? ' (' + detail + ')' : '') + (pkg.purl ? ' ' + pkg.purl : ''));
      });
    }

    return {
      meta: meta,
      text: lines.join('\n').slice(0, IMPORTED_CONTEXT_MAX_CHARS),
      loadedAt: nowIso()
    };
  }

  function summarizeSbomDocument(doc, fileName) {
    if (doc && String(doc.bomFormat || '').toLowerCase() === 'cyclonedx') {
      return summarizeCycloneDxDocument(doc, fileName);
    }
    if (doc && (doc.spdxVersion || doc.SPDXID || Array.isArray(doc.packages))) {
      return summarizeSpdxDocument(doc, fileName);
    }
    throw new Error('SBOM upload must be CycloneDX JSON or SPDX JSON.');
  }

  async function handleImportedContextUpload(kind, file) {
    if (!file) return;
    var label = importedContextLabel(kind);
    try {
      if (kind === 'sarif') setSarifStatus('Parsing ' + file.name + ' locally...', '');
      else setSbomStatus('Parsing ' + file.name + ' locally...', '');
      var raw = await file.text();
      var parsed = JSON.parse(raw);
      var summary = kind === 'sarif'
        ? summarizeSarifDocument(parsed, file.name)
        : summarizeSbomDocument(parsed, file.name);
      setImportedContextBundle(kind, summary);
      state[importedContextStateMap(kind).include] = true;
      localStorage.setItem(importedContextToggleStoreKey(kind), 'true');
      updateImportedContextUI(kind);
      syncAgentInputSelectionsFromToggles();
      updateAgentMarketplacePreview();
      if (els.agentStatus && !state.agentRunning) {
        els.agentStatus.textContent = label + ' context imported locally. Include it in a chat prompt or agent run when needed.';
        els.agentStatus.setAttribute('data-kind', 'ok');
      }
    } catch (error) {
      var detail = error && error.message ? error.message : 'JSON parsing failed.';
      if (kind === 'sarif') setSarifStatus('SARIF upload failed. Hover for details.', 'error', detail);
      else setSbomStatus('SBOM upload failed. Hover for details.', 'error', detail);
    } finally {
      updateSettingsSummary();
    }
  }

  function clearImportedContext(kind) {
    var map = importedContextStateMap(kind);
    setImportedContextBundle(kind, null);
    state[map.include] = false;
    localStorage.removeItem(importedContextToggleStoreKey(kind));
    if (kind === 'sarif' && els.sarifFileInput) els.sarifFileInput.value = '';
    if (kind === 'sbom' && els.sbomFileInput) els.sbomFileInput.value = '';
    updateImportedContextUI(kind);
    syncAgentInputSelectionsFromToggles();
    updateAgentMarketplacePreview();
  }

  function updateImportedContextUI(kind) {
    var bundle = importedContextBundle(kind);
    var label = importedContextLabel(kind);
    if (kind === 'sarif' && els.includeSarif) els.includeSarif.checked = bundle.enabled;
    if (kind === 'sbom' && els.includeSbom) els.includeSbom.checked = bundle.enabled;
    updateSettingsSummary();

    if (bundle.meta && bundle.loadedAt) {
      var prefix = bundle.enabled ? (label + ' ready: ') : (label + ' cached locally: ');
      var suffix = bundle.enabled
        ? ' Included in prompts when the channel is selected.'
        : ' Toggle it on to include it in prompts.';
      if (kind === 'sarif') setSarifStatus(prefix + importedContextSummaryLine(kind, bundle) + '.' + suffix, bundle.enabled ? 'ok' : '');
      else setSbomStatus(prefix + importedContextSummaryLine(kind, bundle) + '.' + suffix, bundle.enabled ? 'ok' : '');
      return;
    }

    if (bundle.enabled) {
      if (kind === 'sarif') setSarifStatus('SARIF enabled. Upload a local SARIF 2.1.0 JSON file to attach scanner findings.', '');
      else setSbomStatus('SBOM enabled. Upload a local CycloneDX or SPDX JSON file to attach package inventory context.', '');
      return;
    }

    if (kind === 'sarif') setSarifStatus('Optional: upload a local SARIF 2.1.0 JSON file for SAST, SCA, secrets, or IaC findings.', '');
    else setSbomStatus('Optional: upload a local CycloneDX or SPDX JSON SBOM for package, dependency, and vulnerability context.', '');
  }

  async function prepareGitHubContext() {
    state.githubContextText = '';
    state.githubContextLoadedAt = '';
    if (!state.includeGitHub) return '';

    var parsed = parseGitHubRepository(currentGitHubRepositoryInput());
    if (!parsed) {
      state.githubContextText = 'Public GitHub repository context requested, but no valid public repository URL or owner/repo was provided.';
      setGitHubStatus('Enter a public GitHub repository, for example owner/repo.', 'error');
      return state.githubContextText;
    }

    state.githubRepoUrl = parsed.fullName;
    localStorage.setItem(STORE.githubRepoUrl, state.githubRepoUrl);
    if (els.githubRepoInput) els.githubRepoInput.value = state.githubRepoUrl;

    setGitHubStatus('Loading GitHub context for ' + state.githubRepoUrl + '...', '');
    try {
      var result = await fetchGitHubRepoContext(state.githubRepoUrl);
      state.githubContextLoadedAt = nowIso();
      state.githubContextText = result.text;
      setGitHubStatus('GitHub context ready: ' + result.repo.full_name + ' with ' + result.fileCount + ' files, ' + result.issueCount + ' issues, and ' + result.prCount + ' PRs.', 'ok');
      updateGitHubUI();
    } catch (error) {
      var detail = error && error.message ? error.message : 'unknown GitHub API error';
      state.githubContextText = 'GitHub repository context requested, but loading failed: ' + detail;
      setGitHubStatus('GitHub context failed to load. Hover for details.', 'error', detail);
    }
    updateSettingsSummary();
    return state.githubContextText;
  }

  async function prepareDepsDevContext() {
    state.depsDevContextText = '';
    state.depsDevContextLoadedAt = '';
    if (!state.includeDepsDev) return '';

    var parsed = parseGitHubRepository(currentGitHubRepositoryInput());
    if (!parsed) {
      state.depsDevContextText = 'deps.dev dependency intelligence requested, but no valid public GitHub repository URL or owner/repo was provided.';
      setDepsDevStatus('Enter a public GitHub repository before checking deps.dev.', 'error');
      return state.depsDevContextText;
    }

    state.githubRepoUrl = parsed.fullName;
    localStorage.setItem(STORE.githubRepoUrl, state.githubRepoUrl);
    if (els.githubRepoInput) els.githubRepoInput.value = state.githubRepoUrl;

    setDepsDevStatus('Checking GitHub Dependency Graph SBOM and deps.dev for ' + state.githubRepoUrl + '...', '');
    try {
      state.depsDevContextText = await fetchDepsDevVulnerabilityContext(state.githubRepoUrl);
      state.depsDevContextLoadedAt = nowIso();
      setDepsDevStatus('deps.dev dependency intelligence ready for ' + state.githubRepoUrl + '.', 'ok');
      updateDepsDevUI();
    } catch (error) {
      var detail = error && error.message ? error.message : 'unknown deps.dev error';
      state.depsDevContextText = 'deps.dev dependency intelligence requested, but loading failed: ' + detail;
      setDepsDevStatus('deps.dev dependency check failed. Hover for details.', 'error', detail);
    }
    updateSettingsSummary();
    return state.depsDevContextText;
  }

  function nodeTextWithoutChrome(node, limit) {
    var clone = node.cloneNode(true);
    var remove = clone.querySelectorAll('script, style, noscript, svg, nav, footer, .ai-chatbot-shell, .docs-search-shell');
    Array.prototype.forEach.call(remove, function (n) { n.remove(); });
    return collapseText(clone.textContent).slice(0, limit || 4200);
  }

  function querySnippetsFromPage(root, query) {
    var terms = termsFor(query);
    if (!terms.length) return [];
    var seen = {};
    var selectors = [
      'article',
      'section',
      'li',
      'tr',
      'a',
      'p',
      'h1',
      'h2',
      'h3',
      'h4',
      '[class*="card"]',
      '[class*="recipe"]'
    ].join(',');

    return Array.prototype.slice.call(root.querySelectorAll(selectors))
      .filter(function (node) {
        return !node.closest('.ai-chatbot-shell, .docs-search-shell, nav, footer, script, style, noscript');
      })
      .map(function (node) {
        var text = nodeTextWithoutChrome(node, 900);
        var lower = text.toLowerCase();
        var score = 0;
        terms.forEach(function (term) {
          var idx = lower.indexOf(term);
          if (idx !== -1) {
            score += node.matches('h1,h2,h3,h4') ? 12 : 5;
            if (idx < 90) score += 3;
          }
        });
        if (!score || text.length < 12 || seen[text]) return null;
        seen[text] = true;
        return { text: text, score: score };
      })
      .filter(Boolean)
      .sort(function (a, b) { return b.score - a.score; })
      .slice(0, 8)
      .map(function (item) { return item.text; });
  }

  function currentPageContext(query) {
    var root = document.querySelector('main, article, .hextra-content') || document.body;
    var headings = Array.prototype.slice.call(document.querySelectorAll('h1, h2, h3'))
      .filter(function (h) { return !h.closest('.ai-chatbot-shell'); })
      .map(function (h) { return collapseText(h.textContent); })
      .filter(Boolean)
      .slice(0, 12);
    var description = '';
    var meta = document.querySelector('meta[name="description"]');
    if (meta) description = meta.getAttribute('content') || '';
    return {
      title: document.title || 'SecurityRecipes',
      path: window.location.pathname,
      description: collapseText(description),
      headings: headings,
      text: nodeTextWithoutChrome(root),
      matches: querySnippetsFromPage(root, query)
    };
  }

  function termsFor(query) {
    var stop = {
      the: true, and: true, for: true, with: true, from: true, this: true,
      that: true, into: true, what: true, when: true, where: true, which: true,
      your: true, about: true, please: true, security: false, remediation: false
    };
    return String(query || '')
      .toLowerCase()
      .replace(/[^a-z0-9\- ]+/g, ' ')
      .split(/\s+/)
      .filter(function (t) { return t.length > 2 && stop[t] !== true; })
      .slice(0, 18);
  }

  function scoreDoc(doc, terms) {
    var hay = [
      doc.title || '',
      doc.section || '',
      doc.agent || '',
      (doc.tags || []).join(' '),
      doc.summary || '',
      doc.content || ''
    ].join(' ').toLowerCase();
    var title = String(doc.title || '').toLowerCase();
    var score = 0;
    terms.forEach(function (term) {
      if (title.indexOf(term) !== -1) score += 9;
      if (hay.indexOf(term) !== -1) score += 3;
    });
    if (String(doc.section || '').toLowerCase().indexOf('security-remediation') !== -1) score += 3;
    if (String(doc.section || '').toLowerCase().indexOf('prompt-library') !== -1) score += 2;
    return score;
  }

  function relevantDocs(query) {
    if (!state.docs.length) return [];
    var terms = termsFor(query);
    if (!terms.length) terms = ['remediation', 'security', 'agent'];
    return state.docs
      .map(function (doc) {
        var out = {};
        for (var k in doc) out[k] = doc[k];
        out._score = scoreDoc(doc, terms);
        return out;
      })
      .filter(function (doc) { return doc._score > 0; })
      .sort(function (a, b) { return b._score - a._score; })
      .slice(0, 5);
  }

  function searchDocs(query) {
    if (!state.docs.length) return [];
    var terms = termsFor(query);
    if (!terms.length) return [];
    return state.docs
      .map(function (doc) {
        var out = {};
        for (var k in doc) out[k] = doc[k];
        out._score = scoreDoc(doc, terms);
        return out;
      })
      .filter(function (doc) { return doc._score > 0; })
      .sort(function (a, b) { return b._score - a._score; })
      .slice(0, 8);
  }

  function recipeDocs() {
    return state.docs
      .filter(function (doc) {
        var section = String(doc.section || '').toLowerCase();
        var path = String(doc.path || '').toLowerCase();
        return section.indexOf('prompt-library') !== -1 ||
          section.indexOf('security-remediation') !== -1 ||
          path.indexOf('/prompt-library/') !== -1 ||
          path.indexOf('/security-remediation/') !== -1;
      })
      .sort(function (a, b) {
        return String(a.title || '').localeCompare(String(b.title || ''));
      });
  }

  function recipeLabel(doc) {
    if (!doc) return '';
    var title = collapseText(doc.title || 'Untitled recipe');
    var section = collapseText(doc.section || '');
    return section ? title + ' - ' + section : title;
  }

  function findRecipeByPath(path) {
    if (!path) return null;
    return state.docs.find(function (doc) {
      return doc && (doc.path === path || doc.url === path);
    }) || null;
  }

  function selectedRecipe() {
    var byPath = findRecipeByPath(state.agentRecipePath);
    if (byPath) return byPath;
    var typed = collapseText(els.agentRecipeInput && els.agentRecipeInput.value);
    if (!typed) return null;
    var typedLower = typed.toLowerCase();
    var exact = recipeDocs().find(function (doc) {
      return recipeLabel(doc).toLowerCase() === typedLower || String(doc.title || '').toLowerCase() === typedLower;
    });
    if (exact) return exact;
    return matchAgentRecipes(typed)[0] || null;
  }

  function matchAgentRecipes(query) {
    var docs = recipeDocs();
    var terms = termsFor(query);
    if (!terms.length) return docs.slice(0, 8);
    return docs
      .map(function (doc) {
        var out = {};
        for (var k in doc) out[k] = doc[k];
        out._score = scoreDoc(doc, terms);
        return out;
      })
      .filter(function (doc) { return doc._score > 0; })
      .sort(function (a, b) { return b._score - a._score; })
      .slice(0, 8);
  }

  function buildSystemPrompt(query) {
    var page = currentPageContext(query);
    var parts = [
      'You are the SecurityRecipes AI remediation assistant.',
      'Focus on security engineering, vulnerability remediation, secure agent operation, MCP context boundaries, reviewer-gated fixes, and practical runbooks.',
      'Do not ask for, reveal, transform, or validate API tokens or secrets. If code or logs may contain secrets, recommend quarantine and rotation steps.',
      'Prefer bounded remediation plans with evidence, rollback, review gates, and clean stop conditions. Avoid destructive changes unless the user explicitly asks for them.',
      'When using site context, cite page titles or paths from the provided context instead of inventing sources.'
    ];

    if (state.includeContext) {
      parts.push('Current page title: ' + page.title);
      parts.push('Current page path: ' + page.path);
      if (page.description) parts.push('Current page description: ' + page.description);
      if (page.headings.length) parts.push('Current page headings: ' + page.headings.join(' | '));
      if (page.text) parts.push('Current page excerpt: ' + page.text);
      if (page.matches.length) {
        parts.push('Current page query-matching excerpts. Treat these as high-confidence evidence from the visible/current page:');
        page.matches.forEach(function (snippet, i) {
          parts.push(String(i + 1) + '. ' + snippet);
        });
      }
    }

    if (state.includeRelated) {
      var docs = relevantDocs(query);
      if (docs.length) {
        parts.push('Relevant SecurityRecipes index entries:');
        docs.forEach(function (doc, i) {
          parts.push([
            String(i + 1) + '. ' + (doc.title || 'Untitled'),
            'path=' + (doc.path || doc.url || ''),
            'section=' + (doc.section || 'page'),
            'tags=' + ((doc.tags || []).join(', ') || 'none'),
            'summary=' + collapseText(doc.summary || '').slice(0, 420)
          ].join(' | '));
        });
      }
    }

    if (state.includeGitHub) {
      parts.push('GitHub repository context is enabled. Use it only as bounded repository context from GitHub API data. Call out when repository context is missing, partial, unauthenticated, auth-limited, or rate-limited.');
      if (state.githubContextLoadedAt) parts.push('GitHub context checked: ' + formatTimestamp(state.githubContextLoadedAt));
      parts.push(state.githubContextText || 'GitHub repository context enabled but no repository context was loaded.');
    }

    if (state.includeDepsDev) {
      parts.push('deps.dev dependency intelligence is enabled. Treat it as evidence from GitHub Dependency Graph SBOM package URLs and deps.dev v3 package-version advisory data. Call out missing SBOM data, unsupported package ecosystems, version-range limitations, auth limits, rate limits, and partial sampled checks.');
      if (state.depsDevContextLoadedAt) parts.push('deps.dev dependency intelligence checked: ' + formatTimestamp(state.depsDevContextLoadedAt));
      parts.push(state.depsDevContextText || 'deps.dev dependency intelligence enabled but no dependency context was loaded.');
    }

    if (state.includeSarif) {
      parts.push('Local SARIF scanner evidence is enabled. Treat it as a bounded browser-local summary of a user-supplied SARIF 2.1.0 upload. Call out when the upload is missing, partial, or insufficient to prove exploitability or remediation priority.');
      if (state.sarifContextLoadedAt) parts.push('SARIF context imported: ' + formatTimestamp(state.sarifContextLoadedAt));
      parts.push(state.sarifContextText || 'SARIF upload is enabled but no local SARIF summary has been imported.');
    }

    if (state.includeSbom) {
      parts.push('Local SBOM evidence is enabled. Treat it as a bounded browser-local summary of a user-supplied CycloneDX or SPDX JSON upload. Call out when package, dependency, or vulnerability coverage is incomplete.');
      if (state.sbomContextLoadedAt) parts.push('SBOM context imported: ' + formatTimestamp(state.sbomContextLoadedAt));
      parts.push(state.sbomContextText || 'SBOM upload is enabled but no local SBOM summary has been imported.');
    }

    return parts.join('\n');
  }

  function apiHistory() {
    return state.messages
      .filter(function (m) { return !m.error; })
      .slice(-10)
      .map(function (m) {
        return {
          role: m.role === 'assistant' ? 'assistant' : 'user',
          content: m.content
        };
      });
  }

  function transcript(history) {
    return history.map(function (m) {
      return (m.role === 'assistant' ? 'Assistant' : 'User') + ': ' + m.content;
    }).join('\n\n');
  }

  async function responseError(response, provider, endpoint) {
    var detail = '';
    try {
      var text = await response.text();
      var data = JSON.parse(text);
      detail = data.error && (data.error.message || data.error.type) ? (data.error.message || data.error.type) : text;
    } catch (e) {
      detail = response.statusText || 'Request failed';
    }
    recordConnectivity(provider, {
      endpoint: endpoint || providerEndpoint(provider),
      connected: true,
      apiKeyStatus: apiKeyStatusFor(response),
      statusCode: response.status,
      statusText: response.statusText,
      detail: detail
    });
    if ((response.status === 404 || response.status === 405) && endpoint && endpoint.indexOf('/ai-provider-proxy/') !== -1) {
      return new Error(PROVIDERS[provider].label + ' relay is not available at ' + endpoint + '. Status code: ' + statusLine(response.status, response.statusText) + '. The Docker/nginx runtime must expose the same-origin AI provider relay.');
    }
    return new Error(PROVIDERS[provider].label + ' API returned status ' + statusLine(response.status, response.statusText) + ': ' + detail);
  }

  async function providerFetch(provider, endpoint, options) {
    try {
      var response = await fetch(endpoint, options);
      recordConnectivity(provider, {
        endpoint: endpoint,
        connected: true,
        apiKeyStatus: apiKeyStatusFor(response),
        statusCode: response.status,
        statusText: response.statusText
      });
      return response;
    } catch (error) {
      var browserMessage = error && error.message ? error.message : 'Fetch failed before an HTTP response was returned.';
      var providerName = PROVIDERS[provider].label;
      var causes = [
        'browser CORS or direct-browser API restrictions',
        'a blocked request from a privacy/ad-blocking extension',
        'network/DNS/TLS connectivity',
        'a provider outage or endpoint mismatch'
      ].join(', ');
      recordConnectivity(provider, {
        endpoint: endpoint,
        connected: false,
        apiKeyStatus: 'not validated',
        statusCode: null,
        statusText: '',
        detail: browserMessage
      });
      throw new Error(
        providerName + ' request could not reach ' + endpoint + '. ' +
        'Status code: n/a (no HTTP response). ' +
        'Browser fetch reported: ' + browserMessage + '. ' +
        'Likely causes: ' + causes + '.'
      );
    }
  }

  function extractOpenAI(data) {
    if (data && typeof data.output_text === 'string' && data.output_text.trim()) return data.output_text.trim();
    var chunks = [];
    if (data && Array.isArray(data.output)) {
      data.output.forEach(function (item) {
        if (Array.isArray(item.content)) {
          item.content.forEach(function (part) {
            if (part && typeof part.text === 'string') chunks.push(part.text);
          });
        }
      });
    }
    return chunks.join('\n').trim() || 'The OpenAI response did not include text output.';
  }

  function extractChatCompletion(data) {
    var choice = data && data.choices && data.choices[0];
    var message = choice && choice.message;
    if (!message) return 'The chat completion response did not include a message.';
    if (typeof message.content === 'string') return message.content.trim();
    if (Array.isArray(message.content)) {
      return message.content.map(function (p) { return p && (p.text || p.content || ''); }).join('\n').trim();
    }
    return 'The chat completion response did not include text content.';
  }

  function extractClaude(data) {
    if (!data || !Array.isArray(data.content)) return 'The Claude response did not include content.';
    return data.content
      .filter(function (part) { return part && part.type === 'text' && typeof part.text === 'string'; })
      .map(function (part) { return part.text; })
      .join('\n')
      .trim() || 'The Claude response did not include text content.';
  }

  function sseDataPayload(rawEvent) {
    var lines = String(rawEvent || '').split(/\r?\n/);
    var data = [];
    lines.forEach(function (line) {
      if (line.indexOf('data:') === 0) data.push(line.slice(5).trimStart());
    });
    return data.join('\n').trim();
  }

  function sseBoundary(buffer) {
    var lf = buffer.indexOf('\n\n');
    var crlf = buffer.indexOf('\r\n\r\n');
    if (lf === -1) return crlf === -1 ? null : { index: crlf, length: 4 };
    if (crlf === -1 || lf < crlf) return { index: lf, length: 2 };
    return { index: crlf, length: 4 };
  }

  async function readSse(response, onJson) {
    if (!response.body || !response.body.getReader) {
      throw new Error('This browser did not expose a readable stream for the provider response.');
    }
    var reader = response.body.getReader();
    var decoder = new TextDecoder();
    var buffer = '';

    while (true) {
      var read = await reader.read();
      if (read.value) buffer += decoder.decode(read.value, { stream: !read.done });
      var boundary = sseBoundary(buffer);
      while (boundary) {
        var rawEvent = buffer.slice(0, boundary.index);
        buffer = buffer.slice(boundary.index + boundary.length);
        var payload = sseDataPayload(rawEvent);
        if (payload && payload !== '[DONE]') onJson(JSON.parse(payload));
        boundary = sseBoundary(buffer);
      }
      if (read.done) break;
    }

    var finalPayload = sseDataPayload(buffer);
    if (finalPayload && finalPayload !== '[DONE]') onJson(JSON.parse(finalPayload));
  }

  function openAIStreamDelta(data) {
    if (!data) return '';
    if (typeof data.delta === 'string') return data.delta;
    if (data.type === 'response.output_text.delta' && typeof data.delta === 'string') return data.delta;
    if (data.type === 'response.refusal.delta' && typeof data.delta === 'string') return data.delta;
    return '';
  }

  function chatCompletionStreamDelta(data) {
    var choice = data && data.choices && data.choices[0];
    var delta = choice && choice.delta;
    if (!delta) return '';
    if (typeof delta.content === 'string') return delta.content;
    if (Array.isArray(delta.content)) {
      return delta.content.map(function (part) { return part && (part.text || part.content || ''); }).join('');
    }
    return '';
  }

  function claudeStreamDelta(data) {
    if (!data || data.type !== 'content_block_delta' || !data.delta) return '';
    return data.delta.type === 'text_delta' && typeof data.delta.text === 'string' ? data.delta.text : '';
  }

  function isSseResponse(response) {
    return (response.headers.get('content-type') || '').toLowerCase().indexOf('text/event-stream') !== -1;
  }

  function emitFallbackDelta(text, onDelta) {
    if (onDelta && text) onDelta(text);
    return text;
  }

  async function streamProviderResponse(response, provider, deltaForEvent, onDelta) {
    var text = '';
    await readSse(response, function (event) {
      var delta = deltaForEvent(event);
      if (!delta) return;
      text += delta;
      if (onDelta) onDelta(delta);
    });
    return text.trim() || 'The streamed ' + providerFor(provider).label + ' response did not include text output.';
  }

  async function callOpenAI(token, model, system, history, options) {
    options = options || {};
    var endpoint = providerEndpoint('openai');
    var response = await providerFetch('openai', endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({
        model: model,
        instructions: system,
        input: transcript(history),
        stream: !!options.onDelta
      })
    });
    if (!response.ok) throw await responseError(response, 'openai', endpoint);
    if (options.onDelta && isSseResponse(response)) return streamProviderResponse(response, 'openai', openAIStreamDelta, options.onDelta);
    var openAIText = extractOpenAI(await response.json());
    return options.onDelta ? emitFallbackDelta(openAIText, options.onDelta) : openAIText;
  }

  async function callGrok(token, model, system, history, options) {
    options = options || {};
    var endpoint = providerEndpoint('grok');
    var response = await providerFetch('grok', endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({
        model: model,
        stream: !!options.onDelta,
        messages: [{ role: 'system', content: system }].concat(history)
      })
    });
    if (!response.ok) throw await responseError(response, 'grok', endpoint);
    if (options.onDelta && isSseResponse(response)) return streamProviderResponse(response, 'grok', chatCompletionStreamDelta, options.onDelta);
    var grokText = extractChatCompletion(await response.json());
    return options.onDelta ? emitFallbackDelta(grokText, options.onDelta) : grokText;
  }

  async function callClaude(token, model, system, history, options) {
    options = options || {};
    var endpoint = providerEndpoint('claude');
    var headers = {
      'Content-Type': 'application/json',
      'anthropic-version': '2023-06-01',
      'anthropic-dangerous-direct-browser-access': 'true'
    };
    if (getCredentialMode('claude') === 'oauth') {
      headers.Authorization = 'Bearer ' + token;
    } else {
      headers['x-api-key'] = token;
    }
    var response = await providerFetch('claude', endpoint, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({
        model: model,
        max_tokens: 1400,
        system: system,
        messages: history,
        stream: !!options.onDelta
      })
    });
    if (!response.ok) throw await responseError(response, 'claude', endpoint);
    if (options.onDelta && isSseResponse(response)) return streamProviderResponse(response, 'claude', claudeStreamDelta, options.onDelta);
    var claudeText = extractClaude(await response.json());
    return options.onDelta ? emitFallbackDelta(claudeText, options.onDelta) : claudeText;
  }

  async function sendToProvider(userText, options) {
    options = options || {};
    var provider = options.provider || state.provider;
    var token = getToken(provider);
    if (!token) throw new Error('Save a ' + tokenLabel(provider) + ' in Chat settings before sending.');
    var model = options.model || getModel(provider);
    var history = options.history || apiHistory();
    var system = options.system || buildSystemPrompt(userText);

    if (provider === 'openai') return callOpenAI(token, model, system, history, options);
    if (provider === 'grok') return callGrok(token, model, system, history, options);
    return callClaude(token, model, system, history, options);
  }

  function healthCheckRequest(provider, token, model) {
    if (provider === 'openai') {
      return {
        endpoint: providerEndpoint('openai'),
        options: {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
          },
          body: JSON.stringify({
            model: model,
            instructions: 'Reply with OK.',
            input: 'Connectivity check.',
            max_output_tokens: 8
          })
        }
      };
    }
    if (provider === 'grok') {
      return {
        endpoint: providerEndpoint('grok'),
        options: {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
          },
          body: JSON.stringify({
            model: model,
            stream: false,
            max_tokens: 4,
            messages: [{ role: 'user', content: 'Reply with OK.' }]
          })
        }
      };
    }
    var headers = {
      'Content-Type': 'application/json',
      'anthropic-version': '2023-06-01',
      'anthropic-dangerous-direct-browser-access': 'true'
    };
    if (getCredentialMode('claude') === 'oauth') {
      headers.Authorization = 'Bearer ' + token;
    } else {
      headers['x-api-key'] = token;
    }
    return {
      endpoint: providerEndpoint('claude'),
      options: {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({
          model: model,
          max_tokens: 4,
          system: 'Reply with OK.',
          messages: [{ role: 'user', content: 'Connectivity check.' }]
        })
      }
    };
  }

  function scheduleProviderConnectivityChecks() {
    if (state.connectivityTimer) {
      window.clearInterval(state.connectivityTimer);
      state.connectivityTimer = null;
    }
    if (!getToken(state.provider)) return;
    state.connectivityTimer = window.setInterval(function () {
      if (document.visibilityState === 'hidden') return;
      refreshProviderConnectivity({ silent: true }).catch(function () {
        // refreshProviderConnectivity records details for the hover tooltip.
      });
    }, CONNECTIVITY_CHECK_INTERVAL_MS);
    if (!state.connectivity[state.provider]) {
      window.setTimeout(function () {
        if (document.visibilityState === 'hidden' || !getToken(state.provider)) return;
        refreshProviderConnectivity({ silent: true }).catch(function () {
          // Initial automatic refresh is best-effort.
        });
      }, 800);
    }
  }

  async function refreshProviderConnectivity(options) {
    options = options || {};
    var provider = state.provider;
    var token = getToken(provider);
    if (!token) {
      recordConnectivity(provider, {
        endpoint: providerEndpoint(provider),
        connected: false,
        apiKeyStatus: 'not validated',
        statusCode: null,
        statusText: '',
        detail: 'No token saved.'
      });
      if (!options.silent) setStatus('Save a ' + tokenLabel(provider) + ' before checking connectivity.', 'error');
      return;
    }

    state.connectivity[provider] = {
      provider: provider,
      checkedAt: nowIso(),
      endpoint: providerEndpoint(provider),
      checking: true
    };
    updateProviderBadge();
    if (!options.silent) setStatus('Checking ' + providerFor(provider).label + ' connectivity...', '');

    try {
      var request = healthCheckRequest(provider, token, getModel(provider));
      var response = await providerFetch(provider, request.endpoint, request.options);
      if (!response.ok) throw await responseError(response, provider, request.endpoint);
      await response.text();
      if (!options.silent) setStatus('Connection refreshed: ' + statusLine(response.status, response.statusText), 'ok');
    } catch (error) {
      if (!options.silent) setStatus('Connection check failed', 'error');
    }
  }

  function renderThinkingIndicator(provider) {
    var label = providerConfig(provider).label;
    return '<div class="ai-chatbot-thinking" aria-live="polite" aria-label="' + html(label) + ' is thinking">' +
      '<span class="ai-chatbot-thinking-pulse" aria-hidden="true"></span>' +
      '<span>' + html(label) + ' is thinking</span>' +
      '<span class="ai-chatbot-thinking-dots" aria-hidden="true"><i></i><i></i><i></i></span>' +
    '</div>';
  }

  function renderMessages() {
    if (!els.messages) return;
    if (!state.messages.length) {
      els.messages.innerHTML = '<div class="ai-chatbot-empty">Ready for security remediation questions.</div>';
      return;
    }
    els.messages.innerHTML = state.messages.map(function (m) {
      var roleLabel = m.role === 'assistant' ? 'Assistant' : 'You';
      var timestamp = formatTimestamp(m.createdAt);
      var isThinking = m.streaming && !String(m.content || '').trim();
      var body = isThinking ? renderThinkingIndicator(m.provider || state.provider) : renderMarkdown(m.content);
      return '<div class="ai-chatbot-message" data-role="' + html(m.role) + '" data-error="' + (m.error ? 'true' : 'false') + '" data-streaming="' + (isThinking ? 'true' : 'false') + '">' +
        '<div class="ai-chatbot-message-meta">' +
          '<span>' + html(roleLabel) + '</span>' +
          '<time datetime="' + html(m.createdAt || '') + '">' + html(timestamp) + '</time>' +
        '</div>' +
        '<div class="ai-chatbot-message-body">' + body + '</div>' +
      '</div>';
    }).join('');
    els.messages.scrollTop = els.messages.scrollHeight;
    if (!state.messages.some(function (m) { return m.streaming; })) queueMermaidRender();
  }

  function failureMessage(error) {
    var detail = error && error.message ? error.message : 'The provider request failed before returning details.';
    return 'Request failed.\n\nWhy: ' + detail;
  }

  function setStatus(text, kind) {
    if (!els.status) return;
    els.status.textContent = text || '';
    if (kind) els.status.setAttribute('data-kind', kind);
    else els.status.removeAttribute('data-kind');
  }

  function getAgentProvider() {
    var provider = localStorage.getItem(STORE.agentProvider) || state.provider;
    return PROVIDERS[provider] ? provider : state.provider;
  }

  function settingsSummary() {
    var pieces = [providerConfig().label, getModel()];
    pieces.push(getToken() ? credentialModeLabel(state.provider) + ' saved' : 'no credential');
    if (state.includeGitHub) pieces.push(state.githubRepoUrl ? 'GitHub repo context on' : 'GitHub repo needed');
    if (state.includeDepsDev) pieces.push(state.githubRepoUrl ? 'deps.dev on' : 'deps.dev needs repo');
    if (state.includeSarif) pieces.push(state.sarifContextLoadedAt ? 'SARIF on' : 'SARIF needs upload');
    if (state.includeSbom) pieces.push(state.sbomContextLoadedAt ? 'SBOM on' : 'SBOM needs upload');
    return pieces.join(' / ');
  }

  function credentialStorageTooltip() {
    var cfg = providerConfig();
    var githubToken = getGitHubToken();
    var githubNote = githubToken
      ? ' GitHub ' + githubCredentialLabel(githubAuthMode()).toLowerCase() + ' is also saved in this browser profile and is sent only to GitHub API requests for repository context or issue creation.'
      : ' No GitHub credential is saved; public repository context can still be loaded without auth where GitHub allows it.';
    var importNote = ' Imported SARIF and SBOM summaries, if you load them, are also stored in this browser profile until you clear them.';
    if (!getToken()) {
      return 'No ' + cfg.label + ' credential is saved. If you save one, it stays in this browser profile for ' + window.location.origin + ' until you clear it.' + githubNote + importNote;
    }
    return cfg.label + ' ' + credentialModeLabel(state.provider).toLowerCase() + ' is saved in this browser profile for ' + window.location.origin + ' using localStorage. It is not stored in a site database; requests send it from this browser to the selected provider through the same-origin relay. Clear it here or in browser site data if this is a shared machine.' + githubNote + importNote;
  }

  function updateSettingsSummary() {
    if (!els.settingsSummary) return;
    els.settingsSummary.textContent = settingsSummary();
    var tooltip = credentialStorageTooltip();
    els.settingsSummary.title = tooltip;
    els.settingsSummary.setAttribute('aria-label', tooltip);
    if (els.settingsToggle) els.settingsToggle.title = tooltip;
  }

  function setSettingsOpen(open) {
    state.settingsOpen = !!open;
    localStorage.setItem(STORE.settingsOpen, state.settingsOpen ? 'true' : 'false');
    if (els.settings) els.settings.setAttribute('data-open', state.settingsOpen ? 'true' : 'false');
    if (els.settingsToggle) els.settingsToggle.setAttribute('aria-expanded', state.settingsOpen ? 'true' : 'false');
    if (els.settingsContent) els.settingsContent.hidden = !state.settingsOpen;
    updateSettingsSummary();
  }

  function setDefaultSettingsOpenForProvider() {
    state.settingsOpen = !getToken(state.provider);
    localStorage.setItem(STORE.settingsOpen, state.settingsOpen ? 'true' : 'false');
  }

  function updateAgentUI() {
    var provider = getAgentProvider();
    if (els.agentProvider) els.agentProvider.value = provider;
    populateModelSelect(els.agentModel, provider);
    populateWorkflowTemplates();
    populateReportProfiles();
    populateInputChannels();
    populateAgentOutputRoutes();
    updateAgentIntegrationUI();
    if (els.agentRecipeInput && state.agentRecipePath) {
      var recipe = findRecipeByPath(state.agentRecipePath);
      if (recipe) els.agentRecipeInput.value = recipeLabel(recipe);
    }
    if (els.agentReportProfile && persistedReportProfile() && reportProfileById(persistedReportProfile())) {
      els.agentReportProfile.value = persistedReportProfile();
    }
    if (els.agentOutputRoute && persistedAgentOutputChannel() && outputChannelById(persistedAgentOutputChannel())) {
      els.agentOutputRoute.value = outputChannelById(persistedAgentOutputChannel()).id;
    }
    if (els.agentInputChannels) setSelectValues(els.agentInputChannels, storedInputChannelIds());
    setAgentWorkflow(els.agentWorkflow && els.agentWorkflow.value ? els.agentWorkflow.value : AGENT_WORKFLOWS[0].value);
    syncSelectedInputChannels();
    if (persistedWorkflowTemplate() && workflowTemplateById(persistedWorkflowTemplate())) {
      applyWorkflowTemplate(persistedWorkflowTemplate(), { skipRecipeAutofill: true });
    } else {
      updateAgentTemplateHint();
      updateAgentRouteHint();
      updateAgentMarketplacePreview();
    }
    renderAgentActions();
    if (els.agentStatus && !state.agentRunning) {
      els.agentStatus.textContent = getToken(provider)
        ? 'Beta agents use the saved ' + providerConfig(provider).label + ' credential, selected marketplace inputs, report pack, and optional delivery integrations. Scheduled runs stay local drafts until a scheduler backend is connected.'
        : 'Save a ' + tokenLabel(provider) + ' in Chat settings before running this agent.';
      els.agentStatus.removeAttribute('data-kind');
    }
  }

  function updateOAuthUI() {
    var mode = getCredentialMode(state.provider);
    if (els.credentialModeButtons) {
      Array.prototype.forEach.call(els.credentialModeButtons, function (button) {
        button.setAttribute('aria-pressed', button.getAttribute('data-credential-mode') === mode ? 'true' : 'false');
      });
    }
    if (els.oauthDetails) {
      els.oauthDetails.hidden = mode !== 'oauth';
      if (mode === 'oauth' && !getToken(state.provider, 'oauth')) els.oauthDetails.open = true;
    }
    if (els.oauthClientId) els.oauthClientId.value = getOAuthField(state.provider, 'clientId');
    if (els.oauthScope) els.oauthScope.value = getOAuthField(state.provider, 'scope');
    if (els.oauthAuthUrl) els.oauthAuthUrl.value = getOAuthField(state.provider, 'authUrl');
    if (els.oauthTokenUrl) els.oauthTokenUrl.value = getOAuthField(state.provider, 'tokenUrl');
    if (mode === 'oauth') {
      setOAuthStatus('Paste an OAuth bearer token above, or configure browser OAuth with PKCE. Redirect URI: ' + oauthRedirectUri(), getToken(state.provider, 'oauth') ? 'ok' : '');
    } else {
      setOAuthStatus('', '');
    }
  }

  function updateProviderUI() {
    updateProviderBadge();
    if (els.provider) els.provider.value = state.provider;
    populateModelSelect(els.model, state.provider);
    if (els.tokenLabel) els.tokenLabel.textContent = tokenLabel(state.provider);
    if (els.tokenInput) els.tokenInput.value = '';
    if (els.providerCredentialDetails) els.providerCredentialDetails.open = !getToken(state.provider);
    updateOAuthUI();
    setStatus(maskToken(getToken()), getToken() ? 'ok' : '');
    setSettingsOpen(state.settingsOpen);
    updateAgentUI();
    scheduleProviderConnectivityChecks();
  }

  function renderAgentRecipeResults(items) {
    if (!els.agentRecipeResults) return;
    state.agentRecipeResults = items || [];
    state.agentRecipeActive = Math.min(state.agentRecipeActive, state.agentRecipeResults.length - 1);
    if (!state.agentRecipeResults.length) {
      els.agentRecipeResults.hidden = true;
      if (els.agentRecipeInput) els.agentRecipeInput.setAttribute('aria-expanded', 'false');
      return;
    }
    els.agentRecipeResults.innerHTML = state.agentRecipeResults.map(function (doc, i) {
      var summary = collapseText(doc.summary || doc.content || '').slice(0, 120);
      return '<button class="ai-chatbot-typeahead-option" type="button" data-recipe-index="' + i + '" aria-selected="' + (i === state.agentRecipeActive ? 'true' : 'false') + '">' +
        '<span>' + html(doc.title || 'Untitled recipe') + '</span>' +
        '<small>' + html(doc.section || doc.path || 'recipe') + '</small>' +
        (summary ? '<em>' + html(summary) + '</em>' : '') +
      '</button>';
    }).join('');
    els.agentRecipeResults.hidden = false;
    if (els.agentRecipeInput) els.agentRecipeInput.setAttribute('aria-expanded', 'true');
  }

  async function runAgentRecipeTypeahead() {
    if (!els.agentRecipeInput) return;
    await ensureDocsIndex();
    var items = matchAgentRecipes(els.agentRecipeInput.value);
    state.agentRecipeActive = items.length ? 0 : -1;
    renderAgentRecipeResults(items);
  }

  function selectAgentRecipe(doc) {
    if (!doc) return;
    state.agentRecipePath = doc.path || doc.url || '';
    localStorage.setItem(STORE.agentRecipe, state.agentRecipePath);
    if (els.agentRecipeInput) {
      els.agentRecipeInput.value = recipeLabel(doc);
      els.agentRecipeInput.setAttribute('aria-expanded', 'false');
    }
    if (els.agentRecipeResults) els.agentRecipeResults.hidden = true;
    updateAgentMarketplacePreview();
    if (els.agentStatus && !state.agentRunning) {
      els.agentStatus.textContent = 'Recipe selected: ' + (doc.title || state.agentRecipePath) + '.';
      els.agentStatus.removeAttribute('data-kind');
    }
  }

  function switchTab(tab) {
    Array.prototype.forEach.call(document.querySelectorAll('.ai-chatbot-tab'), function (button) {
      var active = button.getAttribute('data-tab') === tab;
      button.setAttribute('aria-selected', active ? 'true' : 'false');
    });
    Array.prototype.forEach.call(document.querySelectorAll('.ai-chatbot-tab-panel'), function (panel) {
      panel.hidden = panel.getAttribute('data-panel') !== tab;
    });
  }

  function renderSearchResults(items, query) {
    if (!els.searchResults) return;
    if (!query) {
      els.searchResults.innerHTML = '<div class="ai-chatbot-search-empty">Search SecurityRecipes docs, prompts, CVEs, and remediation workflows.</div>';
      if (els.searchStatus) els.searchStatus.textContent = '';
      return;
    }
    if (!items.length) {
      els.searchResults.innerHTML = '<div class="ai-chatbot-search-empty">No matches found.</div>';
      if (els.searchStatus) els.searchStatus.textContent = '0 results';
      return;
    }
    els.searchResults.innerHTML = items.map(function (doc) {
      var href = doc.path || doc.url || '#';
      var summary = collapseText(doc.summary || doc.content || '').slice(0, 170);
      return '<a class="ai-chatbot-search-result" href="' + html(href) + '">' +
        '<span class="ai-chatbot-search-result-title">' + html(doc.title || 'Untitled') + '</span>' +
        '<span class="ai-chatbot-search-result-meta">' + html(doc.section || 'page') + '</span>' +
        (summary ? '<span class="ai-chatbot-search-result-summary">' + html(summary) + '</span>' : '') +
      '</a>';
    }).join('');
    if (els.searchStatus) els.searchStatus.textContent = String(items.length) + ' results';
  }

  async function runSearch() {
    if (!els.searchInput) return;
    var query = els.searchInput.value.trim();
    if (!query) {
      renderSearchResults([], '');
      return;
    }
    if (els.searchStatus) els.searchStatus.textContent = 'Searching...';
    await ensureDocsIndex();
    renderSearchResults(searchDocs(query), query);
  }

  function openPanel(tabName) {
    updatePanelOffset();
    els.panel.hidden = false;
    els.launch.setAttribute('aria-expanded', 'true');
    switchTab(tabName || 'chat');
    window.setTimeout(function () {
      if (tabName === 'search' && els.searchInput) {
        els.searchInput.focus();
      } else if (getToken()) {
        els.prompt.focus();
      } else {
        if (!state.settingsOpen) setSettingsOpen(true);
        els.tokenInput.focus();
      }
    }, 0);
  }

  function setExpanded(expanded) {
    if (!els.panel || !els.expand) return;
    updatePanelOffset();
    var isExpanded = !!expanded;
    els.panel.setAttribute('data-expanded', isExpanded ? 'true' : 'false');
    els.shell.classList.toggle('is-expanded', isExpanded);
    document.documentElement.classList.toggle('ai-chatbot-fullscreen-open', isExpanded && !els.panel.hidden);
    els.expand.innerHTML = icon(isExpanded ? 'collapse' : 'expand');
    els.expand.setAttribute('aria-label', isExpanded ? 'Exit full screen' : 'Expand full screen');
    els.expand.setAttribute('aria-pressed', isExpanded ? 'true' : 'false');
    els.expand.title = isExpanded ? 'Exit full screen' : 'Expand full screen';
  }

  function selectedText(select) {
    if (!select) return '';
    var option = select.options[select.selectedIndex];
    return option ? collapseText(option.textContent) : collapseText(select.value);
  }

  function agentWorkflowByValue(value) {
    return AGENT_WORKFLOWS.find(function (workflow) { return workflow.value === value; }) || AGENT_WORKFLOWS[0];
  }

  function currentAgentWorkflow() {
    return agentWorkflowByValue(els.agentWorkflow ? els.agentWorkflow.value : AGENT_WORKFLOWS[0].value);
  }

  function agentOutputRouteByValue(value) {
    return outputChannelById(value);
  }

  function currentAgentOutputRoute() {
    var fallback = outputChannels()[0];
    return agentOutputRouteByValue(els.agentOutputRoute ? els.agentOutputRoute.value : (fallback ? fallback.id : 'draft-pr'));
  }

  function currentWorkflowTemplate() {
    return workflowTemplateById(els.agentTemplate ? els.agentTemplate.value : persistedWorkflowTemplate());
  }

  function currentReportProfile() {
    return reportProfileById(els.agentReportProfile ? els.agentReportProfile.value : persistedReportProfile());
  }

  function currentInputChannelIds() {
    return els.agentInputChannels ? selectValues(els.agentInputChannels) : storedInputChannelIds();
  }

  function currentInputChannels() {
    return currentInputChannelIds().map(inputChannelById).filter(Boolean);
  }

  function inputChannelRuntimeState(channelId) {
    var imported = importedChannelBundle(channelId);
    if (imported) {
      return {
        ready: !!imported.text,
        loaded_at: imported.loadedAt || '',
        summary: imported.meta || null
      };
    }
    if (channelId === 'page-context' || channelId === 'recipe-index') {
      return { ready: true };
    }
    if (channelId === 'github-repository') {
      return {
        ready: !!state.githubContextText,
        loaded_at: state.githubContextLoadedAt || '',
        summary: state.githubRepoUrl ? { repository: state.githubRepoUrl } : null
      };
    }
    if (channelId === 'deps-dev-advisories') {
      return {
        ready: !!state.depsDevContextText,
        loaded_at: state.depsDevContextLoadedAt || '',
        summary: state.githubRepoUrl ? { repository: state.githubRepoUrl } : null
      };
    }
    return { ready: false };
  }

  function blankSeverityCounts() {
    return {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };
  }

  function mergeSeverityCounts(target, source) {
    var out = target || blankSeverityCounts();
    ['critical', 'high', 'medium', 'low', 'info'].forEach(function (key) {
      out[key] = Number(out[key] || 0) + Number(source && source[key] || 0);
    });
    return out;
  }

  function highestSeverityLevel(counts) {
    if (counts && counts.critical) return 'critical';
    if (counts && counts.high) return 'high';
    if (counts && counts.medium) return 'medium';
    if (counts && counts.low) return 'low';
    return 'info';
  }

  function uniqueStrings(values, limit) {
    var seen = {};
    var out = [];
    (values || []).forEach(function (value) {
      var text = collapseText(value);
      var key = text.toLowerCase();
      if (!text || seen[key]) return;
      seen[key] = true;
      out.push(text);
    });
    return typeof limit === 'number' ? out.slice(0, limit) : out;
  }

  function sanitizeFilePart(value) {
    return collapseText(value || '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 64) || 'report';
  }

  function selectedInputChannelsForConfig(config) {
    return (((config && config.inputChannelIds) || currentInputChannelIds()) || [])
      .map(inputChannelById)
      .filter(Boolean);
  }

  function reportSourceSummaryText(channel, runtime) {
    var kind = channel.id === importedContextChannelId('sarif')
      ? 'sarif'
      : (channel.id === importedContextChannelId('sbom') ? 'sbom' : '');
    if (kind) return importedContextSummaryLine(kind, importedContextBundle(kind));
    if (channel.id === 'github-repository' && state.githubRepoUrl) return 'Repository: ' + state.githubRepoUrl;
    if (channel.id === 'deps-dev-advisories' && state.githubRepoUrl) return 'Repository advisory scope: ' + state.githubRepoUrl;
    if (channel.id === 'page-context') return 'Current page context from the active browser document.';
    if (channel.id === 'recipe-index') return 'Bounded SecurityRecipes search results from the local docs index.';
    return collapseText(channel.description || '');
  }

  function reportSourceDescriptor(channel) {
    var runtime = inputChannelRuntimeState(channel.id);
    var descriptor = {
      id: channel.id,
      label: channel.label,
      category: channel.category || '',
      status: channel.status || '',
      runtime_support: channel.runtime_support || '',
      ready: !!runtime.ready
    };
    if (Array.isArray(channel.auth_modes) && channel.auth_modes.length) descriptor.auth_modes = channel.auth_modes.slice();
    if (runtime.loaded_at) descriptor.loaded_at = runtime.loaded_at;
    if (runtime.summary) descriptor.runtime_summary = runtime.summary;
    var summary = reportSourceSummaryText(channel, runtime);
    if (summary) descriptor.summary = summary;

    var imported = importedChannelBundle(channel.id);
    if (imported && imported.meta) {
      descriptor.imported_artifact = {
        type: imported.meta.type || '',
        file_name: imported.meta.file_name || '',
        meta: imported.meta
      };
    }
    return descriptor;
  }

  function buildAgentReportContext(config, outputText) {
    var report = reportProfileById((config && config.reportProfileId) || (currentReportProfile() && currentReportProfile().id));
    if (!report) return null;

    var route = outputChannelById((config && (config.outputChannelId || config.outputRouteValue)) || currentAgentOutputRoute().id);
    var template = workflowTemplateById(config && config.workflowTemplateId);
    var channels = selectedInputChannelsForConfig(config);
    var sources = channels.map(reportSourceDescriptor);
    var importedSources = sources.filter(function (source) {
      return !!(source.imported_artifact && source.imported_artifact.meta);
    });
    var severityCounts = blankSeverityCounts();
    var findingSamples = [];
    var componentSamples = [];
    var vulnerabilityIds = [];
    var artifactFiles = [];
    var primaryWorkflow = config && config.actions && config.actions[0]
      ? (config.actions[0].workflowValue || config.actions[0].workflowLabel || config.actions[0].workflow)
      : (config && (config.workflowValue || config.workflow));
    var recommended = uniqueStrings([primaryWorkflow], 6);
    var summary = {
      finding_count: 0,
      sbom_component_count: 0,
      sbom_package_count: 0,
      sbom_vulnerability_count: 0,
      sbom_security_reference_count: 0,
      dependency_count: 0
    };

    importedSources.forEach(function (source) {
      var meta = source.imported_artifact.meta || {};
      if (meta.file_name) artifactFiles.push(meta.file_name);
      recommended = uniqueStrings(recommended.concat(meta.recommended_workflows || []), 6);

      if (meta.type === 'sarif') {
        summary.finding_count += Number(meta.finding_count || 0);
        mergeSeverityCounts(severityCounts, meta.severity_counts);
        findingSamples = findingSamples.concat((meta.sample_findings || []).map(function (item) {
          return {
            source_id: source.id,
            source_label: source.label,
            severity: item.severity || 'info',
            rule_id: item.rule_id || '',
            message: item.message || '',
            file: item.file || '',
            line: item.line || ''
          };
        }));
        return;
      }

      if (meta.type === 'sbom') {
        summary.sbom_component_count += Number(meta.component_count || 0);
        summary.sbom_package_count += Number(meta.package_count || 0);
        summary.sbom_vulnerability_count += Number(meta.vulnerability_count || 0);
        summary.sbom_security_reference_count += Number(meta.security_reference_count || 0);
        summary.dependency_count += Number(meta.dependency_count || meta.relationship_count || 0);
        componentSamples = componentSamples.concat((meta.sample_components || []).map(function (item) {
          return {
            source_id: source.id,
            source_label: source.label,
            name: item.name || '',
            version: item.version || '',
            type: item.type || item.purpose || '',
            purl: item.purl || ''
          };
        }));
        vulnerabilityIds = vulnerabilityIds.concat(meta.vulnerability_ids || []);
      }
    });

    findingSamples = findingSamples.slice(0, SARIF_SAMPLE_FINDINGS);
    componentSamples = componentSamples.slice(0, SBOM_SAMPLE_COMPONENTS);
    vulnerabilityIds = uniqueStrings(vulnerabilityIds, SBOM_TOP_ITEMS);
    artifactFiles = uniqueStrings(artifactFiles, 8);

    var readyCount = sources.filter(function (source) { return source.ready; }).length;
    var output = typeof outputText === 'string' ? outputText : (state.agentLastOutput || '');
    var title = firstMarkdownTitle(output, (config && config.scope) || 'Security remediation action');
    var recipe = config && config.recipe ? {
      title: config.recipe.title || 'Untitled recipe',
      path: config.recipe.path || config.recipe.url || '',
      summary: collapseText(config.recipe.summary || '').slice(0, 240)
    } : null;

    return {
      config: config || {},
      report: report,
      route: route,
      template: template,
      sources: sources,
      importedSources: importedSources,
      summary: summary,
      severityCounts: severityCounts,
      riskLevel: highestSeverityLevel(severityCounts),
      recommendedWorkflows: recommended,
      findingSamples: findingSamples,
      componentSamples: componentSamples,
      vulnerabilityIds: vulnerabilityIds,
      artifactFiles: artifactFiles,
      title: title,
      output: output,
      outputSummary: collapseText(output).slice(0, 520),
      recipe: recipe,
      sourceSummary: {
        selected_channel_count: sources.length,
        ready_channel_count: readyCount,
        imported_artifact_count: importedSources.length,
        finding_count: summary.finding_count,
        sbom_component_count: summary.sbom_component_count,
        sbom_package_count: summary.sbom_package_count,
        sbom_vulnerability_count: summary.sbom_vulnerability_count,
        severity_counts: severityCounts,
        recommended_workflows: recommended
      }
    };
  }

  function buildAgentReportPayload(config, outputText) {
    var ctx = buildAgentReportContext(config || agentConfig(), outputText);
    if (!ctx) return {};

    var provider = providerConfig(ctx.config.provider || state.provider);
    var base = {
      report_type: ctx.report.id,
      report_label: ctx.report.label,
      destination: ctx.route ? ctx.route.id : '',
      format: ctx.report.format,
      sections: ctx.report.sections || [],
      title: ctx.title,
      generated_at: nowIso(),
      runtime: {
        mode: 'browser',
        byo_tokens: true,
        human_review_required: true,
        provider: provider.label,
        model: ctx.config.model || getModel(ctx.config.provider || state.provider)
      },
      workflow_template: ctx.template ? {
        id: ctx.template.id,
        label: ctx.template.label,
        status: ctx.template.status
      } : null,
      workflow: {
        action: ctx.config.workflow || '',
        scope: ctx.config.scope || '',
        cadence: ctx.config.cadence || '',
        approval_gate: ctx.config.approvalGate || '',
        context_pack: ctx.config.contextPack || ''
      },
      recipe: ctx.recipe,
      sources: ctx.sources,
      source_summary: ctx.sourceSummary,
      generated_output: ctx.output || ''
    };

    if (ctx.report.id === 'scan-findings-bundle') {
      return Object.assign(base, {
        metadata: {
          highest_severity: ctx.riskLevel,
          report_profile: ctx.report.label,
          output_channel: ctx.route ? ctx.route.label : '',
          workflow_template: ctx.template ? ctx.template.label : 'Custom'
        },
        source: {
          selected_channel_ids: ctx.sources.map(function (source) { return source.id; }),
          scanner_artifacts: ctx.artifactFiles,
          repository: state.githubRepoUrl || ''
        },
        summary: {
          finding_count: ctx.summary.finding_count,
          sbom_component_count: ctx.summary.sbom_component_count,
          sbom_package_count: ctx.summary.sbom_package_count,
          sbom_vulnerability_count: ctx.summary.sbom_vulnerability_count,
          dependency_count: ctx.summary.dependency_count,
          highest_severity: ctx.riskLevel
        },
        findings: ctx.findingSamples,
        severity_counts: ctx.severityCounts,
        recommended_workflows: ctx.recommendedWorkflows,
        artifacts: {
          sbom_components: ctx.componentSamples,
          vulnerability_ids: ctx.vulnerabilityIds
        }
      });
    }

    if (ctx.report.id === 'run-receipt') {
      return Object.assign(base, {
        run_metadata: {
          generated_at: base.generated_at,
          runtime: 'browser',
          byo_tokens: true,
          output_channel: ctx.route ? ctx.route.label : ''
        },
        inputs: {
          input_channel_ids: ctx.sources.map(function (source) { return source.id; }),
          imported_artifacts: ctx.artifactFiles,
          recipe: ctx.recipe
        },
        decisions: {
          approval_gate: ctx.config.approvalGate || '',
          recommended_workflows: ctx.recommendedWorkflows,
          highest_severity: ctx.riskLevel
        },
        outputs: {
          destination: ctx.route ? ctx.route.label : '',
          generated_output: ctx.output || ''
        },
        operator_notes: 'Human review remains required before any external write or production change.'
      });
    }

    if (ctx.report.id === 'ticket-ready-brief') {
      return Object.assign(base, {
        impact: 'Highest observed severity: ' + ctx.riskLevel + '. Findings: ' + ctx.summary.finding_count + '.',
        scope: ctx.config.scope || '',
        actions: ctx.output || 'Review the generated plan and convert it into the target ticketing system format.',
        owner_notes: 'Keep this ticket reviewer-gated and attach validation evidence before execution.',
        links: uniqueStrings([
          ctx.recipe && ctx.recipe.path,
          state.githubRepoUrl
        ], 4)
      });
    }

    if (ctx.report.id === 'exec-risk-brief') {
      return Object.assign(base, {
        risk_statement: ctx.summary.finding_count
          ? ctx.summary.finding_count + ' imported findings require review before downstream action.'
          : 'Browser-generated security report prepared for reviewer assessment.',
        trend: ctx.importedSources.length
          ? 'Point-in-time browser snapshot assembled from imported scan evidence and selected context channels.'
          : 'Point-in-time browser snapshot without imported scanner artifacts.',
        top_findings: ctx.findingSamples.slice(0, 5),
        business_impact: 'AI-assisted security work is being routed through explicit browser-held contracts and review gates.',
        next_actions: [
          'Review the generated plan.',
          'Confirm scope and approvals.',
          'Route the normalized report to the selected downstream system.'
        ]
      });
    }

    if (ctx.report.id === 'connector-intake-decision') {
      return Object.assign(base, {
        candidate: {
          workflow_template: ctx.template ? ctx.template.label : 'Custom',
          output_channel: ctx.route ? ctx.route.label : '',
          scope: ctx.config.scope || ''
        },
        auth: {
          input_auth_modes: uniqueStrings([].concat.apply([], ctx.sources.map(function (source) {
            return source.auth_modes || [];
          })), 8)
        },
        egress: {
          output_runtime_support: ctx.route ? ctx.route.runtime_support : '',
          browser_delivery: ctx.route ? !!ctx.route.browser_delivery : false
        },
        tool_surface: {
          selected_channel_count: ctx.sources.length,
          imported_artifact_count: ctx.importedSources.length
        },
        decision: 'hold_for_review',
        required_controls: [
          'human_review_required',
          'browser_secret_storage_only',
          'explicit_output_contract'
        ]
      });
    }

    if (ctx.report.id === 'remediation-pr-packet') {
      return Object.assign(base, {
        executive_summary: ctx.outputSummary || 'Draft remediation packet generated locally in the browser.',
        scope: ctx.config.scope || '',
        root_cause: ctx.findingSamples.length
          ? 'Imported findings indicate ' + (ctx.findingSamples[0].rule_id || 'scanner-reported issues') + ' as the leading remediation target.'
          : 'Root cause still needs reviewer confirmation.',
        proposed_change: ctx.output || 'Use the generated plan as the draft PR body and reviewer handoff.',
        validation: ctx.artifactFiles.length
          ? 'Validate against imported artifacts: ' + ctx.artifactFiles.join(', ') + '.'
          : 'Attach tests, scanner reruns, and reviewer checks before merge.',
        rollback: 'Keep the change reviewer-gated and prepare branch-level rollback instructions before merge.',
        approvals: [ctx.config.approvalGate || 'Security reviewer required']
      });
    }

    return base;
  }

  function reportPreviewPayload(config, outputText) {
    return buildAgentReportPayload(config || agentConfig(), outputText);
  }

  function deliveryEnvelopePayload(config, outputText) {
    var route = outputChannelById((config && (config.outputChannelId || config.outputRouteValue)) || currentAgentOutputRoute().id);
    return {
      generated_at: nowIso(),
      runtime: {
        mode: 'browser',
        byo_tokens: true,
        human_review_required: true
      },
      output_channel: route ? {
        id: route.id,
        label: route.label,
        driver: route.driver,
        runtime_support: route.runtime_support,
        browser_delivery: !!route.browser_delivery,
        config: route.config || {}
      } : null,
      report: buildAgentReportPayload(config || agentConfig(), outputText),
      marketplace_contract: marketplacePreviewPayload(config || agentConfig(), outputText)
    };
  }

  function reportDownloadFileName(config) {
    var report = reportProfileById((config && config.reportProfileId) || (currentReportProfile() && currentReportProfile().id));
    var scope = sanitizeFilePart(config && config.scope);
    return 'securityrecipes-' + sanitizeFilePart(report && report.id) + '-' + scope + '.json';
  }

  function populateWorkflowTemplates() {
    if (!els.agentTemplate) return;
    var templates = workflowTemplates();
    var current = els.agentTemplate.value || persistedWorkflowTemplate();
    var options = ['<option value="">Custom / no preset</option>'].concat(templates.map(function (template) {
      var badge = template.status === 'community' ? ' (Community)' : '';
      return '<option value="' + html(template.id) + '">' + html(template.label + badge) + '</option>';
    }));
    els.agentTemplate.innerHTML = options.join('');
    if (current && workflowTemplateById(current)) els.agentTemplate.value = current;
  }

  function populateReportProfiles() {
    if (!els.agentReportProfile) return;
    var profiles = reportProfiles();
    var current = els.agentReportProfile.value || persistedReportProfile();
    els.agentReportProfile.innerHTML = profiles.map(function (profile) {
      return '<option value="' + html(profile.id) + '">' + html(profile.label) + '</option>';
    }).join('');
    if (current && reportProfileById(current)) els.agentReportProfile.value = current;
    else if (profiles[0]) els.agentReportProfile.value = profiles[0].id;
  }

  function populateInputChannels() {
    if (!els.agentInputChannels) return;
    var selected = currentInputChannelIds();
    els.agentInputChannels.innerHTML = inputChannels().map(function (channel) {
      var meta = [channel.category, channel.runtime_support].filter(Boolean).join(' · ');
      return '<option value="' + html(channel.id) + '">' + html(channel.label + (meta ? ' - ' + meta : '')) + '</option>';
    }).join('');
    setSelectValues(els.agentInputChannels, selected.length ? selected : defaultInputChannelIds());
  }

  function populateAgentOutputRoutes() {
    if (!els.agentOutputRoute) return;
    var current = els.agentOutputRoute.value || persistedAgentOutputChannel();
    var channels = outputChannels();
    els.agentOutputRoute.innerHTML = channels.map(function (route) {
      return '<option value="' + html(route.id) + '">' + html(route.label) + '</option>';
    }).join('');
    if (current && agentOutputRouteByValue(current)) els.agentOutputRoute.value = agentOutputRouteByValue(current).id;
    else if (channels[0]) els.agentOutputRoute.value = channels[0].id;
    updateAgentRouteHint();
  }

  function updateAgentRouteHint() {
    if (!els.agentRouteHint) return;
    var route = currentAgentOutputRoute();
    var profile = currentReportProfile();
    var parts = [route.requirement];
    if (profile && profile.format) parts.push('Report format: ' + profile.format + '.');
    if (profile && profile.id === 'scan-findings-bundle') {
      parts.push('Imported SARIF and SBOM evidence is emitted as a normalized browser-side scan bundle JSON.');
    }
    els.agentRouteHint.textContent = parts.join(' ');
  }

  function updateAgentTemplateHint() {
    if (!els.agentTemplateHint) return;
    var template = currentWorkflowTemplate();
    var channels = currentInputChannels();
    if (!template) {
      els.agentTemplateHint.textContent = 'Custom workflow pack. Select one or more input channels, choose a report profile, then route the output downstream.';
      return;
    }
    var parts = [
      template.label + ': ' + template.description,
      'Default scope hint: ' + (template.target_hint || 'set a narrow scope'),
      channels.length ? 'Inputs: ' + channels.map(function (channel) { return channel.label; }).join(', ') + '.' : ''
    ].filter(Boolean);
    els.agentTemplateHint.textContent = parts.join(' ');
  }

  function syncSelectedInputChannels() {
    var ids = currentInputChannelIds();
    localStorage.setItem(STORE.agentInputChannels, JSON.stringify(ids));
    state.includeContext = ids.indexOf('page-context') !== -1;
    state.includeRelated = ids.indexOf('recipe-index') !== -1;
    state.includeGitHub = ids.indexOf('github-repository') !== -1;
    state.includeDepsDev = ids.indexOf('deps-dev-advisories') !== -1;
    state.includeSarif = ids.indexOf(importedContextChannelId('sarif')) !== -1;
    state.includeSbom = ids.indexOf(importedContextChannelId('sbom')) !== -1;
    if (els.includeContext) els.includeContext.checked = state.includeContext;
    if (els.includeRelated) els.includeRelated.checked = state.includeRelated;
    if (els.includeGitHub) els.includeGitHub.checked = state.includeGitHub;
    if (els.includeDepsDev) els.includeDepsDev.checked = state.includeDepsDev;
    if (els.includeSarif) els.includeSarif.checked = state.includeSarif;
    if (els.includeSbom) els.includeSbom.checked = state.includeSbom;
    localStorage.setItem(STORE.context, String(state.includeContext));
    localStorage.setItem(STORE.related, String(state.includeRelated));
    localStorage.setItem(STORE.githubContext, String(state.includeGitHub));
    localStorage.setItem(STORE.depsDevContext, String(state.includeDepsDev));
    localStorage.setItem(STORE.sarifContext, String(state.includeSarif));
    localStorage.setItem(STORE.sbomContext, String(state.includeSbom));
    updateGitHubUI();
    updateDepsDevUI();
    updateImportedContextUI('sarif');
    updateImportedContextUI('sbom');
  }

  function syncAgentInputSelectionsFromToggles() {
    if (!els.agentInputChannels) return;
    var ids = selectValues(els.agentInputChannels).filter(function (id) {
      return [
        'page-context',
        'recipe-index',
        'github-repository',
        'deps-dev-advisories',
        importedContextChannelId('sarif'),
        importedContextChannelId('sbom')
      ].indexOf(id) === -1;
    });
    if (state.includeContext) ids.push('page-context');
    if (state.includeRelated) ids.push('recipe-index');
    if (state.includeGitHub) ids.push('github-repository');
    if (state.includeDepsDev) ids.push('deps-dev-advisories');
    if (state.includeSarif) ids.push(importedContextChannelId('sarif'));
    if (state.includeSbom) ids.push(importedContextChannelId('sbom'));
    setSelectValues(els.agentInputChannels, ids);
    localStorage.setItem(STORE.agentInputChannels, JSON.stringify(ids));
    updateAgentTemplateHint();
    updateAgentMarketplacePreview();
  }

  function applyWorkflowTemplate(templateId, options) {
    options = options || {};
    if (els.agentTemplate) {
      if (templateId && workflowTemplateById(templateId)) {
        els.agentTemplate.value = templateId;
        localStorage.setItem(STORE.agentWorkflowTemplate, templateId);
      } else {
        els.agentTemplate.value = '';
        localStorage.removeItem(STORE.agentWorkflowTemplate);
      }
    }
    var template = workflowTemplateById(templateId);
    if (!template) {
      updateAgentTemplateHint();
      updateAgentRouteHint();
      updateAgentMarketplacePreview();
      return;
    }
    setAgentWorkflow(template.workflow_value || currentAgentWorkflow().value);
    if (els.agentReportProfile && reportProfileById(template.default_report_profile_id)) {
      els.agentReportProfile.value = template.default_report_profile_id;
      localStorage.setItem(STORE.agentReportProfile, template.default_report_profile_id);
    }
    if (els.agentOutputRoute && outputChannelById(template.default_output_channel_id)) {
      els.agentOutputRoute.value = outputChannelById(template.default_output_channel_id).id;
      localStorage.setItem(STORE.agentOutputChannel, els.agentOutputRoute.value);
    }
    if (els.agentInputChannels && Array.isArray(template.default_input_channel_ids)) {
      setSelectValues(els.agentInputChannels, template.default_input_channel_ids);
      syncSelectedInputChannels();
    }
    if (els.agentApproval && template.default_approval_gate) selectByText(els.agentApproval, template.default_approval_gate);
    if (els.agentCadence && template.default_cadence) selectByText(els.agentCadence, template.default_cadence);
    if (els.agentContextPack && template.default_context_pack) selectByText(els.agentContextPack, template.default_context_pack);
    if (els.agentScope && template.target_hint) {
      els.agentScope.placeholder = 'repo/package/CVE/file path, e.g. ' + template.target_hint;
    }
    if (els.agentRecipeInput && template.default_recipe_query && !options.skipRecipeAutofill) {
      if (!collapseText(els.agentRecipeInput.value) || options.forceRecipeAutofill) {
        els.agentRecipeInput.value = template.default_recipe_query;
        state.agentRecipePath = '';
        localStorage.removeItem(STORE.agentRecipe);
      }
    }
    updateAgentTemplateHint();
    updateAgentRouteHint();
    updateAgentMarketplacePreview();
  }

  function marketplacePreviewPayload(config, outputText) {
    config = config || agentConfig();
    var template = workflowTemplateById(config.workflowTemplateId);
    var report = reportProfileById(config.reportProfileId);
    var route = outputChannelById(config.outputChannelId || config.outputRouteValue);
    var selectedChannels = (config.inputChannelIds || currentInputChannelIds()).map(inputChannelById).filter(Boolean);
    return {
      generated_at: nowIso(),
      runtime: {
        mode: 'browser',
        byo_tokens: true,
        storage: 'localStorage',
        human_review_required: true
      },
      workflow_template: template ? {
        id: template.id,
        label: template.label,
        status: template.status
      } : null,
      workflow: {
        action: config.workflow,
        scope: config.scope,
        cadence: config.cadence,
        approval_gate: config.approvalGate,
        context_pack: config.contextPack
      },
      recipe: config.recipe ? {
        title: config.recipe.title || 'Untitled recipe',
        path: config.recipe.path || config.recipe.url || '',
        summary: collapseText(config.recipe.summary || '').slice(0, 240)
      } : null,
      input_channels: selectedChannels.map(function (channel) {
        return {
          id: channel.id,
          label: channel.label,
          runtime_support: channel.runtime_support,
          status: channel.status,
          auth_modes: channel.auth_modes || [],
          config: channel.config || {},
          runtime_state: inputChannelRuntimeState(channel.id)
        };
      }),
      report_profile: report ? {
        id: report.id,
        label: report.label,
        format: report.format,
        sections: report.sections || [],
        example_output: report.example_output || {}
      } : null,
      output_channel: route ? {
        id: route.id,
        label: route.label,
        driver: route.value,
        runtime_support: route.runtime_support,
        browser_delivery: !!route.browser_delivery,
        requirement: route.requirement,
        config: route.config || {}
      } : null,
      queued_actions: (config.actions || []).map(function (action) {
        return {
          workflow: action.workflowLabel || action.workflow,
          scope: action.scope,
          approval_gate: action.approvalGate,
          output_channel: action.outputRoute,
          report_profile: report ? report.label : ''
        };
      }),
      generated_output: outputText || state.agentLastOutput || ''
    };
  }

  function updateAgentMarketplacePreview() {
    var config = agentConfig();
    if (els.agentMarketplacePreview) {
      els.agentMarketplacePreview.textContent = JSON.stringify(marketplacePreviewPayload(config), null, 2);
    }
    if (els.agentReportPreview) {
      els.agentReportPreview.textContent = JSON.stringify(reportPreviewPayload(config), null, 2);
    }
  }

  function formatAgentSchedule(value, cadence) {
    if (value && value !== 'manual start' && value !== 'not scheduled') {
      return 'scheduled for ' + formatTimestamp(value);
    }
    var label = cadence || 'Manual approval';
    return label === 'Manual approval' ? 'manual approval, no automatic run' : label;
  }

  function agentStatusLabel(action) {
    var status = action.status || 'queued';
    if (status === 'scheduled-draft') return 'Scheduled draft';
    if (status === 'generated') return 'Plan generated';
    if (status === 'delivered') return 'Delivered';
    if (status === 'failed') return 'Needs attention';
    return 'Queued';
  }

  function setAgentWorkflow(value) {
    var workflow = agentWorkflowByValue(value);
    if (els.agentWorkflow) els.agentWorkflow.value = workflow.value;
    Array.prototype.forEach.call(document.querySelectorAll('[data-agent-workflow-card]'), function (button) {
      var selected = button.getAttribute('data-agent-workflow-card') === workflow.value;
      button.setAttribute('aria-pressed', selected ? 'true' : 'false');
    });
  }

  function saveAgentActions() {
    state.agentActions = state.agentActions.slice(0, 12);
    saveStoredJson(STORE.agentActions, state.agentActions);
  }

  function agentDraftAction() {
    var workflow = currentAgentWorkflow();
    var recipe = selectedRecipe();
    var route = currentAgentOutputRoute();
    var report = currentReportProfile();
    var template = currentWorkflowTemplate();
    var now = nowIso();
    return {
      workflow: workflow.prompt,
      workflowValue: workflow.value,
      workflowLabel: workflow.label,
      recipeTitle: recipe ? recipe.title || 'Untitled recipe' : collapseText(els.agentRecipeInput && els.agentRecipeInput.value),
      recipePath: recipe ? recipe.path || recipe.url || '' : '',
      scope: collapseText(els.agentScope && els.agentScope.value) || 'scope to be provided before run',
      cadence: selectedText(els.agentCadence),
      nextRun: els.agentNextRun && els.agentNextRun.value ? els.agentNextRun.value : 'manual start',
      approvalGate: selectedText(els.agentApproval),
      contextPack: selectedText(els.agentContextPack),
      workflowTemplateId: template ? template.id : '',
      workflowTemplateLabel: template ? template.label : 'Custom',
      inputChannelIds: currentInputChannelIds(),
      reportProfileId: report ? report.id : '',
      reportProfileLabel: report ? report.label : '',
      outputRoute: route.label,
      outputRouteValue: route.value,
      outputChannelId: route.id,
      status: 'queued',
      createdAt: now,
      updatedAt: now,
      scheduledFor: els.agentNextRun && els.agentNextRun.value ? els.agentNextRun.value : ''
    };
  }

  function agentActionTitle(action) {
    return (action.workflowLabel || action.workflow || 'Agent action') + ' - ' + (action.scope || 'unspecified scope');
  }

  function renderAgentActions() {
    if (!els.agentActionList) return;
    if (!state.agentActions.length) {
      els.agentActionList.innerHTML = '<div class="ai-chatbot-agent-empty">No queued actions yet. Configure one precise action and add it to the queue.</div>';
      return;
    }
    els.agentActionList.innerHTML = state.agentActions.map(function (action, index) {
      var bits = [
        action.recipeTitle ? 'Recipe: ' + action.recipeTitle : '',
        action.workflowTemplateLabel ? 'Pack: ' + action.workflowTemplateLabel : '',
        'Runs: ' + formatAgentSchedule(action.nextRun || action.scheduledFor, action.cadence),
        'Gate: ' + (action.approvalGate || 'review required'),
        'Output: ' + (action.outputRoute || 'run receipt'),
        action.reportProfileLabel ? 'Report: ' + action.reportProfileLabel : ''
      ].filter(Boolean).join(' | ');
      return '<article class="ai-chatbot-agent-queued">' +
        '<div><span class="ai-chatbot-agent-status-pill" data-status="' + html(action.status || 'queued') + '">' + html(agentStatusLabel(action)) + '</span><strong>' + html(agentActionTitle(action)) + '</strong><small>' + html(bits) + '</small></div>' +
        '<button class="ai-chatbot-agent-remove" type="button" data-agent-remove-action="' + index + '" aria-label="Remove action">Remove</button>' +
      '</article>';
    }).join('');
  }

  function addAgentAction() {
    var action = agentDraftAction();
    state.agentActions.push(action);
    saveAgentActions();
    renderAgentActions();
    updateAgentMarketplacePreview();
    if (els.agentStatus && !state.agentRunning) {
      els.agentStatus.textContent = 'Queued "' + action.workflowLabel + '" for ' + action.scope + '.';
      els.agentStatus.setAttribute('data-kind', 'ok');
    }
  }

  function agentConfig() {
    var recipe = selectedRecipe();
    var draft = agentDraftAction();
    var actions = state.agentActions.length ? state.agentActions.slice() : [draft];
    var report = currentReportProfile();
    var template = currentWorkflowTemplate();
    var route = currentAgentOutputRoute();
    return {
      provider: getAgentProvider(),
      model: els.agentModel ? collapseText(els.agentModel.value) || getModel(getAgentProvider()) : getModel(getAgentProvider()),
      workflow: draft.workflow,
      recipe: recipe,
      scope: draft.scope,
      actions: actions,
      cadence: selectedText(els.agentCadence),
      nextRun: els.agentNextRun && els.agentNextRun.value ? els.agentNextRun.value : 'not scheduled',
      approvalGate: selectedText(els.agentApproval),
      contextPack: selectedText(els.agentContextPack),
      workflowTemplateId: template ? template.id : '',
      reportProfileId: report ? report.id : '',
      inputChannelIds: currentInputChannelIds(),
      outputRoute: route.label,
      outputRouteValue: route.value,
      outputChannelId: route.id
    };
  }

  function agentPrompt(config) {
    var route = outputChannelById(config.outputChannelId || config.outputRouteValue);
    var report = reportProfileById(config.reportProfileId);
    var template = workflowTemplateById(config.workflowTemplateId);
    var selectedInputs = (config.inputChannelIds || []).map(inputChannelById).filter(Boolean);
    var actions = (config.actions || []).map(function (action, index) {
      return [
        String(index + 1) + '. ' + (action.workflow || config.workflow),
        'scope=' + (action.scope || 'unspecified'),
        action.recipeTitle ? 'recipe=' + action.recipeTitle : '',
        action.recipePath ? 'path=' + action.recipePath : '',
        action.workflowTemplateLabel ? 'workflow_pack=' + action.workflowTemplateLabel : '',
        action.reportProfileLabel ? 'report=' + action.reportProfileLabel : '',
        'cadence=' + (action.cadence || config.cadence),
        'next=' + (action.nextRun || config.nextRun),
        'gate=' + (action.approvalGate || config.approvalGate),
        'context=' + (action.contextPack || config.contextPack),
        'output=' + (action.outputRoute || config.outputRoute),
        'status=' + (action.status || 'queued')
      ].filter(Boolean).join(' | ');
    });
    return [
      'Run a beta security remediation agent preview for this configuration.',
      'Workflow: ' + config.workflow,
      'Target scope: ' + config.scope,
      template ? 'Workflow template: ' + template.label + ' - ' + template.description : 'Workflow template: custom',
      config.recipe ? 'Selected recipe: ' + (config.recipe.title || 'Untitled recipe') : 'Selected recipe: none',
      config.recipe && (config.recipe.path || config.recipe.url) ? 'Selected recipe path: ' + (config.recipe.path || config.recipe.url) : '',
      config.recipe && config.recipe.summary ? 'Selected recipe summary: ' + collapseText(config.recipe.summary).slice(0, 900) : '',
      selectedInputs.length ? 'Input channels: ' + selectedInputs.map(function (channel) {
        return channel.label + ' [' + channel.runtime_support + ']';
      }).join('; ') : 'Input channels: none selected',
      actions.length ? 'Queued precise actions:\n' + actions.join('\n') : '',
      'Cadence: ' + config.cadence,
      'Next run: ' + config.nextRun,
      'Approval gate: ' + config.approvalGate,
      'Context pack: ' + config.contextPack,
      report ? 'Report profile: ' + report.label + ' (' + report.format + ')' : 'Report profile: none selected',
      report && Array.isArray(report.sections) ? 'Report sections: ' + report.sections.join(', ') : '',
      'Output route: ' + config.outputRoute,
      'Output route requirement: ' + route.requirement,
      'Output route runtime support: ' + route.runtime_support,
      'Return a concise, route-specific draft that can be delivered by the browser if the required integration is configured.',
      'For Draft PR packet: include branch name, commit summary, PR title, PR body, test plan, rollback, and reviewer checklist.',
      'For GitHub issue, Jira, Slack, Teams, ServiceNow, Linear, Elastic, or Email: include a title or subject and a body/message suitable for that destination.',
      'For Runbook receipt or Server runbook: include exact steps, evidence to collect, stop conditions, and rollback.'
    ].filter(Boolean).join('\n');
  }

  function renderAgentOutput(text, error) {
    if (!els.agentOutput) return;
    els.agentOutput.hidden = false;
    els.agentOutput.setAttribute('data-kind', error ? 'error' : 'ok');
    els.agentOutput.innerHTML = renderMarkdown(text);
    queueMermaidRender();
  }

  function firstMarkdownTitle(text, fallback) {
    var lines = String(text || '').split('\n').map(collapseText).filter(Boolean);
    for (var i = 0; i < lines.length; i++) {
      var heading = /^#{1,4}\s+(.+)$/.exec(lines[i]);
      if (heading) return heading[1].slice(0, 120);
    }
    return (lines[0] || fallback || 'Security remediation action').replace(/^\*+|\*+$/g, '').slice(0, 120);
  }

  function agentDeliverySummary(config, output) {
    var route = outputChannelById(config.outputChannelId || config.outputRouteValue);
    var report = reportProfileById(config.reportProfileId);
    var template = workflowTemplateById(config.workflowTemplateId);
    return [
      'SecurityRecipes beta agent output',
      '',
      'Route: ' + route.label,
      'Provider: ' + providerConfig(config.provider).label + ' / ' + config.model,
      'Scope: ' + config.scope,
      template ? 'Workflow template: ' + template.label : 'Workflow template: custom',
      'Approval gate: ' + config.approvalGate,
      report ? 'Report profile: ' + report.label + ' (' + report.format + ')' : 'Report profile: none selected',
      'Generated: ' + formatTimestamp(nowIso()),
      '',
      String(output || '').trim()
    ].join('\n');
  }

  function deliveryReportContext(config, output) {
    return buildAgentReportContext(config || agentConfig(), output);
  }

  function deliverySeverity(config, output) {
    var ctx = deliveryReportContext(config, output);
    return (ctx && ctx.riskLevel) || 'info';
  }

  function serviceNowPriorityForSeverity(severity) {
    return {
      critical: '1',
      high: '2',
      medium: '3',
      low: '4',
      info: '4'
    }[severity || 'info'] || '4';
  }

  function elasticSeverityForLevel(level) {
    return {
      critical: 'critical',
      high: 'high',
      medium: 'medium',
      low: 'low',
      info: 'low'
    }[level || 'info'] || 'low';
  }

  function genericWebhookHeaders() {
    var headers = parseJsonObjectInput(getIntegrationField('genericWebhookHeaders'), 'Generic webhook headers');
    var authHeader = trimText(getIntegrationField('genericWebhookAuthHeader'));
    if (authHeader && !headers.Authorization) headers.Authorization = authHeader;
    return headers;
  }

  async function deliverGitHubIssue(config, output) {
    var parsed = parseGitHubRepository(currentGitHubRepositoryInput());
    if (!parsed) throw new Error('GitHub issue output needs a repository in Settings, for example owner/repo.');
    if (!getGitHubToken()) throw new Error('GitHub issue output needs a saved GitHub PAT or OAuth token with issues write access.');
    var title = firstMarkdownTitle(output, agentActionTitle((config.actions || [])[0] || {}));
    var body = agentDeliverySummary(config, output);
    var issue = await githubWriteJson('/repos/' + repoApiPath(parsed.fullName) + '/issues', {
      title: title,
      body: body,
      labels: ['security-remediation', 'ai-agent-draft']
    });
    return 'GitHub issue created: ' + (issue.html_url || ('#' + issue.number));
  }

  async function deliverSlack(config, output) {
    var webhook = getIntegrationField('slackWebhook');
    if (!webhook) throw new Error('Slack output needs an incoming webhook URL saved in Agent integrations.');
    var payload = { text: agentDeliverySummary(config, output) };
    var response = await fetch(webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!response.ok) throw new Error('Slack webhook returned ' + statusLine(response.status, response.statusText) + '.');
    return 'Slack message delivered: ' + statusLine(response.status, response.statusText) + '.';
  }

  async function deliverTeams(config, output) {
    var webhook = getIntegrationField('teamsWebhook');
    if (!webhook) throw new Error('Teams output needs a Teams Workflows webhook URL saved in Agent integrations.');
    var summary = agentDeliverySummary(config, output);
    var payload = { text: summary.slice(0, 24000) };
    var posted = await postJson(webhook, { body: payload });
    if (!posted.response.ok) {
      throw new Error('Teams workflow webhook returned ' + statusLine(posted.response.status, posted.response.statusText) + '. Browser CORS or workflow ownership may require a different endpoint.');
    }
    return 'Teams workflow accepted handoff: ' + statusLine(posted.response.status, posted.response.statusText) + '.';
  }

  async function deliverEmail(config, output) {
    var to = getIntegrationField('emailRecipient');
    if (!to) throw new Error('Email output needs a recipient saved in Agent integrations.');
    var subject = firstMarkdownTitle(output, 'Security remediation handoff');
    var body = agentDeliverySummary(config, output);
    var relay = getIntegrationField('smtpRelayUrl');
    if (relay) {
      var response = await fetch(relay, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to: to, subject: subject, body: body })
      });
      if (!response.ok) throw new Error('Email relay returned ' + statusLine(response.status, response.statusText) + '. Browser CORS may require a same-origin relay.');
      return 'Email relay accepted handoff: ' + statusLine(response.status, response.statusText) + '.';
    }
    var mailto = 'mailto:' + encodeURIComponent(to) +
      '?subject=' + encodeURIComponent(subject) +
      '&body=' + encodeURIComponent(body.slice(0, 6500));
    window.location.href = mailto;
    return 'Email draft opened for ' + to + '.';
  }

  async function deliverJira(config, output) {
    var base = getIntegrationField('jiraBaseUrl').replace(/\/+$/, '');
    var email = getIntegrationField('jiraEmail');
    var token = getIntegrationField('jiraToken');
    var project = getIntegrationField('jiraProject');
    if (!base || !email || !token || !project) {
      throw new Error('Jira output needs base URL, account email, API token, and project key saved in Agent integrations.');
    }
    var response = await fetch(base + '/rest/api/3/issue', {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + btoa(email + ':' + token),
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        fields: {
          project: { key: project },
          issuetype: { name: 'Task' },
          summary: firstMarkdownTitle(output, 'Security remediation task'),
          description: {
            type: 'doc',
            version: 1,
            content: [{
              type: 'paragraph',
              content: [{ type: 'text', text: agentDeliverySummary(config, output).slice(0, 30000) }]
            }]
          }
        }
      })
    });
    if (!response.ok) throw new Error('Jira returned ' + statusLine(response.status, response.statusText) + '. Browser CORS may require a backend relay.');
    var data = await response.json();
    return 'Jira issue created: ' + (data.key || 'created');
  }

  async function deliverServiceNow(config, output) {
    var base = getIntegrationField('serviceNowBaseUrl').replace(/\/+$/, '');
    var table = collapseText(getIntegrationField('serviceNowTable') || 'incident');
    var token = getIntegrationField('serviceNowToken');
    if (!base || !table || !token) {
      throw new Error('ServiceNow output needs an instance URL, table name, and OAuth bearer token saved in Agent integrations.');
    }
    var title = firstMarkdownTitle(output, 'Security remediation incident');
    var summary = agentDeliverySummary(config, output);
    var severity = deliverySeverity(config, output);
    var posted = await postJson(base + '/api/now/v1/table/' + encodeURIComponent(table), {
      headers: {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: {
        short_description: title,
        description: summary.slice(0, 32000),
        comments: 'Generated in SecurityRecipes browser runtime.',
        impact: serviceNowPriorityForSeverity(severity),
        urgency: serviceNowPriorityForSeverity(severity)
      }
    });
    if (!posted.response.ok) {
      throw new Error('ServiceNow returned ' + statusLine(posted.response.status, posted.response.statusText) + '. Browser CORS or token scope may require an approved relay.');
    }
    var record = posted.data && posted.data.result ? posted.data.result : {};
    return 'ServiceNow record created: ' + (record.number || record.sys_id || 'created');
  }

  async function deliverLinear(config, output) {
    var apiKey = getIntegrationField('linearApiKey');
    var teamId = getIntegrationField('linearTeamId');
    if (!apiKey || !teamId) {
      throw new Error('Linear output needs a personal API key and a team ID saved in Agent integrations.');
    }
    var title = firstMarkdownTitle(output, 'Security remediation issue');
    var summary = agentDeliverySummary(config, output);
    var posted = await postJson('https://api.linear.app/graphql', {
      headers: {
        'Authorization': apiKey
      },
      body: {
        query: 'mutation SecurityRecipesIssueCreate($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier title url } } }',
        variables: {
          input: {
            title: title,
            description: summary.slice(0, 50000),
            teamId: teamId
          }
        }
      }
    });
    if (!posted.response.ok) {
      throw new Error('Linear returned ' + statusLine(posted.response.status, posted.response.statusText) + '. Browser CORS or key permissions may require an approved relay.');
    }
    if (posted.data && Array.isArray(posted.data.errors) && posted.data.errors.length) {
      throw new Error('Linear issue creation failed: ' + (posted.data.errors[0].message || 'GraphQL error') + '.');
    }
    var createResult = posted.data && posted.data.data && posted.data.data.issueCreate;
    if (createResult && createResult.success === false) throw new Error('Linear issue creation failed.');
    var issue = createResult && createResult.issue;
    return 'Linear issue created: ' + (issue && (issue.identifier || issue.id || issue.title) || 'created');
  }

  async function deliverSplunkHec(config, output) {
    var hecUrl = getIntegrationField('splunkHecUrl');
    var token = getIntegrationField('splunkHecToken');
    if (!hecUrl || !token) {
      throw new Error('Splunk output needs an HEC URL and HEC token saved in Agent integrations.');
    }
    var envelope = deliveryEnvelopePayload(config, output);
    var eventPayload = {
      event: envelope
    };
    var sourceType = collapseText(getIntegrationField('splunkSourceType') || 'securityrecipes:report');
    var index = collapseText(getIntegrationField('splunkIndex') || '');
    if (sourceType) eventPayload.sourcetype = sourceType;
    if (index) eventPayload.index = index;
    var posted = await postJson(hecUrl, {
      headers: {
        'Authorization': 'Splunk ' + token
      },
      body: eventPayload
    });
    if (!posted.response.ok) {
      throw new Error('Splunk HEC returned ' + statusLine(posted.response.status, posted.response.statusText) + '. Browser CORS or HEC settings may require a relay.');
    }
    if (posted.data && Number(posted.data.code) !== 0) {
      throw new Error('Splunk HEC rejected the event: ' + (posted.data.text || 'unknown error') + '.');
    }
    return 'Splunk HEC accepted event: ' + statusLine(posted.response.status, posted.response.statusText) + '.';
  }

  async function deliverElasticCase(config, output) {
    var base = getIntegrationField('elasticBaseUrl').replace(/\/+$/, '');
    var apiKey = getIntegrationField('elasticApiKey');
    if (!base || !apiKey) {
      throw new Error('Elastic output needs a Kibana base URL and API key saved in Agent integrations.');
    }
    var spaceId = collapseText(getIntegrationField('elasticSpaceId'));
    var owner = collapseText(getIntegrationField('elasticOwner') || 'securitySolution');
    var path = (spaceId && spaceId !== 'default' ? '/s/' + encodeURIComponent(spaceId) : '') + '/api/cases';
    var title = firstMarkdownTitle(output, 'Security remediation case');
    var summary = agentDeliverySummary(config, output);
    var posted = await postJson(base + path, {
      headers: {
        'Authorization': 'ApiKey ' + apiKey,
        'kbn-xsrf': 'securityrecipes-browser'
      },
      body: {
        connector: {
          id: 'none',
          name: 'none',
          type: '.none',
          fields: null
        },
        description: summary.slice(0, 30000),
        owner: owner,
        settings: {
          extractObservables: true,
          syncAlerts: false
        },
        severity: elasticSeverityForLevel(deliverySeverity(config, output)),
        status: 'open',
        tags: ['security-recipes', 'browser-agent'],
        title: title
      }
    });
    if (!posted.response.ok) {
      throw new Error('Elastic Cases returned ' + statusLine(posted.response.status, posted.response.statusText) + '. Browser CORS or API key privileges may require an approved relay.');
    }
    return 'Elastic case created: ' + ((posted.data && (posted.data.id || posted.data.title)) || 'created');
  }

  async function deliverGenericWebhook(config, output) {
    var url = getIntegrationField('genericWebhookUrl');
    if (!url) throw new Error('Generic webhook output needs a target URL saved in Agent integrations.');
    var method = collapseText(getIntegrationField('genericWebhookMethod') || 'POST').toUpperCase();
    var posted = await postJson(url, {
      method: method,
      headers: genericWebhookHeaders(),
      body: deliveryEnvelopePayload(config, output)
    });
    if (!posted.response.ok) {
      throw new Error('Generic webhook returned ' + statusLine(posted.response.status, posted.response.statusText) + '.');
    }
    return 'Generic webhook delivered: ' + statusLine(posted.response.status, posted.response.statusText) + '.';
  }

  async function deliverAgentOutput() {
    if (!state.agentLastOutput || !state.agentLastConfig) {
      renderAgentOutput('Generate an agent plan first, then run the selected output.', true);
      return;
    }
    var selectedRoute = currentAgentOutputRoute();
    var config = Object.assign({}, state.agentLastConfig, {
      outputRoute: selectedRoute.label,
      outputRouteValue: selectedRoute.value,
      outputChannelId: selectedRoute.id
    });
    var route = selectedRoute;
    try {
      if (els.agentDeliver) els.agentDeliver.disabled = true;
      if (els.agentStatus) {
        els.agentStatus.textContent = 'Running output route: ' + route.label + '...';
        els.agentStatus.removeAttribute('data-kind');
      }
      var result;
      if (route.value === 'github-issue') result = await deliverGitHubIssue(config, state.agentLastOutput);
      else if (route.value === 'slack') result = await deliverSlack(config, state.agentLastOutput);
      else if (route.value === 'teams') result = await deliverTeams(config, state.agentLastOutput);
      else if (route.value === 'email') result = await deliverEmail(config, state.agentLastOutput);
      else if (route.value === 'jira') result = await deliverJira(config, state.agentLastOutput);
      else if (route.value === 'servicenow') result = await deliverServiceNow(config, state.agentLastOutput);
      else if (route.value === 'linear') result = await deliverLinear(config, state.agentLastOutput);
      else if (route.value === 'splunk-hec') result = await deliverSplunkHec(config, state.agentLastOutput);
      else if (route.value === 'elastic-case') result = await deliverElasticCase(config, state.agentLastOutput);
      else if (route.value === 'generic-webhook') result = await deliverGenericWebhook(config, state.agentLastOutput);
      else {
        var copyValue = (route.runtime_support === 'config_only' || route.value === 'clipboard')
          ? JSON.stringify(deliveryEnvelopePayload(config, state.agentLastOutput), null, 2)
          : agentDeliverySummary(config, state.agentLastOutput);
        try {
          await copyText(copyValue);
          result = route.label + ' copied locally. No external write was attempted.';
        } catch (copyError) {
          result = route.label + ' generated locally. Clipboard copy was unavailable, so review the plan above; no external write was attempted.';
        }
      }

      state.agentActions = state.agentActions.map(function (action) {
        action.status = 'delivered';
        action.updatedAt = nowIso();
        return action;
      });
      saveAgentActions();
      renderAgentActions();
      if (els.agentStatus) {
        els.agentStatus.textContent = result;
        els.agentStatus.setAttribute('data-kind', 'ok');
      }
    } catch (error) {
      if (els.agentStatus) {
        els.agentStatus.textContent = error && error.message ? error.message : 'Output route failed.';
        els.agentStatus.setAttribute('data-kind', 'error');
      }
      renderAgentOutput((state.agentLastOutput || '') + '\n\nDelivery note: ' + failureMessage(error), true);
    } finally {
      if (els.agentDeliver) els.agentDeliver.disabled = false;
    }
  }

  function saveAgentIntegrationSettings() {
    setIntegrationField('slackWebhook', els.slackWebhook && els.slackWebhook.value);
    setIntegrationField('teamsWebhook', els.teamsWebhook && els.teamsWebhook.value);
    setIntegrationField('emailRecipient', els.emailRecipient && els.emailRecipient.value);
    setIntegrationField('smtpRelayUrl', els.smtpRelayUrl && els.smtpRelayUrl.value);
    setIntegrationField('jiraBaseUrl', els.jiraBaseUrl && els.jiraBaseUrl.value);
    setIntegrationField('jiraEmail', els.jiraEmail && els.jiraEmail.value);
    setIntegrationField('jiraToken', els.jiraToken && els.jiraToken.value);
    setIntegrationField('jiraProject', els.jiraProject && els.jiraProject.value);
    setIntegrationField('serviceNowBaseUrl', els.serviceNowBaseUrl && els.serviceNowBaseUrl.value);
    setIntegrationField('serviceNowTable', els.serviceNowTable && els.serviceNowTable.value);
    setIntegrationField('serviceNowToken', els.serviceNowToken && els.serviceNowToken.value);
    setIntegrationField('linearApiKey', els.linearApiKey && els.linearApiKey.value);
    setIntegrationField('linearTeamId', els.linearTeamId && els.linearTeamId.value);
    setIntegrationField('splunkHecUrl', els.splunkHecUrl && els.splunkHecUrl.value);
    setIntegrationField('splunkHecToken', els.splunkHecToken && els.splunkHecToken.value);
    setIntegrationField('splunkIndex', els.splunkIndex && els.splunkIndex.value);
    setIntegrationField('splunkSourceType', els.splunkSourceType && els.splunkSourceType.value);
    setIntegrationField('elasticBaseUrl', els.elasticBaseUrl && els.elasticBaseUrl.value);
    setIntegrationField('elasticApiKey', els.elasticApiKey && els.elasticApiKey.value);
    setIntegrationField('elasticSpaceId', els.elasticSpaceId && els.elasticSpaceId.value);
    setIntegrationField('elasticOwner', els.elasticOwner && els.elasticOwner.value);
    setIntegrationField('genericWebhookUrl', els.genericWebhookUrl && els.genericWebhookUrl.value);
    setIntegrationField('genericWebhookMethod', els.genericWebhookMethod && els.genericWebhookMethod.value);
    setIntegrationField('genericWebhookAuthHeader', els.genericWebhookAuthHeader && els.genericWebhookAuthHeader.value);
    setIntegrationField('genericWebhookHeaders', els.genericWebhookHeaders && els.genericWebhookHeaders.value);
    if (els.agentStatus && !state.agentRunning) {
      els.agentStatus.textContent = 'Agent integration settings saved in this browser.';
      els.agentStatus.setAttribute('data-kind', 'ok');
    }
  }

  function updateAgentIntegrationUI() {
    if (els.slackWebhook) els.slackWebhook.value = getIntegrationField('slackWebhook');
    if (els.teamsWebhook) els.teamsWebhook.value = getIntegrationField('teamsWebhook');
    if (els.emailRecipient) els.emailRecipient.value = getIntegrationField('emailRecipient');
    if (els.smtpRelayUrl) els.smtpRelayUrl.value = getIntegrationField('smtpRelayUrl');
    if (els.jiraBaseUrl) els.jiraBaseUrl.value = getIntegrationField('jiraBaseUrl');
    if (els.jiraEmail) els.jiraEmail.value = getIntegrationField('jiraEmail');
    if (els.jiraToken) els.jiraToken.value = getIntegrationField('jiraToken');
    if (els.jiraProject) els.jiraProject.value = getIntegrationField('jiraProject');
    if (els.serviceNowBaseUrl) els.serviceNowBaseUrl.value = getIntegrationField('serviceNowBaseUrl');
    if (els.serviceNowTable) els.serviceNowTable.value = getIntegrationField('serviceNowTable') || 'incident';
    if (els.serviceNowToken) els.serviceNowToken.value = getIntegrationField('serviceNowToken');
    if (els.linearApiKey) els.linearApiKey.value = getIntegrationField('linearApiKey');
    if (els.linearTeamId) els.linearTeamId.value = getIntegrationField('linearTeamId');
    if (els.splunkHecUrl) els.splunkHecUrl.value = getIntegrationField('splunkHecUrl');
    if (els.splunkHecToken) els.splunkHecToken.value = getIntegrationField('splunkHecToken');
    if (els.splunkIndex) els.splunkIndex.value = getIntegrationField('splunkIndex');
    if (els.splunkSourceType) els.splunkSourceType.value = getIntegrationField('splunkSourceType') || 'securityrecipes:report';
    if (els.elasticBaseUrl) els.elasticBaseUrl.value = getIntegrationField('elasticBaseUrl');
    if (els.elasticApiKey) els.elasticApiKey.value = getIntegrationField('elasticApiKey');
    if (els.elasticSpaceId) els.elasticSpaceId.value = getIntegrationField('elasticSpaceId') || 'default';
    if (els.elasticOwner) els.elasticOwner.value = getIntegrationField('elasticOwner') || 'securitySolution';
    if (els.genericWebhookUrl) els.genericWebhookUrl.value = getIntegrationField('genericWebhookUrl');
    if (els.genericWebhookMethod) els.genericWebhookMethod.value = getIntegrationField('genericWebhookMethod') || 'POST';
    if (els.genericWebhookAuthHeader) els.genericWebhookAuthHeader.value = getIntegrationField('genericWebhookAuthHeader');
    if (els.genericWebhookHeaders) els.genericWebhookHeaders.value = getIntegrationField('genericWebhookHeaders');
  }

  function saveScheduleDraft() {
    var now = nowIso();
    if (!state.agentActions.length) state.agentActions.push(agentDraftAction());
    state.agentActions = state.agentActions.map(function (action) {
      action.status = 'scheduled-draft';
      action.updatedAt = now;
      action.scheduledAt = now;
      action.scheduledFor = action.nextRun && action.nextRun !== 'manual start' ? action.nextRun : '';
      return action;
    });
    saveAgentActions();
    renderAgentActions();
    if (els.agentStatus) {
      els.agentStatus.textContent = 'Schedule draft saved locally for ' + state.agentActions.length + ' action(s). Runs are prepared in-browser; a backend scheduler is still required for unattended execution.';
      els.agentStatus.setAttribute('data-kind', 'ok');
    }
  }

  async function handleAgentPreview() {
    if (state.agentRunning) return;
    await ensureDocsIndex();
    if (state.includeGitHub) await prepareGitHubContext();
    if (state.includeDepsDev) await prepareDepsDevContext();
    if (!state.agentRecipePath && els.agentRecipeInput && collapseText(els.agentRecipeInput.value)) {
      var inferredRecipe = selectedRecipe();
      if (inferredRecipe) selectAgentRecipe(inferredRecipe);
    }
    var config = agentConfig();
    state.agentRunning = true;
    if (els.agentPreview) els.agentPreview.disabled = true;
    if (els.agentStatus) {
      els.agentStatus.textContent = 'Running ' + config.workflow + ' with ' + providerConfig(config.provider).label + '...';
      els.agentStatus.removeAttribute('data-kind');
    }

    try {
      var prompt = agentPrompt(config);
      var system = buildSystemPrompt(prompt) +
        '\n\nYou are running as a scheduled remediation agent preview. Do not claim to have created tickets, commits, pull requests, or background jobs.';
      var answer = await sendToProvider(prompt, {
        provider: config.provider,
        model: config.model,
        history: [],
        system: system
      });
      state.agentLastOutput = answer;
      state.agentLastConfig = config;
      state.agentActions = (config.actions || state.agentActions).map(function (action) {
        action.status = 'generated';
        action.updatedAt = nowIso();
        return action;
      });
      saveAgentActions();
      renderAgentActions();
      renderAgentOutput(answer, false);
      updateAgentMarketplacePreview();
      if (els.agentStatus) {
        els.agentStatus.textContent = 'Preview completed with ' + providerConfig(config.provider).label + ' / ' + config.model + '.';
        els.agentStatus.setAttribute('data-kind', 'ok');
      }
    } catch (error) {
      renderAgentOutput(failureMessage(error), true);
      if (els.agentStatus) {
        els.agentStatus.textContent = 'Agent preview failed.';
        els.agentStatus.setAttribute('data-kind', 'error');
      }
    } finally {
      state.agentRunning = false;
      if (els.agentPreview) els.agentPreview.disabled = false;
    }
  }

  async function handleSend(event) {
    event.preventDefault();
    if (state.sending) return;
    var text = collapseText(els.prompt.value);
    if (!text) return;
    var assistantMessage = null;

    state.messages.push({ role: 'user', content: text, createdAt: nowIso() });
    saveChatHistoryStorage();
    els.prompt.value = '';
    renderMessages();
    setStatus('Building site context...', '');
    state.sending = true;
    els.send.disabled = true;

    try {
      await ensureDocsIndex();
      if (state.includeGitHub) await prepareGitHubContext();
      if (state.includeDepsDev) await prepareDepsDevContext();
      var history = apiHistory();
      var system = buildSystemPrompt(text);
      assistantMessage = { role: 'assistant', content: '', createdAt: nowIso(), streaming: true, provider: state.provider };
      state.messages.push(assistantMessage);
      renderMessages();
      setStatus('Streaming from ' + providerConfig().label + '...', '');
      var answer = await sendToProvider(text, {
        history: history,
        system: system,
        onDelta: function (delta) {
          assistantMessage.content += delta;
          renderMessages();
        }
      });
      assistantMessage.streaming = false;
      if (!assistantMessage.content.trim()) assistantMessage.content = answer;
      saveChatHistoryStorage();
      setStatus(maskToken(getToken()), 'ok');
    } catch (error) {
      if (assistantMessage) {
        assistantMessage.streaming = false;
        assistantMessage.error = true;
        assistantMessage.content = assistantMessage.content.trim()
          ? assistantMessage.content + '\n\n' + failureMessage(error)
          : failureMessage(error);
      } else {
        state.messages.push({
          role: 'assistant',
          content: failureMessage(error),
          error: true,
          createdAt: nowIso()
        });
      }
      saveChatHistoryStorage();
      setStatus('Request failed', 'error');
    } finally {
      state.sending = false;
      els.send.disabled = false;
      renderMessages();
    }
  }

  function mount() {
    var shell = document.createElement('div');
    shell.className = 'ai-chatbot-shell';
    shell.innerHTML =
      '<button class="ai-chatbot-launch" type="button" aria-expanded="false" aria-controls="ai-chatbot-panel">' +
        icon('bot') + '<span>AI Remediation</span>' +
      '</button>' +
      '<section id="ai-chatbot-panel" class="ai-chatbot-panel" aria-label="AI remediation assistant" hidden>' +
        '<header class="ai-chatbot-header">' +
          '<div class="ai-chatbot-title">' +
            '<strong>Security Remediation AI</strong>' +
            '<span>Client-side provider token</span>' +
            '<button class="ai-chatbot-provider-badge" type="button" data-provider-badge></button>' +
          '</div>' +
          '<div class="ai-chatbot-header-actions">' +
            '<button class="ai-chatbot-icon-button" type="button" data-expand aria-label="Expand full screen" aria-pressed="false" title="Expand full screen">' + icon('expand') + '</button>' +
            '<button class="ai-chatbot-icon-button" type="button" data-close aria-label="Close">' + icon('close') + '</button>' +
          '</div>' +
        '</header>' +
        '<div class="ai-chatbot-tabs" role="tablist" aria-label="AI assistant views">' +
          '<button class="ai-chatbot-tab" type="button" data-tab="chat" aria-selected="true">Chat</button>' +
          '<button class="ai-chatbot-tab" type="button" data-tab="search" aria-selected="false">Search</button>' +
          '<button class="ai-chatbot-tab" type="button" data-tab="agents" aria-selected="false">Agents <span class="ai-chatbot-beta-tag">Beta</span></button>' +
        '</div>' +
        '<div class="ai-chatbot-panel-body">' +
          '<div class="ai-chatbot-tab-panel" data-panel="chat">' +
            '<div class="ai-chatbot-settings">' +
              '<button class="ai-chatbot-settings-toggle" type="button" data-settings-toggle aria-expanded="false" aria-controls="ai-chatbot-settings-content">' +
                '<span>Settings</span><strong data-settings-summary></strong>' + icon('chevron') +
              '</button>' +
              '<div id="ai-chatbot-settings-content" class="ai-chatbot-settings-content" data-settings-content hidden>' +
                '<div class="ai-chatbot-settings-row">' +
                  '<label class="ai-chatbot-field"><span>Provider</span><select data-provider><option value="openai">OpenAI</option><option value="grok">Grok</option><option value="claude">Claude</option></select></label>' +
                  '<label class="ai-chatbot-field"><span>Model</span><select data-model></select></label>' +
                '</div>' +
                '<details class="ai-chatbot-settings-block" data-provider-credential-details>' +
                  '<summary class="ai-chatbot-github-heading"><span>Provider credential</span><small>API key or OAuth bearer. Saved only in this browser profile.</small></summary>' +
                  '<div class="ai-chatbot-github-content">' +
                    '<div class="ai-chatbot-credential-row" role="group" aria-label="Credential type">' +
                      '<button class="ai-chatbot-mode-button" type="button" data-credential-mode="api_key" aria-pressed="true">API key</button>' +
                      '<button class="ai-chatbot-mode-button" type="button" data-credential-mode="oauth" aria-pressed="false">OAuth bearer</button>' +
                    '</div>' +
                    '<div class="ai-chatbot-token-row">' +
                      '<label class="ai-chatbot-field"><span data-token-label>API token</span><input data-token type="password" autocomplete="off" placeholder="Stored in this browser"></label>' +
                      '<button class="ai-chatbot-action" type="button" data-save-token>' + icon('save') + '<span>Save</span></button>' +
                      '<button class="ai-chatbot-action danger" type="button" data-clear-token>Clear</button>' +
                    '</div>' +
                    '<details class="ai-chatbot-oauth-block" data-oauth-details hidden>' +
                      '<summary class="ai-chatbot-oauth-heading"><span>Browser OAuth</span><small>Optional PKCE flow; bearer token stays in this browser.</small></summary>' +
                      '<div class="ai-chatbot-oauth-content">' +
                        '<div class="ai-chatbot-oauth-grid">' +
                          '<label class="ai-chatbot-field"><span>Client ID</span><input data-oauth-client-id type="text" autocomplete="off" placeholder="OAuth app client ID"></label>' +
                          '<label class="ai-chatbot-field"><span>Scope</span><input data-oauth-scope type="text" autocomplete="off" placeholder="Optional scopes"></label>' +
                          '<label class="ai-chatbot-field ai-chatbot-wide-field"><span>Authorization URL</span><input data-oauth-auth-url type="url" autocomplete="off" placeholder="https://provider.example/oauth/authorize"></label>' +
                          '<label class="ai-chatbot-field ai-chatbot-wide-field"><span>Token URL</span><input data-oauth-token-url type="url" autocomplete="off" placeholder="https://provider.example/oauth/token"></label>' +
                        '</div>' +
                        '<div class="ai-chatbot-actions-row">' +
                          '<div class="ai-chatbot-status" data-oauth-status></div>' +
                          '<div class="ai-chatbot-inline-actions">' +
                            '<button class="ai-chatbot-action secondary" type="button" data-save-oauth-config>Save OAuth config</button>' +
                            '<button class="ai-chatbot-action" type="button" data-start-oauth>Authorize in browser</button>' +
                          '</div>' +
                        '</div>' +
                      '</div>' +
                    '</details>' +
                  '</div>' +
                '</details>' +
                '<details class="ai-chatbot-settings-block" data-context-details>' +
                  '<summary class="ai-chatbot-github-heading"><span>Context sources</span><small>Toggle exactly what gets sent with prompts.</small></summary>' +
                  '<div class="ai-chatbot-github-content">' +
                    '<div class="ai-chatbot-context-row">' +
                      '<label class="ai-chatbot-check"><input data-context type="checkbox"><span>Page context</span></label>' +
                      '<label class="ai-chatbot-check"><input data-related type="checkbox"><span>Recipe index</span></label>' +
                      '<label class="ai-chatbot-check"><input data-github-context type="checkbox"><span>GitHub repository</span></label>' +
                      '<label class="ai-chatbot-check"><input data-depsdev-context type="checkbox"><span>deps.dev CVEs</span></label>' +
                      '<label class="ai-chatbot-check"><input data-sarif-context type="checkbox"><span>SARIF upload</span></label>' +
                      '<label class="ai-chatbot-check"><input data-sbom-context type="checkbox"><span>SBOM upload</span></label>' +
                    '</div>' +
                  '</div>' +
                '</details>' +
                '<details class="ai-chatbot-github-block" data-github-details>' +
                  '<summary class="ai-chatbot-github-heading"><span>GitHub repository context</span><small>Public metadata needs no auth; private repos and write actions need GitHub auth.</small></summary>' +
                  '<div class="ai-chatbot-github-content">' +
                    '<div class="ai-chatbot-capability-list">' +
                      '<span>README, SECURITY, CONTRIBUTING, manifests <em>public: no auth / private: token</em></span>' +
                      '<span>Open issues and pull requests <em>public: no auth / private or higher limits: token</em></span>' +
                      '<span>Dependency Graph SBOM <em>repo must expose graph; private requires token</em></span>' +
                      '<span>Create GitHub issue from agent output <em>token with issue write access</em></span>' +
                    '</div>' +
                    '<div class="ai-chatbot-token-row">' +
                      '<label class="ai-chatbot-field"><span>Repository</span><input data-github-repo-url type="text" autocomplete="off" placeholder="https://github.com/owner/repo or owner/repo"></label>' +
                      '<button class="ai-chatbot-action" type="button" data-load-github-context>Load context</button>' +
                      '<button class="ai-chatbot-action danger" type="button" data-clear-github-context>Clear</button>' +
                    '</div>' +
                    '<div class="ai-chatbot-credential-row" role="group" aria-label="GitHub credential type">' +
                      '<button class="ai-chatbot-mode-button" type="button" data-github-auth-mode="pat" aria-pressed="true">PAT</button>' +
                      '<button class="ai-chatbot-mode-button" type="button" data-github-auth-mode="oauth" aria-pressed="false">OAuth token</button>' +
                    '</div>' +
                    '<div class="ai-chatbot-token-row">' +
                      '<label class="ai-chatbot-field"><span data-github-token-label>GitHub PAT</span><input data-github-token type="password" autocomplete="off" placeholder="Stored in this browser"></label>' +
                      '<button class="ai-chatbot-action" type="button" data-save-github-token>' + icon('save') + '<span>Save</span></button>' +
                      '<button class="ai-chatbot-action danger" type="button" data-clear-github-token>Clear</button>' +
                    '</div>' +
                    '<details class="ai-chatbot-oauth-block" data-github-oauth-details hidden>' +
                      '<summary class="ai-chatbot-oauth-heading"><span>GitHub browser OAuth</span><small>PKCE where supported; paste an OAuth token if your app requires a server exchange.</small></summary>' +
                      '<div class="ai-chatbot-oauth-content">' +
                        '<div class="ai-chatbot-oauth-grid">' +
                          '<label class="ai-chatbot-field"><span>Client ID</span><input data-github-oauth-client-id type="text" autocomplete="off" placeholder="GitHub OAuth app client ID"></label>' +
                          '<label class="ai-chatbot-field"><span>Scope</span><input data-github-oauth-scope type="text" autocomplete="off" placeholder="repo read:org workflow"></label>' +
                          '<label class="ai-chatbot-field ai-chatbot-wide-field"><span>Authorization URL</span><input data-github-oauth-auth-url type="url" autocomplete="off"></label>' +
                          '<label class="ai-chatbot-field ai-chatbot-wide-field"><span>Token URL</span><input data-github-oauth-token-url type="url" autocomplete="off"></label>' +
                        '</div>' +
                        '<div class="ai-chatbot-actions-row">' +
                          '<div class="ai-chatbot-status">GitHub credentials stay in localStorage and are sent only with GitHub API requests from this browser.</div>' +
                          '<div class="ai-chatbot-inline-actions">' +
                            '<button class="ai-chatbot-action secondary" type="button" data-save-github-oauth-config>Save OAuth config</button>' +
                            '<button class="ai-chatbot-action" type="button" data-start-github-oauth>Login via browser</button>' +
                          '</div>' +
                        '</div>' +
                      '</div>' +
                    '</details>' +
                    '<div class="ai-chatbot-actions-row">' +
                      '<div class="ai-chatbot-status" data-github-status></div>' +
                    '</div>' +
                  '</div>' +
                '</details>' +
                '<details class="ai-chatbot-depsdev-block" data-depsdev-details>' +
                  '<summary class="ai-chatbot-github-heading"><span>Dependency intelligence</span><small>GitHub Dependency Graph SBOM plus deps.dev advisory checks.</small></summary>' +
                  '<div class="ai-chatbot-github-content">' +
                    '<div class="ai-chatbot-actions-row">' +
                      '<div class="ai-chatbot-status" data-depsdev-status></div>' +
                      '<button class="ai-chatbot-action secondary" type="button" data-load-depsdev-context>Check dependencies</button>' +
                    '</div>' +
                  '</div>' +
                '</details>' +
                '<details class="ai-chatbot-settings-block" data-imported-context-details>' +
                  '<summary class="ai-chatbot-github-heading"><span>Imported scan evidence</span><small>Upload local SARIF or SBOM files. The browser stores only a bounded summary until you clear it.</small></summary>' +
                  '<div class="ai-chatbot-github-content">' +
                    '<div class="ai-chatbot-capability-list">' +
                      '<span>SARIF 2.1.0 uploads <em>CodeQL, Semgrep, Snyk, Gitleaks, Checkov, and other scanners that export SARIF.</em></span>' +
                      '<span>CycloneDX or SPDX JSON uploads <em>Software inventory, dependency relationships, and vulnerability metadata for package review.</em></span>' +
                    '</div>' +
                    '<div class="ai-chatbot-agent-grid">' +
                      '<div class="ai-chatbot-settings-block">' +
                        '<div class="ai-chatbot-github-heading"><span>SARIF findings</span><small>Attach scanner results locally for SAST, SCA, secret, or IaC triage.</small></div>' +
                        '<label class="ai-chatbot-field"><span>Local SARIF file</span><input data-sarif-file type="file" accept=".sarif,.sarif.json,.json,application/json"></label>' +
                        '<div class="ai-chatbot-actions-row">' +
                          '<div class="ai-chatbot-status" data-sarif-status></div>' +
                          '<button class="ai-chatbot-action danger" type="button" data-clear-sarif-context>Clear</button>' +
                        '</div>' +
                      '</div>' +
                      '<div class="ai-chatbot-settings-block">' +
                        '<div class="ai-chatbot-github-heading"><span>SBOM inventory</span><small>Attach CycloneDX or SPDX JSON locally for dependency and package risk review.</small></div>' +
                        '<label class="ai-chatbot-field"><span>Local SBOM file</span><input data-sbom-file type="file" accept=".cdx.json,.spdx.json,.bom.json,.json,application/json"></label>' +
                        '<div class="ai-chatbot-actions-row">' +
                          '<div class="ai-chatbot-status" data-sbom-status></div>' +
                          '<button class="ai-chatbot-action danger" type="button" data-clear-sbom-context>Clear</button>' +
                        '</div>' +
                      '</div>' +
                    '</div>' +
                  '</div>' +
                '</details>' +
                '<div class="ai-chatbot-actions-row">' +
                  '<div class="ai-chatbot-status" data-status></div>' +
                  '<button class="ai-chatbot-action secondary" type="button" data-reset>' + icon('reset') + '<span>Reset</span></button>' +
                '</div>' +
              '</div>' +
            '</div>' +
            '<div class="ai-chatbot-messages" data-messages></div>' +
            '<form class="ai-chatbot-composer" data-form>' +
              '<label class="ai-chatbot-field"><textarea data-prompt placeholder="Ask for a remediation plan, prompt, runbook, or context check"></textarea></label>' +
              '<button class="ai-chatbot-action" type="submit" data-send>' + icon('send') + '<span>Send</span></button>' +
            '</form>' +
          '</div>' +
          '<div class="ai-chatbot-tab-panel ai-chatbot-search-panel" data-panel="search" hidden>' +
            '<div class="ai-chatbot-search">' +
              '<label class="ai-chatbot-field"><span>Search docs</span><input data-search-input type="search" autocomplete="off" placeholder="Find docs, prompts, CVEs, and workflows"></label>' +
              '<div class="ai-chatbot-search-results" data-search-results></div>' +
              '<div class="ai-chatbot-status" data-search-status></div>' +
            '</div>' +
          '</div>' +
          '<div class="ai-chatbot-tab-panel" data-panel="agents" hidden>' +
            '<div class="ai-chatbot-agents">' +
              '<div class="ai-chatbot-agent-intro">' +
                '<div><span class="ai-chatbot-beta-tag">Beta</span><strong>Agent planner</strong><span>Queue one precise action, generate a reviewed output, then deliver through an optional integration.</span></div>' +
                '<a href="' + html(siteHref('automation/agent-scheduling/')) + '" target="_blank" rel="noopener noreferrer">How this works</a>' +
              '</div>' +
              '<div class="ai-chatbot-agent-compact-row">' +
                '<label class="ai-chatbot-field"><span>Provider</span><select data-agent-provider><option value="openai">OpenAI</option><option value="grok">Grok</option><option value="claude">Claude</option></select></label>' +
                '<label class="ai-chatbot-field"><span>Model</span><select data-agent-model></select></label>' +
              '</div>' +
              '<div class="ai-chatbot-agent-step">' +
                '<div class="ai-chatbot-agent-step-title"><span>1</span><strong>Choose one narrow action</strong></div>' +
                '<select data-agent-workflow hidden><option value="dependency">Vulnerable dependency remediation</option><option value="sast">SAST finding triage</option><option value="sensitive-data">Sensitive data remediation</option><option value="mcp-guardrail">MCP connector guardrail review</option><option value="base-image">Base image update</option><option value="recipe-runbook">Apply SecurityRecipes runbook</option></select>' +
                '<div class="ai-chatbot-agent-cards" role="group" aria-label="Agent action type">' +
                  '<button class="ai-chatbot-agent-card" type="button" data-agent-workflow-card="dependency" data-accent="teal" aria-pressed="true"><h3>Dependency fix</h3><p>Bump the narrowest package set and hold for review.</p></button>' +
                  '<button class="ai-chatbot-agent-card" type="button" data-agent-workflow-card="sast" data-accent="amber" aria-pressed="false"><h3>SAST triage</h3><p>Group findings, remove false positives, and draft fixes.</p></button>' +
                  '<button class="ai-chatbot-agent-card" type="button" data-agent-workflow-card="sensitive-data" data-accent="rose" aria-pressed="false"><h3>Sensitive data</h3><p>Quarantine exposure, route rotation, and preserve evidence.</p></button>' +
                  '<button class="ai-chatbot-agent-card" type="button" data-agent-workflow-card="mcp-guardrail" data-accent="violet" aria-pressed="false"><h3>MCP guardrail</h3><p>Check connector egress, auth, and runtime policy.</p></button>' +
                  '<button class="ai-chatbot-agent-card" type="button" data-agent-workflow-card="base-image" data-accent="slate" aria-pressed="false"><h3>Base image</h3><p>Pick a patched base image and prove compatibility.</p></button>' +
                  '<button class="ai-chatbot-agent-card" type="button" data-agent-workflow-card="recipe-runbook" data-accent="blue" aria-pressed="false"><h3>Apply recipe</h3><p>Convert a recipe into commands, checks, and rollback.</p></button>' +
                '</div>' +
              '</div>' +
              '<div class="ai-chatbot-agent-step">' +
                '<div class="ai-chatbot-agent-step-title"><span>2</span><strong>Name the recipe and target</strong></div>' +
                '<div class="ai-chatbot-agent-grid">' +
                  '<div class="ai-chatbot-field ai-chatbot-typeahead ai-chatbot-wide-field">' +
                    '<label for="ai-chatbot-agent-recipe"><span>Recipe</span></label>' +
                    '<input id="ai-chatbot-agent-recipe" data-agent-recipe type="search" autocomplete="off" role="combobox" aria-autocomplete="list" aria-expanded="false" aria-controls="ai-chatbot-agent-recipe-results" placeholder="Type a CVE, prompt, or workflow recipe">' +
                    '<div id="ai-chatbot-agent-recipe-results" class="ai-chatbot-typeahead-results" data-agent-recipe-results hidden></div>' +
                  '</div>' +
                  '<label class="ai-chatbot-field ai-chatbot-wide-field"><span>Target scope</span><input data-agent-scope type="text" autocomplete="off" placeholder="repo/package/CVE/file path, e.g. org/app package log4j"></label>' +
                '</div>' +
              '</div>' +
              '<div class="ai-chatbot-agent-step">' +
                '<div class="ai-chatbot-agent-step-title"><span>3</span><strong>Choose context, report, and outcome</strong></div>' +
                '<div class="ai-chatbot-agent-grid">' +
                  '<label class="ai-chatbot-field"><span>Workflow template</span><select data-agent-template></select></label>' +
                  '<label class="ai-chatbot-field"><span>Report profile</span><select data-agent-report-profile></select></label>' +
                  '<label class="ai-chatbot-field ai-chatbot-wide-field"><span>Input channels</span><select data-agent-input-channels multiple></select></label>' +
                  '<label class="ai-chatbot-field"><span>Cadence</span><select data-agent-cadence><option>Manual approval</option><option>Once at next run</option><option>Daily review queue</option><option>Weekly sweep</option><option>On new finding</option></select></label>' +
                  '<label class="ai-chatbot-field"><span>Next run</span><input data-agent-next-run type="datetime-local"></label>' +
                  '<label class="ai-chatbot-field"><span>Approval gate</span><select data-agent-approval><option>Security reviewer required</option><option>Code owner required</option><option>Ticket required</option><option>Two-person review</option></select></label>' +
                  '<label class="ai-chatbot-field"><span>Output</span><select data-agent-output-route></select></label>' +
                  '<label class="ai-chatbot-field ai-chatbot-wide-field"><span>Context pack</span><select data-agent-context-pack><option>Secure context trust pack</option><option>Agentic assurance pack</option><option>MCP gateway policy</option><option>Runtime controls</option></select></label>' +
                '</div>' +
                '<div class="ai-chatbot-agent-hint" data-agent-route-hint></div>' +
                '<div class="ai-chatbot-agent-hint" data-agent-template-hint></div>' +
                '<details class="ai-chatbot-agent-integrations">' +
                  '<summary class="ai-chatbot-github-heading"><span>Marketplace JSON preview</span><small>Review the browser-side config contract and the normalized downstream report bundle.</small></summary>' +
                  '<div class="ai-chatbot-github-content">' +
                    '<div class="ai-chatbot-agent-hint">Config contract</div>' +
                    '<pre class="ai-chatbot-agent-json" data-agent-marketplace-preview></pre>' +
                    '<div class="ai-chatbot-agent-hint">Generated report bundle</div>' +
                    '<pre class="ai-chatbot-agent-json" data-agent-report-preview></pre>' +
                    '<div class="ai-chatbot-agent-actions">' +
                      '<button class="ai-chatbot-agent-button secondary" type="button" data-agent-copy-config>Copy config JSON</button>' +
                      '<button class="ai-chatbot-agent-button secondary" type="button" data-agent-copy-report>Copy report JSON</button>' +
                      '<button class="ai-chatbot-agent-button secondary" type="button" data-agent-download-report>Download report JSON</button>' +
                    '</div>' +
                  '</div>' +
                '</details>' +
                '<details class="ai-chatbot-agent-integrations">' +
                  '<summary class="ai-chatbot-github-heading"><span>Delivery integrations</span><small>Only needed for live or live_or_copy output routes. Secrets stay in this browser.</small></summary>' +
                  '<div class="ai-chatbot-github-content">' +
                    '<div class="ai-chatbot-agent-grid">' +
                      '<label class="ai-chatbot-field"><span>Slack webhook</span><input data-slack-webhook type="url" autocomplete="off" placeholder="https://hooks.slack.com/services/..."></label>' +
                      '<label class="ai-chatbot-field"><span>Teams workflow webhook</span><input data-teams-webhook type="url" autocomplete="off" placeholder="https://prod-00.westus.logic.azure.com/workflows/..."></label>' +
                      '<label class="ai-chatbot-field"><span>Email recipient</span><input data-email-recipient type="email" autocomplete="off" placeholder="security@example.com"></label>' +
                      '<label class="ai-chatbot-field"><span>Email relay URL</span><input data-smtp-relay-url type="url" autocomplete="off" placeholder="Optional CORS-enabled SMTP relay endpoint"></label>' +
                    '</div>' +
                    '<div class="ai-chatbot-agent-grid">' +
                      '<label class="ai-chatbot-field"><span>Jira URL</span><input data-jira-base-url type="url" autocomplete="off" placeholder="https://example.atlassian.net"></label>' +
                      '<label class="ai-chatbot-field"><span>Jira project</span><input data-jira-project type="text" autocomplete="off" placeholder="SEC"></label>' +
                      '<label class="ai-chatbot-field"><span>Jira email</span><input data-jira-email type="email" autocomplete="off" placeholder="you@example.com"></label>' +
                      '<label class="ai-chatbot-field"><span>Jira token</span><input data-jira-token type="password" autocomplete="off" placeholder="Stored in this browser"></label>' +
                    '</div>' +
                    '<div class="ai-chatbot-agent-grid">' +
                      '<label class="ai-chatbot-field"><span>ServiceNow URL</span><input data-servicenow-base-url type="url" autocomplete="off" placeholder="https://example.service-now.com"></label>' +
                      '<label class="ai-chatbot-field"><span>ServiceNow table</span><input data-servicenow-table type="text" autocomplete="off" placeholder="incident"></label>' +
                      '<label class="ai-chatbot-field ai-chatbot-wide-field"><span>ServiceNow bearer token</span><input data-servicenow-token type="password" autocomplete="off" placeholder="Stored in this browser"></label>' +
                    '</div>' +
                    '<div class="ai-chatbot-agent-grid">' +
                      '<label class="ai-chatbot-field"><span>Linear API key</span><input data-linear-api-key type="password" autocomplete="off" placeholder="Stored in this browser"></label>' +
                      '<label class="ai-chatbot-field"><span>Linear team ID</span><input data-linear-team-id type="text" autocomplete="off" placeholder="9cfb482a-81e3-4154-b5b9-2c805e70a02d"></label>' +
                      '<label class="ai-chatbot-field"><span>Splunk HEC URL</span><input data-splunk-hec-url type="url" autocomplete="off" placeholder="https://splunk.example.com:8088/services/collector/event"></label>' +
                      '<label class="ai-chatbot-field"><span>Splunk HEC token</span><input data-splunk-hec-token type="password" autocomplete="off" placeholder="Stored in this browser"></label>' +
                    '</div>' +
                    '<div class="ai-chatbot-agent-grid">' +
                      '<label class="ai-chatbot-field"><span>Splunk index</span><input data-splunk-index type="text" autocomplete="off" placeholder="secops"></label>' +
                      '<label class="ai-chatbot-field"><span>Splunk sourcetype</span><input data-splunk-sourcetype type="text" autocomplete="off" placeholder="securityrecipes:report"></label>' +
                      '<label class="ai-chatbot-field"><span>Elastic Kibana URL</span><input data-elastic-base-url type="url" autocomplete="off" placeholder="https://elastic.example.com"></label>' +
                      '<label class="ai-chatbot-field"><span>Elastic API key</span><input data-elastic-api-key type="password" autocomplete="off" placeholder="Stored in this browser"></label>' +
                    '</div>' +
                    '<div class="ai-chatbot-agent-grid">' +
                      '<label class="ai-chatbot-field"><span>Elastic space</span><input data-elastic-space-id type="text" autocomplete="off" placeholder="default"></label>' +
                      '<label class="ai-chatbot-field"><span>Elastic owner</span><input data-elastic-owner type="text" autocomplete="off" placeholder="securitySolution"></label>' +
                      '<label class="ai-chatbot-field"><span>Generic webhook URL</span><input data-generic-webhook-url type="url" autocomplete="off" placeholder="https://example.internal/hooks/security-recipes"></label>' +
                      '<label class="ai-chatbot-field"><span>Generic webhook method</span><input data-generic-webhook-method type="text" autocomplete="off" placeholder="POST"></label>' +
                    '</div>' +
                    '<div class="ai-chatbot-agent-grid">' +
                      '<label class="ai-chatbot-field"><span>Generic auth header</span><input data-generic-webhook-auth-header type="text" autocomplete="off" placeholder="Bearer token or ApiKey value"></label>' +
                      '<label class="ai-chatbot-field ai-chatbot-wide-field"><span>Generic headers JSON</span><input data-generic-webhook-headers type="text" autocomplete="off" placeholder="{&quot;X-Environment&quot;:&quot;prod&quot;}"></label>' +
                    '</div>' +
                    '<button class="ai-chatbot-agent-button secondary" type="button" data-agent-save-integrations>Save integrations</button>' +
                  '</div>' +
                '</details>' +
                '<div class="ai-chatbot-agent-actions">' +
                  '<button class="ai-chatbot-agent-button" type="button" data-agent-add-action>Add action to queue</button>' +
                  '<button class="ai-chatbot-agent-button secondary" type="button" data-agent-clear-actions>Clear queue</button>' +
                '</div>' +
              '</div>' +
              '<div class="ai-chatbot-agent-queue" data-agent-action-list></div>' +
              '<div class="ai-chatbot-agent-footer">' +
                '<div class="ai-chatbot-status" data-agent-status>Queue precise actions, then preview the run plan. Scheduling remains a local placeholder.</div>' +
                '<div class="ai-chatbot-agent-output" data-agent-output hidden></div>' +
                '<div class="ai-chatbot-agent-actions">' +
                  '<button class="ai-chatbot-agent-button" type="button" data-agent-preview>Generate plan</button>' +
                  '<button class="ai-chatbot-agent-button secondary" type="button" data-agent-deliver>Run selected output</button>' +
                  '<button class="ai-chatbot-agent-button secondary" type="button" data-agent-schedule>Save schedule draft</button>' +
                '</div>' +
              '</div>' +
            '</div>' +
          '</div>' +
        '</div>' +
      '</section>';

    document.body.appendChild(shell);

    els.shell = shell;
    els.launch = shell.querySelector('.ai-chatbot-launch');
    els.panel = shell.querySelector('.ai-chatbot-panel');
    els.expand = shell.querySelector('[data-expand]');
    els.providerBadge = shell.querySelector('[data-provider-badge]');
    els.settings = shell.querySelector('.ai-chatbot-settings');
    els.settingsToggle = shell.querySelector('[data-settings-toggle]');
    els.settingsContent = shell.querySelector('[data-settings-content]');
    els.settingsSummary = shell.querySelector('[data-settings-summary]');
    els.provider = shell.querySelector('[data-provider]');
    els.model = shell.querySelector('[data-model]');
    els.providerCredentialDetails = shell.querySelector('[data-provider-credential-details]');
    els.contextDetails = shell.querySelector('[data-context-details]');
    els.tokenLabel = shell.querySelector('[data-token-label]');
    els.tokenInput = shell.querySelector('[data-token]');
    els.credentialModeButtons = shell.querySelectorAll('[data-credential-mode]');
    els.oauthDetails = shell.querySelector('[data-oauth-details]');
    els.oauthClientId = shell.querySelector('[data-oauth-client-id]');
    els.oauthScope = shell.querySelector('[data-oauth-scope]');
    els.oauthAuthUrl = shell.querySelector('[data-oauth-auth-url]');
    els.oauthTokenUrl = shell.querySelector('[data-oauth-token-url]');
    els.oauthStatus = shell.querySelector('[data-oauth-status]');
    els.status = shell.querySelector('[data-status]');
    els.messages = shell.querySelector('[data-messages]');
    els.form = shell.querySelector('[data-form]');
    els.prompt = shell.querySelector('[data-prompt]');
    els.send = shell.querySelector('[data-send]');
    els.includeContext = shell.querySelector('[data-context]');
    els.includeRelated = shell.querySelector('[data-related]');
    els.includeGitHub = shell.querySelector('[data-github-context]');
    els.includeDepsDev = shell.querySelector('[data-depsdev-context]');
    els.includeSarif = shell.querySelector('[data-sarif-context]');
    els.includeSbom = shell.querySelector('[data-sbom-context]');
    els.githubRepoInput = shell.querySelector('[data-github-repo-url]');
    els.githubStatus = shell.querySelector('[data-github-status]');
    els.githubAuthModeButtons = shell.querySelectorAll('[data-github-auth-mode]');
    els.githubTokenLabel = shell.querySelector('[data-github-token-label]');
    els.githubTokenInput = shell.querySelector('[data-github-token]');
    els.githubOAuthDetails = shell.querySelector('[data-github-oauth-details]');
    els.githubOAuthClientId = shell.querySelector('[data-github-oauth-client-id]');
    els.githubOAuthScope = shell.querySelector('[data-github-oauth-scope]');
    els.githubOAuthAuthUrl = shell.querySelector('[data-github-oauth-auth-url]');
    els.githubOAuthTokenUrl = shell.querySelector('[data-github-oauth-token-url]');
    els.depsDevStatus = shell.querySelector('[data-depsdev-status]');
    els.sarifFileInput = shell.querySelector('[data-sarif-file]');
    els.sarifStatus = shell.querySelector('[data-sarif-status]');
    els.sbomFileInput = shell.querySelector('[data-sbom-file]');
    els.sbomStatus = shell.querySelector('[data-sbom-status]');
    els.searchInput = shell.querySelector('[data-search-input]');
    els.searchResults = shell.querySelector('[data-search-results]');
    els.searchStatus = shell.querySelector('[data-search-status]');
    els.agentProvider = shell.querySelector('[data-agent-provider]');
    els.agentModel = shell.querySelector('[data-agent-model]');
    els.agentRecipeInput = shell.querySelector('[data-agent-recipe]');
    els.agentRecipeResults = shell.querySelector('[data-agent-recipe-results]');
    els.agentWorkflow = shell.querySelector('[data-agent-workflow]');
    els.agentScope = shell.querySelector('[data-agent-scope]');
    els.agentCadence = shell.querySelector('[data-agent-cadence]');
    els.agentNextRun = shell.querySelector('[data-agent-next-run]');
    els.agentApproval = shell.querySelector('[data-agent-approval]');
    els.agentContextPack = shell.querySelector('[data-agent-context-pack]');
    els.agentTemplate = shell.querySelector('[data-agent-template]');
    els.agentReportProfile = shell.querySelector('[data-agent-report-profile]');
    els.agentInputChannels = shell.querySelector('[data-agent-input-channels]');
    els.agentOutputRoute = shell.querySelector('[data-agent-output-route]');
    els.agentRouteHint = shell.querySelector('[data-agent-route-hint]');
    els.agentTemplateHint = shell.querySelector('[data-agent-template-hint]');
    els.agentMarketplacePreview = shell.querySelector('[data-agent-marketplace-preview]');
    els.agentReportPreview = shell.querySelector('[data-agent-report-preview]');
    els.agentCopyConfig = shell.querySelector('[data-agent-copy-config]');
    els.agentCopyReport = shell.querySelector('[data-agent-copy-report]');
    els.agentDownloadReport = shell.querySelector('[data-agent-download-report]');
    els.agentActionList = shell.querySelector('[data-agent-action-list]');
    els.agentStatus = shell.querySelector('[data-agent-status]');
    els.agentOutput = shell.querySelector('[data-agent-output]');
    els.agentPreview = shell.querySelector('[data-agent-preview]');
    els.agentDeliver = shell.querySelector('[data-agent-deliver]');
    els.slackWebhook = shell.querySelector('[data-slack-webhook]');
    els.teamsWebhook = shell.querySelector('[data-teams-webhook]');
    els.emailRecipient = shell.querySelector('[data-email-recipient]');
    els.smtpRelayUrl = shell.querySelector('[data-smtp-relay-url]');
    els.jiraBaseUrl = shell.querySelector('[data-jira-base-url]');
    els.jiraEmail = shell.querySelector('[data-jira-email]');
    els.jiraToken = shell.querySelector('[data-jira-token]');
    els.jiraProject = shell.querySelector('[data-jira-project]');
    els.serviceNowBaseUrl = shell.querySelector('[data-servicenow-base-url]');
    els.serviceNowTable = shell.querySelector('[data-servicenow-table]');
    els.serviceNowToken = shell.querySelector('[data-servicenow-token]');
    els.linearApiKey = shell.querySelector('[data-linear-api-key]');
    els.linearTeamId = shell.querySelector('[data-linear-team-id]');
    els.splunkHecUrl = shell.querySelector('[data-splunk-hec-url]');
    els.splunkHecToken = shell.querySelector('[data-splunk-hec-token]');
    els.splunkIndex = shell.querySelector('[data-splunk-index]');
    els.splunkSourceType = shell.querySelector('[data-splunk-sourcetype]');
    els.elasticBaseUrl = shell.querySelector('[data-elastic-base-url]');
    els.elasticApiKey = shell.querySelector('[data-elastic-api-key]');
    els.elasticSpaceId = shell.querySelector('[data-elastic-space-id]');
    els.elasticOwner = shell.querySelector('[data-elastic-owner]');
    els.genericWebhookUrl = shell.querySelector('[data-generic-webhook-url]');
    els.genericWebhookMethod = shell.querySelector('[data-generic-webhook-method]');
    els.genericWebhookAuthHeader = shell.querySelector('[data-generic-webhook-auth-header]');
    els.genericWebhookHeaders = shell.querySelector('[data-generic-webhook-headers]');

    cleanupLegacyGitHubAuth();
    updatePanelOffset();
    els.includeContext.checked = state.includeContext;
    els.includeRelated.checked = state.includeRelated;
    els.includeGitHub.checked = state.includeGitHub;
    els.includeDepsDev.checked = state.includeDepsDev;
    if (els.includeSarif) els.includeSarif.checked = state.includeSarif;
    if (els.includeSbom) els.includeSbom.checked = state.includeSbom;
    setDefaultSettingsOpenForProvider();
    saveChatHistoryStorage();
    updateProviderUI();
    updateGitHubUI();
    updateDepsDevUI();
    updateImportedContextUI('sarif');
    updateImportedContextUI('sbom');
    renderMessages();
    renderSearchResults([], '');

    els.launch.addEventListener('click', function () {
      var isOpen = !els.panel.hidden;
      els.panel.hidden = isOpen;
      els.launch.setAttribute('aria-expanded', isOpen ? 'false' : 'true');
      if (isOpen) {
        setExpanded(false);
        return;
      }
      openPanel('chat');
    });

    els.expand.addEventListener('click', function () {
      if (els.panel.hidden) openPanel('chat');
      setExpanded(els.panel.getAttribute('data-expanded') !== 'true');
    });

    els.providerBadge.addEventListener('click', refreshProviderConnectivity);

    shell.querySelector('[data-close]').addEventListener('click', function () {
      setExpanded(false);
      els.panel.hidden = true;
      els.launch.setAttribute('aria-expanded', 'false');
      els.launch.focus();
    });

    Array.prototype.forEach.call(shell.querySelectorAll('.ai-chatbot-tab'), function (button) {
      button.addEventListener('click', function () {
        var tabName = button.getAttribute('data-tab');
        switchTab(tabName);
        if (tabName === 'search' && els.searchInput) {
          window.setTimeout(function () { els.searchInput.focus(); }, 0);
        }
      });
    });

    if (els.searchInput) {
      els.searchInput.addEventListener('input', runSearch);
      els.searchInput.addEventListener('focus', runSearch);
    }

    els.panel.addEventListener('click', handleMessageClick);

    els.settingsToggle.addEventListener('click', function () {
      setSettingsOpen(!state.settingsOpen);
    });

    els.provider.addEventListener('change', function () {
      state.provider = els.provider.value;
      localStorage.setItem(STORE.provider, state.provider);
      setDefaultSettingsOpenForProvider();
      updateProviderUI();
    });

    els.model.addEventListener('change', function () {
      var value = collapseText(els.model.value);
      if (value) localStorage.setItem(modelKey(state.provider), value);
      else localStorage.removeItem(modelKey(state.provider));
      updateProviderUI();
    });

    Array.prototype.forEach.call(els.credentialModeButtons, function (button) {
      button.addEventListener('click', function () {
        var mode = button.getAttribute('data-credential-mode');
        setCredentialMode(state.provider, mode);
        state.settingsOpen = true;
        updateProviderUI();
        setStatus(credentialModeLabel(state.provider, mode) + ' mode selected. Credential storage remains local to this browser.', '');
      });
    });

    els.agentProvider.addEventListener('change', function () {
      localStorage.setItem(STORE.agentProvider, els.agentProvider.value);
      updateAgentUI();
    });

    els.agentModel.addEventListener('change', function () {
      var provider = getAgentProvider();
      var value = collapseText(els.agentModel.value);
      if (value) localStorage.setItem(modelKey(provider), value);
      else localStorage.removeItem(modelKey(provider));
      updateAgentUI();
      updateProviderUI();
    });

    els.agentRecipeInput.addEventListener('input', function () {
      state.agentRecipePath = '';
      localStorage.removeItem(STORE.agentRecipe);
      updateAgentMarketplacePreview();
      runAgentRecipeTypeahead();
    });

    els.agentRecipeInput.addEventListener('focus', runAgentRecipeTypeahead);

    els.agentRecipeInput.addEventListener('keydown', function (event) {
      if (event.key === 'Escape') {
        els.agentRecipeResults.hidden = true;
        els.agentRecipeInput.setAttribute('aria-expanded', 'false');
        return;
      }
      if (!state.agentRecipeResults.length) return;
      if (event.key === 'ArrowDown') {
        event.preventDefault();
        state.agentRecipeActive = Math.min(state.agentRecipeResults.length - 1, state.agentRecipeActive + 1);
        renderAgentRecipeResults(state.agentRecipeResults);
      } else if (event.key === 'ArrowUp') {
        event.preventDefault();
        state.agentRecipeActive = Math.max(0, state.agentRecipeActive - 1);
        renderAgentRecipeResults(state.agentRecipeResults);
      } else if (event.key === 'Enter') {
        event.preventDefault();
        selectAgentRecipe(state.agentRecipeResults[Math.max(0, state.agentRecipeActive)]);
      }
    });

    els.agentRecipeResults.addEventListener('mousedown', function (event) {
      var button = event.target.closest('[data-recipe-index]');
      if (!button) return;
      event.preventDefault();
      selectAgentRecipe(state.agentRecipeResults[Number(button.getAttribute('data-recipe-index'))]);
    });

    Array.prototype.forEach.call(shell.querySelectorAll('[data-agent-workflow-card]'), function (button) {
      button.addEventListener('click', function () {
        setAgentWorkflow(button.getAttribute('data-agent-workflow-card'));
        updateAgentMarketplacePreview();
      });
    });

    if (els.agentTemplate) {
      els.agentTemplate.addEventListener('change', function () {
        applyWorkflowTemplate(els.agentTemplate.value, { forceRecipeAutofill: true });
      });
    }

    if (els.agentReportProfile) {
      els.agentReportProfile.addEventListener('change', function () {
        localStorage.setItem(STORE.agentReportProfile, els.agentReportProfile.value);
        updateAgentRouteHint();
        updateAgentMarketplacePreview();
      });
    }

    if (els.agentInputChannels) {
      els.agentInputChannels.addEventListener('change', function () {
        syncSelectedInputChannels();
        updateAgentTemplateHint();
        updateAgentMarketplacePreview();
      });
    }

    els.agentOutputRoute.addEventListener('change', function () {
      localStorage.setItem(STORE.agentOutputChannel, els.agentOutputRoute.value);
      updateAgentRouteHint();
      updateAgentMarketplacePreview();
    });

    if (els.agentCadence) els.agentCadence.addEventListener('change', updateAgentMarketplacePreview);
    if (els.agentNextRun) els.agentNextRun.addEventListener('change', updateAgentMarketplacePreview);
    if (els.agentApproval) els.agentApproval.addEventListener('change', updateAgentMarketplacePreview);
    if (els.agentContextPack) els.agentContextPack.addEventListener('change', updateAgentMarketplacePreview);
    if (els.agentScope) els.agentScope.addEventListener('input', updateAgentMarketplacePreview);

    if (els.agentCopyConfig) {
      els.agentCopyConfig.addEventListener('click', function () {
        copyText(JSON.stringify(marketplacePreviewPayload(agentConfig()), null, 2))
          .then(function () {
            if (els.agentStatus && !state.agentRunning) {
              els.agentStatus.textContent = 'Marketplace config JSON copied locally.';
              els.agentStatus.setAttribute('data-kind', 'ok');
            }
          })
          .catch(function () {
            if (els.agentStatus && !state.agentRunning) {
              els.agentStatus.textContent = 'Marketplace config JSON is shown above. Clipboard copy was unavailable.';
              els.agentStatus.setAttribute('data-kind', 'error');
            }
          });
      });
    }

    if (els.agentCopyReport) {
      els.agentCopyReport.addEventListener('click', function () {
        copyText(JSON.stringify(reportPreviewPayload(agentConfig()), null, 2))
          .then(function () {
            if (els.agentStatus && !state.agentRunning) {
              els.agentStatus.textContent = 'Normalized report JSON copied locally.';
              els.agentStatus.setAttribute('data-kind', 'ok');
            }
          })
          .catch(function () {
            if (els.agentStatus && !state.agentRunning) {
              els.agentStatus.textContent = 'Report JSON is shown above. Clipboard copy was unavailable.';
              els.agentStatus.setAttribute('data-kind', 'error');
            }
          });
      });
    }

    if (els.agentDownloadReport) {
      els.agentDownloadReport.addEventListener('click', function () {
        try {
          var config = agentConfig();
          downloadJsonFile(reportDownloadFileName(config), reportPreviewPayload(config));
          if (els.agentStatus && !state.agentRunning) {
            els.agentStatus.textContent = 'Normalized report JSON downloaded locally.';
            els.agentStatus.setAttribute('data-kind', 'ok');
          }
        } catch (error) {
          if (els.agentStatus && !state.agentRunning) {
            els.agentStatus.textContent = error && error.message ? error.message : 'Report download failed.';
            els.agentStatus.setAttribute('data-kind', 'error');
          }
        }
      });
    }

    shell.querySelector('[data-agent-add-action]').addEventListener('click', addAgentAction);

    shell.querySelector('[data-agent-save-integrations]').addEventListener('click', saveAgentIntegrationSettings);

    shell.querySelector('[data-agent-clear-actions]').addEventListener('click', function () {
      state.agentActions = [];
      saveAgentActions();
      renderAgentActions();
      updateAgentMarketplacePreview();
      if (els.agentStatus && !state.agentRunning) {
        els.agentStatus.textContent = 'Action queue cleared.';
        els.agentStatus.removeAttribute('data-kind');
      }
    });

    els.agentActionList.addEventListener('click', function (event) {
      var button = event.target.closest('[data-agent-remove-action]');
      if (!button) return;
      state.agentActions.splice(Number(button.getAttribute('data-agent-remove-action')), 1);
      saveAgentActions();
      renderAgentActions();
      updateAgentMarketplacePreview();
    });

    shell.querySelector('[data-save-token]').addEventListener('click', function () {
      var value = els.tokenInput.value.trim();
      if (!value) {
        setStatus('Paste a token first.', 'error');
        return;
      }
      localStorage.setItem(tokenKey(state.provider), value);
      if (getCredentialMode(state.provider) === 'api_key') localStorage.removeItem(legacyTokenKey(state.provider));
      els.tokenInput.value = '';
      updateProviderBadge();
      setStatus(maskToken(value), 'ok');
      setSettingsOpen(false);
      updateAgentUI();
      scheduleProviderConnectivityChecks();
    });

    shell.querySelector('[data-clear-token]').addEventListener('click', function () {
      localStorage.removeItem(tokenKey(state.provider, 'api_key'));
      localStorage.removeItem(tokenKey(state.provider, 'oauth'));
      localStorage.removeItem(legacyTokenKey(state.provider));
      state.settingsOpen = true;
      updateProviderUI();
    });

    shell.querySelector('[data-save-oauth-config]').addEventListener('click', function () {
      setOAuthField(state.provider, 'clientId', els.oauthClientId.value);
      setOAuthField(state.provider, 'scope', els.oauthScope.value);
      setOAuthField(state.provider, 'authUrl', els.oauthAuthUrl.value);
      setOAuthField(state.provider, 'tokenUrl', els.oauthTokenUrl.value);
      setOAuthStatus('OAuth browser config saved locally for ' + providerConfig().label + '. Redirect URI: ' + oauthRedirectUri(), 'ok');
    });

    shell.querySelector('[data-start-oauth]').addEventListener('click', function () {
      setOAuthField(state.provider, 'clientId', els.oauthClientId.value);
      setOAuthField(state.provider, 'scope', els.oauthScope.value);
      setOAuthField(state.provider, 'authUrl', els.oauthAuthUrl.value);
      setOAuthField(state.provider, 'tokenUrl', els.oauthTokenUrl.value);
      startOAuthBrowserFlow().catch(function (error) {
        setOAuthStatus(error && error.message ? error.message : 'OAuth browser authorization could not start.', 'error');
      });
    });

    Array.prototype.forEach.call(els.githubAuthModeButtons, function (button) {
      button.addEventListener('click', function () {
        setGitHubAuthMode(button.getAttribute('data-github-auth-mode'));
        updateGitHubAuthUI();
        setGitHubStatus('GitHub ' + githubCredentialLabel() + ' mode selected. Credential storage remains local to this browser.', '');
      });
    });

    shell.querySelector('[data-save-github-token]').addEventListener('click', function () {
      var value = els.githubTokenInput.value.trim();
      if (!value) {
        setGitHubStatus('Paste a GitHub token first.', 'error');
        return;
      }
      localStorage.setItem(githubTokenKey(), value);
      els.githubTokenInput.value = '';
      updateGitHubAuthUI();
      updateSettingsSummary();
      setGitHubStatus('GitHub ' + githubCredentialLabel().toLowerCase() + ' saved locally: ' + maskToken(value), 'ok');
    });

    shell.querySelector('[data-clear-github-token]').addEventListener('click', function () {
      localStorage.removeItem(githubTokenKey('pat'));
      localStorage.removeItem(githubTokenKey('oauth'));
      updateGitHubAuthUI();
      updateSettingsSummary();
      setGitHubStatus('GitHub credentials cleared from this browser.', '');
    });

    shell.querySelector('[data-save-github-oauth-config]').addEventListener('click', function () {
      setGitHubOAuthField('clientId', els.githubOAuthClientId.value);
      setGitHubOAuthField('scope', els.githubOAuthScope.value);
      setGitHubOAuthField('authUrl', els.githubOAuthAuthUrl.value);
      setGitHubOAuthField('tokenUrl', els.githubOAuthTokenUrl.value);
      updateGitHubAuthUI();
      setGitHubStatus('GitHub OAuth browser config saved locally. Redirect URI: ' + oauthRedirectUri(), 'ok');
    });

    shell.querySelector('[data-start-github-oauth]').addEventListener('click', function () {
      setGitHubOAuthField('clientId', els.githubOAuthClientId.value);
      setGitHubOAuthField('scope', els.githubOAuthScope.value);
      setGitHubOAuthField('authUrl', els.githubOAuthAuthUrl.value);
      setGitHubOAuthField('tokenUrl', els.githubOAuthTokenUrl.value);
      startGitHubOAuthBrowserFlow().catch(function (error) {
        setGitHubStatus(error && error.message ? error.message : 'GitHub OAuth browser authorization could not start.', 'error');
      });
    });

    shell.querySelector('[data-load-github-context]').addEventListener('click', function () {
      state.includeGitHub = true;
      localStorage.setItem(STORE.githubContext, 'true');
      if (els.includeGitHub) els.includeGitHub.checked = true;
      prepareGitHubContext().catch(function (error) {
        var detail = error && error.message ? error.message : 'GitHub context load failed.';
        setGitHubStatus('GitHub context failed to load. Hover for details.', 'error', detail);
      });
    });

    shell.querySelector('[data-load-depsdev-context]').addEventListener('click', function () {
      state.includeDepsDev = true;
      localStorage.setItem(STORE.depsDevContext, 'true');
      if (els.includeDepsDev) els.includeDepsDev.checked = true;
      prepareDepsDevContext().catch(function (error) {
        var detail = error && error.message ? error.message : 'deps.dev dependency check failed.';
        setDepsDevStatus('deps.dev dependency check failed. Hover for details.', 'error', detail);
      });
    });

    if (els.sarifFileInput) {
      els.sarifFileInput.addEventListener('change', function () {
        handleImportedContextUpload('sarif', els.sarifFileInput.files && els.sarifFileInput.files[0]);
      });
    }

    if (els.sbomFileInput) {
      els.sbomFileInput.addEventListener('change', function () {
        handleImportedContextUpload('sbom', els.sbomFileInput.files && els.sbomFileInput.files[0]);
      });
    }

    shell.querySelector('[data-clear-sarif-context]').addEventListener('click', function () {
      clearImportedContext('sarif');
      if (els.agentStatus && !state.agentRunning) {
        els.agentStatus.textContent = 'Local SARIF summary cleared from this browser.';
        els.agentStatus.removeAttribute('data-kind');
      }
    });

    shell.querySelector('[data-clear-sbom-context]').addEventListener('click', function () {
      clearImportedContext('sbom');
      if (els.agentStatus && !state.agentRunning) {
        els.agentStatus.textContent = 'Local SBOM summary cleared from this browser.';
        els.agentStatus.removeAttribute('data-kind');
      }
    });

    shell.querySelector('[data-clear-github-context]').addEventListener('click', function () {
      state.githubRepoUrl = '';
      state.githubContextText = '';
      state.githubContextLoadedAt = '';
      state.depsDevContextText = '';
      state.depsDevContextLoadedAt = '';
      localStorage.removeItem(STORE.githubRepoUrl);
      if (els.githubRepoInput) els.githubRepoInput.value = '';
      updateGitHubUI();
      updateDepsDevUI();
      updateAgentMarketplacePreview();
    });

    els.githubRepoInput.addEventListener('change', function () {
      var parsed = parseGitHubRepository(els.githubRepoInput.value);
      state.githubRepoUrl = parsed ? parsed.fullName : collapseText(els.githubRepoInput.value);
      state.githubContextText = '';
      state.githubContextLoadedAt = '';
      state.depsDevContextText = '';
      state.depsDevContextLoadedAt = '';
      if (state.githubRepoUrl) localStorage.setItem(STORE.githubRepoUrl, state.githubRepoUrl);
      else localStorage.removeItem(STORE.githubRepoUrl);
      updateGitHubUI();
      updateDepsDevUI();
      updateAgentMarketplacePreview();
    });

    els.includeContext.addEventListener('change', function () {
      state.includeContext = els.includeContext.checked;
      localStorage.setItem(STORE.context, String(state.includeContext));
      syncAgentInputSelectionsFromToggles();
    });

    els.includeRelated.addEventListener('change', function () {
      state.includeRelated = els.includeRelated.checked;
      localStorage.setItem(STORE.related, String(state.includeRelated));
      syncAgentInputSelectionsFromToggles();
    });

    els.includeGitHub.addEventListener('change', function () {
      state.includeGitHub = els.includeGitHub.checked;
      localStorage.setItem(STORE.githubContext, String(state.includeGitHub));
      if (!state.includeGitHub) state.githubContextText = '';
      updateGitHubUI();
      syncAgentInputSelectionsFromToggles();
    });

    els.includeDepsDev.addEventListener('change', function () {
      state.includeDepsDev = els.includeDepsDev.checked;
      localStorage.setItem(STORE.depsDevContext, String(state.includeDepsDev));
      if (!state.includeDepsDev) {
        state.depsDevContextText = '';
        state.depsDevContextLoadedAt = '';
      }
      updateDepsDevUI();
      syncAgentInputSelectionsFromToggles();
    });

    if (els.includeSarif) {
      els.includeSarif.addEventListener('change', function () {
        state.includeSarif = els.includeSarif.checked;
        localStorage.setItem(STORE.sarifContext, String(state.includeSarif));
        updateImportedContextUI('sarif');
        syncAgentInputSelectionsFromToggles();
      });
    }

    if (els.includeSbom) {
      els.includeSbom.addEventListener('change', function () {
        state.includeSbom = els.includeSbom.checked;
        localStorage.setItem(STORE.sbomContext, String(state.includeSbom));
        updateImportedContextUI('sbom');
        syncAgentInputSelectionsFromToggles();
      });
    }

    shell.querySelector('[data-reset]').addEventListener('click', function () {
      state.messages = [];
      clearChatHistoryStorage();
      renderMessages();
      setStatus(maskToken(getToken()), getToken() ? 'ok' : '');
      els.prompt.focus();
    });

    els.form.addEventListener('submit', handleSend);
    els.prompt.addEventListener('keydown', function (event) {
      if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        els.form.requestSubmit();
      }
    });

    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && els.panel && !els.panel.hidden && els.panel.getAttribute('data-expanded') === 'true') {
        event.preventDefault();
        setExpanded(false);
        els.expand.focus();
        return;
      }
      var target = event.target;
      var tag = target && target.tagName ? target.tagName.toLowerCase() : '';
      var isTyping = tag === 'input' || tag === 'textarea' || tag === 'select' ||
        (target && target.isContentEditable) ||
        (target && target.closest && target.closest('input, textarea, select, [contenteditable=""], [contenteditable="true"], [role="textbox"]'));
      if (event.key === '/' && !isTyping && !event.ctrlKey && !event.metaKey && !event.altKey) {
        event.preventDefault();
        openPanel('search');
      }
    });

    document.addEventListener('mousedown', function (event) {
      if (!els.agentRecipeResults || els.agentRecipeResults.hidden) return;
      if (event.target.closest('.ai-chatbot-typeahead')) return;
      els.agentRecipeResults.hidden = true;
      els.agentRecipeInput.setAttribute('aria-expanded', 'false');
    });

    window.addEventListener('resize', updatePanelOffset);
    window.addEventListener('scroll', updatePanelOffset, { passive: true });
    enablePersistentSiteNavigation();

    els.agentPreview.addEventListener('click', handleAgentPreview);
    els.agentDeliver.addEventListener('click', deliverAgentOutput);

    shell.querySelector('[data-agent-schedule]').addEventListener('click', saveScheduleDraft);

    handleOAuthCallback().catch(function (error) {
      setSettingsOpen(true);
      setOAuthStatus(error && error.message ? error.message : 'OAuth callback handling failed.', 'error');
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mount);
  } else {
    mount();
  }
})();
