/*
 * Host-aware MCP configuration helper for /mcp-servers/.
 * The site is static, so derive public endpoints from the page origin and keep
 * the Docker Compose source feed pinned to the internal service name.
 */
(function () {
  'use strict';

  function basePrefix() {
    var raw = (window.__SITE_BASE_PREFIX || '/').toString();
    if (!raw.startsWith('/')) raw = '/' + raw;
    if (!raw.endsWith('/')) raw = raw + '/';
    return raw;
  }

  function withoutTrailingSlash(value) {
    return (value || '').replace(/\/+$/, '');
  }

  function endpoint(path) {
    return new URL(basePrefix() + path.replace(/^\/+/, ''), window.location.origin).toString();
  }

  function mcpEndpointOverride(root, fallback) {
    var raw = root && root.getAttribute
      ? root.getAttribute('data-mcp-config-endpoint')
      : '';
    if (!raw) return fallback;

    try {
      var parsed = new URL(raw);
      if (['http:', 'https:'].indexOf(parsed.protocol) === -1) return fallback;
      if (parsed.username || parsed.password) return fallback;
      return parsed.toString();
    } catch (error) {
      return fallback;
    }
  }

  function hostList(hostname, isLocal) {
    var hosts = ['security-recipes'];
    if (hostname) hosts.push(hostname);
    if (isLocal) {
      hosts.push('localhost');
      hosts.push('127.0.0.1');
      hosts.push('::1');
    }
    if (hostname !== 'security-recipes.ai') hosts.push('security-recipes.ai');
    return hosts.filter(function (item, index, list) {
      return item && list.indexOf(item) === index;
    });
  }

  function shellQuote(value) {
    return "'" + String(value).replace(/'/g, "'\"'\"'") + "'";
  }

  function tomlString(value) {
    return '"' + String(value)
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\u0008/g, '\\b')
      .replace(/\t/g, '\\t')
      .replace(/\n/g, '\\n')
      .replace(/\f/g, '\\f')
      .replace(/\r/g, '\\r')
      .replace(/[\u0000-\u0007\u000b\u000e-\u001f\u007f]/g, function (character) {
        return '\\u' + character.charCodeAt(0).toString(16).padStart(4, '0');
      }) + '"';
  }

  function tomlArray(values) {
    return '[' + values.map(tomlString).join(', ') + ']';
  }

  function composeEnv(config) {
    return [
      'RECIPES_MCP_SOURCE_INDEX_URL=http://security-recipes/api/recipes.json',
      'RECIPES_MCP_ALLOWED_SOURCE_HOSTS=' + config.allowedHosts.join(','),
      'RECIPES_MCP_PUBLIC_BASE_URL=' + config.mcpUrl,
      'RECIPES_MCP_TRANSPORT=streamable-http',
      'RECIPES_MCP_HOST=0.0.0.0',
      'RECIPES_MCP_PORT=80',
      'RECIPES_MCP_PATH=/mcp',
      'RECIPES_MCP_LOG_LEVEL=info'
    ].join('\n');
  }

  function standaloneToml(config) {
    return [
      '# Use this when the MCP server runs outside docker compose.',
      'source_index_url = ' + tomlString(config.feedUrl),
      'allowed_source_hosts = ' + tomlArray(config.publicAllowedHosts),
      'server_public_base_url = ' + tomlString(config.mcpUrl),
      'cache_ttl_seconds = 3600',
      'request_timeout_seconds = 15',
      'max_results_default = 8',
      'max_results_cap = 25'
    ].join('\n');
  }

  function healthChecks(config) {
    return [
      '# Compose stack',
      'docker compose ps',
      '',
      '# Confirm the site recipe feed is reachable from this browser host',
      'curl -fsS ' + shellQuote(config.feedUrl) + ' | head',
      '',
      '# In an MCP client, try these tools next',
      'recipes_server_info',
      'recipes_search {"query":"react server components rce","limit":2}',
      'recipes_get {"slug_or_path":"cve-2025-55182-react-server-components-rce"}'
    ].join('\n');
  }

  function clientJson(config) {
    return JSON.stringify({
      mcpServers: {
        'security-recipes': {
          transport: 'streamable-http',
          url: config.mcpUrl
        }
      }
    }, null, 2);
  }

  function setText(root, selector, text) {
    var node = root.querySelector(selector);
    if (node) node.textContent = text;
  }

  function fallbackCopy(text) {
    var field = document.createElement('textarea');
    field.value = text;
    field.setAttribute('readonly', '');
    field.style.position = 'fixed';
    field.style.top = '0';
    field.style.left = '-9999px';
    document.body.appendChild(field);
    field.focus();
    field.select();
    field.setSelectionRange(0, field.value.length);

    var copied = false;
    try {
      copied = document.execCommand('copy');
    } catch (error) {
      copied = false;
    }

    document.body.removeChild(field);
    if (!copied) throw new Error('Clipboard copy was unavailable.');
  }

  async function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      try {
        await navigator.clipboard.writeText(text);
        return;
      } catch (error) {
        fallbackCopy(text);
        return;
      }
    }

    fallbackCopy(text);
  }

  function copyLabel(key) {
    return {
      url: 'MCP client URL',
      client: 'MCP client JSON',
      env: 'Docker Compose environment',
      toml: 'standalone TOML',
      checks: 'health checks'
    }[key] || key;
  }

  function setCopy(root, key, text) {
    var button = root.querySelector('[data-mcp-config-copy="' + key + '"]');
    if (!button) return;
    button.addEventListener('click', async function () {
      try {
        await copyText(text);
        setText(root, '[data-mcp-config-status]', 'Copied ' + copyLabel(key) + '.');
      } catch (error) {
        setText(root, '[data-mcp-config-status]', 'Copy unavailable. Select the code block text above.');
      }
    });
  }

  function init(root) {
    var hostname = window.location.hostname;
    var isLocal = ['localhost', '127.0.0.1', '::1'].indexOf(hostname) !== -1;
    var isProduction = hostname === 'security-recipes.ai' || hostname === 'www.security-recipes.ai';
    var mcpUrl = mcpEndpointOverride(root, endpoint('/mcp'));
    var config = {
      origin: withoutTrailingSlash(window.location.origin),
      mcpUrl: mcpUrl,
      feedUrl: endpoint('/api/recipes.json'),
      allowedHosts: hostList(hostname, isLocal),
      publicAllowedHosts: hostList(hostname, isLocal).filter(function (host) {
        return host !== 'security-recipes';
      })
    };
    var mode = isLocal ? 'Local MCP configuration' : (isProduction ? 'security-recipes.ai MCP configuration' : 'Hosted MCP configuration');
    var summary = isLocal
      ? 'Use the current localhost origin for clients; Compose keeps the MCP sidecar on the internal recipe feed.'
      : 'Use this host as the public MCP endpoint; standalone servers should read this host\'s recipe feed.';
    var badge = isLocal ? 'localhost' : (isProduction ? 'production' : 'hosted');
    var client = clientJson(config);
    var env = composeEnv(config);
    var toml = standaloneToml(config);
    var checks = healthChecks(config);

    setText(root, '[data-mcp-config-mode]', mode);
    setText(root, '[data-mcp-config-summary]', summary);
    setText(root, '[data-mcp-config-badge]', badge);
    setText(root, '[data-mcp-config-url]', config.mcpUrl);
    setText(root, '[data-mcp-config-feed]', config.feedUrl);
    setText(root, '[data-mcp-config-hosts]', config.allowedHosts.join(','));
    setText(root, '[data-mcp-config-client-json]', client);
    setText(root, '[data-mcp-config-env]', env);
    setText(root, '[data-mcp-config-toml]', toml);
    setText(root, '[data-mcp-config-checks]', checks);
    setCopy(root, 'url', config.mcpUrl);
    setCopy(root, 'client', client);
    setCopy(root, 'env', env);
    setCopy(root, 'toml', toml);
    setCopy(root, 'checks', checks);
  }

  function initAll() {
    document.querySelectorAll('[data-mcp-config-helper]').forEach(init);
  }

  var api = {
    healthChecks: healthChecks,
    mcpEndpointOverride: mcpEndpointOverride,
    shellQuote: shellQuote,
    standaloneToml: standaloneToml,
    tomlArray: tomlArray,
    tomlString: tomlString
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', initAll);
    } else {
      initAll();
    }
  }
})();
