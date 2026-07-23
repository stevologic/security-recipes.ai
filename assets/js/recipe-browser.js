/*
 * Recipe browser for /recipes/.
 * The page ships a small server-rendered first page of cards; this layer
 * fetches the slim /recipes-browser.json feed and renders, filters, sorts,
 * and paginates the reviewed workflow collection client-side. The much
 * larger CVE collection remains on its lazy worker-and-shard search path.
 */
(function () {
  'use strict';

  var win = window;

  function escapeHtml(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function normalize(value) {
    return (value || '')
      .toString()
      .toLowerCase()
      .normalize('NFKD')
      .replace(/[̀-ͯ]/g, '')
      .trim();
  }

  function tokens(value) {
    return normalize(value).split(/\s+/).filter(Boolean);
  }

  function pluralize(count, singular, plural) {
    return count + ' ' + (count === 1 ? singular : plural);
  }

  function aiProvenanceHtml(model, label) {
    var normalizedModel = String(model || '').trim();
    if (!normalizedModel) return '';
    var normalizedLabel = String(label || 'AI-assisted').trim() || 'AI-assisted';
    var title = /\bwith$/i.test(normalizedLabel)
      ? normalizedLabel + ' ' + normalizedModel
      : normalizedLabel + ' with ' + normalizedModel;
    return (
      '<span class="sr-ai-provenance" title="' + escapeHtml(title) + '" aria-label="' + escapeHtml(title) + '">' +
      '<span class="sr-ai-provenance__icon" aria-hidden="true">✦</span>' +
      '<span class="sr-ai-provenance__label">' + escapeHtml(normalizedLabel) + '</span>' +
      '<code>' + escapeHtml(normalizedModel) + '</code>' +
      '</span>'
    );
  }

  function sanitizeFilePart(value) {
    var clean = normalize(value)
      .replace(/[^a-z0-9._-]+/g, '-')
      .replace(/^-+|-+$/g, '');
    return clean || 'recipe';
  }

  function basePrefix() {
    var raw = (window.__SITE_BASE_PREFIX || '/').toString();
    if (!raw.startsWith('/')) raw = '/' + raw;
    if (!raw.endsWith('/')) raw = raw + '/';
    return raw;
  }

  function absoluteUrl(path) {
    try {
      return new URL(path, window.location.origin).toString();
    } catch (error) {
      return path;
    }
  }

  function endpointCandidates(root) {
    var prefix = basePrefix();
    var origin = window.location.origin;
    var configured = root.getAttribute('data-recipe-api') || '/api/curated-recipes.json';
    return [
      new URL(configured, origin).toString(),
      new URL(prefix + 'api/curated-recipes.json', origin).toString()
    ].filter(function (url, index, list) {
      return list.indexOf(url) === index;
    });
  }

  function feedCandidates(root) {
    var prefix = basePrefix();
    var origin = window.location.origin;
    var configured = root.getAttribute('data-recipe-feed') || '/recipes-browser.json';
    return [
      new URL(configured, origin).toString(),
      new URL(prefix + 'recipes-browser.json', origin).toString()
    ].filter(function (url, index, list) {
      return list.indexOf(url) === index;
    });
  }

  function mcpEndpoint(root) {
    return absoluteUrl(root.getAttribute('data-recipe-mcp') || '/mcp');
  }

  function agentPrompt(root) {
    var jsonEndpoint = absoluteUrl(root.getAttribute('data-recipe-api') || '/api/curated-recipes.json');
    var mcp = mcpEndpoint(root);
    return [
      'Use Security Recipes as read-only remediation context.',
      '',
      'Recipe JSON endpoint: ' + jsonEndpoint,
      'MCP endpoint: ' + mcp,
      '',
      'Preferred MCP tools:',
      '- recipes_search: search by finding title, package, CVE/GHSA, ecosystem, rule id, or keywords.',
      '- recipes_get: retrieve the selected recipe by slug, path, URL, or source_file.',
      '- recipes_match_finding: suggest best-fit recipes for one concrete finding.',
      '- recipes_quality_report: inspect completeness tiers and find recipes missing review signals.',
      '',
      'Select by facet before acting: remediation for patch work, risk for exploitability and impact, audit for evidence mapping, compliance for standards readiness, and code-hygiene for cleanup or hardening work.',
      'For synchronized vulnerability intelligence, use ' + absoluteUrl('/cve-database/') + ' or the dedicated recipes_cve_* MCP tools; do not mix the CVE corpus into curated workflow selection.',
      '',
      'Use one recipe for one finding, preserve the recipe stop conditions, run the requested tests, and produce a reviewer-ready PR or triage note. Do not use MCP for writes, ticket creation, deployments, secret rotation, or cloud changes unless this task explicitly grants that permission.'
    ].join('\n');
  }

  function normalizeIndexPayload(data) {
    if (Array.isArray(data)) {
      return { api_version: 'legacy-array', recipes: data };
    }
    if (data && Array.isArray(data.recipes)) return data;
    return { api_version: 'unknown', recipes: [] };
  }

  function downloadJson(fileName, payload) {
    var blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: 'application/json;charset=utf-8'
    });
    var url = URL.createObjectURL(blob);
    var link = document.createElement('a');
    link.href = url;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(function () {
      URL.revokeObjectURL(url);
    }, 0);
  }

  function severityRank(value) {
    var rank = { critical: 4, high: 3, medium: 2, low: 1, unspecified: 0 };
    return rank[normalize(value)] || 0;
  }

  function workflowArchetypeLabel(value) {
    if (value === '*') return 'All CVEs';
    return String(value || '')
      .split('_')
      .filter(Boolean)
      .map(function (part) {
        return ['ssrf', 'xxe', 'idor', 'dos', 'sql', 'http'].indexOf(part) !== -1
          ? part.toUpperCase()
          : part.charAt(0).toUpperCase() + part.slice(1);
      })
      .join(' ');
  }

  function workflowRelationshipText(card) {
    var archetypes = Array.isArray(card.cveArchetypes) ? card.cveArchetypes : [];
    if (!archetypes.length) return '';
    var shown = archetypes.slice(0, 2).map(workflowArchetypeLabel).join(', ');
    var remaining = archetypes.length - 2;
    var roleText = String(card.cveWorkflowRole || 'remediate').replace(/-/g, ' ');
    var role = roleText.charAt(0).toUpperCase() + roleText.slice(1);
    return 'CVE ' + role + ' · ' + shown + (remaining > 0 ? ' +' + remaining : '');
  }

  // Card object built from a /recipes-browser.json entry. Field names mirror the
  // feed; `indexText` is the precomputed lowercase search haystack.
  function toCard(entry, index) {
    return {
      initialIndex: index,
      slug: entry.slug || '',
      displayTitle: entry.title || '',
      title: normalize(entry.title || ''),
      url: entry.url || '',
      category: entry.category || 'general',
      categoryLabel: entry.categoryLabel || '',
      severity: entry.severity || 'unspecified',
      maturity: entry.maturity || 'unspecified',
      quality: Number(entry.quality || 0),
      tier: entry.tier || 'starter',
      facets: Array.isArray(entry.facets) ? entry.facets : [],
      date: entry.date || '',
      published: entry.published || '',
      ecosystem: entry.ecosystem || '',
      identity: entry.identity || '',
      cve: entry.cve || '',
      cveArchetypes: Array.isArray(entry.cveArchetypes) ? entry.cveArchetypes : [],
      cveWorkflowRole: entry.cveWorkflowRole || '',
      summary: entry.summary || '',
      model: entry.model || '',
      aiAssisted: entry.aiAssisted === true || entry.ai_assisted === true,
      generatedBy: entry.generatedBy || entry.generated_by || '',
      zeroDay: !!entry.zeroDay,
      indexText: (entry.search || '').toString()
    };
  }

  // Inline seed emitted by lib/shortcodes/recipe-browser.js: the SSR first
  // page plus a bounded slice of every lane, so filters always have data
  // even before (or without) the full feed.
  function parseSeed(root) {
    var script = root.querySelector('script[type="application/json"][data-recipe-seed]');
    if (!script) return [];
    try {
      var data = JSON.parse(script.textContent || '[]');
      return Array.isArray(data) ? data : [];
    } catch (error) {
      return [];
    }
  }

  // Map a rich /api/recipes.json entry onto the slim feed-entry shape so it
  // can flow through toCard(). Browser lanes are narrower than feed
  // categories: tool-specific lanes (claude, codex, ...) fold into General.
  var BROWSER_LANES = {
    'classic-defaults': 'Defaults',
    'compliance-standards': 'Compliance',
    'code-hygiene': 'Code Hygiene',
    'crypto-defi': 'Crypto/DeFi'
  };

  function apiRecipeToFeedEntry(recipe) {
    var sourceFile = String(recipe.source_file || '').replace(/\\/g, '/');
    if (sourceFile && (
      sourceFile.indexOf('recipes/') !== 0 ||
      sourceFile.indexOf('recipes/cve/') === 0
    )) return null;
    var feedSlug = recipe.category && recipe.category.slug ? recipe.category.slug : 'general';
    if (feedSlug === 'cve') return null;
    var lane = BROWSER_LANES[feedSlug] ? feedSlug : 'general';
    var label = BROWSER_LANES[lane] || 'General';
    var tags = Array.isArray(recipe.tags) ? recipe.tags : [];
    var aliases = Array.isArray(recipe.aliases) ? recipe.aliases : [];
    var facets = Array.isArray(recipe.facets) ? recipe.facets : [];
    var searchParts = [
      recipe.title, recipe.summary, recipe.cve, recipe.ghsa, label,
      recipe.severity, recipe.maturity, tags.join(' '), facets.join(' '),
      recipe.ecosystem, recipe.model, recipe.date,
      Array.isArray(recipe.cve_archetypes) ? recipe.cve_archetypes.join(' ') : '',
      recipe.cve_workflow_role
    ].concat(aliases);
    return {
      slug: recipe.slug || '',
      title: recipe.title || '',
      url: recipe.path || recipe.url || '',
      category: lane,
      categoryLabel: label,
      severity: recipe.severity || 'unspecified',
      maturity: recipe.maturity || 'unspecified',
      quality: (recipe.quality && recipe.quality.score) || 0,
      tier: (recipe.quality && recipe.quality.tier) || 'starter',
      facets: facets,
      date: recipe.date || '',
      published: lane === 'cve' ? recipe.date || '' : '',
      ecosystem: recipe.ecosystem || '',
      identity: recipe.cve || recipe.ghsa || recipe.agent || label,
      cve: recipe.cve || '',
      cveArchetypes: Array.isArray(recipe.cve_archetypes) ? recipe.cve_archetypes : [],
      cveWorkflowRole: recipe.cve_workflow_role || '',
      summary: recipe.summary || '',
      model: recipe.model || '',
      aiAssisted: recipe.ai_assisted === true,
      generatedBy: recipe.generated_by || '',
      zeroDay: !!recipe.zero_day,
      search: searchParts.filter(Boolean).join(' ').toLowerCase()
    };
  }

  // Server-side mirror of lib/recipe-cards.js renderCardHtml(). Must match.
  function buildCardHtml(card) {
    var severity = card.severity || 'unspecified';
    var displayTier = card.tier === 'world-class' ? 'complete' : card.tier;
    var topline =
      '<span>' + escapeHtml(card.categoryLabel) + '</span>' +
      (card.zeroDay ? '<span class="recipe-browser-card__fresh">0-Day</span>' : '') +
      (severity !== 'unspecified'
        ? '<span class="recipe-browser-card__severity recipe-browser-card__severity--' + escapeHtml(severity) + '">' + escapeHtml(severity) + '</span>'
        : '<span>' + escapeHtml(card.maturity) + '</span>') +
      '<span class="recipe-browser-card__quality recipe-browser-card__quality--' + escapeHtml(card.tier) + '">' + escapeHtml(displayTier) + ' ' + card.quality + '</span>';

    var meta =
      (card.identity ? '<span>' + escapeHtml(card.identity) + '</span>' : '') +
      (card.published ? '<span>Published ' + escapeHtml(card.published) + '</span>' : '') +
      (card.ecosystem ? '<span>' + escapeHtml(card.ecosystem) + '</span>' : '') +
      aiProvenanceHtml(card.model, card.aiAssisted ? 'AI-enriched' : 'Tested with');
    var evidenceLink = card.cve
      ? '<a class="recipe-browser-card__evidence" href="/cve/' + encodeURIComponent(card.cve.toUpperCase()) + '/" aria-describedby="recipe-card-' + escapeHtml(card.slug) + '">CVE evidence</a>'
      : '';
    var workflowRelationship = workflowRelationshipText(card);

    return (
      '<article class="recipe-browser-card recipe-browser-card--' + escapeHtml(card.category) + (card.zeroDay ? ' recipe-browser-card--zero-day' : '') + '" data-recipe-card data-recipe-slug="' + escapeHtml(card.slug) + '" data-recipe-path="' + escapeHtml(card.url) + '" aria-labelledby="recipe-card-' + escapeHtml(card.slug) + '">' +
      '<div class="recipe-browser-card__visual" aria-hidden="true"><span>' + escapeHtml(card.categoryLabel.slice(0, 2).toUpperCase()) + '</span></div>' +
      '<div class="recipe-browser-card__content">' +
      '<div class="recipe-browser-card__topline">' + topline + '</div>' +
      '<h3 id="recipe-card-' + escapeHtml(card.slug) + '"><a href="' + escapeHtml(card.url) + '">' + escapeHtml(card.displayTitle) + '</a></h3>' +
      (card.summary ? '<p>' + escapeHtml(card.summary) + '</p>' : '') +
      '<ul class="recipe-browser-card__facets" aria-label="Recipe outcomes">' + card.facets.map(function (f) { return '<li>' + escapeHtml(f.replace(/-/g, ' ')) + '</li>'; }).join('') + '</ul>' +
      '<div class="recipe-browser-card__meta">' + meta +
      (workflowRelationship
        ? '<span class="recipe-browser-card__cve-linkage">' + escapeHtml(workflowRelationship) + '</span>'
        : '') +
      '</div>' +
      '<div class="recipe-browser-card__actions">' +
      '<a class="recipe-browser-card__open" href="' + escapeHtml(card.url) + '" aria-describedby="recipe-card-' + escapeHtml(card.slug) + '">Open</a>' +
      evidenceLink +
      '<button type="button" class="recipe-browser-card__download" data-recipe-download aria-label="Download ' + escapeHtml(card.displayTitle) + ' recipe JSON">' +
      '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4v10m0 0 4-4m-4 4-4-4M5 19h14"/></svg>' +
      '<span>Download</span></button></div>' +
      '</div></article>'
    );
  }

  function initRecipeBrowser(root) {
    if (root.dataset.recipeBrowserReady === 'true') return;
    document.documentElement.dataset.recipeBrowserPage = 'true';

    var searchInput = root.querySelector('[data-recipe-search]');
    var severityFilter = root.querySelector('[data-recipe-severity-filter]');
    var facetFilter = root.querySelector('[data-recipe-facet-filter]');
    var qualityFilter = root.querySelector('[data-recipe-quality-filter]');
    var sortSelect = root.querySelector('[data-recipe-sort]');
    var clearSearchButton = root.querySelector('[data-recipe-clear-search]');
    var summary = root.querySelector('[data-recipe-summary]');
    var empty = root.querySelector('[data-recipe-empty]');
    var status = root.querySelector('[data-recipe-status]');
    var grid = root.querySelector('[data-recipe-grid]');
    var loadMoreButton = root.querySelector('[data-recipe-load-more]');
    var filterButtons = Array.prototype.slice.call(root.querySelectorAll('[data-recipe-filter]'));
    var resetFiltersButton = root.querySelector('[data-recipe-reset-filters]');
    var activeFilters = root.querySelector('[data-recipe-active-filters]');
    var filterDrawer = root.querySelector('.recipe-library__facets');
    var filterToggle = root.querySelector('[data-recipe-filter-toggle]');
    var filterClose = root.querySelector('[data-recipe-filter-close]');
    var filterCount = root.querySelector('[data-recipe-filter-count]');
    var filterLabels = {};
    var typeahead = null;
    var typeaheadList = null;
    var typeaheadItems = [];
    var activeTypeaheadIndex = -1;

    var pageSize = Math.max(12, Number(root.getAttribute('data-recipe-page-size') || 36));
    var allCards = [];
    var visible = [];
    var renderedCount = 0;
    var activeCategory = 'all';
    var restoringHistory = false;
    var filterReturnFocus = null;
    var loadedIndex = null;
    // False until the full catalogue (feed or API fallback) has loaded; until
    // then allCards holds only the inline seed slice. catalogueFailed flips
    // when every source has been tried, so messaging stops saying "loading".
    var catalogueComplete = false;
    var catalogueFailed = false;

    var seed = parseSeed(root);
    if (seed.length) allCards = seed.map(toCard);

    function setStatus(message, tone) {
      if (!status) return;
      status.textContent = message || '';
      status.dataset.tone = tone || '';
    }

    function allowed(value, values, fallback) {
      return values.indexOf(value) !== -1 ? value : fallback;
    }

    function relevantParams() {
      try {
        return new URL(win.location.href).searchParams;
      } catch (error) {
        return new URLSearchParams();
      }
    }

    function replaceUrlForCurated() {
      if (restoringHistory || !win.history || !win.history.replaceState) return;
      var url = new URL(win.location.href);
      ['view', 'q', 'category', 'severity', 'facet', 'quality', 'sort', 'year', 'kev'].forEach(function (key) {
        url.searchParams.delete(key);
      });
      var query = searchInput ? searchInput.value.trim().slice(0, 160) : '';
      if (query) url.searchParams.set('q', query);
      if (activeCategory !== 'all') url.searchParams.set('category', activeCategory);
      if (severityFilter && severityFilter.value !== 'all') url.searchParams.set('severity', severityFilter.value);
      if (facetFilter && facetFilter.value !== 'all') url.searchParams.set('facet', facetFilter.value);
      if (qualityFilter && qualityFilter.value !== '0') url.searchParams.set('quality', qualityFilter.value);
      if (sortSelect && sortSelect.value !== 'newest') url.searchParams.set('sort', sortSelect.value);
      win.history.replaceState({ recipeLibrary: true }, '', url.pathname + url.search + url.hash);
    }

    function renderActiveFilters() {
      if (!activeFilters) return;
      activeFilters.textContent = '';
      var items = [];
      var query = searchInput ? searchInput.value.trim() : '';
      if (query) items.push({ key: 'query', label: 'Search: ' + query });
      if (activeCategory !== 'all') {
        items.push({ key: 'category', label: filterLabels[activeCategory] || prettyToken(activeCategory) });
      }
      if (severityFilter && severityFilter.value !== 'all') {
        items.push({ key: 'severity', label: 'Severity: ' + prettyToken(severityFilter.value) });
      }
      if (facetFilter && facetFilter.value !== 'all') {
        items.push({ key: 'facet', label: 'Outcome: ' + prettyToken(facetFilter.value) });
      }
      if (qualityFilter && qualityFilter.value !== '0') {
        items.push({ key: 'quality', label: 'Review score: ' + qualityFilter.options[qualityFilter.selectedIndex].text });
      }
      items.forEach(function (item) {
        var button = document.createElement('button');
        button.type = 'button';
        button.dataset.activeFilter = item.key;
        button.textContent = item.label + ' ×';
        button.setAttribute('aria-label', 'Remove ' + item.label + ' filter');
        activeFilters.appendChild(button);
      });
      activeFilters.hidden = items.length === 0;
      if (filterCount) filterCount.textContent = String(items.length);
      root.dataset.filterCount = String(items.length);
    }

    function resetCuratedFilters(focusSearch) {
      if (searchInput) searchInput.value = '';
      if (severityFilter) severityFilter.value = 'all';
      if (facetFilter) facetFilter.value = 'all';
      if (qualityFilter) qualityFilter.value = '0';
      if (sortSelect) sortSelect.value = 'newest';
      activeCategory = 'all';
      filterButtons.forEach(function (button) {
        var active = button.getAttribute('data-recipe-filter') === 'all';
        button.classList.toggle('is-active', active);
        button.setAttribute('aria-pressed', active ? 'true' : 'false');
      });
      applyFilters();
      closeTypeahead();
      if (focusSearch && searchInput) searchInput.focus();
    }

    function setFilterDrawer(open) {
      if (!filterDrawer || !filterToggle) return;
      var mobile = win.matchMedia && win.matchMedia('(max-width: 900px)').matches;
      var expanded = !!open && mobile;
      filterDrawer.classList.toggle('is-open', expanded);
      filterDrawer.setAttribute('aria-hidden', mobile && !expanded ? 'true' : 'false');
      filterDrawer.inert = mobile && !expanded;
      filterToggle.setAttribute('aria-expanded', expanded ? 'true' : 'false');
      document.documentElement.classList.toggle('recipe-filter-open', expanded);
      if (expanded) {
        filterReturnFocus = document.activeElement;
        var first = filterDrawer.querySelector('button, select');
        if (first) first.focus();
      } else if (filterReturnFocus && typeof filterReturnFocus.focus === 'function') {
        filterReturnFocus.focus();
        filterReturnFocus = null;
      }
    }

    function restoreFromUrl() {
      var params = relevantParams();
      if (params.get('view') === 'cve' && win.location && typeof win.location.replace === 'function') {
        var legacyTarget = new URL('/cve-database/', win.location.origin);
        ['q', 'severity', 'year', 'kev'].forEach(function (key) {
          var value = params.get(key);
          if (value) legacyTarget.searchParams.set(key, value);
        });
        win.location.replace(legacyTarget.pathname + legacyTarget.search);
        return;
      }
      var categories = filterButtons.map(function (button) {
        return button.getAttribute('data-recipe-filter');
      });
      restoringHistory = true;
      if (searchInput) searchInput.value = String(params.get('q') || '').slice(0, 160);
      activeCategory = allowed(params.get('category') || 'all', categories, 'all');
      if (severityFilter) {
        severityFilter.value = allowed(params.get('severity') || 'all', ['all', 'critical', 'high', 'medium', 'low', 'unspecified'], 'all');
      }
      if (facetFilter) {
        facetFilter.value = allowed(params.get('facet') || 'all', ['all', 'remediation', 'risk', 'audit', 'compliance', 'code-hygiene'], 'all');
      }
      if (qualityFilter) qualityFilter.value = allowed(params.get('quality') || '0', ['0', '50', '70', '85'], '0');
      if (sortSelect) sortSelect.value = allowed(params.get('sort') || 'newest', ['newest', 'title', 'severity', 'quality'], 'newest');
      filterButtons.forEach(function (button) {
        var active = button.getAttribute('data-recipe-filter') === activeCategory;
        button.classList.toggle('is-active', active);
        button.setAttribute('aria-pressed', active ? 'true' : 'false');
      });
      restoringHistory = false;
      applyFilters();
    }

    // Rich agent feed (/api/recipes.json), used for downloads only.
    async function loadIndex() {
      if (loadedIndex) return loadedIndex;
      var urls = endpointCandidates(root);
      var lastError = null;
      for (var i = 0; i < urls.length; i++) {
        try {
          var response = await fetch(urls[i], { credentials: 'same-origin' });
          if (!response.ok) throw new Error('endpoint-unavailable');
          var data = normalizeIndexPayload(await response.json());
          if (data.recipes.length) {
            data.endpoint = urls[i];
            loadedIndex = data;
            return loadedIndex;
          }
        } catch (error) {
          lastError = error;
        }
      }
      if (lastError) console.warn('[recipe-browser] recipe endpoint unavailable');
      loadedIndex = { api_version: 'card-fallback', recipes: [] };
      return loadedIndex;
    }

    // Slim card feed (/recipes-browser.json) that drives the catalogue.
    async function loadFeed() {
      var urls = feedCandidates(root);
      for (var i = 0; i < urls.length; i++) {
        try {
          var response = await fetch(urls[i], { credentials: 'same-origin' });
          if (!response.ok) throw new Error('feed-unavailable');
          var data = await response.json();
          var recipes = Array.isArray(data) ? data : (data && data.recipes) || [];
          if (recipes.length) return recipes;
        } catch (error) {
          /* try next candidate */
        }
      }
      return null;
    }

    function renderSummary(count) {
      if (!summary) return;
      var suffix = activeCategory === 'all' ? '' : ' in ' + (filterLabels[activeCategory] || 'this category');
      var note = '';
      if (!catalogueComplete) {
        note = catalogueFailed
          ? ' Partial curated list — reload to retry the curated feed.'
          : ' Curated collection still loading.';
      }
      summary.textContent = 'Showing ' + Math.min(renderedCount, count) + ' of ' +
        pluralize(count, 'curated recipe', 'curated recipes') + suffix + '.' + note;
    }

    function updateLoadMore() {
      if (!loadMoreButton) return;
      var remaining = visible.length - renderedCount;
      if (remaining > 0) {
        loadMoreButton.hidden = false;
        loadMoreButton.textContent = 'Load ' + Math.min(pageSize, remaining) + ' more of ' + visible.length;
      } else {
        loadMoreButton.hidden = true;
      }
    }

    // Render the first `renderedCount` visible cards, replacing the grid.
    function renderPage() {
      if (!grid) return;
      var slice = visible.slice(0, renderedCount);
      var html = '';
      for (var i = 0; i < slice.length; i++) html += buildCardHtml(slice[i]);
      grid.innerHTML = html;
      if (empty) empty.hidden = visible.length > 0;
      updateLoadMore();
    }

    function appendNextPage() {
      if (!grid) return;
      var from = renderedCount;
      renderedCount = Math.min(visible.length, renderedCount + pageSize);
      var slice = visible.slice(from, renderedCount);
      var html = '';
      for (var i = 0; i < slice.length; i++) html += buildCardHtml(slice[i]);
      grid.insertAdjacentHTML('beforeend', html);
      updateLoadMore();
      renderSummary(visible.length);
      var firstAdded = grid.children[from];
      var firstAction = firstAdded && firstAdded.querySelector('a, button');
      if (firstAction) firstAction.focus();
    }

    function sortVisible(items) {
      var mode = sortSelect ? sortSelect.value : 'newest';
      items.sort(function (a, b) {
        if (mode === 'title') return a.title.localeCompare(b.title);
        if (mode === 'severity') {
          var severityDelta = severityRank(b.severity) - severityRank(a.severity);
          if (severityDelta) return severityDelta;
          return b.date.localeCompare(a.date);
        }
        if (mode === 'quality') {
          var qualityDelta = b.quality - a.quality;
          if (qualityDelta) return qualityDelta;
          return b.date.localeCompare(a.date);
        }
        var dateDelta = b.date.localeCompare(a.date);
        if (dateDelta) return dateDelta;
        return a.initialIndex - b.initialIndex;
      });
    }

    function applyFilters() {
      var queryTokens = tokens(searchInput ? searchInput.value : '');
      var severity = severityFilter ? severityFilter.value : 'all';
      var facet = facetFilter ? facetFilter.value : 'all';
      var minimumQuality = qualityFilter ? Number(qualityFilter.value || 0) : 0;

      visible = allCards.filter(function (card) {
        var categoryMatch = activeCategory === 'all' ||
          (activeCategory === 'zero-day' ? card.zeroDay : card.category === activeCategory);
        if (!categoryMatch) return false;
        if (severity !== 'all' && card.severity !== severity) return false;
        if (facet !== 'all' && card.facets.indexOf(facet) === -1) return false;
        if (minimumQuality && card.quality < minimumQuality) return false;
        if (queryTokens.length) {
          for (var t = 0; t < queryTokens.length; t++) {
            if (card.indexText.indexOf(queryTokens[t]) === -1) return false;
          }
        }
        return true;
      });

      sortVisible(visible);
      renderedCount = Math.min(visible.length, pageSize);
      renderPage();

      if (clearSearchButton) clearSearchButton.hidden = queryTokens.length === 0;
      renderSummary(visible.length);
      renderActiveFilters();
      root.dataset.filtered = queryTokens.length || activeCategory !== 'all' || severity !== 'all' || facet !== 'all' || minimumQuality > 0 ? 'true' : 'false';
      if (document.activeElement === searchInput) renderTypeahead();
      replaceUrlForCurated();
    }

    function setActiveCategory(nextCategory) {
      activeCategory = nextCategory || 'all';
      filterButtons.forEach(function (button) {
        var active = button.getAttribute('data-recipe-filter') === activeCategory;
        button.classList.toggle('is-active', active);
        button.setAttribute('aria-pressed', active ? 'true' : 'false');
      });
      applyFilters();
    }

    function clearSearch() {
      if (!searchInput) return;
      searchInput.value = '';
      applyFilters();
      closeTypeahead();
      searchInput.focus();
    }

    /* ---- typeahead ---------------------------------------------------- */

    function prettyToken(value) {
      return (value || '').toString().replace(/-/g, ' ').replace(/\b\w/g, function (letter) {
        return letter.toUpperCase();
      });
    }

    function suggestionMeta(parts) {
      return parts.filter(Boolean).join(' · ');
    }

    function scoreSuggestion(card, query, queryTokens) {
      if (!queryTokens.length) return 0;
      var score = 0;
      if (card.title === query) score += 100;
      if (card.title.indexOf(query) === 0) score += 70;
      if (card.indexText.indexOf(query) !== -1) score += 25;
      queryTokens.forEach(function (token) {
        if (card.title.indexOf(token) !== -1) score += 18;
        if (card.indexText.indexOf(token) !== -1) score += 8;
      });
      if (card.severity === 'critical') score += 5;
      if (card.zeroDay) score += 5;
      score += Math.min(5, Math.floor(card.quality / 20));
      return score;
    }

    function setTypeaheadActive(nextIndex) {
      activeTypeaheadIndex = nextIndex;
      typeaheadItems.forEach(function (item, index) {
        var active = index === activeTypeaheadIndex;
        item.classList.toggle('is-active', active);
        item.setAttribute('aria-selected', active ? 'true' : 'false');
      });
      if (searchInput) {
        var activeItem = typeaheadItems[activeTypeaheadIndex];
        searchInput.setAttribute('aria-activedescendant', activeItem ? activeItem.id : '');
      }
    }

    function closeTypeahead() {
      if (!typeahead) return;
      typeahead.hidden = true;
      typeaheadItems = [];
      activeTypeaheadIndex = -1;
      if (typeaheadList) typeaheadList.replaceChildren();
      if (searchInput) {
        searchInput.setAttribute('aria-expanded', 'false');
        searchInput.removeAttribute('aria-activedescendant');
      }
    }

    function applySuggestion(suggestion) {
      if (!suggestion || !searchInput) return;
      if (suggestion.kind === 'category') {
        searchInput.value = '';
        setActiveCategory(suggestion.value);
      } else if (suggestion.kind === 'severity') {
        searchInput.value = '';
        if (severityFilter) severityFilter.value = suggestion.value;
        applyFilters();
      } else if (suggestion.kind === 'facet') {
        searchInput.value = '';
        if (facetFilter) facetFilter.value = suggestion.value;
        applyFilters();
      } else if (suggestion.kind === 'quality') {
        searchInput.value = '';
        if (qualityFilter) qualityFilter.value = suggestion.value;
        applyFilters();
      } else {
        searchInput.value = suggestion.query || suggestion.title || '';
        applyFilters();
      }
      closeTypeahead();
      searchInput.focus();
    }

    function buildSuggestions(queryTokens) {
      var query = normalize(searchInput ? searchInput.value : '');
      if (!queryTokens.length) return [];

      var suggestions = [];
      var filters = [];

      Object.keys(filterLabels).forEach(function (key) {
        if (key === 'all') return;
        var label = filterLabels[key] || key;
        var haystack = normalize(label + ' ' + key);
        if (haystack.indexOf(query) !== -1 || queryTokens.some(function (token) { return haystack.indexOf(token) !== -1; })) {
          filters.push({ kind: 'category', title: label, meta: 'Browse lane', value: key });
        }
      });

      ['critical', 'high', 'medium', 'low', 'unspecified'].forEach(function (severity) {
        if (normalize(severity).indexOf(query) === -1 && queryTokens.indexOf(severity) === -1) return;
        filters.push({ kind: 'severity', title: prettyToken(severity), meta: 'Severity filter', value: severity });
      });

      ['remediation', 'risk', 'audit', 'compliance', 'code-hygiene'].forEach(function (facet) {
        var label = prettyToken(facet);
        var haystack = normalize(label + ' ' + facet);
        if (haystack.indexOf(query) === -1 && !queryTokens.some(function (token) { return haystack.indexOf(token) !== -1; })) return;
        filters.push({ kind: 'facet', title: label, meta: 'Agent facet', value: facet });
      });

      if ('world-class'.indexOf(query) !== -1 || queryTokens.indexOf('world') !== -1 || queryTokens.indexOf('quality') !== -1) {
        filters.push({ kind: 'quality', title: 'World-class recipes', meta: 'Quality filter', value: '85' });
      }

      suggestions = suggestions.concat(filters.slice(0, 4));

      allCards
        .map(function (card) {
          return { card: card, score: scoreSuggestion(card, query, queryTokens) };
        })
        .filter(function (item) { return item.score > 0; })
        .sort(function (a, b) {
          if (b.score !== a.score) return b.score - a.score;
          if (b.card.quality !== a.card.quality) return b.card.quality - a.card.quality;
          return b.card.date.localeCompare(a.card.date);
        })
        .slice(0, Math.max(4, 8 - suggestions.length))
        .forEach(function (item) {
          var card = item.card;
          suggestions.push({
            kind: 'recipe',
            title: card.displayTitle,
            query: card.displayTitle,
            meta: suggestionMeta([
              card.categoryLabel || filterLabels[card.category] || prettyToken(card.category),
              card.zeroDay ? '0-Day' : '',
              card.severity !== 'unspecified' ? prettyToken(card.severity) : '',
              card.quality ? 'Score ' + card.quality : ''
            ]),
            summary: card.summary,
            path: card.url
          });
        });

      return suggestions.slice(0, 8);
    }

    function renderTypeahead() {
      if (!searchInput || !typeahead || !typeaheadList) return;
      var queryTokens = tokens(searchInput.value);
      var suggestions = buildSuggestions(queryTokens);
      if (!suggestions.length) {
        closeTypeahead();
        return;
      }

      typeaheadList.replaceChildren();
      typeaheadItems = suggestions.map(function (suggestion, index) {
        var button = document.createElement('button');
        var id = 'recipe-browser-typeahead-option-' + index;
        button.id = id;
        button.type = 'button';
        button.className = 'recipe-browser__typeahead-item recipe-browser__typeahead-item--' + suggestion.kind;
        button.setAttribute('role', 'option');
        button.setAttribute('aria-selected', 'false');
        button.tabIndex = -1;
        button.dataset.typeaheadIndex = String(index);

        var label = document.createElement('span');
        label.className = 'recipe-browser__typeahead-title';
        label.textContent = suggestion.title;

        var meta = document.createElement('span');
        meta.className = 'recipe-browser__typeahead-meta';
        meta.textContent = suggestion.meta;

        button.appendChild(label);
        button.appendChild(meta);

        if (suggestion.summary) {
          var summaryLine = document.createElement('span');
          summaryLine.className = 'recipe-browser__typeahead-summary';
          summaryLine.textContent = suggestion.summary;
          button.appendChild(summaryLine);
        }

        button.addEventListener('pointerdown', function (event) { event.preventDefault(); });
        button.addEventListener('click', function () { applySuggestion(suggestion); });

        typeaheadList.appendChild(button);
        return button;
      });

      typeahead.hidden = false;
      searchInput.setAttribute('aria-expanded', 'true');
      setTypeaheadActive(-1);
    }

    /* ---- downloads ---------------------------------------------------- */

    async function downloadRecipe(slug, path) {
      var index = await loadIndex();
      // Match by path first: filename-derived slugs can collide across tool
      // directories, but page paths are unique.
      var recipe = (path && index.recipes.find(function (item) {
        return (item.path || '') === path;
      })) || index.recipes.find(function (item) {
        return (item.slug || '') === slug;
      });
      if (!recipe) {
        var card = allCards.find(function (c) { return c.url === path; }) ||
          allCards.find(function (c) { return c.slug === slug; });
        recipe = card ? {
          slug: card.slug, title: card.displayTitle, url: absoluteUrl(card.url), path: card.url,
          category: card.category, severity: card.severity, facets: card.facets,
          quality: card.quality, readiness: card.tier, maturity: card.maturity,
          published: card.published, summary: card.summary
        } : { slug: slug };
      }
      var title = recipe.title || 'recipe';
      downloadJson('security-recipe-' + sanitizeFilePart(recipe.slug || title) + '.json', {
        schema: 'https://security-recipes.ai/schemas/recipe-download/v1',
        downloaded_at: new Date().toISOString(),
        source_endpoint: index.endpoint || absoluteUrl(root.getAttribute('data-recipe-api') || '/api/recipes.json'),
        recipe: recipe
      });
      setStatus('Downloaded ' + title + '.', 'ok');
    }

    async function downloadAllRecipes() {
      var index = await loadIndex();
      var payload = index.recipes.length ? index : {
        api_version: 'card-fallback',
        endpoint: absoluteUrl(root.getAttribute('data-recipe-api') || '/api/recipes.json'),
        recipes: allCards
      };
      downloadJson('security-recipes-curated-library.json', payload);
      setStatus('Downloaded the curated recipe feed.', 'ok');
    }

    async function copyEndpoint() {
      var endpoint = absoluteUrl(
        root.getAttribute('data-recipe-api') || '/api/curated-recipes.json'
      );
      try {
        await navigator.clipboard.writeText(endpoint);
        setStatus('Copied ' + endpoint + '.', 'ok');
      } catch (error) {
        setStatus(endpoint, 'info');
      }
    }

    async function copyAgentPrompt() {
      var prompt = agentPrompt(root);
      try {
        await navigator.clipboard.writeText(prompt);
        setStatus('Copied agent recipe instructions.', 'ok');
      } catch (error) {
        setStatus(prompt, 'info');
      }
    }

    /* ---- wiring ------------------------------------------------------- */

    if (searchInput) {
      var field = searchInput.closest('.recipe-browser__search-field');
      if (field) {
        typeahead = document.createElement('div');
        typeahead.className = 'recipe-browser__typeahead';
        typeahead.hidden = true;
        typeaheadList = document.createElement('div');
        typeaheadList.className = 'recipe-browser__typeahead-list';
        typeaheadList.setAttribute('role', 'listbox');
        typeaheadList.id = 'recipe-browser-typeahead';
        typeahead.appendChild(typeaheadList);
        field.appendChild(typeahead);
        searchInput.setAttribute('role', 'combobox');
        searchInput.setAttribute('aria-controls', typeaheadList.id);
        searchInput.setAttribute('aria-haspopup', 'listbox');
      }
      searchInput.addEventListener('input', applyFilters);
      searchInput.addEventListener('search', applyFilters);
      searchInput.addEventListener('focus', renderTypeahead);
      searchInput.addEventListener('keydown', function (event) {
        var exactCve = /^CVE-\d{4}-\d{4,}$/i.test(searchInput.value.trim());
        if (event.key === 'Enter' && exactCve && activeTypeaheadIndex < 0) {
          event.preventDefault();
          closeTypeahead();
          var cveTarget = '/cve-database/?q=' +
            encodeURIComponent(searchInput.value.trim().toUpperCase());
          if (win.location && typeof win.location.assign === 'function') {
            win.location.assign(cveTarget);
          } else {
            win.location.href = cveTarget;
          }
          return;
        }
        if (!typeahead || typeahead.hidden) return;
        if (event.key === 'ArrowDown') {
          event.preventDefault();
          setTypeaheadActive(Math.min(typeaheadItems.length - 1, activeTypeaheadIndex + 1));
        } else if (event.key === 'ArrowUp') {
          event.preventDefault();
          setTypeaheadActive(Math.max(0, activeTypeaheadIndex - 1));
        } else if (event.key === 'Enter') {
          if (activeTypeaheadIndex < 0) return;
          event.preventDefault();
          var activeButton = typeaheadItems[activeTypeaheadIndex];
          if (activeButton) activeButton.click();
        } else if (event.key === 'Escape') {
          event.preventDefault();
          closeTypeahead();
        }
      });
      searchInput.addEventListener('blur', function () { window.setTimeout(closeTypeahead, 120); });
    }

    if (clearSearchButton && searchInput) {
      clearSearchButton.addEventListener('pointerdown', function (event) { event.preventDefault(); });
      clearSearchButton.addEventListener('click', function (event) { event.preventDefault(); clearSearch(); });
      clearSearchButton.addEventListener('keydown', function (event) {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        clearSearch();
      });
    }

    if (severityFilter) severityFilter.addEventListener('change', applyFilters);
    if (facetFilter) facetFilter.addEventListener('change', applyFilters);
    if (qualityFilter) qualityFilter.addEventListener('change', applyFilters);
    if (sortSelect) sortSelect.addEventListener('change', applyFilters);

    filterButtons.forEach(function (button) {
      var filter = button.getAttribute('data-recipe-filter') || 'all';
      filterLabels[filter] = button.getAttribute('data-recipe-filter-label') ||
        (button.querySelector('strong') ? button.querySelector('strong').textContent.trim() : filter);
      button.setAttribute('aria-pressed', button.classList.contains('is-active') ? 'true' : 'false');
      button.addEventListener('click', function () { setActiveCategory(filter); });
    });

    if (resetFiltersButton) {
      resetFiltersButton.addEventListener('click', function () { resetCuratedFilters(true); });
    }

    if (activeFilters) {
      activeFilters.addEventListener('click', function (event) {
        var button = event.target.closest ? event.target.closest('[data-active-filter]') : null;
        if (!button || !activeFilters.contains(button)) return;
        var key = button.getAttribute('data-active-filter');
        if (key === 'query' && searchInput) searchInput.value = '';
        if (key === 'category') activeCategory = 'all';
        if (key === 'severity' && severityFilter) severityFilter.value = 'all';
        if (key === 'facet' && facetFilter) facetFilter.value = 'all';
        if (key === 'quality' && qualityFilter) qualityFilter.value = '0';
        filterButtons.forEach(function (filterButton) {
          var active = filterButton.getAttribute('data-recipe-filter') === activeCategory;
          filterButton.classList.toggle('is-active', active);
          filterButton.setAttribute('aria-pressed', active ? 'true' : 'false');
        });
        applyFilters();
        if (searchInput) searchInput.focus();
      });
    }

    if (filterToggle) filterToggle.addEventListener('click', function () { setFilterDrawer(true); });
    if (filterClose) filterClose.addEventListener('click', function () { setFilterDrawer(false); });
    win.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && filterDrawer && filterDrawer.classList.contains('is-open')) {
        setFilterDrawer(false);
      }
    });
    if (win.matchMedia) {
      var mobileFilters = win.matchMedia('(max-width: 900px)');
      var syncFilterDrawer = function () { setFilterDrawer(false); };
      if (mobileFilters.addEventListener) mobileFilters.addEventListener('change', syncFilterDrawer);
      else if (mobileFilters.addListener) mobileFilters.addListener(syncFilterDrawer);
      syncFilterDrawer();
    }

    if (loadMoreButton) {
      loadMoreButton.addEventListener('click', function () { appendNextPage(); });
    }

    // Per-card download via delegation (cards are re-rendered on every filter).
    if (grid) {
      grid.addEventListener('click', function (event) {
        var button = event.target.closest ? event.target.closest('[data-recipe-download]') : null;
        if (!button || !grid.contains(button)) return;
        var card = button.closest('[data-recipe-card]');
        var slug = card ? card.getAttribute('data-recipe-slug') : '';
        var path = card ? card.getAttribute('data-recipe-path') : '';
        if (slug || path) downloadRecipe(slug, path).catch(function () { setStatus('Recipe download failed.', 'error'); });
      });
    }

    var downloadAll = root.querySelector('[data-recipe-download-all]');
    if (downloadAll) {
      downloadAll.addEventListener('click', function () {
        downloadAllRecipes().catch(function () { setStatus('Curated recipe download failed.', 'error'); });
      });
    }

    var copyButton = root.querySelector('[data-recipe-copy-endpoint]');
    if (copyButton) copyButton.addEventListener('click', copyEndpoint);

    var copyPromptButton = root.querySelector('[data-recipe-copy-agent-prompt]');
    if (copyPromptButton) copyPromptButton.addEventListener('click', copyAgentPrompt);

    restoreFromUrl();
    win.addEventListener('popstate', restoreFromUrl);
    root.dataset.recipeBrowserReady = 'true';

    // Fetch the catalogue feed, then take over rendering. Until it arrives the
    // server-rendered first page stays on screen and filters run over the
    // inline seed, so there is never a blank grid. If the slim feed is
    // unavailable, fall back to the rich agent feed before settling for the
    // seed slice.
    function adoptPartialCatalogue() {
      catalogueFailed = true;
      setStatus('Showing a partial curated collection. Reload to fetch the complete curated feed.', 'info');
      if (root.dataset.filtered === 'true') applyFilters();
    }

    loadFeed().then(function (recipes) {
      if (recipes) {
        allCards = recipes.map(toCard);
        catalogueComplete = true;
        applyFilters();
        return null;
      }
      return loadIndex().then(function (index) {
        if (index.recipes.length) {
          allCards = index.recipes.map(apiRecipeToFeedEntry).filter(Boolean).map(toCard);
          catalogueComplete = true;
          applyFilters();
        } else {
          adoptPartialCatalogue();
        }
      });
    }).catch(function () {
      adoptPartialCatalogue();
    });
  }

  function init() {
    document.querySelectorAll('[data-recipe-browser]').forEach(initRecipeBrowser);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
