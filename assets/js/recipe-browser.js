/*
 * Recipe browser controls for /prompt-library/.
 * Static Hugo renders the catalogue; this layer filters, sorts, and downloads
 * portable recipe JSON without adding any runtime service dependency.
 */
(function () {
  'use strict';

  function normalize(value) {
    return (value || '')
      .toString()
      .toLowerCase()
      .normalize('NFKD')
      .replace(/[\u0300-\u036f]/g, '')
      .trim();
  }

  function tokens(value) {
    return normalize(value).split(/\s+/).filter(Boolean);
  }

  function pluralize(count, singular, plural) {
    return count + ' ' + (count === 1 ? singular : plural);
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
    var configured = root.getAttribute('data-recipe-api') || '/api/recipes.json';
    var legacy = root.getAttribute('data-recipe-legacy-api') || '/recipes-index.json';
    return [
      new URL(configured, origin).toString(),
      new URL(prefix + 'api/recipes.json', origin).toString(),
      new URL(legacy, origin).toString(),
      new URL(prefix + 'recipes-index.json', origin).toString()
    ].filter(function (url, index, list) {
      return list.indexOf(url) === index;
    });
  }

  function mcpEndpoint(root) {
    return absoluteUrl(root.getAttribute('data-recipe-mcp') || '/mcp');
  }

  function agentPrompt(root) {
    var jsonEndpoint = absoluteUrl(root.getAttribute('data-recipe-api') || '/api/recipes.json');
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
      '- recipes_quality_report: inspect quality tiers and find recipes missing world-class signals.',
      '',
      'Select by facet before acting: remediation for patch work, risk for exploitability and impact, audit for evidence mapping, compliance for standards readiness, and code-hygiene for cleanup or hardening work.',
      '',
      'Use one recipe for one finding, preserve the recipe stop conditions, run the requested tests, and produce a reviewer-ready PR or triage note. Do not use MCP for writes, ticket creation, deployments, secret rotation, or cloud changes unless this task explicitly grants that permission.'
    ].join('\n');
  }

  function normalizeIndexPayload(data) {
    if (Array.isArray(data)) {
      return {
        api_version: 'legacy-array',
        recipes: data
      };
    }
    if (data && Array.isArray(data.recipes)) return data;
    return {
      api_version: 'unknown',
      recipes: []
    };
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

  function matchesRecipe(recipe, card) {
    if (!recipe || !card) return false;

    var cardSlug = card.dataset.recipeSlug || '';
    var cardPath = card.dataset.recipePath || '';
    var cardSource = card.dataset.recipeSource || '';
    var candidates = [
      recipe.slug,
      recipe.path,
      recipe.url,
      recipe.source_file,
      recipe.sourceFile
    ].map(function (value) {
      return (value || '').toString();
    });

    return candidates.some(function (value) {
      return value === cardSlug ||
        value === cardPath ||
        value === cardSource ||
        value.endsWith(cardPath) ||
        value.endsWith(cardSource);
    });
  }

  function recipeFromCard(card) {
    return {
      slug: card.dataset.recipeSlug || '',
      title: card.dataset.recipeTitle || '',
      path: card.dataset.recipePath || '',
      url: absoluteUrl(card.dataset.recipePath || ''),
      category: card.dataset.recipeCategory || 'general',
      severity: card.dataset.recipeSeverity || 'unspecified',
      facets: tokens(card.dataset.recipeFacets || ''),
      quality: Number(card.dataset.recipeQuality || 0),
      readiness: card.dataset.recipeReadiness || 'starter',
      maturity: card.dataset.recipeMaturity || 'unspecified',
      published: card.dataset.recipePublished || '',
      summary: card.dataset.recipeSummary || '',
      source_file: card.dataset.recipeSource || ''
    };
  }

  function severityRank(value) {
    var rank = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
      unspecified: 0
    };
    return rank[normalize(value)] || 0;
  }

  function stopGlobalHandlers(node) {
    return node;
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
    var filterButtons = Array.prototype.slice.call(root.querySelectorAll('[data-recipe-filter]'));
    var filterLabels = {};
    var typeahead = null;
    var typeaheadList = null;
    var typeaheadItems = [];
    var activeTypeaheadIndex = -1;
    var cards = Array.prototype.slice.call(root.querySelectorAll('[data-recipe-card]')).map(function (node, index) {
      return {
        node: node,
        initialIndex: index,
        indexText: normalize(node.dataset.recipeIndex || node.textContent || ''),
        category: node.dataset.recipeCategory || 'general',
        categoryLabel: '',
        zeroDay: node.dataset.recipeZeroDay === 'true',
        severity: node.dataset.recipeSeverity || 'unspecified',
        facets: tokens(node.dataset.recipeFacets || ''),
        quality: Number(node.dataset.recipeQuality || 0),
        title: normalize(node.dataset.recipeTitle || ''),
        displayTitle: node.dataset.recipeTitle || '',
        summary: node.dataset.recipeSummary || '',
        path: node.dataset.recipePath || '',
        slug: node.dataset.recipeSlug || '',
        date: node.dataset.recipeDate || ''
      };
    });
    var activeCategory = 'all';
    var loadedIndex = null;

    function setStatus(message, tone) {
      if (!status) return;
      status.textContent = message || '';
      status.dataset.tone = tone || '';
    }

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
            loadedIndex = data;
            return loadedIndex;
          }
        } catch (error) {
          lastError = error;
        }
      }

      if (lastError) {
        console.warn('[recipe-browser] recipe endpoint unavailable');
      }
      loadedIndex = { api_version: 'card-fallback', recipes: [] };
      return loadedIndex;
    }

    function renderSummary(visibleCount) {
      if (!summary) return;
      var suffix = activeCategory === 'all' ? '' : ' in ' + (filterLabels[activeCategory] || 'this category');
      summary.textContent = 'Showing ' + pluralize(visibleCount, 'recipe', 'recipes') + suffix + '.';
    }

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
          filters.push({
            kind: 'category',
            title: label,
            meta: 'Browse lane',
            value: key
          });
        }
      });

      ['critical', 'high', 'medium', 'low', 'unspecified'].forEach(function (severity) {
        if (normalize(severity).indexOf(query) === -1 && queryTokens.indexOf(severity) === -1) return;
        filters.push({
          kind: 'severity',
          title: prettyToken(severity),
          meta: 'Severity filter',
          value: severity
        });
      });

      ['remediation', 'risk', 'audit', 'compliance', 'code-hygiene'].forEach(function (facet) {
        var label = prettyToken(facet);
        var haystack = normalize(label + ' ' + facet);
        if (haystack.indexOf(query) === -1 && !queryTokens.some(function (token) { return haystack.indexOf(token) !== -1; })) return;
        filters.push({
          kind: 'facet',
          title: label,
          meta: 'Agent facet',
          value: facet
        });
      });

      if ('world-class'.indexOf(query) !== -1 || queryTokens.indexOf('world') !== -1 || queryTokens.indexOf('quality') !== -1) {
        filters.push({
          kind: 'quality',
          title: 'World-class recipes',
          meta: 'Quality filter',
          value: '85'
        });
      }

      suggestions = suggestions.concat(filters.slice(0, 4));

      cards
        .map(function (card) {
          return {
            card: card,
            score: scoreSuggestion(card, query, queryTokens)
          };
        })
        .filter(function (item) {
          return item.score > 0;
        })
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
            path: card.path
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

        button.addEventListener('pointerdown', function (event) {
          event.preventDefault();
        });
        button.addEventListener('click', function () {
          applySuggestion(suggestion);
        });

        typeaheadList.appendChild(button);
        return button;
      });

      typeahead.hidden = false;
      searchInput.setAttribute('aria-expanded', 'true');
      setTypeaheadActive(-1);
    }

    function sortCards(visibleItems) {
      var mode = sortSelect ? sortSelect.value : 'newest';
      visibleItems.sort(function (a, b) {
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
      var visible = [];

      cards.forEach(function (card) {
        var categoryMatch = activeCategory === 'all' ||
          (activeCategory === 'zero-day' ? card.zeroDay : card.category === activeCategory);
        var severityMatch = severity === 'all' || card.severity === severity;
        var facetMatch = facet === 'all' || card.facets.indexOf(facet) !== -1;
        var qualityMatch = !minimumQuality || card.quality >= minimumQuality;
        var queryMatch = !queryTokens.length || queryTokens.every(function (token) {
          return card.indexText.indexOf(token) !== -1;
        });
        var show = categoryMatch && severityMatch && facetMatch && qualityMatch && queryMatch;
        card.node.hidden = !show;
        if (show) visible.push(card);
      });

      sortCards(visible);
      visible.forEach(function (card) {
        grid.appendChild(card.node);
      });

      if (empty) empty.hidden = visible.length > 0;
      if (clearSearchButton) clearSearchButton.hidden = queryTokens.length === 0;
      renderSummary(visible.length);
      root.dataset.filtered = queryTokens.length || activeCategory !== 'all' || severity !== 'all' || facet !== 'all' || minimumQuality > 0 ? 'true' : 'false';
      if (document.activeElement === searchInput) renderTypeahead();
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
      searchInput.dispatchEvent(new Event('input', { bubbles: true }));
      applyFilters();
      closeTypeahead();
      searchInput.focus();
    }

    async function downloadRecipe(card) {
      var index = await loadIndex();
      var recipe = index.recipes.find(function (item) {
        return matchesRecipe(item, card);
      }) || recipeFromCard(card);
      var title = recipe.title || card.dataset.recipeTitle || 'recipe';
      var payload = {
        schema: 'https://security-recipes.ai/schemas/recipe-download/v1',
        downloaded_at: new Date().toISOString(),
        source_endpoint: index.endpoint || absoluteUrl(root.getAttribute('data-recipe-api') || '/api/recipes.json'),
        recipe: recipe
      };
      downloadJson('security-recipe-' + sanitizeFilePart(recipe.slug || title) + '.json', payload);
      setStatus('Downloaded ' + title + '.', 'ok');
    }

    async function downloadAllRecipes() {
      var index = await loadIndex();
      var payload = index.recipes.length ? index : {
        api_version: 'card-fallback',
        endpoint: absoluteUrl(root.getAttribute('data-recipe-api') || '/api/recipes.json'),
        recipes: cards.map(function (card) {
          return recipeFromCard(card.node);
        })
      };
      downloadJson('security-recipes-agent-library.json', payload);
      setStatus('Downloaded the recipe library JSON.', 'ok');
    }

    async function copyEndpoint() {
      var endpoint = absoluteUrl(root.getAttribute('data-recipe-api') || '/api/recipes.json');
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
      searchInput.addEventListener('input', function () {
        applyFilters();
        renderTypeahead();
      });
      searchInput.addEventListener('search', function () {
        applyFilters();
        renderTypeahead();
      });
      searchInput.addEventListener('focus', renderTypeahead);
      searchInput.addEventListener('keydown', function (event) {
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
      searchInput.addEventListener('blur', function () {
        window.setTimeout(closeTypeahead, 120);
      });
      stopGlobalHandlers(searchInput);
    }

    if (clearSearchButton && searchInput) {
      clearSearchButton.addEventListener('pointerdown', function (event) {
        event.preventDefault();
      });
      clearSearchButton.addEventListener('click', function (event) {
        event.preventDefault();
        clearSearch();
      });
      clearSearchButton.addEventListener('keydown', function (event) {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        clearSearch();
      });
    }

    if (severityFilter) {
      severityFilter.addEventListener('change', applyFilters);
      stopGlobalHandlers(severityFilter);
    }
    if (facetFilter) {
      facetFilter.addEventListener('change', applyFilters);
      stopGlobalHandlers(facetFilter);
    }
    if (qualityFilter) {
      qualityFilter.addEventListener('change', applyFilters);
      stopGlobalHandlers(qualityFilter);
    }
    if (sortSelect) {
      sortSelect.addEventListener('change', applyFilters);
      stopGlobalHandlers(sortSelect);
    }

    filterButtons.forEach(function (button) {
      var filter = button.getAttribute('data-recipe-filter') || 'all';
      filterLabels[filter] = button.getAttribute('data-recipe-filter-label') ||
        (button.querySelector('strong') ? button.querySelector('strong').textContent.trim() : filter);
      button.setAttribute('aria-pressed', button.classList.contains('is-active') ? 'true' : 'false');
      stopGlobalHandlers(button);
      button.addEventListener('click', function () {
        setActiveCategory(filter);
      });
    });

    cards.forEach(function (card) {
      card.categoryLabel = filterLabels[card.category] || prettyToken(card.category);
    });

    root.querySelectorAll('[data-recipe-download]').forEach(function (button) {
      stopGlobalHandlers(button);
      button.addEventListener('click', function () {
        var card = button.closest('[data-recipe-card]');
        if (!card) return;
        downloadRecipe(card).catch(function () {
          downloadJson('security-recipe-' + sanitizeFilePart(card.dataset.recipeSlug || card.dataset.recipeTitle) + '.json', {
            schema: 'https://security-recipes.ai/schemas/recipe-download/v1',
            downloaded_at: new Date().toISOString(),
            recipe: recipeFromCard(card)
          });
          setStatus('Downloaded a fallback recipe card.', 'info');
        });
      });
    });

    var downloadAll = root.querySelector('[data-recipe-download-all]');
    if (downloadAll) {
      stopGlobalHandlers(downloadAll);
      downloadAll.addEventListener('click', function () {
        downloadAllRecipes().catch(function () {
          setStatus('Recipe library download failed.', 'error');
        });
      });
    }

    var copyButton = root.querySelector('[data-recipe-copy-endpoint]');
    if (copyButton) {
      stopGlobalHandlers(copyButton);
      copyButton.addEventListener('click', copyEndpoint);
    }

    var copyPromptButton = root.querySelector('[data-recipe-copy-agent-prompt]');
    if (copyPromptButton) {
      stopGlobalHandlers(copyPromptButton);
      copyPromptButton.addEventListener('click', copyAgentPrompt);
    }

    root.dataset.recipeBrowserReady = 'true';
    applyFilters();
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
