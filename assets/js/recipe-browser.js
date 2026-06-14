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
    var sortSelect = root.querySelector('[data-recipe-sort]');
    var clearSearchButton = root.querySelector('[data-recipe-clear-search]');
    var summary = root.querySelector('[data-recipe-summary]');
    var empty = root.querySelector('[data-recipe-empty]');
    var status = root.querySelector('[data-recipe-status]');
    var grid = root.querySelector('[data-recipe-grid]');
    var openAiButton = root.querySelector('[data-recipe-open-ai]');
    var filterButtons = Array.prototype.slice.call(root.querySelectorAll('[data-recipe-filter]'));
    var filterLabels = {};
    var cards = Array.prototype.slice.call(root.querySelectorAll('[data-recipe-card]')).map(function (node, index) {
      return {
        node: node,
        initialIndex: index,
        indexText: normalize(node.dataset.recipeIndex || node.textContent || ''),
        category: node.dataset.recipeCategory || 'general',
        zeroDay: node.dataset.recipeZeroDay === 'true',
        severity: node.dataset.recipeSeverity || 'unspecified',
        title: normalize(node.dataset.recipeTitle || ''),
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

    function sortCards(visibleItems) {
      var mode = sortSelect ? sortSelect.value : 'newest';
      visibleItems.sort(function (a, b) {
        if (mode === 'title') return a.title.localeCompare(b.title);
        if (mode === 'severity') {
          var severityDelta = severityRank(b.severity) - severityRank(a.severity);
          if (severityDelta) return severityDelta;
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
      var visible = [];

      cards.forEach(function (card) {
        var categoryMatch = activeCategory === 'all' ||
          (activeCategory === 'zero-day' ? card.zeroDay : card.category === activeCategory);
        var severityMatch = severity === 'all' || card.severity === severity;
        var queryMatch = !queryTokens.length || queryTokens.every(function (token) {
          return card.indexText.indexOf(token) !== -1;
        });
        var show = categoryMatch && severityMatch && queryMatch;
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
      root.dataset.filtered = queryTokens.length || activeCategory !== 'all' || severity !== 'all' ? 'true' : 'false';
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

    function openAiRemediation() {
      var shell = document.querySelector('.ai-chatbot-shell');
      var panel = shell && shell.querySelector('.ai-chatbot-panel');
      var launch = shell && shell.querySelector('.ai-chatbot-launch');
      var agentsTab = shell && shell.querySelector('.ai-chatbot-tab[data-tab="agents"]');

      if (!shell || !panel || !launch || !agentsTab) {
        setStatus('AI Remediation is still loading. Try again in a moment.', 'error');
        return;
      }

      if (panel.hidden) launch.click();
      agentsTab.click();
      setStatus('Opened AI Remediation.', 'ok');

      window.setTimeout(function () {
        var recipeInput = shell.querySelector('[data-agent-recipe]');
        if (recipeInput) recipeInput.focus();
      }, 0);
    }

    if (searchInput) {
      searchInput.addEventListener('input', applyFilters);
      searchInput.addEventListener('search', applyFilters);
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

    if (openAiButton) {
      stopGlobalHandlers(openAiButton);
      openAiButton.addEventListener('click', openAiRemediation);
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
