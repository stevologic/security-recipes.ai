/*
 * Sidebar collapse defaults - security-recipes.ai.
 *
 * Keep desktop left-nav tree menus collapsed by default, but preserve the
 * open ancestry for the current page so readers still see context. Prompt
 * Library pages are the exception: the sidebar should stay flat and show
 * only top-level section links.
 */
(function () {
  'use strict';

  var PROMPT_LIBRARY_PATH = /(^|\/)prompt-library(\/|$)/;

  function isPromptLibraryPath() {
    return PROMPT_LIBRARY_PATH.test(window.location.pathname || '');
  }

  function linkPointsToPromptLibrary(link) {
    try {
      return PROMPT_LIBRARY_PATH.test(new URL(link.href, window.location.origin).pathname);
    } catch (error) {
      return false;
    }
  }

  function getDesktopSidebarRoots() {
    var sidebar = document.querySelector('.sidebar-container');
    if (sidebar) {
      var lists = Array.prototype.slice.call(sidebar.querySelectorAll('.hextra-scrollbar > ul'));
      var desktopLists = lists.filter(function (list) {
        return (list.className || '').indexOf('max-md:hx-hidden') !== -1;
      });

      if (desktopLists.length) {
        return desktopLists;
      }
    }

    return Array.prototype.slice.call(
      document.querySelectorAll('.hextra-sidebar, aside nav, .nextra-sidebar')
    );
  }

  function closeExpandedTrees(root) {
    root.querySelectorAll('details[open]').forEach(function (node) {
      node.removeAttribute('open');
    });

    root.querySelectorAll('li.open').forEach(function (node) {
      node.classList.remove('open');
    });
  }

  function openCurrentAncestry(root) {
    root.querySelectorAll('.sidebar-active-item, [aria-current="page"]').forEach(function (current) {
      var parent = current.parentElement;

      while (parent && parent !== root.parentElement) {
        if (parent.tagName) {
          var tagName = parent.tagName.toLowerCase();

          if (tagName === 'details') {
            parent.setAttribute('open', '');
          }

          if (tagName === 'li') {
            parent.classList.add('open');
          }
        }

        parent = parent.parentElement;
      }
    });
  }

  function flattenPromptLibraryLinks(root) {
    root.querySelectorAll('a').forEach(function (link) {
      if (!linkPointsToPromptLibrary(link)) return;

      var item = link.parentElement;
      if (!item || !item.tagName || item.tagName.toLowerCase() !== 'li') return;

      var button = link.querySelector('.hextra-sidebar-collapsible-button');
      if (button) {
        button.remove();
      }

      Array.prototype.slice.call(item.children).forEach(function (child) {
        if (child !== link) {
          child.remove();
        }
      });
    });
  }

  function collapseSidebar() {
    var roots = getDesktopSidebarRoots();
    if (!roots.length) return;

    var keepPromptLibraryFlat = isPromptLibraryPath();

    roots.forEach(function (root) {
      closeExpandedTrees(root);

      if (keepPromptLibraryFlat) {
        flattenPromptLibraryLinks(root);
      } else {
        openCurrentAncestry(root);
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', collapseSidebar);
  } else {
    collapseSidebar();
  }
})();
