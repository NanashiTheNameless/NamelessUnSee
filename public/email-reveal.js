/* Reveals the operator contact address using ALTCHA's Obfuscation module
 * (public/altcha-obfuscation.min.js). The address is delivered encrypted; the
 * browser solves a small offline proof-of-work to decrypt it, which keeps the
 * address away from scrapers. Runs entirely in this page: no network requests,
 * no logging, no visible widget. */
(function () {
  'use strict';

  function obfuscationModule() {
    var registry = (typeof globalThis !== 'undefined' && globalThis.$altcha && globalThis.$altcha.plugins) || null;
    if (!registry) return null;
    var found = null;
    registry.forEach(function (plugin) {
      if (!found && typeof plugin.deobfuscate === 'function') found = plugin;
    });
    return found;
  }

  function reveal() {
    var plugin = obfuscationModule();
    var nodes = document.querySelectorAll('[data-obfuscated-email]');
    if (!plugin || !nodes.length) return;
    nodes.forEach(function (node) {
      plugin
        .deobfuscate(node.getAttribute('data-obfuscated-email'))
        .then(function (address) {
          var link = document.createElement('a');
          link.href = 'mailto:' + address;
          link.textContent = address;
          node.textContent = '';
          node.appendChild(link);
        })
        .catch(function () {
          /* leave the fallback text in place */
        });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', reveal);
  } else {
    reveal();
  }
})();
