'use strict';

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function inlineMarkdown(value) {
  const token = /\[([^\]]+)\]\((?:<([^>]+)>|([^\s)]+))\)|\*\*([^*]+)\*\*|__([^_]+)__|`([^`]+)`|\*([^*]+)\*/g;
  let html = '';
  let last = 0;
  let match;
  while ((match = token.exec(value))) {
    html += escapeHtml(value.slice(last, match.index));
    if (match[1]) {
      const href = match[2] || match[3];
      const safeHref = /^(?:https?:\/\/|\/)/i.test(href) ? href : '#';
      html += `<a href="${escapeHtml(safeHref)}">${inlineMarkdown(match[1])}</a>`;
    } else if (match[4] || match[5]) {
      html += `<strong>${inlineMarkdown(match[4] || match[5])}</strong>`;
    } else if (match[6]) {
      html += `<code>${escapeHtml(match[6])}</code>`;
    } else {
      html += `<em>${inlineMarkdown(match[7])}</em>`;
    }
    last = token.lastIndex;
  }
  return html + escapeHtml(value.slice(last));
}

function renderMarkdown(markdown) {
  const lines = String(markdown).replace(/\r\n?/g, '\n').split('\n');
  const output = [];
  let paragraph = [];
  let list = [];

  function flushParagraph() {
    if (paragraph.length) {
      output.push(`<p>${inlineMarkdown(paragraph.join(' '))}</p>`);
      paragraph = [];
    }
  }

  function flushList() {
    if (list.length) {
      output.push(`<ul>${list.map((item) => `<li>${inlineMarkdown(item)}</li>`).join('')}</ul>`);
      list = [];
    }
  }

  for (const line of lines) {
    const heading = /^(#{1,6})\s+(.+)$/.exec(line);
    const item = /^\s*-\s+(.+)$/.exec(line);
    if (heading) {
      flushParagraph();
      flushList();
      const level = heading[1].length;
      output.push(`<h${level}>${inlineMarkdown(heading[2])}</h${level}>`);
    } else if (/^\s*([-*_])(?:\s*\1){2,}\s*$/.test(line)) {
      flushParagraph();
      flushList();
      output.push('<hr>');
    } else if (item) {
      flushParagraph();
      list.push(item[1]);
    } else if (!line.trim()) {
      flushParagraph();
      flushList();
    } else {
      flushList();
      paragraph.push(line.trim());
    }
  }
  flushParagraph();
  flushList();
  return output.join('\n');
}

module.exports = { renderMarkdown };
