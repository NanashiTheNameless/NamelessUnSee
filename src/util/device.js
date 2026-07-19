'use strict';

// Minimal, dependency-free User-Agent parser. Good enough to bake identifying
// device info into a watermark and to log a readable summary. Not exhaustive.

function parseUserAgent(ua) {
  ua = String(ua || '');
  const out = { browser: 'Unknown', browserVersion: '', os: 'Unknown', osVersion: '', deviceType: 'desktop', raw: ua };

  if (!ua) return out;

  // Operating system
  const osMatchers = [
    [/Windows NT 10\.0/i, 'Windows', '10/11'],
    [/Windows NT 6\.3/i, 'Windows', '8.1'],
    [/Windows NT 6\.1/i, 'Windows', '7'],
    [/Windows NT ([\d.]+)/i, 'Windows', null],
    [/iPhone OS ([\d_]+)/i, 'iOS', null],
    [/iPad;.*OS ([\d_]+)/i, 'iPadOS', null],
    [/Mac OS X ([\d_]+)/i, 'macOS', null],
    [/Android ([\d.]+)/i, 'Android', null],
    [/CrOS/i, 'ChromeOS', ''],
    [/Linux/i, 'Linux', ''],
  ];
  for (const [re, name, ver] of osMatchers) {
    const m = ua.match(re);
    if (m) {
      out.os = name;
      out.osVersion = ver !== null ? ver : (m[1] || '').replace(/_/g, '.');
      break;
    }
  }

  // Browser (order matters: check Edge/Opera before Chrome, Chrome before Safari)
  const browserMatchers = [
    [/Edg(?:A|iOS)?\/([\d.]+)/i, 'Edge'],
    [/OPR\/([\d.]+)/i, 'Opera'],
    [/SamsungBrowser\/([\d.]+)/i, 'Samsung Internet'],
    [/Firefox\/([\d.]+)/i, 'Firefox'],
    [/FxiOS\/([\d.]+)/i, 'Firefox'],
    [/CriOS\/([\d.]+)/i, 'Chrome'],
    [/Chrome\/([\d.]+)/i, 'Chrome'],
    [/Version\/([\d.]+).*Safari/i, 'Safari'],
    [/Safari\/([\d.]+)/i, 'Safari'],
  ];
  for (const [re, name] of browserMatchers) {
    const m = ua.match(re);
    if (m) {
      out.browser = name;
      out.browserVersion = m[1] || '';
      break;
    }
  }

  // Device type
  if (/iPad|Tablet/i.test(ua)) out.deviceType = 'tablet';
  else if (/(?:Mobi|iPhone)/i.test(ua) || (ua.includes('Android') && ua.includes('Mobile'))) out.deviceType = 'mobile';
  else if (/Android/i.test(ua)) out.deviceType = 'tablet';

  return out;
}

function summarize(parsed) {
  const b = [parsed.browser, parsed.browserVersion].filter(Boolean).join(' ');
  const o = [parsed.os, parsed.osVersion].filter(Boolean).join(' ');
  const device = parsed.deviceType ? parsed.deviceType[0].toUpperCase() + parsed.deviceType.slice(1) : '';
  return [b, o, device].filter(Boolean).join(' - ');
}

module.exports = { parseUserAgent, summarize };
