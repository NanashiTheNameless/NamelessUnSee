'use strict';

const config = require('./config');

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function cleanFrom(value) {
  const raw = String(value || '').trim().replace(/^`|`$/g, '').trim();
  const match = raw.match(/^(.*?)\s*<([^<>]+)>$/);
  if (!match) return raw;
  let address = match[2].trim();
  // Accept the old documented typo: local-part.domain becomes local-part@domain.
  if (!address.includes('@')) {
    const dot = address.indexOf('.');
    if (dot > 0) address = `${address.slice(0, dot)}@${address.slice(dot + 1)}`;
  }
  return `${match[1].trim()} <${address}>`;
}

// Notify admins that a new account is awaiting approval. Uses Resend if
// configured; otherwise logs to the server console. Never throws.
async function notifyPendingSignup(user) {
  // The applicant's written case for wanting an account, so an admin can judge
  // the request from the notification itself.
  const reason = String(user.signup_reason || '').trim();
  const line = `[NamelessUnSee] New signup awaiting approval: ${user.username} <${user.email}> (id ${user.id})${reason ? `\n  Reason: ${reason}` : ''}`;
  const { apiKey, to } = config.resend;
  const from = cleanFrom(config.resend.from);

  if (!apiKey || !from || !to) {
    console.log(line + '- approve at ' + config.baseUrl + '/admin');
    return;
  }

  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from,
        to: to.split(',').map((s) => s.trim()).filter(Boolean),
        subject: 'NamelessUnSee: new account awaiting approval',
        text:
          `A new account is awaiting admin approval.\n\n` +
          `Username: ${user.username}\nEmail: ${user.email}\n\n` +
          `Why they want an account:\n${reason || '(not provided)'}\n\n` +
          `Approve or reject at: ${config.baseUrl}/admin\n`,
        html:
          `<p>A new account is awaiting admin approval.</p>` +
          `<p><strong>Username:</strong> ${escapeHtml(user.username)}<br><strong>Email:</strong> ${escapeHtml(user.email)}</p>` +
          `<p><strong>Why they want an account:</strong></p><p style="white-space:pre-wrap">${escapeHtml(reason || '(not provided)')}</p>` +
          `<p><a href="${escapeHtml(config.baseUrl + '/admin')}">Approve or reject</a></p>`,
      }),
    });
    if (!res.ok) {
      console.warn('[NamelessUnSee] Resend notify failed:', res.status, await res.text());
      console.log(line);
    }
  } catch (err) {
    console.warn('[NamelessUnSee] Resend notify error:', err.message);
    console.log(line);
  }
}

// Send an administrator notification to the configured recipient list. These
// alerts are best-effort and never block the action that produced them.
async function notifyAdmins(subject, text, html, fallback) {
  const { apiKey, to } = config.resend;
  const from = cleanFrom(config.resend.from);
  if (!apiKey || !from || !to) {
    console.log(fallback);
    return false;
  }
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from,
        to: to.split(',').map((s) => s.trim()).filter(Boolean),
        subject,
        text,
        html,
      }),
    });
    if (!res.ok) {
      console.warn('[NamelessUnSee] Resend admin alert failed:', res.status, await res.text());
      console.log(fallback);
      return false;
    }
    return true;
  } catch (err) {
    console.warn('[NamelessUnSee] Resend admin alert error:', err.message);
    console.log(fallback);
    return false;
  }
}

async function notifyAdminFlag(flag) {
  const reason = flag.reason || 'moderation flag';
  const score = flag.score == null ? '' : `\nScore: ${Number(flag.score).toFixed(3)}`;
  const reports = Array.isArray(flag.reports) ? flag.reports : [];
  const classifierText = reports.length
    ? `\nClassifiers:\n${reports.map((report) => {
      const result = report.error ? report.error : `${report.label || 'neutral'} (${Number(report.score || 0).toFixed(3)})`;
      return `- ${String(report.model || 'unknown')}: ${result}`;
    }).join('\n')}`
    : '';
  const classifierHtml = reports.length
    ? `<br><strong>Classifiers:</strong><ul>${reports.map((report) => {
      const result = report.error ? report.error : `${report.label || 'neutral'} (${Number(report.score || 0).toFixed(3)})`;
      return `<li><span class="mono">${escapeHtml(report.model || 'unknown')}</span>: ${escapeHtml(result)}</li>`;
    }).join('')}</ul>`
    : '';
  const link = `${config.baseUrl}/admin/review`;
  return notifyAdmins(
    'NamelessUnSee: upload flagged for moderation',
    `An upload was flagged for administrator review.\n\n` +
      `Owner: ${flag.username} <${flag.email}>\n` +
      `Image: ${flag.title || '(untitled)'}\nToken: ${flag.token}\n` +
      `Reason: ${reason}${score}${classifierText}\n\nReview it at: ${link}\n`,
    `<p>An upload was flagged for administrator review.</p><p><strong>Owner:</strong> ${escapeHtml(flag.username)} &lt;${escapeHtml(flag.email)}&gt;<br><strong>Image:</strong> ${escapeHtml(flag.title || '(untitled)')}<br><strong>Token:</strong> ${escapeHtml(flag.token)}<br><strong>Reason:</strong> ${escapeHtml(reason)}${score ? `<br><strong>Score:</strong> ${escapeHtml(Number(flag.score).toFixed(3))}` : ''}${classifierHtml}</p><p><a href="${escapeHtml(link)}">Open moderation review</a></p>`,
    `[NamelessUnSee] Upload flagged: ${flag.title || flag.token} (${reason})`
  );
}

async function notifyAdminReport(report) {
  const link = `${config.baseUrl}/admin/reports`;
  return notifyAdmins(
    'NamelessUnSee: new report submitted',
    `A new report was submitted.\n\n` +
      `Report: #${report.id}\n` +
      `Reporter: ${report.reporterUsername} <${report.reporterEmail}>\n` +
      `Image: ${report.title || '(untitled)'}\nToken: ${report.token}\n` +
      `Reason: ${report.reason}\nDetails: ${report.details}\n\nReview it at: ${link}\n`,
    `<p>A new report was submitted.</p><p><strong>Report:</strong> #${escapeHtml(report.id)}<br><strong>Reporter:</strong> ${escapeHtml(report.reporterUsername)} &lt;${escapeHtml(report.reporterEmail)}&gt;<br><strong>Image:</strong> ${escapeHtml(report.title || '(untitled)')}<br><strong>Token:</strong> ${escapeHtml(report.token)}<br><strong>Reason:</strong> ${escapeHtml(report.reason)}<br><strong>Details:</strong> ${escapeHtml(report.details)}</p><p><a href="${escapeHtml(link)}">Open reports</a></p>`,
    `[NamelessUnSee] New report #${report.id} for ${report.token}`
  );
}

// Notify a new user about their account approval state. Uses the same
// transactional sender as the existing admin and security notifications.
// Never throws so account state changes are not held up by email delivery.
// `note` is an optional message written by the admin making the decision. It is
// appended to the body verbatim (escaped for the HTML part) so the applicant is
// told why, rather than receiving a bare decision.
async function sendSignupStatus(user, status, note = '') {
  const adminNote = String(note || '').trim().slice(0, 1000);
  // Where a denied applicant should write for more information. Configured as
  // OPERATOR_CONTACT, the same address the legal pages publish.
  const contact = String(config.operator.contact || '').trim();
  const messages = {
    pending: {
      subject: 'NamelessUnSee account pending approval',
      text: [
        `Hi ${user.username},`,
        '',
        'Your NamelessUnSee account has been created and is awaiting administrator approval.',
        'You will receive another email when a decision has been made.',
      ].join('\n'),
      html: `<p>Hi ${escapeHtml(user.username)},</p><p>Your NamelessUnSee account has been created and is awaiting administrator approval.</p><p>You will receive another email when a decision has been made.</p>`,
    },
    approved: {
      subject: 'NamelessUnSee account approved',
      text: [
        `Hi ${user.username},`,
        '',
        'Your NamelessUnSee account has been approved.',
        `You can now log in at ${config.baseUrl}/login and start using the service.`,
      ].join('\n'),
      html: `<p>Hi ${escapeHtml(user.username)},</p><p>Your NamelessUnSee account has been approved.</p><p><a href="${escapeHtml(config.baseUrl + '/login')}">Log in to NamelessUnSee</a> to start using the service.</p>`,
    },
    banned: {
      subject: 'NamelessUnSee account not approved',
      text: [
        `Hi ${user.username},`,
        '',
        'Your NamelessUnSee account was not approved, and this email address has been blocked from registering again.',
        ...(contact ? ['', `If you believe this was a mistake, email ${contact}.`] : []),
      ].join('\n'),
      html: `<p>Hi ${escapeHtml(user.username)},</p><p>Your NamelessUnSee account was not approved, and this email address has been blocked from registering again.</p>` +
        (contact
          ? `<p>If you believe this was a mistake, email <a href="mailto:${escapeHtml(contact)}">${escapeHtml(contact)}</a>.</p>`
          : ''),
    },
    rejected: {
      subject: 'NamelessUnSee account not approved',
      text: [
        `Hi ${user.username},`,
        '',
        'Your NamelessUnSee account was not approved.',
        'You will not be able to log in with this account.',
        ...(contact ? ['', `If you would like more information, or believe this was a mistake, email ${contact}.`] : []),
      ].join('\n'),
      html: `<p>Hi ${escapeHtml(user.username)},</p><p>Your NamelessUnSee account was not approved.</p><p>You will not be able to log in with this account.</p>` +
        (contact
          ? `<p>If you would like more information, or believe this was a mistake, email <a href="mailto:${escapeHtml(contact)}">${escapeHtml(contact)}</a>.</p>`
          : ''),
    },
  };
  const base = messages[status];
  if (!base) return false;
  const message = adminNote
    ? {
      subject: base.subject,
      text: `${base.text}\n\nMessage from the administrator:\n${adminNote}\n`,
      html: `${base.html}<p><strong>Message from the administrator:</strong></p><p style="white-space:pre-wrap">${escapeHtml(adminNote)}</p>`,
    }
    : base;

  const { apiKey } = config.resend;
  const from = cleanFrom(config.resend.from);
  if (!apiKey || !from || !user.email) {
    console.log(`[NamelessUnSee] Signup status for ${user.email}: ${status}${adminNote ? ` - ${adminNote}` : ''}`);
    return false;
  }

  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from, to: [user.email], ...message }),
    });
    if (!res.ok) {
      console.warn('[NamelessUnSee] Resend signup status failed:', res.status, await res.text());
      return false;
    }
    return true;
  } catch (err) {
    console.warn('[NamelessUnSee] Resend signup status error:', err.message);
    return false;
  }
}

async function sendSignupVerification(user, code) {
  const { apiKey } = config.resend;
  const from = cleanFrom(config.resend.from);
  const subject = 'NamelessUnSee email verification code';
  // One-click link, like the login code email. It only works in the browser that
  // started the signup, because the challenge is held in a signed cookie there.
  const link = `${config.baseUrl}/signup/verify/email?token=${encodeURIComponent(code)}`;
  const text = [
    `Hi ${user.username},`, '',
    `Your NamelessUnSee email verification code is ${code}.`,
    'It expires in 5 minutes.',
    '',
    'Or verify in one click, in the browser you signed up with:',
    link,
  ].join('\n');
  const html = `<p>Hi ${escapeHtml(user.username)},</p><p>Your NamelessUnSee email verification code is <strong>${escapeHtml(code)}</strong>.</p><p>It expires in 5 minutes.</p>` +
    `<p><a href="${escapeHtml(link)}">Verify my email address</a><br><span style="color:#8b949e">This link only works in the browser you signed up with.</span></p>`;
  if (!apiKey || !from) {
    if (config.twofa.consoleFallback) {
      console.log(`[NamelessUnSee] Signup verification for ${user.email}: ${code}`);
      return true;
    }
    console.warn('[NamelessUnSee] Signup email verification unavailable: configure RESEND_API_KEY and ADMIN_NOTIFY_FROM.');
    return false;
  }
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from, to: [user.email], subject, text, html }),
    });
    return res.ok;
  } catch (err) {
    console.warn('[NamelessUnSee] Signup verification email error:', err.message);
    return false;
  }
}

async function sendLoginCode(user, code, link) {
  const { apiKey } = config.resend;
  const from = cleanFrom(config.resend.from);
  if (!apiKey || !from) {
    if (config.twofa.consoleFallback) {
      console.log(`[NamelessUnSee] 2FA code for ${user.email}: ${code} (${link})`);
      return true;
    }
    console.warn('[NamelessUnSee] Email 2FA unavailable: configure RESEND_API_KEY and ADMIN_NOTIFY_FROM.');
    return false;
  }

  try {
    const minutes = Math.round(config.twofa.challengeTtlMs / 60000);
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from,
        to: [user.email],
        subject: 'NamelessUnSee login verification code',
        text: [
          `Your NamelessUnSee login verification code is ${code}.`,
          '',
          'You can also verify automatically in the browser that requested this login:',
          link,
          '',
          `This code and link expire in ${minutes} minutes. If you did not try to log in, ignore this email.`,
        ].join('\n'),
        html: `<p>Your NamelessUnSee login verification code is <strong>${escapeHtml(code)}</strong>.</p>
<p><a href="${escapeHtml(link)}">Verify this login automatically in this browser</a></p>
<p>This code and link expire in ${minutes} minutes. If you did not try to log in, ignore this email.</p>`,
      }),
    });
    if (!res.ok) {
      console.warn('[NamelessUnSee] Resend 2FA failed:', res.status, await res.text());
      return false;
    }
    return true;
  } catch (err) {
    console.warn('[NamelessUnSee] Resend 2FA error:', err.message);
    return false;
  }
}

async function sendAccountDeletionCode(user, code) {
  const { apiKey } = config.resend;
  const from = cleanFrom(config.resend.from);
  if (!apiKey || !from) {
    if (config.twofa.consoleFallback) {
      console.log(`[NamelessUnSee] Account deletion code for ${user.email}: ${code}`);
      return true;
    }
    console.warn('[NamelessUnSee] Account deletion email unavailable: configure RESEND_API_KEY and ADMIN_NOTIFY_FROM.');
    return false;
  }

  try {
    const minutes = Math.round(config.twofa.challengeTtlMs / 60000);
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from,
        to: [user.email],
        subject: 'NamelessUnSee account deletion verification code',
        text: [
          `Your NamelessUnSee account deletion verification code is ${code}.`,
          '',
          `This code expires in ${minutes} minutes. If you did not request this, you can ignore this email.`,
        ].join('\n'),
        html: `<p>Your NamelessUnSee account deletion verification code is <strong>${escapeHtml(code)}</strong>.</p>` +
          `<p>This code expires in ${escapeHtml(minutes)} minutes. If you did not request this, you can ignore this email.</p>`,
      }),
    });
    if (!res.ok) {
      console.warn('[NamelessUnSee] Resend account deletion email failed:', res.status, await res.text());
      return false;
    }
    return true;
  } catch (err) {
    console.warn('[NamelessUnSee] Resend account deletion email error:', err.message);
    return false;
  }
}

async function sendRecoveryCode(user, code, purpose) {
  const { apiKey } = config.resend;
  const from = cleanFrom(config.resend.from);
  const subject = `NamelessUnSee ${purpose} verification code`;
  const text = `Your NamelessUnSee ${purpose.toLowerCase()} verification code is ${code}.\n\nThis code expires in 5 minutes. If you did not request this, ignore this email.`;
  if (!apiKey || !from) {
    if (config.twofa.consoleFallback) {
      console.log(`[NamelessUnSee] ${purpose} code for ${user.email}: ${code}`);
      return true;
    }
    console.warn('[NamelessUnSee] Recovery email unavailable: configure RESEND_API_KEY and ADMIN_NOTIFY_FROM.');
    return false;
  }
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from,
        to: [user.email],
        subject,
        text,
        html: `<p>Your NamelessUnSee ${escapeHtml(purpose.toLowerCase())} verification code is <strong>${escapeHtml(code)}</strong>.</p><p>This code expires in 5 minutes. If you did not request this, ignore this email.</p>`,
      }),
    });
    if (!res.ok) {
      console.warn('[NamelessUnSee] Resend recovery failed:', res.status, await res.text());
      return false;
    }
    return true;
  } catch (err) {
    console.warn('[NamelessUnSee] Resend recovery error:', err.message);
    return false;
  }
}

async function sendForgottenValue(user, label, value) {
  const { apiKey } = config.resend;
  const from = cleanFrom(config.resend.from);
  const subject = `NamelessUnSee forgotten ${label.toLowerCase()}`;
  const text = `The ${label.toLowerCase()} associated with this account is: ${value}\n\nIf you did not request this, ignore this email.`;
  if (!apiKey || !from) {
    if (config.twofa.consoleFallback) {
      console.log(`[NamelessUnSee] Forgotten ${label.toLowerCase()} for ${user.email}: ${value}`);
      return true;
    }
    return false;
  }
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from, to: [user.email], subject, text, html: `<p>The ${escapeHtml(label.toLowerCase())} associated with this account is:</p><p><strong>${escapeHtml(value)}</strong></p>` }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

module.exports = {
  notifyPendingSignup,
  notifyAdminFlag,
  notifyAdminReport,
  sendSignupStatus,
  sendSignupVerification,
  sendLoginCode,
  sendAccountDeletionCode,
  sendRecoveryCode,
  sendForgottenValue,
};
