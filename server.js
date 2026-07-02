'use strict';

/*
 * Outreach Tracker — backend
 * Single Node + Express service: serves the frontend and a JSON API, authenticates
 * users, enforces per-contact access control, and persists to a file-backed JSON
 * store (atomic writes, serialized) on a Docker volume.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const nodemailer = require('nodemailer');

const PORT = parseInt(process.env.PORT, 10) || 3000;
const DATA_DIR = process.env.DATA_DIR || '/data';
const DB_FILE = path.join(DATA_DIR, 'db.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
// Public base path the browser sees (Traefik strips it before reaching us).
// Empty for local/direct access; e.g. "/outreach" behind the reverse proxy.
const BASE_PATH = (process.env.PUBLIC_BASE_PATH || '').replace(/\/+$/, '');
const SESSION_DAYS = 30;

// ── DATA STORE ───────────────────────────────────────────────────────────────
function defaultSettings() {
  return {
    tierDefaults: {
      star: { retail: 4, wholesale: 4 }, major: { retail: 3, wholesale: 4 },
      mid: { retail: 2, wholesale: 4 }, general: { retail: 1, wholesale: 4 },
    },
    dailyGoal: 10, dashSort: 'tier', countMode: 'all', taskFilter: 'mine',
  };
}

let db;
function loadDB() {
  try {
    db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch {
    db = {};
  }
  db.users = db.users || [];
  db.contacts = db.contacts || [];
  db.settingsByUser = db.settingsByUser || {};
  db.dashByUser = db.dashByUser || {};
  db.campaigns = db.campaigns || [];
  db.meta = db.meta || {};
  db.meta.resetTokens = db.meta.resetTokens || [];
  db.syncLog = db.syncLog || [];
  // Ensure at least one campaign exists, and that every contact belongs to one.
  if (db.campaigns.length === 0) {
    db.campaigns.push({ id: newId('camp'), name: 'Beta — test data', createdAt: Date.now() });
  }
  const firstCampaignId = db.campaigns[0].id;
  db.contacts.forEach((c) => { if (!c.campaignId) c.campaignId = firstCampaignId; });
  // One-time cleanup: before self-service 0-entry existed, blank target fields
  // were silently saved as 0. Convert those legacy zeros to "unset" so blanks
  // display as "—". Runs once; deliberate 0s entered afterwards are preserved.
  if (!db.meta.zeroTargetsCleaned) {
    db.contacts.forEach((c) => {
      ['low', 'medium', 'high', 'target', 'actual'].forEach((f) => { if (c[f] === 0) delete c[f]; });
    });
    db.meta.zeroTargetsCleaned = true;
  }
  // One-time cleanup: imports used to auto-assign the 'general' tier to everyone.
  // Clear those so contacts have no tier until one is chosen. Runs once;
  // deliberate 'general' choices made afterwards are preserved.
  if (!db.meta.autoTierCleaned) {
    db.contacts.forEach((c) => { if (c.tier === 'general') delete c.tier; });
    db.meta.autoTierCleaned = true;
  }
  if (!db.meta.sessionSecret) {
    db.meta.sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
  }
}

// ── BACKUPS / VERSIONING ──────────────────────────────────────────────────
// Rolling snapshots of the whole data file so a bad import/edit can be rolled back.
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
const MAX_BACKUPS = 40;
let lastSnapshotAt = 0;
function snapshot(reason) {
  try {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const safe = String(reason || 'auto').replace(/[^a-z0-9_-]/gi, '').slice(0, 40) || 'auto';
    fs.writeFileSync(path.join(BACKUP_DIR, stamp + '__' + safe + '.json'), JSON.stringify(db));
    lastSnapshotAt = Date.now();
    const files = fs.readdirSync(BACKUP_DIR).filter((f) => f.endsWith('.json')).sort();
    while (files.length > MAX_BACKUPS) { try { fs.unlinkSync(path.join(BACKUP_DIR, files.shift())); } catch {} }
  } catch (e) { console.error('snapshot error', e); }
}
// Periodic safety snapshot (at most once per 20 min of activity).
function autoSnapshot() { if (Date.now() - lastSnapshotAt > 20 * 60 * 1000) snapshot('auto'); }

let writeChain = Promise.resolve();
function persist() {
  autoSnapshot();
  const snapshot = JSON.stringify(db);
  writeChain = writeChain.then(() => new Promise((resolve) => {
    const tmp = DB_FILE + '.tmp';
    fs.writeFile(tmp, snapshot, (err) => {
      if (err) { console.error('persist write error', err); return resolve(); }
      fs.rename(tmp, DB_FILE, (err2) => {
        if (err2) console.error('persist rename error', err2);
        resolve();
      });
    });
  }));
  return writeChain;
}

// ── AUTH HELPERS ─────────────────────────────────────────────────────────────
function hashPassword(password, salt) {
  return crypto.scryptSync(String(password), salt, 64).toString('hex');
}
function makePasswordRecord(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { salt, hash: hashPassword(password, salt) };
}
function verifyPassword(password, salt, hash) {
  const got = Buffer.from(hashPassword(password, salt), 'hex');
  const want = Buffer.from(hash, 'hex');
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}
function newId(prefix) {
  return prefix + '_' + crypto.randomBytes(9).toString('hex');
}
function sign(value) {
  return crypto.createHmac('sha256', db.meta.sessionSecret).update(value).digest('hex');
}
function makeToken(userId) {
  const exp = Date.now() + SESSION_DAYS * 86400000;
  const payload = userId + '.' + exp;
  return payload + '.' + sign(payload);
}
function verifyToken(token) {
  if (!token) return null;
  const i = token.lastIndexOf('.');
  if (i < 0) return null;
  const payload = token.slice(0, i);
  const sig = token.slice(i + 1);
  const expected = sign(payload);
  if (sig.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  const [userId, expStr] = payload.split('.');
  if (!userId || Number(expStr) < Date.now()) return null;
  return userId;
}
function safeUser(u) {
  return { id: u.id, email: u.email, name: u.name, role: u.role, hasSecurityQuestion: !!u.securityQuestion };
}
function userById(id) { return db.users.find((u) => u.id === id); }

// ── PASSWORD-RESET / EMAIL HELPERS ─────────────────────────────────────────
function escHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
// Security answers are compared case/space-insensitively.
function normAnswer(a) { return String(a || '').trim().toLowerCase().replace(/\s+/g, ' '); }
function hashToken(t) { return crypto.createHash('sha256').update(String(t)).digest('hex'); }
function maskEmail(email) {
  const [u, d] = String(email || '').split('@');
  if (!d) return email;
  const shown = u.length <= 2 ? (u[0] || '') : u.slice(0, 2);
  return shown + '***@' + d;
}
function publicBaseUrl(req) {
  if (process.env.PUBLIC_URL) return process.env.PUBLIC_URL.replace(/\/+$/, '');
  const proto = String(req.headers['x-forwarded-proto'] || '').split(',')[0] || (req.secure ? 'https' : 'http');
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return proto + '://' + host + BASE_PATH;
}

// SMTP mailer (optional). If SMTP_USER/SMTP_PASS aren't set, sending throws and
// the caller reports a friendly error; the reset link is always logged too.
let _mailer = null, _mailerTried = false;
function getMailer() {
  if (_mailerTried) return _mailer;
  _mailerTried = true;
  const user = process.env.SMTP_USER, pass = process.env.SMTP_PASS;
  if (!user || !pass) { console.warn('[outreach] SMTP not configured — reset emails disabled.'); return null; }
  const port = parseInt(process.env.SMTP_PORT, 10) || 465;
  _mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port, secure: port === 465, auth: { user, pass },
  });
  return _mailer;
}
async function sendMail(to, subject, text, html) {
  const m = getMailer();
  if (!m) throw new Error('email-not-configured');
  const from = process.env.SMTP_FROM || ('Outreach Tracker <' + process.env.SMTP_USER + '>');
  await m.sendMail({ from, to, subject, text, html });
}

// In-memory throttle for reset-answer attempts (per email).
const resetAttempts = new Map();
function tooManyAttempts(email) {
  const r = resetAttempts.get(email);
  if (!r) return false;
  if (Date.now() > r.until) { resetAttempts.delete(email); return false; }
  return r.count >= 6;
}
function noteAttempt(email) {
  const r = resetAttempts.get(email) || { count: 0, until: 0 };
  r.count++; r.until = Date.now() + 15 * 60 * 1000;
  resetAttempts.set(email, r);
}
function clearAttempts(email) { resetAttempts.delete(email); }
const RESET_TTL_MS = 45 * 60 * 1000;
function pruneResetTokens() {
  db.meta.resetTokens = (db.meta.resetTokens || []).filter((t) => !t.used && t.exp > Date.now());
}

// ── SALESFORCE (OAuth2 Authorization Code + PKCE, no client secret) ──────────
const SF_CLIENT_ID = process.env.SF_CLIENT_ID || '';
const SF_LOGIN_URL = (process.env.SF_LOGIN_URL || 'https://login.salesforce.com').replace(/\/+$/, '');
const SF_SCOPES = process.env.SF_SCOPES || 'api refresh_token';
const sfPending = new Map(); // state -> { verifier, exp, userId }
function b64url(buf) { return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function sfConfigured() { return !!SF_CLIENT_ID; }
function sfRedirectUri(req) { return publicBaseUrl(req) + '/api/sf/callback'; }
async function sfPostToken(base, params) {
  const r = await fetch(base + '/services/oauth2/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString(),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error_description || data.error || ('token HTTP ' + r.status));
  return data;
}
async function sfRefresh() {
  const sf = db.meta.salesforce;
  if (!sf || !sf.refreshToken) throw new Error('Salesforce not connected');
  const data = await sfPostToken(sf.instanceUrl || SF_LOGIN_URL, {
    grant_type: 'refresh_token', client_id: SF_CLIENT_ID, refresh_token: sf.refreshToken,
  });
  sf.accessToken = data.access_token;
  if (data.instance_url) sf.instanceUrl = data.instance_url;
  sf.issuedAt = Date.now();
  persist();
  return sf.accessToken;
}
// Authenticated Salesforce REST call; auto-refreshes the token once on 401.
async function sfApi(path, opts = {}, _retry = true) {
  const sf = db.meta.salesforce;
  if (!sf || !sf.accessToken) throw new Error('Salesforce not connected');
  const url = path.startsWith('http') ? path : sf.instanceUrl + path;
  const r = await fetch(url, Object.assign({}, opts, {
    headers: Object.assign({ Authorization: 'Bearer ' + sf.accessToken, 'Content-Type': 'application/json' }, opts.headers || {}),
  }));
  if (r.status === 401 && _retry) { await sfRefresh(); return sfApi(path, opts, false); }
  const data = await r.json().catch(() => null);
  if (!r.ok) {
    const msg = (data && (Array.isArray(data) ? data[0] && data[0].message : (data.message || data.error_description))) || ('Salesforce HTTP ' + r.status);
    throw new Error(msg);
  }
  return data;
}
async function sfApiVersion() {
  const v = await sfApi('/services/data/');
  return (Array.isArray(v) && v.length) ? v[v.length - 1].version : '60.0';
}

// Active = not archived and not in the recycle bin. Salesforce sync skips the rest.
function isActiveContact(c) { return !c.status || c.status === 'active'; }
function canSee(user, contact) {
  return user.role === 'admin'
    || contact.ownerId === user.id
    || (contact.assignedUserIds || []).includes(user.id);
}
function canAssign(user, contact) {
  return user.role === 'admin' || contact.ownerId === user.id;
}

// ── APP ──────────────────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', true);
app.use(express.json({ limit: '8mb' }));

function isSecure(req) {
  return req.secure || req.headers['x-forwarded-proto'] === 'https';
}
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function setSession(req, res, userId) {
  res.cookie('ot_session', makeToken(userId), {
    httpOnly: true, sameSite: 'lax', secure: isSecure(req),
    path: '/', maxAge: SESSION_DAYS * 86400000,
  });
}

// Auth middleware for /api routes (except login/me handle their own).
function requireAuth(req, res, next) {
  const userId = verifyToken(parseCookies(req).ot_session);
  const user = userId && userById(userId);
  if (!user) return res.status(401).json({ error: 'not authenticated' });
  req.user = user;
  next();
}
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'admin only' });
  next();
}

// Basic security headers + CSP that permits the CDN (SheetJS) and Google Fonts.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src https://fonts.gstatic.com data:; " +
    "img-src 'self' data:; connect-src 'self'");
  next();
});

// ── AUTH ROUTES ───────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = db.users.find((u) => u.email === email);
  if (!user || !verifyPassword(password, user.salt, user.hash)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  setSession(req, res, user.id);
  res.json({ user: safeUser(user) });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('ot_session', { path: '/' });
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const userId = verifyToken(parseCookies(req).ot_session);
  const user = userId && userById(userId);
  if (!user) return res.status(401).json({ error: 'not authenticated' });
  res.json({ user: safeUser(user) });
});

// ── PASSWORD RESET (public: no session required) ───────────────────────────
// Step 1: look up the account's security question (if any).
app.post('/api/forgot', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const user = db.users.find((u) => u.email === email);
  if (user && user.securityQuestion) {
    return res.json({ ok: true, hasQuestion: true, question: user.securityQuestion });
  }
  // Don't confirm or deny the account beyond whether a self-reset is possible.
  res.json({ ok: true, hasQuestion: false });
});

// Step 2: verify the security answer, then email a one-time reset link.
app.post('/api/forgot/answer', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const user = db.users.find((u) => u.email === email);
  if (!user || !user.securityQuestion || !user.secHash) {
    return res.status(400).json({ error: 'This account can’t be reset automatically. Please ask an administrator.' });
  }
  if (tooManyAttempts(email)) {
    return res.status(429).json({ error: 'Too many attempts. Please wait 15 minutes and try again.' });
  }
  if (!verifyPassword(normAnswer(req.body.answer), user.secSalt, user.secHash)) {
    noteAttempt(email);
    return res.status(400).json({ error: 'That answer is incorrect.' });
  }
  clearAttempts(email);
  pruneResetTokens();
  const raw = crypto.randomBytes(32).toString('hex');
  db.meta.resetTokens.push({ tokenHash: hashToken(raw), userId: user.id, exp: Date.now() + RESET_TTL_MS, used: false });
  persist();
  const link = publicBaseUrl(req) + '/reset?token=' + raw;
  console.log('[outreach] password reset link for ' + email + ': ' + link);
  try {
    await sendMail(
      user.email,
      'Reset your Outreach Tracker password',
      'Hello ' + (user.name || '') + ',\n\n' +
        'We received a request to reset your Outreach Tracker password.\n\n' +
        'Open this link to choose a new password (valid for 45 minutes):\n' + link + '\n\n' +
        'If you didn’t request this, you can safely ignore this email.\n',
      '<p>Hello ' + escHtml(user.name || '') + ',</p>' +
        '<p>We received a request to reset your Outreach Tracker password.</p>' +
        '<p><a href="' + link + '">Click here to choose a new password</a> (valid for 45 minutes).</p>' +
        '<p>If you didn’t request this, you can safely ignore this email.</p>'
    );
    res.json({ ok: true, sent: true, emailHint: maskEmail(user.email) });
  } catch (e) {
    console.error('[outreach] reset email failed:', e.message);
    res.status(500).json({ error: 'We couldn’t send the reset email. Please contact your administrator.' });
  }
});

// Step 3: consume the token and set the new password.
app.post('/api/reset-password', (req, res) => {
  const token = String(req.body.token || '');
  const password = String(req.body.password || '');
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  pruneResetTokens();
  const rec = db.meta.resetTokens.find((t) => t.tokenHash === hashToken(token) && !t.used && t.exp > Date.now());
  if (!rec) return res.status(400).json({ error: 'This reset link is invalid or has expired. Please request a new one.' });
  const user = userById(rec.userId);
  if (!user) return res.status(400).json({ error: 'Account not found.' });
  const pw = makePasswordRecord(password);
  user.salt = pw.salt; user.hash = pw.hash;
  rec.used = true;
  pruneResetTokens();
  persist();
  res.json({ ok: true });
});

// Everything below requires a session.
app.use('/api', requireAuth);

// ── STATE ─────────────────────────────────────────────────────────────────────
app.get('/api/state', (req, res) => {
  const me = req.user;
  const contacts = db.contacts.filter((c) => canSee(me, c));
  const settings = db.settingsByUser[me.id] || defaultSettings();
  const dash = db.dashByUser[me.id] || { day: '', doneCalls: [], streak: { date: '', count: 0, lastGoal: 0 } };
  res.json({
    me: safeUser(me),
    contacts,
    settings,
    dash,
    campaigns: db.campaigns,
    users: db.users.map((u) => ({ id: u.id, name: u.name, email: u.email, role: u.role })),
    sfConnected: !!(db.meta.salesforce && db.meta.salesforce.refreshToken),
  });
});

// ── CONTACTS ───────────────────────────────────────────────────────────────────
// Server-managed fields the client may never overwrite via a plain save.
function stripManaged(data) {
  const c = Object.assign({}, data);
  delete c.ownerId; delete c.assignedUserIds; delete c.updatedAt; delete c.updatedBy;
  delete c.sfQueue; // server-managed: pending Salesforce pushes, never set by the client
  return c;
}

app.post('/api/contacts', (req, res) => {
  const c = stripManaged(req.body || {});
  c.id = c.id || newId('c');
  c.ownerId = req.user.id;
  c.assignedUserIds = [];
  if (!c.campaignId || !db.campaigns.find((x) => x.id === c.campaignId)) c.campaignId = db.campaigns[0].id;
  c.updatedAt = Date.now();
  c.updatedBy = req.user.id;
  db.contacts.push(c);
  persist();
  res.json({ contact: c });
});

app.put('/api/contacts/:id', (req, res) => {
  const idx = db.contacts.findIndex((c) => c.id === req.params.id);
  if (idx < 0) {
    // Upsert: treat as create owned by me.
    const c = stripManaged(req.body || {});
    c.id = req.params.id;
    c.ownerId = req.user.id;
    c.assignedUserIds = [];
    if (!c.campaignId || !db.campaigns.find((x) => x.id === c.campaignId)) c.campaignId = db.campaigns[0].id;
    c.updatedAt = Date.now();
    c.updatedBy = req.user.id;
    db.contacts.push(c);
    persist();
    return res.json({ contact: c });
  }
  const existing = db.contacts[idx];
  if (!canSee(req.user, existing)) return res.status(403).json({ error: 'no access' });
  const incoming = stripManaged(req.body || {});
  const merged = Object.assign({}, existing, incoming, {
    id: existing.id,
    ownerId: existing.ownerId,
    assignedUserIds: existing.assignedUserIds || [],
    campaignId: existing.campaignId,
    updatedAt: Date.now(),
    updatedBy: req.user.id,
  });
  // Queue any edits to synced fields for the next Salesforce sync (not sent instantly).
  if (db.meta.salesforce && db.meta.salesforce.refreshToken) queueSfChanges(existing, incoming, merged);
  db.contacts[idx] = merged;
  persist();
  res.json({ contact: merged });
});

app.delete('/api/contacts/:id', (req, res) => {
  const c = db.contacts.find((x) => x.id === req.params.id);
  if (!c) return res.json({ ok: true });
  if (req.user.role !== 'admin' && c.ownerId !== req.user.id) {
    return res.status(403).json({ error: 'only the owner or an admin can delete' });
  }
  db.contacts = db.contacts.filter((x) => x.id !== req.params.id);
  persist();
  res.json({ ok: true });
});

// Bulk upsert for Excel import. New contacts are owned by the importer; existing
// contacts are updated only when the importer already has access.
app.post('/api/contacts/bulk', (req, res) => {
  const incoming = Array.isArray(req.body.contacts) ? req.body.contacts : [];
  if (incoming.length) snapshot('before-import'); // so an import can be rolled back
  let created = 0, updated = 0, skipped = 0;
  incoming.forEach((raw) => {
    const data = stripManaged(raw);
    const existing = data.id && db.contacts.find((c) => c.id === data.id);
    if (existing) {
      if (!canSee(req.user, existing)) { skipped++; return; }
      Object.assign(existing, data, {
        id: existing.id, ownerId: existing.ownerId,
        assignedUserIds: existing.assignedUserIds || [],
        updatedAt: Date.now(), updatedBy: req.user.id,
      });
      updated++;
    } else {
      data.id = data.id || newId('c');
      data.ownerId = req.user.id;
      data.assignedUserIds = [];
      if (!data.campaignId || !db.campaigns.find((x) => x.id === data.campaignId)) data.campaignId = db.campaigns[0].id;
      data.updatedAt = Date.now();
      data.updatedBy = req.user.id;
      db.contacts.push(data);
      created++;
    }
  });
  persist();
  const contacts = db.contacts.filter((c) => canSee(req.user, c));
  res.json({ created, updated, skipped, contacts });
});

// Assign / share a contact. Admins can assign any; owners can assign their own.
app.put('/api/contacts/:id/assign', (req, res) => {
  const c = db.contacts.find((x) => x.id === req.params.id);
  if (!c) return res.status(404).json({ error: 'not found' });
  if (!canAssign(req.user, c)) return res.status(403).json({ error: 'not allowed to assign' });
  const ids = Array.isArray(req.body.assignedUserIds) ? req.body.assignedUserIds : [];
  c.assignedUserIds = ids.filter((id) => id !== c.ownerId && userById(id));
  c.updatedAt = Date.now();
  c.updatedBy = req.user.id;
  persist();
  res.json({ contact: c });
});

// ── PER-USER SETTINGS + DASHBOARD ────────────────────────────────────────────
// ── CAMPAIGNS ─────────────────────────────────────────────────────────────────
// Any signed-in user can create or switch campaigns; only admins can delete one.
app.get('/api/campaigns', (req, res) => {
  res.json({ campaigns: db.campaigns });
});

app.post('/api/campaigns', (req, res) => {
  const name = String(req.body.name || '').trim();
  if (!name) return res.status(400).json({ error: 'A campaign name is required.' });
  const campaign = { id: newId('camp'), name, createdAt: Date.now(), createdBy: req.user.id };
  db.campaigns.push(campaign);
  persist();
  res.json({ campaign, campaigns: db.campaigns });
});

app.put('/api/campaigns/:id', requireAdmin, (req, res) => {
  const c = db.campaigns.find((x) => x.id === req.params.id);
  if (!c) return res.status(404).json({ error: 'Campaign not found.' });
  if (req.body.name !== undefined) {
    const name = String(req.body.name || '').trim();
    if (!name) return res.status(400).json({ error: 'A campaign name is required.' });
    c.name = name;
  }
  if (req.body.archived !== undefined) {
    const archived = !!req.body.archived;
    if (archived && db.campaigns.filter((x) => !x.archived).length <= 1) {
      return res.status(400).json({ error: 'Keep at least one active campaign.' });
    }
    c.archived = archived;
  }
  persist();
  res.json({ campaign: c, campaigns: db.campaigns });
});

app.delete('/api/campaigns/:id', requireAdmin, (req, res) => {
  if (db.campaigns.length <= 1) {
    return res.status(400).json({ error: 'You cannot delete the only campaign.' });
  }
  const id = req.params.id;
  if (!db.campaigns.find((c) => c.id === id)) {
    return res.json({ ok: true, campaigns: db.campaigns });
  }
  snapshot('before-campaign-delete');
  db.campaigns = db.campaigns.filter((c) => c.id !== id);
  db.contacts = db.contacts.filter((c) => c.campaignId !== id);
  persist();
  res.json({ ok: true, campaigns: db.campaigns });
});

// ── BACKUPS (admin) ───────────────────────────────────────────────────────
app.get('/api/backups', requireAdmin, (req, res) => {
  let backups = [];
  try {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
    backups = fs.readdirSync(BACKUP_DIR).filter((f) => f.endsWith('.json')).sort().reverse().slice(0, MAX_BACKUPS).map((f) => {
      let contacts = null, campaigns = null;
      try { const d = JSON.parse(fs.readFileSync(path.join(BACKUP_DIR, f), 'utf8')); contacts = (d.contacts || []).length; campaigns = (d.campaigns || []).length; } catch {}
      const at = fs.statSync(path.join(BACKUP_DIR, f)).mtimeMs;
      const reason = (f.replace('.json', '').split('__')[1]) || 'auto';
      return { file: f, at, reason, contacts, campaigns };
    });
  } catch (e) { console.error('list backups', e); }
  res.json({ backups });
});

app.post('/api/backups/restore', requireAdmin, (req, res) => {
  const file = String(req.body.file || '');
  if (!/^[A-Za-z0-9_.\-]+\.json$/.test(file)) return res.status(400).json({ error: 'Bad backup name.' });
  const full = path.join(BACKUP_DIR, file);
  if (!fs.existsSync(full)) return res.status(404).json({ error: 'Backup not found.' });
  let restored;
  try { restored = JSON.parse(fs.readFileSync(full, 'utf8')); } catch { return res.status(500).json({ error: 'Backup is unreadable.' }); }
  snapshot('before-restore'); // so a restore itself can be undone
  // Restore DATA only; keep current users + session secret so nobody gets locked out.
  db.contacts = restored.contacts || [];
  db.campaigns = restored.campaigns || [];
  db.settingsByUser = restored.settingsByUser || {};
  db.dashByUser = restored.dashByUser || {};
  if (!db.campaigns.length) db.campaigns.push({ id: newId('camp'), name: 'Beta — test data', createdAt: Date.now() });
  persist();
  res.json({ ok: true });
});

// Master reset (admin): wipe ALL contacts and campaigns, start fresh. Keeps users + login.
app.post('/api/reset', requireAdmin, (req, res) => {
  snapshot('before-reset');
  db.contacts = [];
  db.campaigns = [{ id: newId('camp'), name: 'My Campaign', createdAt: Date.now(), createdBy: req.user.id }];
  persist();
  res.json({ ok: true, campaigns: db.campaigns });
});

app.put('/api/settings', (req, res) => {
  db.settingsByUser[req.user.id] = Object.assign(defaultSettings(), req.body || {});
  persist();
  res.json({ settings: db.settingsByUser[req.user.id] });
});

app.put('/api/dash', (req, res) => {
  db.dashByUser[req.user.id] = req.body || {};
  persist();
  res.json({ ok: true });
});

// ── ACCOUNT: self-service password + security question ──────────────────────
app.put('/api/me/password', (req, res) => {
  const cur = String(req.body.currentPassword || '');
  const next = String(req.body.newPassword || '');
  if (!verifyPassword(cur, req.user.salt, req.user.hash)) {
    return res.status(400).json({ error: 'Your current password is incorrect.' });
  }
  if (next.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  const pw = makePasswordRecord(next);
  req.user.salt = pw.salt; req.user.hash = pw.hash;
  persist();
  res.json({ ok: true });
});

app.put('/api/me/security', (req, res) => {
  const cur = String(req.body.currentPassword || '');
  const question = String(req.body.question || '').trim();
  if (!verifyPassword(cur, req.user.salt, req.user.hash)) {
    return res.status(400).json({ error: 'Your current password is incorrect.' });
  }
  if (!question) return res.status(400).json({ error: 'Please enter a security question.' });
  if (normAnswer(req.body.answer).length < 2) return res.status(400).json({ error: 'Please enter a longer answer.' });
  const rec = makePasswordRecord(normAnswer(req.body.answer));
  req.user.securityQuestion = question; req.user.secSalt = rec.salt; req.user.secHash = rec.hash;
  persist();
  res.json({ ok: true, user: safeUser(req.user) });
});

// ── SALESFORCE CONNECTION (admin) ──────────────────────────────────────────
app.get('/api/sf/status', (req, res) => {
  const sf = db.meta.salesforce;
  res.json({
    configured: sfConfigured(),
    connected: !!(sf && sf.refreshToken),
    instanceUrl: sf ? sf.instanceUrl : null,
    connectedAt: sf ? sf.connectedAt : null,
    connectedBy: sf ? sf.connectedByName : null,
    user: sf ? sf.userInfo : null,
    lastPullAt: db.meta.sfLastPullAt || null,
  });
});

// Start the OAuth PKCE flow — redirects the admin's browser to Salesforce.
app.get('/api/sf/connect', requireAdmin, (req, res) => {
  if (!sfConfigured()) return res.status(400).send('Salesforce is not configured yet (missing Consumer Key).');
  for (const [k, v] of sfPending) { if (v.exp < Date.now()) sfPending.delete(k); }
  const verifier = b64url(crypto.randomBytes(64));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  const state = b64url(crypto.randomBytes(16));
  sfPending.set(state, { verifier, exp: Date.now() + 10 * 60 * 1000, userId: req.user.id });
  const u = new URL(SF_LOGIN_URL + '/services/oauth2/authorize');
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('client_id', SF_CLIENT_ID);
  u.searchParams.set('redirect_uri', sfRedirectUri(req));
  u.searchParams.set('scope', SF_SCOPES);
  u.searchParams.set('code_challenge', challenge);
  u.searchParams.set('code_challenge_method', 'S256');
  u.searchParams.set('state', state);
  u.searchParams.set('prompt', 'login');
  res.redirect(u.toString());
});

// OAuth redirect target — exchange the code, store tokens, bounce back to the app.
app.get('/api/sf/callback', async (req, res) => {
  const base = publicBaseUrl(req);
  try {
    if (req.query.error) throw new Error(req.query.error_description || req.query.error);
    const state = String(req.query.state || '');
    const pend = sfPending.get(state);
    if (!pend || pend.exp < Date.now()) throw new Error('This connection attempt expired — please try again.');
    sfPending.delete(state);
    const tok = await sfPostToken(SF_LOGIN_URL, {
      grant_type: 'authorization_code', code: String(req.query.code || ''),
      client_id: SF_CLIENT_ID, redirect_uri: sfRedirectUri(req), code_verifier: pend.verifier,
    });
    let userInfo = null;
    try {
      if (tok.id) {
        const idr = await fetch(tok.id, { headers: { Authorization: 'Bearer ' + tok.access_token } });
        if (idr.ok) { const j = await idr.json(); userInfo = { name: j.display_name, username: j.username, email: j.email, orgId: j.organization_id }; }
      }
    } catch {}
    const connector = userById(pend.userId);
    db.meta.salesforce = {
      accessToken: tok.access_token, refreshToken: tok.refresh_token, instanceUrl: tok.instance_url,
      idUrl: tok.id, issuedAt: Date.now(), connectedAt: Date.now(),
      connectedById: pend.userId, connectedByName: connector ? connector.name : '', userInfo,
    };
    persist();
    res.redirect(base + '/?sf=connected');
  } catch (e) {
    console.error('[sf] callback error:', e.message);
    res.redirect(base + '/?sf=error&msg=' + encodeURIComponent(e.message));
  }
});

app.post('/api/sf/disconnect', requireAdmin, (req, res) => {
  db.meta.salesforce = null;
  persist();
  res.json({ ok: true });
});

// Read-only sanity check that the connection works.
app.post('/api/sf/test', requireAdmin, async (req, res) => {
  try {
    const version = await sfApiVersion();
    const q = (soql) => sfApi('/services/data/v' + version + '/query/?q=' + encodeURIComponent(soql));
    const accounts = await q('SELECT COUNT() FROM Account');
    const contacts = await q('SELECT COUNT() FROM Contact');
    let opps = null;
    try { opps = (await q('SELECT COUNT() FROM Opportunity WHERE IsWon = true')).totalSize; } catch {}
    res.json({ ok: true, apiVersion: version, accounts: accounts.totalSize, contacts: contacts.totalSize, wonOpportunities: opps });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ── SALESFORCE ↔ APP CONTACT SYNC (Name / Mobile / Email / Personal notes) ──
const SF_CONTACT_QUERY_FIELDS = 'Id,FirstName,LastName,Email,MobilePhone,OneCRM__Personal_Notes__c';
function splitName(full) {
  const t = String(full || '').trim().replace(/\s+/g, ' ');
  if (!t) return { FirstName: '', LastName: '' };
  const i = t.indexOf(' ');
  if (i < 0) return { FirstName: '', LastName: t }; // one word → LastName (SF requires LastName)
  return { FirstName: t.slice(0, i), LastName: t.slice(i + 1) };
}
function joinName(first, last) { return (String(first || '').trim() + ' ' + String(last || '').trim()).trim(); }
function digitsOnly(s) { return String(s == null ? '' : s).replace(/\D/g, ''); }
function logSync(entry) {
  db.syncLog.push(Object.assign({ id: newId('log'), at: Date.now() }, entry));
  if (db.syncLog.length > 10000) db.syncLog.splice(0, db.syncLog.length - 10000);
}
// App person prefix 'p' (primary) / 's' (secondary) → field names + label.
function personDef(pre) {
  return {
    id: pre + 'Id', name: pre + 'Name', email: pre + 'Email', phone: pre + 'Phone', notes: pre + 'Notes',
    label: pre === 'p' ? 'Primary' : 'Secondary',
  };
}
// App fields that sync to Salesforce → [appField, person prefix, SF field label].
const SF_FIELD_MAP = [
  ['pName', 'p', 'Name'], ['pPhone', 'p', 'Mobile'], ['pEmail', 'p', 'Email'], ['pNotes', 'p', 'Personal notes'],
  ['sName', 's', 'Name'], ['sPhone', 's', 'Mobile'], ['sEmail', 's', 'Email'], ['sNotes', 's', 'Personal notes'],
];
// Record edits to synced fields on the contact's push queue instead of sending them
// to Salesforce immediately — the queue is flushed on the scheduled/manual sync.
function queueSfChanges(existing, incoming, target) {
  const q = Array.isArray(target.sfQueue) ? target.sfQueue.slice() : [];
  SF_FIELD_MAP.forEach(([f, person, field]) => {
    if (incoming[f] === undefined) return;              // field not part of this update
    const oldV = existing[f] || '', newV = incoming[f] || '';
    if (String(oldV) === String(newV)) return;          // unchanged
    const sfId = person === 'p' ? existing.pId : existing.sId;
    if (!sfId) return;                                   // person isn't linked to Salesforce
    const i = q.findIndex((e) => e.person === person && e.field === field);
    const entry = { person, field, old: i >= 0 ? q[i].old : oldV, new: newV };
    if (i >= 0) q[i] = entry; else q.push(entry);        // keep only the latest per field
  });
  target.sfQueue = q;
}
// Pull Salesforce → app for the given contacts. Returns number of field changes.
async function sfPullContacts(contacts) {
  if (!(db.meta.salesforce && db.meta.salesforce.refreshToken)) throw new Error('Salesforce not connected');
  const version = await sfApiVersion();
  const ids = [];
  contacts.forEach((c) => { ['p', 's'].forEach((pre) => { if (c[pre + 'Id']) ids.push(c[pre + 'Id']); }); });
  const byId = {};
  for (let i = 0; i < ids.length; i += 200) {
    const chunk = ids.slice(i, i + 200).map((id) => "'" + id + "'").join(',');
    const r = await sfApi('/services/data/v' + version + '/query/?q=' + encodeURIComponent('SELECT ' + SF_CONTACT_QUERY_FIELDS + ' FROM Contact WHERE Id IN (' + chunk + ')'));
    (r.records || []).forEach((rec) => { byId[rec.Id] = rec; });
  }
  let changes = 0;
  contacts.forEach((c) => {
    ['p', 's'].forEach((pre) => {
      const def = personDef(pre); const sfId = c[def.id]; if (!sfId) return;
      const rec = byId[sfId]; if (!rec) return;
      const apply = (appField, newVal, label, cmp) => {
        const oldVal = c[appField] || '';
        const nv = newVal == null ? '' : String(newVal);
        const same = cmp ? cmp(oldVal, nv) : (String(oldVal).trim() === nv.trim());
        if (same) return;
        logSync({ direction: 'sf→app', contactId: c.id, contactName: c.name, person: def.label, personId: sfId, field: label, old: oldVal, new: nv, by: 'Salesforce sync' });
        c[appField] = nv; changes++;
      };
      apply(def.name, joinName(rec.FirstName, rec.LastName), 'Name');
      apply(def.email, rec.Email, 'Email');
      apply(def.phone, rec.MobilePhone, 'Mobile', (a, b) => digitsOnly(a) === digitsOnly(b));
      apply(def.notes, rec.OneCRM__Personal_Notes__c, 'Personal notes');
    });
  });
  db.meta.sfLastPullAt = Date.now();
  persist();
  return changes;
}

// Flush queued app → Salesforce edits (built up since the last sync). Returns the
// number of contacts pushed. Failed pushes stay queued for the next attempt.
async function sfFlushQueue() {
  if (!(db.meta.salesforce && db.meta.salesforce.refreshToken)) return 0;
  const pending = db.contacts.filter((c) => isActiveContact(c) && Array.isArray(c.sfQueue) && c.sfQueue.length);
  if (!pending.length) return 0;
  const version = await sfApiVersion();
  let pushed = 0;
  for (const c of pending) {
    const byPerson = {};
    c.sfQueue.forEach((ch) => { (byPerson[ch.person] = byPerson[ch.person] || []).push(ch); });
    const remaining = [];
    for (const pre of Object.keys(byPerson)) {
      const def = personDef(pre); const sfId = c[def.id];
      if (!sfId) continue; // person no longer linked — drop these
      const patch = {};
      byPerson[pre].forEach((ch) => {
        if (ch.field === 'Name') { const n = splitName(ch.new); patch.FirstName = n.FirstName; patch.LastName = n.LastName; }
        else if (ch.field === 'Email') patch.Email = ch.new || null;
        else if (ch.field === 'Mobile') patch.MobilePhone = ch.new || null;
        else if (ch.field === 'Personal notes') patch.OneCRM__Personal_Notes__c = ch.new || null;
      });
      if (!Object.keys(patch).length) continue;
      try {
        await sfApi('/services/data/v' + version + '/sobjects/Contact/' + sfId, { method: 'PATCH', body: JSON.stringify(patch) });
        byPerson[pre].forEach((ch) => logSync({ direction: 'app→sf', contactId: c.id, contactName: c.name, person: def.label, personId: sfId, field: ch.field, old: ch.old || '', new: ch.new || '', by: 'Scheduled sync' }));
        pushed++;
      } catch (e) {
        console.error('[sf] queued push failed for ' + c.id + ':', e.message);
        remaining.push(...byPerson[pre]); // keep for the next sync
      }
    }
    c.sfQueue = remaining;
  }
  persist();
  return pushed;
}

// Push app → Salesforce for the fields the user just edited on one contact.
app.post('/api/sf/push-contact', async (req, res) => {
  try {
    if (!(db.meta.salesforce && db.meta.salesforce.refreshToken)) throw new Error('Salesforce not connected');
    const c = db.contacts.find((x) => x.id === req.body.contactId);
    if (!c) return res.status(404).json({ error: 'contact not found' });
    if (!canSee(req.user, c)) return res.status(403).json({ error: 'no access' });
    const version = await sfApiVersion();
    const changes = Array.isArray(req.body.changes) ? req.body.changes : [];
    const byPerson = {};
    changes.forEach((ch) => { (byPerson[ch.person] = byPerson[ch.person] || []).push(ch); });
    const results = [];
    for (const pre of Object.keys(byPerson)) {
      const def = personDef(pre); const sfId = c[def.id];
      if (!sfId) { results.push({ person: pre, skipped: 'no Salesforce id' }); continue; }
      const patch = {};
      byPerson[pre].forEach((ch) => {
        if (ch.field === 'Name') { const n = splitName(ch.new); patch.FirstName = n.FirstName; patch.LastName = n.LastName; }
        else if (ch.field === 'Email') patch.Email = ch.new || null;
        else if (ch.field === 'Mobile') patch.MobilePhone = ch.new || null;
        else if (ch.field === 'Personal notes') patch.OneCRM__Personal_Notes__c = ch.new || null;
      });
      if (!Object.keys(patch).length) continue;
      await sfApi('/services/data/v' + version + '/sobjects/Contact/' + sfId, { method: 'PATCH', body: JSON.stringify(patch) });
      byPerson[pre].forEach((ch) => logSync({ direction: 'app→sf', contactId: c.id, contactName: c.name, person: def.label, personId: sfId, field: ch.field, old: ch.old || '', new: ch.new || '', by: req.user.name }));
      results.push({ person: pre, updated: Object.keys(patch) });
    }
    persist();
    res.json({ ok: true, results });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Manual pull (admin): Salesforce → app for all (or given) contacts.
app.post('/api/sf/pull-contacts', requireAdmin, async (req, res) => {
  try {
    const pushed = await sfFlushQueue(); // send queued app edits up first
    const ids = Array.isArray(req.body.contactIds) && req.body.contactIds.length ? req.body.contactIds : null;
    // Sync active contacts only — never quietly rewrite archived / recycle-bin ones.
    const active = db.contacts.filter(isActiveContact);
    const list = ids ? active.filter((c) => ids.includes(c.id)) : active;
    const changes = await sfPullContacts(list);
    res.json({ ok: true, pushed, changes, scanned: list.length, at: db.meta.sfLastPullAt });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Change report.
app.get('/api/sf/changes', requireAdmin, (req, res) => {
  const limit = Math.min(2000, parseInt(req.query.limit, 10) || 200);
  res.json({ changes: db.syncLog.slice(-limit).reverse(), total: db.syncLog.length, lastPullAt: db.meta.sfLastPullAt });
});
app.get('/api/sf/changes.csv', requireAdmin, (req, res) => {
  const q = (v) => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
  const rows = [['When', 'Direction', 'Household', 'Person', 'Field', 'Old', 'New', 'By']];
  db.syncLog.slice().reverse().forEach((l) => rows.push([new Date(l.at).toISOString(), l.direction, l.contactName, l.person, l.field, l.old, l.new, l.by]));
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="salesforce-changes.csv"');
  res.send(rows.map((r) => r.map(q).join(',')).join('\n'));
});

// ── ADMIN: USER MANAGEMENT ────────────────────────────────────────────────────
app.get('/api/users', requireAdmin, (req, res) => {
  res.json({ users: db.users.map(safeUser) });
});

app.post('/api/users', requireAdmin, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const name = String(req.body.name || '').trim();
  const password = String(req.body.password || '');
  const role = req.body.role === 'admin' ? 'admin' : 'user';
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });
  if (db.users.some((u) => u.email === email)) return res.status(409).json({ error: 'email already exists' });
  const pw = makePasswordRecord(password);
  const user = { id: newId('u'), email, name: name || email, role, salt: pw.salt, hash: pw.hash, createdAt: Date.now() };
  db.users.push(user);
  persist();
  res.json({ user: safeUser(user) });
});

app.put('/api/users/:id', requireAdmin, (req, res) => {
  const user = userById(req.params.id);
  if (!user) return res.status(404).json({ error: 'not found' });
  if (typeof req.body.name === 'string' && req.body.name.trim()) user.name = req.body.name.trim();
  if (req.body.role === 'admin' || req.body.role === 'user') {
    // Don't allow removing the last admin.
    if (user.role === 'admin' && req.body.role !== 'admin'
        && db.users.filter((u) => u.role === 'admin').length <= 1) {
      return res.status(400).json({ error: 'cannot demote the last admin' });
    }
    user.role = req.body.role;
  }
  if (req.body.password) {
    const pw = makePasswordRecord(String(req.body.password));
    user.salt = pw.salt; user.hash = pw.hash;
  }
  persist();
  res.json({ user: safeUser(user) });
});

app.delete('/api/users/:id', requireAdmin, (req, res) => {
  const user = userById(req.params.id);
  if (!user) return res.json({ ok: true });
  if (user.role === 'admin' && db.users.filter((u) => u.role === 'admin').length <= 1) {
    return res.status(400).json({ error: 'cannot delete the last admin' });
  }
  if (user.id === req.user.id) return res.status(400).json({ error: 'cannot delete yourself' });
  db.users = db.users.filter((u) => u.id !== user.id);
  // Unassign this user from any contacts (but keep contacts they owned).
  db.contacts.forEach((c) => {
    if (c.assignedUserIds) c.assignedUserIds = c.assignedUserIds.filter((id) => id !== user.id);
  });
  delete db.settingsByUser[user.id];
  delete db.dashByUser[user.id];
  persist();
  res.json({ ok: true });
});

// ── STATIC FRONTEND ────────────────────────────────────────────────────────────
let indexHtml = '';
function loadIndex() {
  indexHtml = fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8')
    .replace('%APP_BASE%', BASE_PATH);
}
app.use(express.static(PUBLIC_DIR, { index: false }));
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.type('html').send(indexHtml);
});

// ── BOOTSTRAP ───────────────────────────────────────────────────────────────────
function bootstrapAdmin() {
  if (db.users.length > 0) return;
  const email = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const password = String(process.env.ADMIN_PASSWORD || '');
  if (!email || !password) {
    console.warn('[outreach] No users yet and ADMIN_EMAIL/ADMIN_PASSWORD not set — set them to create the first admin.');
    return;
  }
  const pw = makePasswordRecord(password);
  db.users.push({
    id: newId('u'), email, name: process.env.ADMIN_NAME || 'Admin',
    role: 'admin', salt: pw.salt, hash: pw.hash, createdAt: Date.now(),
  });
  persist();
  console.log('[outreach] Bootstrapped admin user:', email);
}

function start() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  loadDB();
  persist(); // ensures the session secret is written on first boot
  bootstrapAdmin();
  loadIndex();
  app.listen(PORT, () => {
    console.log(`[outreach] listening on :${PORT} (base path "${BASE_PATH || '/'}")`);
  });
  scheduleSfSync();
}

// Automatic Salesforce → app contact pull every 24h (and once shortly after boot if overdue).
function scheduleSfSync() {
  const DAY = 24 * 60 * 60 * 1000;
  const run = () => {
    if (db.meta.salesforce && db.meta.salesforce.refreshToken) {
      sfFlushQueue()
        .then((p) => { if (p) console.log('[sf] daily push: ' + p + ' contact(s)'); return sfPullContacts(db.contacts.filter(isActiveContact)); })
        .then((n) => console.log('[sf] daily contact pull: ' + n + ' change(s)'))
        .catch((e) => console.error('[sf] daily sync failed:', e.message));
    }
  };
  // If we've never pulled, wait a full day (the admin runs the first pull manually).
  const since = db.meta.sfLastPullAt || Date.now();
  const first = Math.max(60000, DAY - (Date.now() - since));
  setTimeout(function tick() { run(); setTimeout(tick, DAY); }, first);
}

start();
