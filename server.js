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
    dailyGoal: 10, dashSort: 'tier',
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
  // Ensure at least one campaign exists, and that every contact belongs to one.
  if (db.campaigns.length === 0) {
    db.campaigns.push({ id: newId('camp'), name: 'Beta — test data', createdAt: Date.now() });
  }
  const firstCampaignId = db.campaigns[0].id;
  db.contacts.forEach((c) => { if (!c.campaignId) c.campaignId = firstCampaignId; });
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
  return { id: u.id, email: u.email, name: u.name, role: u.role };
}
function userById(id) { return db.users.find((u) => u.id === id); }

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
  });
});

// ── CONTACTS ───────────────────────────────────────────────────────────────────
// Server-managed fields the client may never overwrite via a plain save.
function stripManaged(data) {
  const c = Object.assign({}, data);
  delete c.ownerId; delete c.assignedUserIds; delete c.updatedAt; delete c.updatedBy;
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
  const merged = Object.assign({}, existing, stripManaged(req.body || {}), {
    id: existing.id,
    ownerId: existing.ownerId,
    assignedUserIds: existing.assignedUserIds || [],
    campaignId: existing.campaignId,
    updatedAt: Date.now(),
    updatedBy: req.user.id,
  });
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
}

start();
