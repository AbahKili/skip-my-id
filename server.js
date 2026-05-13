'use strict';

const express = require('express');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3098;
const DB_PATH = path.join(__dirname, 'data.db');

// ── Database ──
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT,
    google_id TEXT,
    avatar TEXT,
    name TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    code TEXT UNIQUE NOT NULL,
    url TEXT NOT NULL,
    title TEXT,
    mode TEXT DEFAULT 'redirect',
    microsite_data TEXT,
    clicks INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS clicks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    link_id INTEGER,
    referer TEXT,
    ip TEXT,
    ua TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(link_id) REFERENCES links(id)
  );
`);

// ── Middleware ──
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function optionalAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return next();
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    req.userId = payload.id;
  } catch {}
  next();
}

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Login required' });
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    req.userId = payload.id;
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

function hash(pw) { return crypto.createHash('sha256').update(pw).digest('hex'); }
function token(id) {
  const h = { alg: 'HS256', typ: 'JWT' };
  const p = { id, exp: Date.now() + 30 * 24 * 3600 * 1000 };
  return Buffer.from(JSON.stringify(h)).toString('base64url') + '.' +
         Buffer.from(JSON.stringify(p)).toString('base64url') + '.sig';
}

// ── Google SSO ──
app.post('/api/auth/google', async (req, res) => {
  const { idToken } = req.body || {};
  if (!idToken) return res.status(400).json({ error: 'idToken required' });
  try {
    // Verify token with Google
    const gRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${idToken}`);
    if (!gRes.ok) return res.status(401).json({ error: 'Invalid Google token' });
    const profile = await gRes.json();

    // Find or create user
    let user = db.prepare('SELECT * FROM users WHERE email = ?').get(profile.email);
    if (!user) {
      db.prepare('INSERT INTO users (email, name, avatar, google_id) VALUES (?, ?, ?, ?)').run(
        profile.email, profile.name || '', profile.picture || '', profile.sub
      );
      user = db.prepare('SELECT * FROM users WHERE email = ?').get(profile.email);
    } else if (!user.google_id) {
      // Link Google to existing account
      db.prepare('UPDATE users SET google_id = ?, avatar = COALESCE(NULLIF(avatar,\"\"), ?) WHERE id = ?').run(
        profile.sub, profile.picture || '', user.id
      );
    }
    res.json({ token: token(user.id), user: { id: user.id, email: user.email, name: user.name || profile.name, avatar: profile.picture } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Auth Routes ──
app.post('/api/register', (req, res) => {
  const { email, password, name } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    db.prepare('INSERT INTO users (email, password, name) VALUES (?, ?, ?)').run(email, hash(password), name || '');
    res.json({ ok: true, message: 'Account created. Please login.' });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Email already registered' });
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE email = ? AND password = ?').get(email, hash(password));
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });
  res.json({ token: token(user.id), user: { id: user.id, email: user.email, name: user.name } });
});

// ── Link Routes ──
app.post('/api/links', optionalAuth, (req, res) => {
  const { url, code, title } = req.body || {};
  const userId = req.userId || null;
  if (!url) return res.status(400).json({ error: 'URL required' });
  // Auto-prepend https:// if no protocol specified
  let finalURL = url.trim();
  if (!/^https?:\/\//i.test(finalURL)) finalURL = 'https://' + finalURL;
  const slug = (code || crypto.randomBytes(4).toString('base64url')).slice(0, 20);
  try {
    db.prepare('INSERT INTO links (user_id, code, url, title) VALUES (?, ?, ?, ?)').run(userId, slug, finalURL, title || '');
    res.json({ ok: true, link: { code: slug, url: finalURL, shortURL: `https://skip.my.id/${slug}` } });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Code already taken. Try another.' });
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/links', auth, (req, res) => {
  const links = db.prepare('SELECT * FROM links WHERE user_id = ? ORDER BY created_at DESC LIMIT 100').all(req.userId);
  res.json(links.map(l => ({ ...l, shortURL: `https://skip.my.id/${l.code}` })));
});

app.put('/api/links/:code', auth, (req, res) => {
  const { url, title, newCode } = req.body || {};
  const link = db.prepare('SELECT * FROM links WHERE code = ? AND user_id = ?').get(req.params.code, req.userId);
  if (!link) return res.status(404).json({ error: 'Link not found' });

  let finalCode = link.code;
  if (newCode && newCode !== link.code) {
    const clean = newCode.toLowerCase().replace(/[^a-z0-9-_]/g, '');
    if (!clean || clean.length < 2) return res.status(400).json({ error: 'Min 2 characters' });
    if (['api','dashboard','login','register','admin','help','docs'].includes(clean)) return res.status(400).json({ error: 'Reserved word' });
    const exists = db.prepare('SELECT 1 FROM links WHERE code = ? AND code != ?').get(clean, link.code);
    if (exists) return res.status(409).json({ error: 'That short name is already taken' });
    finalCode = clean;
  }

  let finalURL = link.url;
  if (url) {
    finalURL = url.trim();
    if (!/^https?:\/\//i.test(finalURL)) finalURL = 'https://' + finalURL;
  }

  if (req.body.mode) db.prepare('UPDATE links SET mode = ? WHERE code = ? AND user_id = ?').run(req.body.mode, link.code, req.userId);
  if (req.body.microsite_data) db.prepare('UPDATE links SET microsite_data = ? WHERE code = ? AND user_id = ?').run(req.body.microsite_data, link.code, req.userId);

  db.prepare('UPDATE links SET url = ?, title = ?, code = ? WHERE code = ? AND user_id = ?').run(
    finalURL, title || link.title, finalCode, req.params.code, req.userId
  );
  const updated = db.prepare('SELECT * FROM links WHERE code = ?').get(finalCode);
  res.json({ ok: true, link: { ...updated, shortURL: `https://skip.my.id/${finalCode}` } });
});

app.delete('/api/links/:code', auth, (req, res) => {
  const link = db.prepare('SELECT id FROM links WHERE code = ? AND user_id = ?').get(req.params.code, req.userId);
  if (!link) return res.status(404).json({ error: 'Link not found' });
  db.prepare('DELETE FROM clicks WHERE link_id = ?').run(link.id);
  db.prepare('DELETE FROM links WHERE id = ?').run(link.id);
  res.json({ ok: true });
});

// ── Page Routes (MUST be before /:code) ──
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── Redirect ── (must be LAST route)
app.get('/:code', (req, res) => {
  const link = db.prepare('SELECT * FROM links WHERE code = ?').get(req.params.code);
  if (!link) return res.redirect('https://nerdstudio.online');
  // Log click
  db.prepare('INSERT INTO clicks (link_id, referer, ip, ua) VALUES (?, ?, ?, ?)').run(
    link.id, req.get('referer') || '', req.ip || '', req.get('user-agent') || ''
  );
  db.prepare('UPDATE links SET clicks = clicks + 1 WHERE id = ?').run(link.id);
  // Microsite mode — render landing page
  if (link.mode === 'microsite') {
    let components = [];
    try { components = JSON.parse(link.microsite_data || '[]'); } catch {}
    const buttonsHTML = components.map(c => `
      <a href="${c.url || '#'}" target="_blank" rel="noopener" class="btn">${c.label || 'Visit'}</a>
    `).join('\n');
    return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" /><meta name="viewport" content="width=device-width,initial-scale=1.0" />
  <title>${link.title || link.code} — Skip My ID</title>
  <meta property="og:title" content="${link.title || link.code}" />
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Plus Jakarta Sans',-apple-system,sans-serif;background:#020617;color:#f8fafc;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:2rem}
    .card{max-width:400px;width:100%;text-align:center}
    h1{font-size:1.5rem;margin-bottom:0.3rem;font-family:'Space Grotesk',sans-serif}
    .sub{color:#94a3b8;font-size:0.85rem;margin-bottom:1.5rem}
    .btn{display:block;width:100%;padding:0.75rem;background:#0f172a;border:1px solid #1e293b;border-radius:10px;color:#f8fafc;text-decoration:none;font-weight:500;margin-bottom:0.5rem;transition:border-color 0.2s,background 0.2s;font-size:0.9rem}
    .btn:hover{border-color:#22c55e;background:rgba(34,197,94,0.05)}
    footer{position:fixed;bottom:1rem;color:#475569;font-size:0.7rem}
    footer a{color:#22c55e;text-decoration:none}
  </style>
</head>
<body>
  <div class="card">
    <h1>${link.title || 'Links'}</h1>
    <p class="sub">${link.url ? 'Curated by Skip My ID' : ''}</p>
    ${buttonsHTML}
  </div>
  <footer>Powered by <a href="https://skip.my.id">Skip My ID</a></footer>
</body>
</html>`);
  }
  // Default: redirect
  res.redirect(301, link.url);
});

// Check if a custom code is available
app.get('/api/check/:code', (req, res) => {
  const code = req.params.code.toLowerCase().replace(/[^a-z0-9-_]/g, '');
  if (!code || code.length < 2) return res.json({ available: false, reason: 'Min 2 characters' });
  if (['api','dashboard','login','register','admin','help','docs'].includes(code)) {
    return res.json({ available: false, reason: 'Reserved word' });
  }
  const exists = db.prepare('SELECT 1 FROM links WHERE code = ?').get(code);
  res.json({ available: !exists });
});

// ── Health ──
app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

// Serve dashboard SPA
app.listen(PORT, '127.0.0.1', () => console.log(`[shortener] http://127.0.0.1:${PORT}`));
