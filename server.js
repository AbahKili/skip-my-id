'use strict';

const express = require('express');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const QRCode = require('qrcode');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3098;
const DB_PATH = path.join(__dirname, 'data.db');
const ADSENSE_PUB_ID = process.env.ADSENSE_PUB_ID || '';
const LEMON_SQUEEZY_SECRET = process.env.LEMON_SQUEEZY_SECRET || '';
const LS_STORE = process.env.LS_STORE || 'skipmyid'; // Lemon Squeezy store slug
const XENDIT_API_KEY = process.env.XENDIT_API_KEY || '';
const XENDIT_CALLBACK_TOKEN = process.env.XENDIT_CALLBACK_TOKEN || '';
const IDP_URL = process.env.IDP_URL || 'https://id.nerdstudio.online';
const IDP_INTERNAL_KEY = process.env.IDP_INTERNAL_KEY || 'internal';
const FREE_MAX_LINKS = 20;

// ── Xendit helpers ──
async function xenditRequest(method, path, body) {
  const opts = {
    method,
    headers: {
      'Authorization': 'Basic ' + Buffer.from(XENDIT_API_KEY + ':').toString('base64'),
      'Content-Type': 'application/json'
    }
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch('https://api.xendit.co' + path, opts);
  return res.json();
}

// ── File uploads ──
const upload = multer({
  storage: multer.diskStorage({
    destination: path.join(__dirname, 'public', 'uploads'),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname) || '.png';
      cb(null, crypto.randomBytes(8).toString('hex') + ext);
    }
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/png', 'image/jpeg', 'image/webp', 'image/gif', 'image/svg+xml'];
    cb(null, allowed.includes(file.mimetype));
  }
});

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
  CREATE TABLE IF NOT EXISTS microsites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    slug TEXT UNIQUE NOT NULL,
    title TEXT,
    description TEXT,
    components TEXT DEFAULT '[]',
    clicks INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);
// Add columns that may not exist (safe on fresh or existing DBs)
for (const col of [
  'ALTER TABLE microsites ADD COLUMN avatar TEXT DEFAULT ""',
  'ALTER TABLE microsites ADD COLUMN theme TEXT DEFAULT "dark"',
  'ALTER TABLE users ADD COLUMN premium INTEGER DEFAULT 0',
  'ALTER TABLE users ADD COLUMN premium_expires TEXT DEFAULT NULL',
  'ALTER TABLE links ADD COLUMN expires_at TEXT DEFAULT NULL',
  'ALTER TABLE microsites ADD COLUMN ga_id TEXT DEFAULT ""',
  'ALTER TABLE microsites ADD COLUMN fb_pixel_id TEXT DEFAULT ""'
]) { try { db.exec(col); } catch {} }
db.exec(`CREATE TABLE IF NOT EXISTS qris_pending (
  history_id TEXT PRIMARY KEY,
  user_id INTEGER,
  plan TEXT,
  amount INTEGER,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id)
)`);

// Clean up expired anonymous links hourly
setInterval(() => {
  db.prepare(`DELETE FROM clicks WHERE link_id IN (SELECT id FROM links WHERE expires_at < datetime('now'))`).run();
  db.prepare(`DELETE FROM links WHERE expires_at < datetime('now')`).run();
}, 3600_000);

// ── Middleware ──
app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));
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
async function checkIdpMembership(email) {
  if (!email) return false;
  try {
    const resp = await fetch(
      `${IDP_URL}/api/membership/check?email=${encodeURIComponent(email)}&key=${encodeURIComponent(IDP_INTERNAL_KEY)}`
    );
    if (!resp.ok) return false;
    const data = await resp.json();
    if (data.membership === 'premium' && data.membership_expires_at) {
      return new Date(data.membership_expires_at) > new Date();
    }
    return false;
  } catch { return false; }
}

function isPremium(uid) {
  if (!uid) return false;
  const u = db.prepare('SELECT premium, premium_expires, email FROM users WHERE id = ?').get(uid);
  if (!u) return false;
  // Check local premium first
  if (u.premium) {
    if (u.premium_expires && new Date(u.premium_expires) < new Date()) {
      // Local premium expired — fall through to IDP check
    } else {
      return true;
    }
  }
  // Sync check: we'll return false here and let async checkIdpMembership be used where needed
  return false;
}

// Async version for routes that can use await
async function isPremiumAsync(uid) {
  if (!uid) return false;
  const u = db.prepare('SELECT premium, premium_expires, email FROM users WHERE id = ?').get(uid);
  if (!u) return false;
  if (u.premium) {
    if (u.premium_expires && new Date(u.premium_expires) < new Date()) {
      // expired — check IDP
      return await checkIdpMembership(u.email);
    }
    return true;
  }
  // Check IDP membership
  return await checkIdpMembership(u.email);
}
function safeUrl(u) {
  if (!u) return '#';
  if (/^https?:\/\//i.test(u) || u.startsWith('/')) return u;
  return 'https://' + u;
}
function requirePremium(req, res, next) {
  if (isPremium(req.userId)) return next();
  res.status(402).json({ error: 'Short codes (≤4 characters) are for premium members only. Upgrade at nerdstudio.online' });
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
// ── Google SSO only (email/password removed) ──

app.get('/api/me', auth, async (req, res) => {
  const user = db.prepare('SELECT id, email, name, premium, premium_expires FROM users WHERE id = ?').get(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const plan = await isPremiumAsync(req.userId) ? 'premium' : 'free';
  const linkCount = db.prepare('SELECT COUNT(*) as cnt FROM links WHERE user_id = ?').get(req.userId);
  res.json({
    id: user.id, email: user.email, name: user.name,
    plan,
    linksUsed: linkCount.cnt,
    linksMax: plan === 'premium' ? null : FREE_MAX_LINKS,
  });
});

// ── Link Routes ──
app.post('/api/links', optionalAuth, async (req, res) => {
  const { url, code, title } = req.body || {};
  const userId = req.userId || null;
  if (!url) return res.status(400).json({ error: 'URL required' });
  // Auto-prepend https:// if no protocol specified
  let finalURL = url.trim();
  if (!/^https?:\/\//i.test(finalURL)) finalURL = 'https://' + finalURL;

  // Premium gate: free users limited to FREE_MAX_LINKS
  if (userId && !(await isPremiumAsync(userId))) {
    const count = db.prepare('SELECT COUNT(*) as cnt FROM links WHERE user_id = ?').get(userId);
    if (count.cnt >= FREE_MAX_LINKS) {
      return res.status(402).json({ error: `Free plan limited to ${FREE_MAX_LINKS} links. Upgrade at nerdstudio.online/upgrade`, upgradeUrl: 'https://nerdstudio.online/upgrade' });
    }
  }
  const slug = (code || crypto.randomBytes(4).toString('base64url')).slice(0, 20);
  // Check against microsites too
  if (db.prepare('SELECT 1 FROM microsites WHERE slug = ?').get(slug)) {
    return res.status(409).json({ error: 'Code already taken. Try another.' });
  }
  // Premium-only: slugs ≤ 4 chars
  if (code && slug.length <= 4 && !isPremium(userId)) {
    return res.status(402).json({ error: 'Short codes (≤4 characters) are for premium members only. Upgrade at nerdstudio.online' });
  }
  // Anonymous links expire in 30 days
  const expiresAt = userId ? null : new Date(Date.now() + 30*24*3600*1000).toISOString();
  try {
    db.prepare('INSERT INTO links (user_id, code, url, title, expires_at) VALUES (?, ?, ?, ?, ?)').run(userId, slug, finalURL, title || '', expiresAt);
    const link = { code: slug, url: finalURL, shortURL: `https://skip.my.id/${slug}` };
    if (!userId) link.expiresAt = expiresAt;
    res.json({ ok: true, link });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Code already taken. Try another.' });
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/links', auth, (req, res) => {
  const links = db.prepare('SELECT * FROM links WHERE user_id = ? ORDER BY created_at DESC LIMIT 100').all(req.userId);
  res.json(links.map(l => ({ ...l, shortURL: `https://skip.my.id/${l.code}` })));
});

// Claim anonymous links after signup
app.post('/api/links/claim', auth, (req, res) => {
  const { codes } = req.body || {};
  if (!codes || !codes.length) return res.json({ claimed: 0 });
  const claimed = [];
  for (const code of codes) {
    const link = db.prepare('SELECT * FROM links WHERE code = ? AND user_id IS NULL').get(code);
    if (link) {
      db.prepare('UPDATE links SET user_id = ?, expires_at = NULL WHERE id = ?').run(req.userId, link.id);
      claimed.push(code);
    }
  }
  res.json({ claimed: claimed.length, codes: claimed });
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
    const microExists = db.prepare('SELECT 1 FROM microsites WHERE slug = ?').get(clean);
    if (microExists) return res.status(409).json({ error: 'That short name is already taken' });
    if (clean.length <= 4 && !isPremium(req.userId)) {
      return res.status(402).json({ error: 'Short codes (≤4 characters) are for premium members only. Upgrade at nerdstudio.online' });
    }
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

// ── Xendit Payment Routes ──
// Create invoice for premium upgrade
app.post('/api/xendit/invoice', auth, async (req, res) => {
  if (!XENDIT_API_KEY) return res.status(500).json({ error: 'Payment not configured' });
  const plans = { monthly: 35000, annual: 350000, lifetime: 1499000 };
  const plan = req.body?.plan;
  const amount = plans[plan];
  if (!amount) return res.status(400).json({ error: 'Invalid plan. Use: monthly, annual, lifetime' });

  const user = db.prepare('SELECT email FROM users WHERE id = ?').get(req.userId);
  const extId = `skip-pro-${req.userId}-${Date.now()}`;

  try {
    const d = await xenditRequest('POST', '/v2/invoices', {
      external_id: extId,
      amount,
      payer_email: user?.email || '',
      description: `Skip Pro - ${plan}`,
      currency: 'IDR',
      success_redirect_url: 'https://skip.my.id/dashboard',
      failure_redirect_url: 'https://skip.my.id/upgrade'
    });
    if (d.id) {
      db.prepare(`INSERT OR REPLACE INTO qris_pending (history_id, user_id, plan, amount, created_at) VALUES (?,?,?,?,datetime('now'))`).run(
        d.id, req.userId, plan, amount
      );
    }
    res.json({ ok: true, invoice_url: d.invoice_url, id: d.id, amount });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Xendit webhook receiver
app.post('/webhook/xendit', (req, res) => {
  res.json({ ok: true });
  const cbToken = req.get('x-callback-token');
  console.log('[xendit] webhook received. token:', cbToken?.slice(0,10) + '...', 'status:', req.body?.status);
  // TODO: re-enable after getting sandbox callback token from Xendit dashboard
  const event = req.body;
  console.log('[xendit] Webhook:', event?.id, event?.status);
  if (event?.status === 'PAID') {
    activatePremium(event.id);
  }
});

function activatePremium(xenditId) {
  const pending = db.prepare('SELECT * FROM qris_pending WHERE history_id = ?').get(xenditId);
  if (!pending) return;
  const plan = pending.plan;
  const isAnnual = plan === 'annual';
  const isLifetime = plan === 'lifetime';
  const expiresAt = isLifetime ? null : new Date(Date.now() + (isAnnual ? 366 : 31) * 24 * 3600 * 1000).toISOString();
  db.prepare('UPDATE users SET premium = 1, premium_expires = ? WHERE id = ?').run(expiresAt, pending.user_id);
  db.prepare('DELETE FROM qris_pending WHERE history_id = ?').run(xenditId);
  const user = db.prepare('SELECT email FROM users WHERE id = ?').get(pending.user_id);
  console.log(`[xendit] Premium activated: ${user?.email} — ${plan}`);
}

// ── Page Routes (MUST be before /:code) ──
app.get('/upgrade', (req, res) => res.sendFile(path.join(__dirname, 'public', 'upgrade.html')));
app.get('/dashboard/microsite/:slug', (req, res) => res.sendFile(path.join(__dirname, 'public', 'microsite-editor.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── Redirect / Microsite — checks microsites then links (must be LAST route)
app.get('/:code', (req, res) => {
  const code = req.params.code;

  // 1. Check dedicated microsites first
  const micro = db.prepare('SELECT * FROM microsites WHERE slug = ?').get(code);
  if (micro) {
    db.prepare('UPDATE microsites SET clicks = clicks + 1 WHERE id = ?').run(micro.id);
    let components = [];
    try { components = JSON.parse(micro.components || '[]'); } catch {}
    const theme = micro.theme || 'dark';
    const themes = {
      dark:  { bg:'#020617', surface:'#0f172a', border:'#1e293b', accent:'#22c55e', text:'#f8fafc', muted:'#94a3b8', dim:'#475569' },
      light: { bg:'#f8fafc', surface:'#ffffff', border:'#e2e8f0', accent:'#16a34a', text:'#0f172a', muted:'#475569', dim:'#94a3b8' },
      green: { bg:'#022c22', surface:'#064e3b', border:'#065f46', accent:'#22c55e', text:'#f8fafc', muted:'#a7f3d0', dim:'#6ee7b7' },
      blue:  { bg:'#0c1929', surface:'#1e3a5f', border:'#1e3a5f', accent:'#3b82f6', text:'#f8fafc', muted:'#93c5fd', dim:'#60a5fa' },
      minimal:{ bg:'#0a0a0a', surface:'#171717', border:'#404040', accent:'#a3a3a3', text:'#f5f5f5', muted:'#a3a3a3', dim:'#737373' }
    };
    const t = themes[theme] || themes.dark;
    const avatarHTML = micro.avatar ? `<img src="${micro.avatar}" alt="" style="width:72px;height:72px;border-radius:50%;object-fit:cover;margin-bottom:0.75rem;border:2px solid ${t.border}" />` : '';
    const componentsHTML = components.map(c => {
      if (c.kind === 'link') return `<a href="${safeUrl(c.url)}" target="_blank" rel="noopener" class="btn" style="background:${t.surface};border-color:${t.border};color:${t.text}">${c.label || 'Link'}</a>`;
      if (c.kind === 'text') return `<div class="txt" style="color:${t.muted};margin-bottom:0.75rem;line-height:1.6">${c.content || ''}</div>`;
      if (c.kind === 'image') return `<img src="${safeUrl(c.url)}" alt="${c.label || ''}" style="max-width:100%;border-radius:10px;margin-bottom:0.5rem" />`;
      if (c.kind === 'divider') return `<hr style="border:none;border-top:1px solid ${t.border};margin:1rem 0" />`;
      return '';
    }).join('\n');
    const ownerPremium = isPremium(micro.user_id);
    const gaHTML = micro.ga_id ? `<script async src="https://www.googletagmanager.com/gtag/js?id=${micro.ga_id}"></script><script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments)}gtag('js',new Date());gtag('config','${micro.ga_id}')</script>` : '';
    const pixelHTML = micro.fb_pixel_id ? `<script>!function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');fbq('init','${micro.fb_pixel_id}');fbq('track','PageView')</script><noscript><img height="1" width="1" style="display:none" src="https://www.facebook.com/tr?id=${micro.fb_pixel_id}&ev=PageView&noscript=1"/></noscript>` : '';
    const adsenseHTML = (!ownerPremium && ADSENSE_PUB_ID) ? `<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-${ADSENSE_PUB_ID}" crossorigin="anonymous"></script><script>(adsbygoogle=window.adsbygoogle||[]).push({});</script>` : '';
    const footerHTML = ownerPremium ? '' : '<footer>Powered by <a href="https://skip.my.id">Skip My ID</a></footer>';
    return res.send(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/><title>${micro.title} — Skip My ID</title><meta property="og:title" content="${micro.title}"/><meta name="description" content="${micro.description||''}"/>${gaHTML}${pixelHTML}<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Plus Jakarta Sans',-apple-system,sans-serif;background:${t.bg};color:${t.text};min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:2rem}.card{max-width:400px;width:100%;text-align:center}h1{font-size:1.5rem;margin-bottom:0.3rem;font-family:'Space Grotesk',sans-serif}.sub{color:${t.muted};font-size:0.85rem;margin-bottom:1.5rem}.btn{display:block;width:100%;padding:0.75rem;border:1px solid;border-radius:10px;text-decoration:none;font-weight:500;margin-bottom:0.5rem;transition:border-color 0.2s,background 0.2s;font-size:0.9rem}.btn:hover{border-color:${t.accent};background:${t.accent}11}.txt a{color:${t.accent}}footer{position:fixed;bottom:1rem;color:${t.dim};font-size:0.7rem}footer a{color:${t.accent};text-decoration:none}</style></head><body><div class="card">${avatarHTML}<h1>${micro.title}</h1>${micro.description?`<p class="sub">${micro.description}</p>`:''}${componentsHTML}</div>${footerHTML}${adsenseHTML}</body></html>`);
  }

  // 2. Check links (skip expired)
  const link = db.prepare("SELECT * FROM links WHERE code = ? AND (expires_at IS NULL OR expires_at > datetime('now'))").get(code);
  if (!link) return res.redirect('https://skip.my.id');
  // Log click
  db.prepare('INSERT INTO clicks (link_id, referer, ip, ua) VALUES (?, ?, ?, ?)').run(
    link.id, req.get('referer') || '', req.ip || '', req.get('user-agent') || ''
  );
  db.prepare('UPDATE links SET clicks = clicks + 1 WHERE id = ?').run(link.id);

  // Legacy link microsite mode
  if (link.mode === 'microsite') {
    let components = [];
    try { components = JSON.parse(link.microsite_data || '[]'); } catch {}
    const componentsHTML = components.map(c => {
      if (c.kind === 'link') return `<a href="${safeUrl(c.url)}" target="_blank" rel="noopener" class="btn">${c.label || 'Visit'}</a>`;
      if (c.kind === 'text') return `<div style="color:#94a3b8;margin-bottom:0.75rem;line-height:1.6;font-size:0.9rem">${c.content || ''}</div>`;
      if (c.kind === 'image') return `<img src="${safeUrl(c.url)}" alt="${c.label || ''}" style="max-width:100%;border-radius:10px;margin-bottom:0.5rem" />`;
      if (c.kind === 'divider') return '<hr style="border:none;border-top:1px solid #1e293b;margin:1rem 0" />';
      return '';
    }).join('\n');
    const linkOwnerPremium = isPremium(link.user_id);
    const adsenseHTML = (!linkOwnerPremium && ADSENSE_PUB_ID) ? `<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-${ADSENSE_PUB_ID}" crossorigin="anonymous"></script><script>(adsbygoogle=window.adsbygoogle||[]).push({});</script>` : '';
    const footerHTML = linkOwnerPremium ? '' : '<footer>Powered by <a href="https://skip.my.id">Skip My ID</a></footer>';
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
    ${componentsHTML}
  </div>
  ${footerHTML}
  ${adsenseHTML}
</body>
</html>`);
  }
  // Default: redirect
  res.redirect(302, link.url);
});

// QR Code for any link/microsite
app.get('/api/qr/:code', async (req, res) => {
  const url = `https://skip.my.id/${req.params.code}`;
  // Check if owner is premium
  let ownerPremium = false;
  const micro = db.prepare('SELECT user_id FROM microsites WHERE slug = ?').get(req.params.code);
  if (micro) { ownerPremium = isPremium(micro.user_id); } else {
    const link = db.prepare('SELECT user_id FROM links WHERE code = ?').get(req.params.code);
    if (link) ownerPremium = isPremium(link.user_id);
  }
  try {
    const svg = await QRCode.toString(url, { type: 'svg', errorCorrectionLevel: 'H', margin: 2, color: { dark: '#22c55e', light: '#020617' } });
    if (ownerPremium) {
      res.set('Content-Type', 'image/svg+xml');
      res.set('Cache-Control', 'public, max-age=86400');
      return res.send(svg);
    }
    // Free: inject centered branding (viewBox is ~37x37 modules)
    const logo = '<rect x="6" y="14" width="25" height="9" rx="1.5" fill="#020617" stroke="#22c55e" stroke-width="0.8"/><text x="18.5" y="20.5" text-anchor="middle" font-family="sans-serif" font-size="3.2" font-weight="bold" fill="#22c55e">skip.my.id</text>';
    const branded = svg.replace('</svg>', logo + '</svg>');
    res.set('Content-Type', 'image/svg+xml');
    res.set('Cache-Control', 'public, max-age=86400');
    res.send(branded);
  } catch (err) {
    res.status(500).json({ error: 'QR generation failed' });
  }
});

// Check if a custom code is available
app.get('/api/check/:code', (req, res) => {
  const code = req.params.code.toLowerCase().replace(/[^a-z0-9-_]/g, '');
  if (!code || code.length < 2) return res.json({ available: false, reason: 'Min 2 characters' });
  if (['api','dashboard','login','register','admin','help','docs'].includes(code)) {
    return res.json({ available: false, reason: 'Reserved word' });
  }
  const exists = db.prepare('SELECT 1 FROM links WHERE code = ?').get(code)
    || db.prepare('SELECT 1 FROM microsites WHERE slug = ?').get(code);
  res.json({ available: !exists });
});

// ── Health ──
// ── Microsite Routes ──
app.post('/api/microsites/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ url: '/uploads/' + req.file.filename });
});

app.post('/api/microsites', auth, async (req, res) => {
  // Microsites are premium-only
  if (!(await isPremiumAsync(req.userId))) {
    return res.status(402).json({ error: 'Microsites are a premium feature. Upgrade at nerdstudio.online/upgrade', upgradeUrl: 'https://nerdstudio.online/upgrade' });
  }
  const { title, slug, description, components } = req.body || {};
  if (!title) return res.status(400).json({ error: 'Title required' });
  const finalSlug = (slug || title.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 30));
  // Check against links table too
  if (db.prepare('SELECT 1 FROM links WHERE code = ?').get(finalSlug)) {
    return res.status(409).json({ error: 'Slug already taken by an existing short link' });
  }
  // Premium-only: slugs ≤ 4 chars
  if (finalSlug.length <= 4 && !isPremium(req.userId)) {
    return res.status(402).json({ error: 'Short codes (≤4 characters) are for premium members only. Upgrade at nerdstudio.online' });
  }
  try {
    db.prepare('INSERT INTO microsites (user_id, slug, title, description, components) VALUES (?,?,?,?,?)').run(
      req.userId, finalSlug, title, description || '', JSON.stringify(components || [])
    );
    res.json({ ok: true, microsite: { slug: finalSlug, title, url: `https://skip.my.id/${finalSlug}` } });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Slug already taken' });
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/microsites', auth, (req, res) => {
  const sites = db.prepare('SELECT * FROM microsites WHERE user_id = ? ORDER BY created_at DESC').all(req.userId);
  res.json(sites.map(s => ({ ...s, url: `https://skip.my.id/${s.slug}`, components: JSON.parse(s.components || '[]') })));
});

app.put('/api/microsites/:slug', auth, (req, res) => {
  const { title, description, components, newSlug, avatar, theme, ga_id, fb_pixel_id } = req.body || {};
  const site = db.prepare('SELECT * FROM microsites WHERE slug = ? AND user_id = ?').get(req.params.slug, req.userId);
  if (!site) return res.status(404).json({ error: 'Not found' });
  const finalSlug = newSlug || site.slug;
  if (newSlug && newSlug !== site.slug) {
    // Check links table for collision
    if (db.prepare('SELECT 1 FROM links WHERE code = ?').get(finalSlug)) {
      return res.status(409).json({ error: 'Slug already taken by an existing short link' });
    }
    // Premium-only: slugs ≤ 4 chars
    if (finalSlug.length <= 4 && !isPremium(req.userId)) {
      return res.status(402).json({ error: 'Short codes (≤4 characters) are for premium members only. Upgrade at nerdstudio.online' });
    }
  }
  try {
    db.prepare('UPDATE microsites SET title=?, description=?, components=?, slug=?, avatar=?, theme=?, ga_id=?, fb_pixel_id=? WHERE slug=? AND user_id=?').run(
      title || site.title, description || site.description, JSON.stringify(components || JSON.parse(site.components || '[]')),
      finalSlug, avatar !== undefined ? avatar : site.avatar, theme || site.theme || 'dark',
      ga_id !== undefined ? ga_id : site.ga_id, fb_pixel_id !== undefined ? fb_pixel_id : site.fb_pixel_id,
      req.params.slug, req.userId
    );
    res.json({ ok: true });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Slug already taken' });
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/microsites/:slug', auth, (req, res) => {
  db.prepare('DELETE FROM microsites WHERE slug = ? AND user_id = ?').run(req.params.slug, req.userId);
  res.json({ ok: true });
});
// ── Lemon Squeezy webhook ──
app.post('/webhook/ls', (req, res) => {
  res.json({ ok: true }); // ack immediately
  const signature = req.get('X-Signature');
  if (signature && LEMON_SQUEEZY_SECRET) {
    const hmac = crypto.createHmac('sha256', LEMON_SQUEEZY_SECRET);
    const digest = hmac.update(req.rawBody).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(signature))) {
      console.log('[webhook] Invalid signature');
      return;
    }
  }
  const event = req.body;
  const eventName = event?.meta?.event_name;
  if (!eventName) return;
  const email = event.data?.attributes?.user_email;
  const variantName = (event.data?.attributes?.variant_name || '').toLowerCase();
  if (!email) return;
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (!user) { console.log(`[webhook] No user found for ${email}`); return; }

  const grantEvents = ['order_created', 'subscription_created', 'subscription_payment_success', 'subscription_resumed', 'subscription_unpaused', 'subscription_payment_recovered'];
  const revokeEvents = ['subscription_expired', 'subscription_cancelled', 'subscription_payment_refunded', 'order_refunded'];
  const planChangeEvents = ['subscription_updated', 'subscription_plan_changed'];

  if (grantEvents.includes(eventName) || planChangeEvents.includes(eventName)) {
    const isAnnual = variantName.includes('annual') || variantName.includes('year');
    const isLifetime = variantName.includes('lifetime');
    const expiresAt = isLifetime ? null : new Date(Date.now() + (isAnnual ? 366 : 31) * 24 * 3600 * 1000).toISOString();
    db.prepare('UPDATE users SET premium = 1, premium_expires = ? WHERE id = ?').run(expiresAt, user.id);
    console.log(`[webhook] Premium granted: ${email} — ${variantName} (${eventName})`);
  } else if (revokeEvents.includes(eventName)) {
    db.prepare('UPDATE users SET premium = 0, premium_expires = NULL WHERE id = ?').run(user.id);
    console.log(`[webhook] Premium revoked: ${email} (${eventName})`);
  } else {
    console.log(`[webhook] Info: ${email} — ${eventName} (${variantName})`);
  }
});

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

// Serve dashboard SPA
app.listen(PORT, '127.0.0.1', () => console.log(`[shortener] http://127.0.0.1:${PORT}`));
