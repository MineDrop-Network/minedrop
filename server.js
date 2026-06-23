const express = require('express');
const session = require('express-session');
const bcrypt  = require('bcryptjs');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

const DATA_FILE  = path.join(__dirname, 'data', 'content.json');
const ADMIN_FILE = path.join(__dirname, 'data', 'admin.json');

/* ─── helpers ─────────────────────────────────────────── */
function readData()       { return JSON.parse(fs.readFileSync(DATA_FILE,  'utf8')); }
function readAdmin()      { return JSON.parse(fs.readFileSync(ADMIN_FILE, 'utf8')); }
function writeData(data)  { fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2)); }
function writeAdmin(data) { fs.writeFileSync(ADMIN_FILE, JSON.stringify(data, null, 2)); }
function uid()            { return Date.now().toString(36) + Math.random().toString(36).slice(2, 6); }

/* ─── middleware ───────────────────────────────────────── */
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'minedrop-super-secret-key-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 8 * 60 * 60 * 1000 } // 8h
}));

// Serve static files (html pages)
app.use(express.static(path.join(__dirname, 'public')));

/* ─── auth guard ───────────────────────────────────────── */
function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

/* ═══════════════════════════════════════════════════════
   AUTH ROUTES
═══════════════════════════════════════════════════════ */

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

  const admin = readAdmin();
  if (username !== admin.username) return res.status(401).json({ error: 'Invalid credentials' });

  const match = await bcrypt.compare(password, admin.passwordHash);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });

  req.session.authenticated = true;
  req.session.username = username;
  res.json({ ok: true, username });
});

// POST /api/auth/logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

// GET /api/auth/me  — lets the frontend check if still logged in
app.get('/api/auth/me', (req, res) => {
  if (req.session && req.session.authenticated) {
    res.json({ authenticated: true, username: req.session.username });
  } else {
    res.json({ authenticated: false });
  }
});

// POST /api/auth/change-password  (requires login)
app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Missing fields' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const admin = readAdmin();
  const match = await bcrypt.compare(currentPassword, admin.passwordHash);
  if (!match) return res.status(401).json({ error: 'Current password is wrong' });

  admin.passwordHash = await bcrypt.hash(newPassword, 10);
  writeAdmin(admin);
  res.json({ ok: true });
});

/* ═══════════════════════════════════════════════════════
   PUBLIC READ ROUTES  (no auth required)
═══════════════════════════════════════════════════════ */

// GET /api/categories
app.get('/api/categories', (req, res) => {
  res.json(readData().categories || []);
});

// GET /api/products
app.get('/api/products', (req, res) => {
  const data = readData();
  res.json(data.products.filter(p => p.visible));
});

// GET /api/news
app.get('/api/news', (req, res) => {
  const data = readData();
  res.json([...(data.news || [])].reverse()); // newest first
});

// GET /api/nav
app.get('/api/nav', (req, res) => {
  res.json(readData().nav || []);
});

// GET /api/ticker
app.get('/api/ticker', (req, res) => {
  res.json(readData().ticker || {});
});

// GET /api/hero/:page
app.get('/api/hero/:page', (req, res) => {
  const data = readData();
  const hero = (data.hero || {})[req.params.page];
  if (!hero) return res.status(404).json({ error: 'Not found' });
  res.json(hero);
});

/* ── ANNOUNCEMENT (Public) ── */
app.get('/api/announcement', (req, res) => {
  res.json(readData().announcement || {});
});

/* ── SIDEBAR (Public) ── */
app.get('/api/sidebar', (req, res) => {
  res.json(readData().sidebar || {});
});

/* ═══════════════════════════════════════════════════════
   ADMIN ROUTES  (all require auth)
═══════════════════════════════════════════════════════ */

// GET /api/admin/all  — full data dump for admin panel
app.get('/api/admin/all', requireAuth, (req, res) => {
  res.json(readData());
});

/* ── CATEGORIES ── */
app.post('/api/admin/categories', requireAuth, (req, res) => {
  const data = readData();
  if (!data.categories) data.categories = [];
  const c = { id: 'cat-' + uid(), name: 'New Category', icon: '📦', ...req.body };
  c.id = 'cat-' + uid(); // ensure unique id
  data.categories.push(c);
  writeData(data);
  res.json(c);
});

app.put('/api/admin/categories/:id', requireAuth, (req, res) => {
  const data = readData();
  const idx = (data.categories || []).findIndex(c => c.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  data.categories[idx] = { ...data.categories[idx], ...req.body, id: req.params.id };
  writeData(data);
  res.json(data.categories[idx]);
});

app.delete('/api/admin/categories/:id', requireAuth, (req, res) => {
  const data = readData();
  const before = (data.categories || []).length;
  data.categories = (data.categories || []).filter(c => c.id !== req.params.id);
  if (data.categories.length === before) return res.status(404).json({ error: 'Not found' });
  writeData(data);
  res.json({ ok: true });
});

/* ── PRODUCTS ── */
app.post('/api/admin/products', requireAuth, (req, res) => {
  const data = readData();
  if (!data.products) data.products = [];
  const p = { id: 'p' + uid(), name: 'New Product', desc: 'Describe this item.', price: '0.00', emoji: '🎯', accent: '#C8FF00', soon: true, visible: true, category: '', ...req.body };
  p.id = 'p' + uid();
  data.products.push(p);
  writeData(data);
  res.json(p);
});

app.put('/api/admin/products/:id', requireAuth, (req, res) => {
  const data = readData();
  const idx  = (data.products || []).findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  data.products[idx] = { ...data.products[idx], ...req.body, id: req.params.id };
  writeData(data);
  res.json(data.products[idx]);
});

app.delete('/api/admin/products/:id', requireAuth, (req, res) => {
  const data = readData();
  const before = (data.products || []).length;
  data.products = (data.products || []).filter(p => p.id !== req.params.id);
  if (data.products.length === before) return res.status(404).json({ error: 'Not found' });
  writeData(data);
  res.json({ ok: true });
});

/* ── NEWS ── */
app.post('/api/admin/news', requireAuth, (req, res) => {
  const data = readData();
  if (!data.news) data.news = [];
  const n = { id: 'n' + uid(), title: 'New Post', tag: 'ANNOUNCEMENT', date: new Date().toISOString().slice(0,10), desc: 'Write your post here.', ...req.body };
  n.id = 'n' + uid();
  data.news.push(n);
  writeData(data);
  res.json(n);
});

app.put('/api/admin/news/:id', requireAuth, (req, res) => {
  const data = readData();
  const idx  = (data.news || []).findIndex(n => n.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  data.news[idx] = { ...data.news[idx], ...req.body, id: req.params.id };
  writeData(data);
  res.json(data.news[idx]);
});

app.delete('/api/admin/news/:id', requireAuth, (req, res) => {
  const data = readData();
  data.news = (data.news || []).filter(n => n.id !== req.params.id);
  writeData(data);
  res.json({ ok: true });
});

/* ── NAV ── */
app.put('/api/admin/nav', requireAuth, (req, res) => {
  const data = readData();
  data.nav = req.body;
  writeData(data);
  res.json(data.nav);
});

/* ── TICKER ── */
app.put('/api/admin/ticker', requireAuth, (req, res) => {
  const data = readData();
  data.ticker = { ...data.ticker, ...req.body };
  writeData(data);
  res.json(data.ticker);
});

/* ── HERO ── */
app.put('/api/admin/hero/:page', requireAuth, (req, res) => {
  const data = readData();
  if (!data.hero) data.hero = {};
  if (!data.hero[req.params.page]) data.hero[req.params.page] = {};
  data.hero[req.params.page] = { ...data.hero[req.params.page], ...req.body };
  writeData(data);
  res.json(data.hero[req.params.page]);
});

/* ── ANNOUNCEMENT ── */
app.put('/api/admin/announcement', requireAuth, (req, res) => {
  const data = readData();
  data.announcement = { ...data.announcement, ...req.body };
  writeData(data);
  res.json(data.announcement);
});

/* ── SIDEBAR CONFIG ── */
app.put('/api/admin/sidebar', requireAuth, (req, res) => {
  const data = readData();
  data.sidebar = { ...data.sidebar, ...req.body };
  writeData(data);
  res.json(data.sidebar);
});

/* ── SETTINGS ── */
app.put('/api/admin/settings', requireAuth, (req, res) => {
  const data = readData();
  data.settings = { ...data.settings, ...req.body };
  writeData(data);
  res.json(data.settings);
});

/* ─── start ────────────────────────────────────────────── */
app.listen(PORT, () => {
  console.log(`✅ MineDrop server running at http://localhost:${PORT}`);
  console.log(`   Admin panel: http://localhost:${PORT}/admin.html`);
});