require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const SESSION_DAYS = Math.max(1, Number(process.env.SESSION_DAYS || 30));
const SESSION_MS = SESSION_DAYS * 86400000;

fs.mkdirSync(DATA_DIR, { recursive: true });
app.set('trust proxy', 1);
app.use(cors({ origin: true, credentials: false }));
app.use(express.json({ limit: '2mb' }));
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

const FILES = {
  users: 'users.json',
  sessions: 'sessions.json',
  posts: 'posts.json',
  messages: 'messages.json',
  keys: 'keys.json',
  claims: 'link_claims.json',
  bannedIps: 'banned_ips.json',
  state: 'server_state.json'
};

const DEFAULTS = {
  users: [],
  sessions: {},
  posts: [],
  messages: [],
  keys: [],
  claims: [],
  bannedIps: [],
  state: { status: 'normal', display: '' }
};

function filePath(name) { return path.join(DATA_DIR, FILES[name]); }
function clone(value) { return JSON.parse(JSON.stringify(value)); }
function read(name) {
  const fallback = DEFAULTS[name];
  try {
    const raw = fs.readFileSync(filePath(name), 'utf8');
    const value = JSON.parse(raw);
    return value ?? clone(fallback);
  } catch {
    return clone(fallback);
  }
}
function write(name, value) {
  const target = filePath(name);
  const tmp = `${target}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), 'utf8');
  fs.renameSync(tmp, target);
}
for (const name of Object.keys(DEFAULTS)) {
  if (!fs.existsSync(filePath(name))) write(name, DEFAULTS[name]);
}

const users = () => read('users');
const sessions = () => read('sessions');
const posts = () => read('posts');
const messages = () => read('messages');
const keys = () => read('keys');
const claims = () => read('claims');
const bannedIps = () => read('bannedIps');
const state = () => read('state');
const save = write;

function publicUser(u) {
  if (!u) return null;
  const { passwordHash, salt, ...safe } = u;
  return safe;
}
function normalizeIp(ip) {
  let x = String(ip || '').trim();
  if (x.startsWith('::ffff:')) x = x.slice(7);
  return x;
}
function requestIp(req) { return normalizeIp(req.ip || req.socket?.remoteAddress || ''); }
function isBannedIp(ip) { return bannedIps().some(x => x.ip === normalizeIp(ip) && x.active !== false); }
function validUrl(v) { return !v || /^https?:\/\//i.test(String(v)); }
function todayVN() { return new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Ho_Chi_Minh' }); }

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, 64, (err, key) => {
      if (err) reject(err); else resolve({ salt, hash: key.toString('hex') });
    });
  });
}
function verifyPassword(password, user) {
  return new Promise((resolve, reject) => {
    if (!user?.salt || !user?.passwordHash) return resolve(false);
    crypto.scrypt(password, user.salt, 64, (err, key) => {
      if (err) return reject(err);
      try {
        const a = Buffer.from(user.passwordHash, 'hex');
        const b = Buffer.from(key);
        resolve(a.length === b.length && crypto.timingSafeEqual(a, b));
      } catch { resolve(false); }
    });
  });
}
function newToken() { return crypto.randomBytes(32).toString('hex'); }

function purgeSessions() {
  const ss = sessions();
  const now = Date.now();
  let changed = false;
  for (const [token, entry] of Object.entries(ss)) {
    const expiresAt = typeof entry === 'string' ? 0 : Number(entry?.expiresAt || 0);
    if ((expiresAt && expiresAt <= now) || !entry) { delete ss[token]; changed = true; }
  }
  if (changed) save('sessions', ss);
  return ss;
}
function createSession(user, ip) {
  const token = newToken();
  const ss = purgeSessions();
  ss[token] = { userId: user.id, createdAt: new Date().toISOString(), lastSeen: new Date().toISOString(), expiresAt: Date.now() + SESSION_MS, ip };
  save('sessions', ss);
  return token;
}
function getAuth(req) {
  const header = String(req.headers.authorization || '');
  if (!header.startsWith('Bearer ')) return { user: null, reason: 'missing' };
  const token = header.slice(7).trim();
  if (!token) return { user: null, reason: 'missing' };
  const ss = purgeSessions();
  const entry = ss[token];
  if (!entry) return { user: null, reason: 'invalid' };
  const userId = typeof entry === 'string' ? entry : entry.userId;
  const expiresAt = typeof entry === 'string' ? 0 : Number(entry.expiresAt || 0);
  if (expiresAt && expiresAt <= Date.now()) { delete ss[token]; save('sessions', ss); return { user: null, reason: 'expired' }; }
  const list = users();
  const user = list.find(x => x.id === userId) || null;
  if (!user) { delete ss[token]; save('sessions', ss); return { user: null, reason: 'invalid' }; }
  if (isBannedIp(requestIp(req))) return { user, reason: 'ip_banned' };
  if (user.banned) return { user, reason: 'banned' };
  if (typeof entry === 'object') {
    entry.lastSeen = new Date().toISOString();
    entry.expiresAt = Date.now() + SESSION_MS;
    ss[token] = entry;
    save('sessions', ss);
  }
  return { user, reason: null };
}
function requireAuth(req, res, next) {
  const a = getAuth(req);
  if (!a.user) return res.status(401).json({ error: a.reason === 'ip_banned' ? 'IP đã bị BAN.' : 'Phiên đăng nhập không hợp lệ. Hãy đăng nhập lại.' });
  if (a.reason === 'ip_banned') return res.status(403).json({ error: 'Thiết bị/mạng này đã bị BAN.' });
  if (a.reason === 'banned') return res.status(403).json({ error: 'Tài khoản đã bị BAN.' });
  req.user = a.user;
  next();
}
function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Chỉ Admin mới được sử dụng chức năng này.' });
    next();
  });
}

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'HOANG MOD', mode: 'shared-node-json', time: new Date().toISOString() }));
app.get('/api/version', (_req, res) => res.json({ name: 'HOANG MOD', version: '2.0.0' }));

app.post('/api/auth/register', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!/^[A-Za-z0-9_.-]{3,12}$/.test(username)) return res.status(400).json({ error: 'Tên tài khoản phải từ 3-12 ký tự, chỉ gồm chữ, số, _, -, .' });
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Email không hợp lệ.' });
    if (password.length < 6) return res.status(400).json({ error: 'Mật khẩu tối thiểu 6 ký tự.' });
    if (isBannedIp(requestIp(req))) return res.status(403).json({ error: 'IP này đã bị BAN.' });
    const list = users();
    if (list.some(u => String(u.email).toLowerCase() === email)) return res.status(409).json({ error: 'Email đã tồn tại.' });
    if (list.some(u => String(u.username).toLowerCase() === username.toLowerCase())) return res.status(409).json({ error: 'Tên tài khoản đã tồn tại.' });
    const h = await hashPassword(password);
    const user = { id: crypto.randomUUID(), username, email, passwordHash: h.hash, salt: h.salt, avatar: '', role: 'user', banned: false, created_at: new Date().toISOString(), last_ip: requestIp(req), dino_best: 0 };
    list.push(user); save('users', list);
    const sessionToken = createSession(user, requestIp(req));
    res.json({ token: sessionToken, user: publicUser(user) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Không tạo được tài khoản.' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (isBannedIp(requestIp(req))) return res.status(403).json({ error: 'IP này đã bị BAN.' });
    const list = users();
    const user = list.find(x => String(x.email).toLowerCase() === email);
    if (!user || !(await verifyPassword(password, user))) return res.status(401).json({ error: 'Email hoặc mật khẩu không đúng.' });
    if (user.banned) return res.status(403).json({ error: 'Tài khoản đã bị BAN.' });
    user.last_ip = requestIp(req); user.last_login = new Date().toISOString(); save('users', list);
    const sessionToken = createSession(user, requestIp(req));
    res.json({ token: sessionToken, user: publicUser(user) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Không đăng nhập được.' }); }
});
app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));
app.post('/api/auth/logout', (req, res) => {
  const h = String(req.headers.authorization || '');
  if (h.startsWith('Bearer ')) { const ss = purgeSessions(); delete ss[h.slice(7).trim()]; save('sessions', ss); }
  res.json({ ok: true });
});
app.post('/api/auth/password', requireAuth, async (req, res) => {
  const password = String(req.body?.password || '');
  if (password.length < 6) return res.status(400).json({ error: 'Mật khẩu tối thiểu 6 ký tự.' });
  const h = await hashPassword(password); const list = users(); const u = list.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'Không tìm thấy tài khoản.' });
  u.passwordHash = h.hash; u.salt = h.salt; save('users', list); res.json({ ok: true });
});
app.post('/api/profile/avatar', requireAuth, (req, res) => {
  const avatar = String(req.body?.avatar || '');
  if (avatar.length > 700000) return res.status(400).json({ error: 'Ảnh quá lớn.' });
  const list = users(); const u = list.find(x => x.id === req.user.id); if (!u) return res.status(404).json({ error: 'Không tìm thấy tài khoản.' });
  u.avatar = avatar; save('users', list); res.json({ user: publicUser(u) });
});

app.get('/api/public/users', (_req, res) => {
  const list = users().map(publicUser).map(u => ({ id: u.id, username: u.username, avatar: u.avatar || '', role: u.role || 'user', banned: !!u.banned, created_at: u.created_at }));
  res.json({ users: list });
});
app.get('/api/admin/users', requireAdmin, (_req, res) => res.json({ users: users().map(publicUser) }));
app.post('/api/admin/users/:id/ban', requireAdmin, (req, res) => {
  const list = users(); const u = list.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'Không tìm thấy user.' });
  if (u.id === req.user.id) return res.status(400).json({ error: 'Không thể tự BAN chính mình.' });
  u.banned = !!req.body?.banned; save('users', list); res.json({ user: publicUser(u) });
});
app.post('/api/admin/users/:id/role', requireAdmin, (req, res) => {
  const role = String(req.body?.role || 'user');
  if (!['user', 'admin', 'free_fire', 'free_fire_max'].includes(role)) return res.status(400).json({ error: 'Role không hợp lệ.' });
  const list = users(); const u = list.find(x => x.id === req.params.id); if (!u) return res.status(404).json({ error: 'Không tìm thấy user.' });
  u.role = role; save('users', list); res.json({ user: publicUser(u) });
});
app.post('/api/admin/ban-ip', requireAdmin, (req, res) => {
  const ip = normalizeIp(req.body?.ip); if (!ip) return res.status(400).json({ error: 'Thiếu IP.' });
  const list = bannedIps(); if (!list.some(x => x.ip === ip)) list.push({ ip, active: true, created_at: new Date().toISOString(), created_by: req.user.id }); else list.forEach(x => { if (x.ip === ip) x.active = true; });
  save('bannedIps', list); const us = users(); us.forEach(u => { if (normalizeIp(u.last_ip) === ip) u.banned = true; }); save('users', us); res.json({ ok: true, ip });
});
app.post('/api/admin/unban-ip', requireAdmin, (req, res) => {
  const ip = normalizeIp(req.body?.ip); if (!ip) return res.status(400).json({ error: 'Thiếu IP.' });
  const list = bannedIps(); list.forEach(x => { if (x.ip === ip) x.active = false; }); save('bannedIps', list); res.json({ ok: true, ip });
});
app.get('/api/admin/banned-ips', requireAdmin, (_req, res) => res.json({ ips: bannedIps().filter(x => x.active !== false) }));

app.get('/api/posts', (_req, res) => {
  const publicPosts = posts().filter(p => p.active !== false).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).map(p => ({ id: p.id, title: p.title, tag: p.tag, image_url: p.image_url, button_text: p.button_text, hot: !!p.hot, created_at: p.created_at, can_claim: !!p.link }));
  res.json({ posts: publicPosts });
});
app.get('/api/admin/posts', requireAdmin, (_req, res) => res.json({ posts: posts() }));
app.post('/api/admin/posts', requireAdmin, (req, res) => {
  const p = req.body || {}; const title = String(p.title || '').trim(); const link = String(p.link || '').trim();
  if (!title) return res.status(400).json({ error: 'Thiếu tiêu đề.' });
  if (!validUrl(link)) return res.status(400).json({ error: 'Link không hợp lệ.' });
  const list = posts(); const item = { id: crypto.randomUUID(), title: title.slice(0, 80), tag: String(p.tag || '').slice(0, 24), link, image_url: String(p.image_url || ''), button_text: String(p.button_text || '👑 LẤY FREE').slice(0, 30), hot: !!p.hot, active: true, created_by: req.user.id, created_at: new Date().toISOString() };
  list.push(item); save('posts', list); res.json({ post: item });
});
app.post('/api/admin/posts/:id/toggle', requireAdmin, (req, res) => {
  const list = posts(); const p = list.find(x => x.id === req.params.id); if (!p) return res.status(404).json({ error: 'Không tìm thấy bài.' });
  p.active = !!req.body?.active; save('posts', list); res.json({ post: p });
});
app.delete('/api/admin/posts/:id', requireAdmin, (req, res) => {
  const list = posts(); const next = list.filter(x => x.id !== req.params.id); if (next.length === list.length) return res.status(404).json({ error: 'Không tìm thấy bài.' });
  save('posts', next); res.json({ ok: true });
});
app.post('/api/posts/:id/claim', requireAuth, (req, res) => {
  if (state().status !== 'normal') return res.status(503).json({ error: state().display || 'Server đang tạm đóng.' });
  const p = posts().find(x => x.id === req.params.id && x.active !== false);
  if (!p || !p.link) return res.status(404).json({ error: 'Link không tồn tại.' });
  const list = claims(); const record = { id: crypto.randomUUID(), post_id: p.id, post_title: p.title, user_id: req.user.id, username: req.user.username, link: p.link, ip: requestIp(req), created_at: new Date().toISOString() };
  list.push(record); save('claims', list.slice(-5000));
  res.json({ ok: true, link: p.link, record: { username: record.username, post_title: record.post_title, created_at: record.created_at } });
});
app.get('/api/admin/claims', requireAdmin, (_req, res) => res.json({ claims: claims().slice(-500).reverse() }));

app.get('/api/chat', requireAuth, (_req, res) => res.json({ messages: messages().slice(-200) }));
app.post('/api/chat', requireAuth, (req, res) => {
  const message = String(req.body?.message || '').trim(); const image = String(req.body?.image_url || '');
  if (message.length > 500) return res.status(400).json({ error: 'Tin nhắn tối đa 500 ký tự.' });
  if (!message && !image) return res.status(400).json({ error: 'Tin nhắn trống.' });
  if (image.length > 1400000) return res.status(400).json({ error: 'Ảnh quá lớn.' });
  const list = messages(); const item = { id: crypto.randomUUID(), user_id: req.user.id, username: req.user.username, avatar: req.user.avatar || '', message, image_url: image, created_at: new Date().toISOString() };
  list.push(item); save('messages', list.slice(-1000)); res.json({ message: item });
});
app.get('/api/admin/chat', requireAdmin, (_req, res) => res.json({ messages: messages().slice(-100) }));
app.post('/api/admin/broadcast', requireAdmin, (req, res) => {
  const message = String(req.body?.message || '').trim(); if (!message) return res.status(400).json({ error: 'Thông báo trống.' });
  const list = messages(); list.push({ id: crypto.randomUUID(), user_id: req.user.id, username: 'Admin', avatar: req.user.avatar || '', message: '📢 ' + message.slice(0, 500), image_url: '', created_at: new Date().toISOString() }); save('messages', list.slice(-1000)); res.json({ ok: true });
});

app.get('/api/keys', requireAdmin, (_req, res) => res.json({ keys: keys() }));
app.post('/api/admin/keys', requireAdmin, (req, res) => {
  const key = String(req.body?.key || '').trim(); const date = String(req.body?.date || '').trim(); const limit = Math.max(1, Math.min(100000, Number(req.body?.limit || 1)));
  if (!key || !date) return res.status(400).json({ error: 'Thiếu KEY hoặc ngày.' });
  const list = keys(); if (list.some(k => k.key === key)) return res.status(409).json({ error: 'KEY đã tồn tại.' });
  const item = { id: crypto.randomUUID(), key, date, limit, used: 0, active: true, claims: [], created_at: new Date().toISOString() }; list.push(item); save('keys', list); res.json({ key: item });
});
app.post('/api/admin/keys/:id/toggle', requireAdmin, (req, res) => {
  const list = keys(); const k = list.find(x => x.id === req.params.id); if (!k) return res.status(404).json({ error: 'Không tìm thấy KEY.' });
  k.active = !k.active; save('keys', list); res.json({ key: k });
});
app.post('/api/claim-key', requireAuth, (req, res) => {
  if (state().status !== 'normal') return res.status(503).json({ error: state().display || 'Server đang tạm đóng.' });
  const date = todayVN(); const list = keys();
  for (const k of list) {
    k.claims = Array.isArray(k.claims) ? k.claims : [];
    if (k.claims.some(c => c.user_id === req.user.id && c.date === date)) return res.status(409).json({ error: 'Bạn đã nhận KEY hôm nay.' });
  }
  const k = list.find(x => x.date === date && x.active && Number(x.used || 0) < Number(x.limit || 1));
  if (!k) return res.status(404).json({ error: 'Hôm nay chưa có KEY hoặc KEY đã hết lượt.' });
  k.used = Number(k.used || 0) + 1; k.claims.push({ user_id: req.user.id, username: req.user.username, date, created_at: new Date().toISOString() }); save('keys', list);
  res.json({ key: k.key });
});

app.get('/api/game/dino/leaderboard', (_req, res) => {
  const list = users().filter(u => Number(u.dino_best || 0) > 0).map(u => ({ username: u.username, score: Number(u.dino_best || 0), role: u.role || 'user' })).sort((a, b) => b.score - a.score || a.username.localeCompare(b.username)).slice(0, 50);
  res.json({ scores: list });
});
app.post('/api/game/dino/score', requireAuth, (req, res) => {
  const score = Math.floor(Number(req.body?.score));
  if (!Number.isFinite(score) || score < 0 || score > 100000) return res.status(400).json({ error: 'Điểm không hợp lệ.' });
  const list = users(); const u = list.find(x => x.id === req.user.id); if (!u) return res.status(404).json({ error: 'Không tìm thấy tài khoản.' });
  if (score > Number(u.dino_best || 0)) { u.dino_best = score; u.dino_best_at = new Date().toISOString(); save('users', list); }
  res.json({ ok: true, best: Number(u.dino_best || 0) });
});

app.get('/api/state', (_req, res) => res.json(state()));
app.post('/api/admin/state', requireAdmin, (req, res) => {
  const status = ['normal', 'maintenance', 'closed'].includes(String(req.body?.status)) ? String(req.body.status) : 'normal';
  const value = { status, display: String(req.body?.display || '').slice(0, 300) }; save('state', value); res.json(value);
});
app.get('/api/stats', (_req, res) => {
  const us = users(); const ks = keys(); const ss = purgeSessions(); const cutoff = Date.now() - 120000;
  const onlineIds = new Set(Object.values(ss).filter(x => typeof x === 'object' && Number(x.lastSeen ? new Date(x.lastSeen).getTime() : 0) >= cutoff).map(x => x.userId));
  res.json({ users: us.length, banned: us.filter(u => u.banned).length, keys: ks.filter(k => k.active).length, online: onlineIds.size });
});

async function ensureAdminFromEnv() {
  const email = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const password = String(process.env.ADMIN_PASSWORD || '');
  if (!email || password.length < 6) return;
  const list = users(); let u = list.find(x => String(x.email).toLowerCase() === email);
  if (u) {
    u.role = 'admin'; u.banned = false;
    if (!u.passwordHash || process.env.RESET_ADMIN_PASSWORD === 'true') { const h = await hashPassword(password); u.passwordHash = h.hash; u.salt = h.salt; }
    save('users', list); return;
  }
  const h = await hashPassword(password);
  u = { id: crypto.randomUUID(), username: String(process.env.ADMIN_USERNAME || 'admin').replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 12) || 'admin', email, passwordHash: h.hash, salt: h.salt, avatar: '', role: 'admin', banned: false, created_at: new Date().toISOString(), last_ip: '', dino_best: 0 };
  list.push(u); save('users', list);
  console.log('Admin account initialized from environment.');
}

app.use(express.static(__dirname, { extensions: ['html'] }));
app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'API endpoint không tồn tại.' });
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ error: 'Internal server error' }); });

ensureAdminFromEnv().then(() => {
  app.listen(PORT, '0.0.0.0', () => console.log(`HOANG MOD server listening on 0.0.0.0:${PORT}`));
}).catch(err => { console.error('Startup failed:', err); process.exit(1); });
