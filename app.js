'use strict';
/*
  Digital Amplifyr Manager - secure backend (single Vercel serverless function)
  - Accounts exist ONLY on the server. There is no public sign-up of any kind.
  - Only an admin can create / update / delete users.
  - Every data endpoint requires a signed session token.
  - The first admin is created from the ADMIN_USERNAME / ADMIN_PASSWORD environment variables
    (set by the owner in the Vercel dashboard) - never from the browser.
*/
const crypto = require('crypto');

const env = () => ({
  url: (process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '').replace(/\/$/, ''),
  tok: process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '',
  secret: process.env.SESSION_SECRET || ''
});
const ITER = 150000;            // same PBKDF2 settings the app always used
const SESSION_SECONDS = 12 * 3600;

/* ---------- storage (Upstash / Vercel KV via REST) ---------- */
async function kv(cmd) {
  const e = env();
  const r = await fetch(e.url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + e.tok, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd)
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok || d.error) throw new Error('kv');
  return d.result;
}

/* ---------- crypto helpers ---------- */
const hashPw = (pw, saltHex) => new Promise((res, rej) =>
  crypto.pbkdf2(String(pw), Buffer.from(saltHex, 'hex'), ITER, 32, 'sha256', (e, k) => e ? rej(e) : res(k.toString('hex'))));
const rnd = n => crypto.randomBytes(n).toString('hex');
const safeEq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const norm = x => String(x || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
function genCode() {
  const a = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789', r = crypto.randomBytes(16);
  let x = ''; for (const v of r) x += a[v % a.length];
  return x.match(/.{4}/g).join('-');
}
function sign(payload) {
  const b = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return b + '.' + crypto.createHmac('sha256', env().secret).update(b).digest('base64url');
}
function verify(token) {
  if (!token || typeof token !== 'string' || token.indexOf('.') < 0) return null;
  const [b, s] = token.split('.');
  const good = crypto.createHmac('sha256', env().secret).update(b).digest('base64url');
  if (!safeEq(s, good)) return null;
  try {
    const p = JSON.parse(Buffer.from(b, 'base64url').toString());
    return p && p.exp > Date.now() / 1000 ? p : null;
  } catch (e) { return null; }
}
const tokenFor = u => sign({ u: u.u, r: u.role, v: u.hash.slice(0, 16), exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS });
const pub = u => ({ u: u.u, role: u.role });

/* ---------- users ---------- */
async function getUsers() {
  const raw = await kv(['GET', 'da:users']);
  if (raw) { try { return JSON.parse(raw); } catch (e) { return []; } }
  // First start only: create the owner's admin from environment variables.
  const au = (process.env.ADMIN_USERNAME || '').trim(), ap = process.env.ADMIN_PASSWORD || '';
  if (au && ap.length >= 6) {
    const salt = rnd(16);
    const users = [{ u: au, salt, hash: await hashPw(ap, salt), role: 'admin' }];
    await kv(['SET', 'da:users', JSON.stringify(users), 'NX']);
    try { return JSON.parse(await kv(['GET', 'da:users'])); } catch (e) { return users; }
  }
  return [];
}
const saveUsers = users => kv(['SET', 'da:users', JSON.stringify(users)]);
const findUser = (users, name) => users.find(x => String(x.u).toLowerCase() === String(name || '').trim().toLowerCase());
function authed(req, users) {
  const h = req.headers.authorization || '';
  const p = verify(h.startsWith('Bearer ') ? h.slice(7) : '');
  if (!p) return null;
  const me = users.find(x => x.u === p.u);
  // password change / role change / deletion instantly invalidates old sessions
  return me && me.role === p.r && me.hash.slice(0, 16) === p.v ? me : null;
}

/* ---------- rate limiting ---------- */
async function limited(key, max, seconds) {
  const n = await kv(['INCR', key]);
  if (n === 1) await kv(['EXPIRE', key, String(seconds)]);
  return n > max;
}

/* ---------- helpers ---------- */
const str = (v, max) => (typeof v === 'string' ? v : '').slice(0, max);
const validOrder = o => o && typeof o === 'object' && !Array.isArray(o) && typeof o.id === 'string' &&
  o.id.length > 0 && o.id.length <= 64 && JSON.stringify(o).length <= 300000;
function send(res, code, obj) { res.status(code).setHeader('Cache-Control', 'no-store'); res.json(obj); }

module.exports = async function handler(req, res) {
  try {
    if (req.method !== 'POST') return send(res, 405, { error: 'method' });
    const e = env();
    if (!e.url || !e.tok || e.secret.length < 16) return send(res, 500, { error: 'not-configured' });
    let b = req.body;
    if (typeof b === 'string') { try { b = JSON.parse(b); } catch (x) { b = null; } }
    if (!b || typeof b !== 'object') return send(res, 400, { error: 'bad' });
    const a = b.a;
    const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'ip').split(',')[0].trim();
    const users = await getUsers();

    /* ----- public: login ----- */
    if (a === 'login') {
      const name = str(b.u, 80).trim(), pw = str(b.p, 200);
      if (await limited('da:rl:ip:' + ip, 60, 900) || await limited('da:rl:l:' + ip + ':' + name.toLowerCase(), 8, 900))
        return send(res, 429, { error: 'wait' });
      const me = findUser(users, name);
      const h = await hashPw(pw, me ? me.salt : '00'.repeat(16));
      if (!me || !safeEq(h, me.hash)) return send(res, 401, { error: 'bad' });
      await kv(['DEL', 'da:rl:l:' + ip + ':' + name.toLowerCase()]);
      return send(res, 200, { token: tokenFor(me), user: pub(me) });
    }

    /* ----- public: forgot password with recovery code ----- */
    if (a === 'forgot') {
      const name = str(b.u, 80).trim(), pw = str(b.p, 200);
      if (await limited('da:rl:f:' + ip + ':' + name.toLowerCase(), 5, 900)) return send(res, 429, { error: 'wait' });
      if (pw.length < 6) return send(res, 400, { error: 'short' });
      const me = findUser(users, name);
      if (me && !me.rh) return send(res, 400, { error: 'norec' });
      const h = await hashPw(norm(b.code), me ? me.rs : '00'.repeat(16));
      if (!me || !safeEq(h, me.rh)) return send(res, 401, { error: 'bad' });
      const salt = rnd(16), code = genCode(), rs = rnd(16);
      const nu = Object.assign({}, me, { salt, hash: await hashPw(pw, salt), rs, rh: await hashPw(norm(code), rs) });
      await saveUsers(users.map(x => x === me ? nu : x));
      return send(res, 200, { token: tokenFor(nu), user: pub(nu), code });
    }

    /* ----- everything below needs a valid login ----- */
    const me = authed(req, users);
    if (!me) return send(res, 401, { error: 'auth' });
    const isAdmin = me.role === 'admin';

    switch (a) {
      case 'me': return send(res, 200, { user: pub(me) });

      case 'load': {
        const flat = await kv(['HGETALL', 'da:orders']);
        const orders = [];
        if (Array.isArray(flat)) for (let i = 1; i < flat.length; i += 2) { try { orders.push(JSON.parse(flat[i])); } catch (x) {} }
        else if (flat && typeof flat === 'object') for (const v of Object.values(flat)) { try { orders.push(JSON.parse(v)); } catch (x) {} }
        let cfg = {}; try { cfg = JSON.parse(await kv(['GET', 'da:cfg']) || '{}'); } catch (x) {}
        return send(res, 200, { orders, cfg });
      }

      case 'put': {
        if (!validOrder(b.order)) return send(res, 400, { error: 'bad' });
        await kv(['HSET', 'da:orders', b.order.id, JSON.stringify(b.order)]);
        return send(res, 200, { ok: 1 });
      }

      case 'del': {
        await kv(['HDEL', 'da:orders', str(b.id, 64)]);
        return send(res, 200, { ok: 1 });
      }

      case 'putmany': {
        if (!isAdmin) return send(res, 403, { error: 'admin' });
        const arr = Array.isArray(b.orders) ? b.orders.slice(0, 100) : [];
        if (!arr.length || !arr.every(validOrder)) return send(res, 400, { error: 'bad' });
        const cmd = ['HSET', 'da:orders'];
        arr.forEach(o => { cmd.push(o.id, JSON.stringify(o)); });
        await kv(cmd);
        return send(res, 200, { ok: arr.length });
      }

      case 'savecfg': {
        if (!b.cfg || typeof b.cfg !== 'object' || Array.isArray(b.cfg)) return send(res, 400, { error: 'bad' });
        let next = b.cfg;
        if (!isAdmin) { // staff may only add sectors
          let cur = {}; try { cur = JSON.parse(await kv(['GET', 'da:cfg']) || '{}'); } catch (x) {}
          next = Object.assign({}, cur, { sectors: Array.isArray(b.cfg.sectors) ? b.cfg.sectors.slice(0, 200).map(s => str(s, 80)) : cur.sectors });
        }
        const js = JSON.stringify(next);
        if (js.length > 900000) return send(res, 413, { error: 'big' });
        await kv(['SET', 'da:cfg', js]);
        return send(res, 200, { ok: 1 });
      }

      case 'changepw': {
        const pw = str(b.p, 200);
        if (pw.length < 6) return send(res, 400, { error: 'short' });
        if (await limited('da:rl:c:' + me.u.toLowerCase(), 10, 900)) return send(res, 429, { error: 'wait' });
        if (!safeEq(await hashPw(str(b.old, 200), me.salt), me.hash)) return send(res, 403, { error: 'badold' });
        const salt = rnd(16), nu = Object.assign({}, me, { salt, hash: await hashPw(pw, salt) });
        await saveUsers(users.map(x => x === me ? nu : x));
        return send(res, 200, { token: tokenFor(nu) });
      }

      case 'recgen': {
        if (await limited('da:rl:c:' + me.u.toLowerCase(), 10, 900)) return send(res, 429, { error: 'wait' });
        if (!safeEq(await hashPw(str(b.old, 200), me.salt), me.hash)) return send(res, 403, { error: 'badold' });
        const code = genCode(), rs = rnd(16);
        const nu = Object.assign({}, me, { rs, rh: await hashPw(norm(code), rs) });
        await saveUsers(users.map(x => x === me ? nu : x));
        return send(res, 200, { code });
      }

      /* ----- admin only: user management ----- */
      case 'users':
        if (!isAdmin) return send(res, 403, { error: 'admin' });
        return send(res, 200, { users: users.map(pub) });

      case 'adduser': {
        if (!isAdmin) return send(res, 403, { error: 'admin' });
        const name = str(b.u, 40).trim(), pw = str(b.p, 200);
        const role = b.role === 'admin' ? 'admin' : 'staff';
        if (!name || /[\u0000-\u001f]/.test(name)) return send(res, 400, { error: 'name' });
        if (pw.length < 6) return send(res, 400, { error: 'short' });
        const ex = findUser(users, name), salt = rnd(16);
        const nu = { u: ex ? ex.u : name, salt, hash: await hashPw(pw, salt), role: ex && ex.u === me.u ? me.role : role };
        if (ex && ex.rs) { nu.rs = ex.rs; nu.rh = ex.rh; }
        const list = ex ? users.map(x => x === ex ? nu : x) : users.concat([nu]);
        if (!list.some(x => x.role === 'admin')) return send(res, 400, { error: 'lastadmin' });
        await saveUsers(list);
        return send(res, 200, { users: list.map(pub), token: ex && ex.u === me.u ? tokenFor(nu) : undefined });
      }

      case 'deluser': {
        if (!isAdmin) return send(res, 403, { error: 'admin' });
        const target = str(b.u, 80);
        if (target === me.u) return send(res, 400, { error: 'self' });
        const list = users.filter(x => x.u !== target);
        if (!list.some(x => x.role === 'admin')) return send(res, 400, { error: 'lastadmin' });
        await saveUsers(list);
        return send(res, 200, { users: list.map(pub) });
      }

      default: return send(res, 400, { error: 'bad' });
    }
  } catch (err) {
    return send(res, 500, { error: 'server' });
  }
};
