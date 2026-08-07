/**
 * Excalibur account service.
 *
 * Deployed as its own Worker (excalibur-auth) so it can never disturb
 * excalibur-cigar-proxy, which serves the cigar-notes feature.
 *
 * Endpoints:
 *   POST /auth/register  {name, email, password} -> {token, user}
 *   POST /auth/login     {email, password}       -> {token, user}
 *   POST /auth/logout    (Bearer token)          -> {ok:true}
 *   GET  /auth/me        (Bearer token)          -> {user}
 *
 * Passwords: PBKDF2-SHA256, per-user 16-byte salt, iteration count stored
 *            per user so it can be raised without invalidating passwords.
 * Sessions:  32 random bytes returned to the client; only the SHA-256 hash
 *            is stored, so a database dump does not yield usable sessions.
 */

// Workers caps PBKDF2 iterations well below the OWASP figure for servers.
// The per-user count is stored in the users table, so this can be raised
// later without invalidating existing passwords.
const PBKDF2_ITERATIONS = 100000;
const SESSION_DAYS = 30;
const MAX_FAILED_ATTEMPTS = 8;
const ATTEMPT_WINDOW_MIN = 15;

/* ── helpers ── */

const enc = new TextEncoder();

function bufToHex(buf){
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomHex(bytes){
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return bufToHex(a);
}

async function sha256Hex(str){
  return bufToHex(await crypto.subtle.digest('SHA-256', enc.encode(str)));
}

async function hashPassword(password, saltHex, iterations){
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const salt = Uint8Array.from(saltHex.match(/../g).map(h => parseInt(h, 16)));
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    key,
    256
  );
  return bufToHex(bits);
}

/** Constant-time comparison so timing cannot reveal how much of a hash matched. */
function timingSafeEqual(a, b){
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function corsHeaders(request, env){
  const allowed = (env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  const origin = request.headers.get('Origin') || '';
  const ok = allowed.includes(origin);
  return {
    'Access-Control-Allow-Origin': ok ? origin : allowed[0] || '',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}

function json(data, status, request, env){
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(request, env) }
  });
}

function normalizeEmail(email){
  return String(email || '').trim().toLowerCase();
}

function validEmail(email){
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) && email.length <= 160;
}

function bearer(request){
  const h = request.headers.get('Authorization') || '';
  return h.startsWith('Bearer ') ? h.slice(7).trim() : null;
}

async function currentUser(request, env){
  const token = bearer(request);
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT u.id, u.name, u.email, u.role, s.expires_at
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?`
  ).bind(await sha256Hex(token)).first();
  if (!row) return null;
  if (Date.parse(row.expires_at) < Date.now()){
    await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?')
      .bind(await sha256Hex(token)).run();
    return null;
  }
  return { id: row.id, name: row.name, email: row.email, role: row.role };
}

async function createSession(env, userId){
  const token = randomHex(32);
  const expires = new Date(Date.now() + SESSION_DAYS * 86400000).toISOString();
  await env.DB.prepare(
    'INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)'
  ).bind(await sha256Hex(token), userId, expires, new Date().toISOString()).run();
  return token;
}

/** Throttle by email+IP so a single account cannot be hammered. */
async function tooManyAttempts(env, key){
  const since = new Date(Date.now() - ATTEMPT_WINDOW_MIN * 60000).toISOString();
  const row = await env.DB.prepare(
    'SELECT COUNT(*) AS n FROM login_attempts WHERE key = ? AND created_at > ?'
  ).bind(key, since).first();
  return (row?.n || 0) >= MAX_FAILED_ATTEMPTS;
}

async function recordAttempt(env, key){
  await env.DB.prepare('INSERT INTO login_attempts (key, created_at) VALUES (?, ?)')
    .bind(key, new Date().toISOString()).run();
}

async function clearAttempts(env, key){
  await env.DB.prepare('DELETE FROM login_attempts WHERE key = ?').bind(key).run();
}

/* ── handlers ── */

async function handleRegister(request, env){
  const body = await request.json().catch(() => ({}));
  const name = String(body.name || '').trim().slice(0, 80);
  const email = normalizeEmail(body.email);
  const password = String(body.password || '');

  if (!name) return json({ error: 'Please enter your name.' }, 400, request, env);
  if (!validEmail(email)) return json({ error: 'Please enter a valid email address.' }, 400, request, env);
  if (password.length < 10) return json({ error: 'Password must be at least 10 characters.' }, 400, request, env);
  if (password.length > 200) return json({ error: 'Password is too long.' }, 400, request, env);

  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  if (existing) return json({ error: 'An account with that email already exists.' }, 409, request, env);

  const salt = randomHex(16);
  const hash = await hashPassword(password, salt, PBKDF2_ITERATIONS);
  const owner = normalizeEmail(env.OWNER_EMAIL || '');
  const role = owner && email === owner ? 'owner' : 'member';
  const now = new Date().toISOString();

  const res = await env.DB.prepare(
    `INSERT INTO users (name, email, pw_hash, pw_salt, iterations, role, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(name, email, hash, salt, PBKDF2_ITERATIONS, role, now).run();

  const userId = res.meta.last_row_id;
  const token = await createSession(env, userId);
  return json({ token, user: { id: userId, name, email, role } }, 201, request, env);
}

async function handleLogin(request, env){
  const body = await request.json().catch(() => ({}));
  const email = normalizeEmail(body.email);
  const password = String(body.password || '');
  const ip = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
  const key = email + '|' + ip;

  if (await tooManyAttempts(env, key)){
    return json({ error: 'Too many attempts. Please wait 15 minutes and try again.' }, 429, request, env);
  }

  const user = await env.DB.prepare(
    'SELECT id, name, email, role, pw_hash, pw_salt, iterations FROM users WHERE email = ?'
  ).bind(email).first();

  // Same response and comparable work whether or not the account exists.
  const salt = user ? user.pw_salt : randomHex(16);
  const iterations = user ? user.iterations : PBKDF2_ITERATIONS;
  const attempt = await hashPassword(password, salt, iterations);

  if (!user || !timingSafeEqual(attempt, user.pw_hash)){
    await recordAttempt(env, key);
    return json({ error: 'Email or password is incorrect.' }, 401, request, env);
  }

  await clearAttempts(env, key);
  const token = await createSession(env, user.id);
  return json({
    token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role }
  }, 200, request, env);
}

async function handleLogout(request, env){
  const token = bearer(request);
  if (token){
    await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?')
      .bind(await sha256Hex(token)).run();
  }
  return json({ ok: true }, 200, request, env);
}

async function handleMe(request, env){
  const user = await currentUser(request, env);
  if (!user) return json({ error: 'Not signed in.' }, 401, request, env);
  return json({ user }, 200, request, env);
}

export default {
  async fetch(request, env){
    const url = new URL(request.url);

    if (request.method === 'OPTIONS'){
      return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    }

    // Health check: confirms the D1 binding and tables without touching auth.
    if (url.pathname === '/auth/health'){
      if (!env.DB) return json({ ok: false, error: 'No D1 binding named DB on this deployment.' }, 500, request, env);
      try {
        const r = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
        return json({ ok: true, users: r.n, ownerEmailSet: !!env.OWNER_EMAIL, origins: env.ALLOWED_ORIGINS || null }, 200, request, env);
      } catch (err){
        return json({ ok: false, error: 'Database error: ' + (err && err.message) }, 500, request, env);
      }
    }

    if (!env.DB){
      return json({ error: 'Accounts are not configured yet (no database binding).' }, 500, request, env);
    }

    try {
      if (url.pathname === '/auth/register' && request.method === 'POST') return await handleRegister(request, env);
      if (url.pathname === '/auth/login'    && request.method === 'POST') return await handleLogin(request, env);
      if (url.pathname === '/auth/logout'   && request.method === 'POST') return await handleLogout(request, env);
      if (url.pathname === '/auth/me'       && request.method === 'GET')  return await handleMe(request, env);
    } catch (err){
      // Detail goes to the worker log, never to the client.
      console.error('auth error', url.pathname, err && err.stack || err);
      return json({ error: 'Server error. Please try again.' }, 500, request, env);
    }

    return json({ error: 'Not found.' }, 404, request, env);
  }
};
