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

/* ── analytics ── */

/** Calendar day in San Diego, so "today" on the dashboard matches the lounge's day. */
function localDay(date){
  try {
    return new Intl.DateTimeFormat('en-CA', {
      timeZone: 'America/Los_Angeles', year: 'numeric', month: '2-digit', day: '2-digit'
    }).format(date);
  } catch (e){
    // Fallback if the runtime lacks timezone data: fixed Pacific offset.
    return new Date(date.getTime() - 8 * 3600000).toISOString().slice(0, 10);
  }
}

function daysAgo(n){
  return localDay(new Date(Date.now() - n * 86400000));
}

/** Per-day visitor hash: no cookie, and it stops being linkable after 24h. */
async function visitorHash(request, env){
  const ip = request.headers.get('CF-Connecting-IP') || '';
  const ua = request.headers.get('User-Agent') || '';
  const salt = env.ANALYTICS_SALT || 'excalibur';
  return (await sha256Hex(ip + '|' + ua + '|' + localDay(new Date()) + '|' + salt)).slice(0, 32);
}

function looksLikeBot(request){
  const ua = (request.headers.get('User-Agent') || '').toLowerCase();
  if (!ua) return true;
  return /bot|crawl|spider|slurp|bingpreview|headless|monitor|pingdom|uptime|lighthouse|curl|wget|python-requests/.test(ua);
}

async function handleTrack(request, env){
  if (looksLikeBot(request)) return json({ ok: true, skipped: 'bot' }, 200, request, env);

  const body = await request.json().catch(() => ({}));
  const type = body.type === 'search' ? 'search' : body.type === 'pageview' ? 'pageview' : null;
  if (!type) return json({ error: 'Unknown event type.' }, 400, request, env);

  const path = String(body.path || '').slice(0, 120) || null;
  const category = ['cigar', 'drink'].includes(body.category) ? body.category : null;
  const term = type === 'search' ? String(body.term || '').trim().slice(0, 80) : null;
  const hits = Number.isFinite(body.hits) ? Math.max(0, Math.min(9999, Math.trunc(body.hits))) : null;

  if (type === 'search' && (!term || !category)) {
    return json({ error: 'Search events need a term and category.' }, 400, request, env);
  }

  await env.DB.prepare(
    `INSERT INTO events (type, path, category, term, hits, visitor, day, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    type, path, category, term, hits,
    await visitorHash(request, env), localDay(new Date()), new Date().toISOString()
  ).run();

  return json({ ok: true }, 200, request, env);
}

async function handleStats(request, env){
  const user = await currentUser(request, env);
  if (!user) return json({ error: 'Not signed in.' }, 401, request, env);
  if (user.role !== 'owner') return json({ error: 'Owner access only.' }, 403, request, env);

  const today = localDay(new Date());
  const week = daysAgo(6);    // today plus the previous 6 days
  const month = daysAgo(29);

  const views = async (where, ...binds) => {
    const r = await env.DB.prepare(
      `SELECT COUNT(*) AS n, COUNT(DISTINCT visitor) AS u FROM events WHERE type = 'pageview'${where}`
    ).bind(...binds).first();
    return { views: r?.n || 0, visitors: r?.u || 0 };
  };

  const searches = async (category) => {
    const r = await env.DB.prepare(
      `SELECT term, COUNT(*) AS n, SUM(CASE WHEN hits = 0 THEN 1 ELSE 0 END) AS zero
         FROM events
        WHERE type = 'search' AND category = ? AND term IS NOT NULL AND term <> ''
        GROUP BY term
        ORDER BY n DESC, term ASC
        LIMIT 200`
    ).bind(category).all();
    return (r.results || []).map(row => ({ term: row.term, count: row.n, zeroResults: row.zero }));
  };

  const pages = await env.DB.prepare(
    `SELECT path, COUNT(*) AS n FROM events
      WHERE type = 'pageview' AND path IS NOT NULL
      GROUP BY path ORDER BY n DESC LIMIT 20`
  ).all();

  return json({
    generatedAt: new Date().toISOString(),
    timezone: 'America/Los_Angeles',
    totals: {
      all:   await views(''),
      today: await views(' AND day = ?', today),
      week:  await views(' AND day >= ?', week),
      month: await views(' AND day >= ?', month)
    },
    searches: {
      cigar: await searches('cigar'),
      drink: await searches('drink')
    },
    pages: (pages.results || []).map(r => ({ path: r.path, count: r.n }))
  }, 200, request, env);
}

/* ── staff: roles, clock, schedules, pay ── */

const ROLE_RANK = { customer: 0, employee: 1, manager: 2, owner: 3 };
const ROLES = Object.keys(ROLE_RANK);

function atLeast(user, role){
  return user && (ROLE_RANK[user.role] || 0) >= ROLE_RANK[role];
}

/** Resolve the caller, or return the response to send back. */
async function requireRole(request, env, role){
  const user = await currentUser(request, env);
  if (!user) return { error: json({ error: 'Not signed in.' }, 401, request, env) };
  if (!atLeast(user, role)) return { error: json({ error: 'You do not have access to that.' }, 403, request, env) };
  return { user };
}

async function audit(env, actor, action, targetUser, entityId, details){
  await env.DB.prepare(
    `INSERT INTO audit_log (actor_id, actor_role, action, target_user, entity_id, details, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(actor.id, actor.role, action, targetUser || null, entityId || null,
         details || null, new Date().toISOString()).run();
}

function money(cents){ return cents == null ? null : cents / 100; }

/** Hours between two ISO instants, rounded to two decimals. */
function hoursBetween(a, b){
  if (!a || !b) return 0;
  return Math.max(0, Math.round(((Date.parse(b) - Date.parse(a)) / 3600000) * 100) / 100);
}

/* People (owner) */

async function handlePeople(request, env){
  const got = await requireRole(request, env, 'owner');
  if (got.error) return got.error;
  const r = await env.DB.prepare(
    `SELECT id, name, email, role, hourly_rate_cents, created_at FROM users ORDER BY
       CASE role WHEN 'owner' THEN 0 WHEN 'manager' THEN 1 WHEN 'employee' THEN 2 ELSE 3 END,
       name COLLATE NOCASE`
  ).all();
  return json({
    people: (r.results || []).map(u => ({
      id: u.id, name: u.name, email: u.email, role: u.role,
      hourlyRate: money(u.hourly_rate_cents), createdAt: u.created_at
    }))
  }, 200, request, env);
}

async function handleSetRole(request, env){
  const got = await requireRole(request, env, 'owner');
  if (got.error) return got.error;
  const body = await request.json().catch(() => ({}));
  const userId = Number(body.userId);
  const role = String(body.role || '');
  if (!ROLES.includes(role)) return json({ error: 'Unknown role.' }, 400, request, env);
  if (userId === got.user.id) return json({ error: 'You cannot change your own role.' }, 400, request, env);

  const target = await env.DB.prepare('SELECT id, name, role FROM users WHERE id = ?').bind(userId).first();
  if (!target) return json({ error: 'No such account.' }, 404, request, env);

  await env.DB.prepare('UPDATE users SET role = ? WHERE id = ?').bind(role, userId).run();
  await audit(env, got.user, 'role.set', userId, null, `${target.name}: ${target.role} → ${role}`);
  return json({ ok: true }, 200, request, env);
}

/* Time clock (employee and up) */

async function getSetting(env, key){
  const r = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind(key).first();
  return r ? r.value : null;
}

/** Metres between two points on the earth. */
function metresBetween(lat1, lon1, lat2, lon2){
  const R = 6371000;
  const toRad = d => d * Math.PI / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 +
            Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return Math.round(R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)));
}

/**
 * How far the punch was from the lounge, in metres, plus the phone's own
 * accuracy estimate. Returns nulls when we can't tell. The coordinates
 * themselves are never stored or returned - only the distance.
 */
async function punchDistance(env, body){
  const lat = Number(body.lat), lng = Number(body.lng);
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return { distance: null, accuracy: null };
  const slat = Number(await getSetting(env, 'lounge_lat'));
  const slng = Number(await getSetting(env, 'lounge_lng'));
  if (!Number.isFinite(slat) || !Number.isFinite(slng)) return { distance: null, accuracy: null };
  const accuracy = Number.isFinite(Number(body.accuracy))
    ? Math.min(99999, Math.round(Number(body.accuracy))) : null;
  return { distance: metresBetween(lat, lng, slat, slng), accuracy };
}

async function handleClockIn(request, env){
  const got = await requireRole(request, env, 'employee');
  if (got.error) return got.error;
  const open = await env.DB.prepare(
    'SELECT id FROM time_entries WHERE user_id = ? AND clock_out IS NULL'
  ).bind(got.user.id).first();
  if (open) return json({ error: 'You are already clocked in.' }, 409, request, env);

  const body = await request.json().catch(() => ({}));
  const { distance, accuracy } = await punchDistance(env, body);
  const now = new Date().toISOString();
  const ip = request.headers.get('CF-Connecting-IP') || null;
  const res = await env.DB.prepare(
    `INSERT INTO time_entries (user_id, clock_in, in_ip, in_distance_m, in_accuracy_m, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(got.user.id, now, ip, distance, accuracy, now).run();
  return json({ ok: true, entryId: res.meta.last_row_id, at: now, distance }, 200, request, env);
}

async function handleClockOut(request, env){
  const got = await requireRole(request, env, 'employee');
  if (got.error) return got.error;
  const open = await env.DB.prepare(
    'SELECT id, clock_in FROM time_entries WHERE user_id = ? AND clock_out IS NULL ORDER BY clock_in DESC'
  ).bind(got.user.id).first();
  if (!open) return json({ error: 'You are not clocked in.' }, 409, request, env);

  const body = await request.json().catch(() => ({}));
  const { distance, accuracy } = await punchDistance(env, body);
  const now = new Date().toISOString();
  await env.DB.prepare(
    'UPDATE time_entries SET clock_out = ?, out_ip = ?, out_distance_m = ?, out_accuracy_m = ? WHERE id = ?'
  ).bind(now, request.headers.get('CF-Connecting-IP') || null, distance, accuracy, open.id).run();
  return json({ ok: true, at: now, hours: hoursBetween(open.clock_in, now), distance }, 200, request, env);
}

/** Owner stands in the lounge and saves its coordinates once. */
async function handleSetLocation(request, env){
  const got = await requireRole(request, env, 'owner');
  if (got.error) return got.error;
  const body = await request.json().catch(() => ({}));
  const lat = Number(body.lat), lng = Number(body.lng);
  const radius = Number(body.radius);
  if (!Number.isFinite(lat) || !Number.isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180){
    return json({ error: 'That location does not look right.' }, 400, request, env);
  }
  const now = new Date().toISOString();
  const put = async (k, v) => env.DB.prepare(
    `INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value,
       updated_by = excluded.updated_by, updated_at = excluded.updated_at`
  ).bind(k, String(v), got.user.id, now).run();

  await put('lounge_lat', lat);
  await put('lounge_lng', lng);
  if (Number.isFinite(radius) && radius >= 25 && radius <= 5000) await put('lounge_radius_m', Math.round(radius));
  await audit(env, got.user, 'location.set', null, null, 'Lounge location updated');
  return json({ ok: true }, 200, request, env);
}

/** An employee's own status, schedule and pay. Never anyone else's. */
async function handleMyStatus(request, env){
  const got = await requireRole(request, env, 'employee');
  if (got.error) return got.error;
  const me = got.user;

  const open = await env.DB.prepare(
    'SELECT id, clock_in FROM time_entries WHERE user_id = ? AND clock_out IS NULL ORDER BY clock_in DESC'
  ).bind(me.id).first();

  const url = new URL(request.url);
  const month = (url.searchParams.get('month') || localDay(new Date()).slice(0, 7)).slice(0, 7);

  const shifts = await env.DB.prepare(
    `SELECT id, starts_at, ends_at, note FROM shifts
      WHERE user_id = ? AND substr(starts_at, 1, 7) >= ? AND substr(starts_at, 1, 7) <= ?
      ORDER BY starts_at`
  ).bind(me.id, month, month).all();

  const entries = await env.DB.prepare(
    `SELECT clock_in, clock_out FROM time_entries
      WHERE user_id = ? AND substr(clock_in, 1, 7) = ? ORDER BY clock_in DESC`
  ).bind(me.id, month).all();

  const tips = await env.DB.prepare(
    `SELECT SUM(amount_cents) AS c FROM tips WHERE user_id = ? AND substr(for_day, 1, 7) = ?`
  ).bind(me.id, month).first();

  const rate = await env.DB.prepare('SELECT hourly_rate_cents FROM users WHERE id = ?').bind(me.id).first();
  const hours = (entries.results || []).reduce((sum, e) => sum + hoursBetween(e.clock_in, e.clock_out), 0);

  return json({
    user: { id: me.id, name: me.name, role: me.role },
    month,
    onClock: open ? { since: open.clock_in } : null,
    shifts: (shifts.results || []),
    monthHours: Math.round(hours * 100) / 100,
    hourlyRate: money(rate?.hourly_rate_cents),
    monthPay: rate?.hourly_rate_cents ? Math.round(hours * rate.hourly_rate_cents) / 100 : null,
    monthTips: money(tips?.c || 0)
  }, 200, request, env);
}

/* Manager views */

async function handleTeam(request, env){
  const got = await requireRole(request, env, 'manager');
  if (got.error) return got.error;
  const url = new URL(request.url);
  const month = (url.searchParams.get('month') || localDay(new Date()).slice(0, 7)).slice(0, 7);

  const staff = await env.DB.prepare(
    `SELECT id, name, email, role, hourly_rate_cents FROM users
      WHERE role IN ('employee','manager','owner') ORDER BY name COLLATE NOCASE`
  ).all();

  const rows = [];
  for (const u of (staff.results || [])){
    const entries = await env.DB.prepare(
      `SELECT id, clock_in, clock_out, in_ip, out_ip, note FROM time_entries
        WHERE user_id = ? AND substr(clock_in, 1, 7) = ? ORDER BY clock_in DESC`
    ).bind(u.id, month).all();
    const tips = await env.DB.prepare(
      'SELECT SUM(amount_cents) AS c FROM tips WHERE user_id = ? AND substr(for_day, 1, 7) = ?'
    ).bind(u.id, month).first();
    const shifts = await env.DB.prepare(
      `SELECT id, starts_at, ends_at, note FROM shifts
        WHERE user_id = ? AND substr(starts_at, 1, 7) = ? ORDER BY starts_at`
    ).bind(u.id, month).all();

    const list = entries.results || [];
    const hours = list.reduce((s, e) => s + hoursBetween(e.clock_in, e.clock_out), 0);
    rows.push({
      id: u.id, name: u.name, email: u.email, role: u.role,
      hourlyRate: money(u.hourly_rate_cents),
      onClock: list.some(e => !e.clock_out),
      hours: Math.round(hours * 100) / 100,
      pay: u.hourly_rate_cents ? Math.round(hours * u.hourly_rate_cents) / 100 : null,
      tips: money(tips?.c || 0),
      entries: list,
      shifts: shifts.results || []
    });
  }
  return json({ month, staff: rows }, 200, request, env);
}

async function handleSetRate(request, env){
  const got = await requireRole(request, env, 'manager');
  if (got.error) return got.error;
  const body = await request.json().catch(() => ({}));
  const userId = Number(body.userId);
  const rate = Number(body.hourlyRate);
  if (!Number.isFinite(rate) || rate < 0 || rate > 1000) {
    return json({ error: 'Enter an hourly rate between 0 and 1000.' }, 400, request, env);
  }
  const target = await env.DB.prepare('SELECT id, name, hourly_rate_cents FROM users WHERE id = ?').bind(userId).first();
  if (!target) return json({ error: 'No such account.' }, 404, request, env);

  const cents = Math.round(rate * 100);
  await env.DB.prepare('UPDATE users SET hourly_rate_cents = ? WHERE id = ?').bind(cents, userId).run();
  await audit(env, got.user, 'rate.set', userId, null,
    `${target.name}: $${money(target.hourly_rate_cents) ?? '—'}/hr → $${rate.toFixed(2)}/hr`);
  return json({ ok: true }, 200, request, env);
}

async function handleShift(request, env){
  const got = await requireRole(request, env, 'manager');
  if (got.error) return got.error;
  const body = await request.json().catch(() => ({}));

  if (body.remove){
    const s = await env.DB.prepare(
      'SELECT s.id, s.starts_at, u.name FROM shifts s JOIN users u ON u.id = s.user_id WHERE s.id = ?'
    ).bind(Number(body.remove)).first();
    if (!s) return json({ error: 'No such shift.' }, 404, request, env);
    await env.DB.prepare('DELETE FROM shifts WHERE id = ?').bind(s.id).run();
    await audit(env, got.user, 'shift.delete', null, s.id, `Removed ${s.name}'s shift on ${s.starts_at.slice(0, 10)}`);
    return json({ ok: true }, 200, request, env);
  }

  const userId = Number(body.userId);
  const starts = String(body.startsAt || '');
  const ends = String(body.endsAt || '');
  if (!userId || !starts || !ends) return json({ error: 'Pick a person, a start and an end.' }, 400, request, env);
  if (Date.parse(ends) <= Date.parse(starts)) return json({ error: 'The shift must end after it starts.' }, 400, request, env);

  const target = await env.DB.prepare('SELECT id, name FROM users WHERE id = ?').bind(userId).first();
  if (!target) return json({ error: 'No such account.' }, 404, request, env);

  const now = new Date().toISOString();
  const res = await env.DB.prepare(
    'INSERT INTO shifts (user_id, starts_at, ends_at, note, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(userId, starts, ends, String(body.note || '').slice(0, 200) || null, got.user.id, now).run();

  await audit(env, got.user, 'shift.create', userId, res.meta.last_row_id,
    `${target.name}: ${starts.slice(0, 16).replace('T', ' ')} → ${ends.slice(11, 16)} UTC`);
  return json({ ok: true, id: res.meta.last_row_id }, 200, request, env);
}

async function handleTip(request, env){
  const got = await requireRole(request, env, 'manager');
  if (got.error) return got.error;
  const body = await request.json().catch(() => ({}));
  const userId = Number(body.userId);
  const amount = Number(body.amount);
  const day = String(body.forDay || localDay(new Date())).slice(0, 10);
  if (!Number.isFinite(amount) || amount <= 0 || amount > 100000) {
    return json({ error: 'Enter a tip amount greater than zero.' }, 400, request, env);
  }
  const target = await env.DB.prepare('SELECT id, name FROM users WHERE id = ?').bind(userId).first();
  if (!target) return json({ error: 'No such account.' }, 404, request, env);

  const now = new Date().toISOString();
  const res = await env.DB.prepare(
    'INSERT INTO tips (user_id, amount_cents, for_day, note, added_by, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(userId, Math.round(amount * 100), day, String(body.note || '').slice(0, 200) || null, got.user.id, now).run();

  await audit(env, got.user, 'tip.add', userId, res.meta.last_row_id,
    `${target.name}: $${amount.toFixed(2)} for ${day}`);
  return json({ ok: true }, 200, request, env);
}

/** Manager corrects a punch. The old value is always kept. */
async function handleEditEntry(request, env){
  const got = await requireRole(request, env, 'manager');
  if (got.error) return got.error;
  const body = await request.json().catch(() => ({}));
  const entry = await env.DB.prepare(
    'SELECT t.*, u.name FROM time_entries t JOIN users u ON u.id = t.user_id WHERE t.id = ?'
  ).bind(Number(body.entryId)).first();
  if (!entry) return json({ error: 'No such time entry.' }, 404, request, env);

  const reason = String(body.reason || '').slice(0, 200);
  if (!reason) return json({ error: 'Give a reason for the change.' }, 400, request, env);

  const now = new Date().toISOString();
  const changes = [];
  for (const field of ['clock_in', 'clock_out']){
    const key = field === 'clock_in' ? 'clockIn' : 'clockOut';
    if (body[key] === undefined) continue;
    const next = body[key] ? String(body[key]) : null;
    if (next === entry[field]) continue;
    if (next && Number.isNaN(Date.parse(next))) {
      return json({ error: 'That time is not valid.' }, 400, request, env);
    }
    await env.DB.prepare(`UPDATE time_entries SET ${field} = ? WHERE id = ?`).bind(next, entry.id).run();
    await env.DB.prepare(
      'INSERT INTO time_edits (entry_id, editor_id, field, old_value, new_value, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(entry.id, got.user.id, field, entry[field], next, reason, now).run();
    changes.push(`${field} ${entry[field] || '—'} → ${next || '—'}`);
  }

  if (!changes.length) return json({ ok: true, unchanged: true }, 200, request, env);
  await audit(env, got.user, 'punch.edit', entry.user_id, entry.id,
    `${entry.name}: ${changes.join('; ')} (${reason})`);
  return json({ ok: true }, 200, request, env);
}

/** Manager's log: who clocked in and out, most recent first. */
async function handleClockLog(request, env){
  const got = await requireRole(request, env, 'manager');
  if (got.error) return got.error;
  const r = await env.DB.prepare(
    `SELECT t.id, t.user_id, u.name, t.clock_in, t.clock_out, t.in_ip, t.out_ip, t.created_by,
            t.in_distance_m, t.in_accuracy_m, t.out_distance_m, t.out_accuracy_m
       FROM time_entries t JOIN users u ON u.id = t.user_id
      ORDER BY t.clock_in DESC LIMIT 300`
  ).all();
  return json({
    entries: r.results || [],
    locationSet: !!(await getSetting(env, 'lounge_lat')),
    radiusM: Number(await getSetting(env, 'lounge_radius_m')) || 150
  }, 200, request, env);
}

/** Owner's log: everything managers (and the owner) did. */
async function handleAudit(request, env){
  const got = await requireRole(request, env, 'owner');
  if (got.error) return got.error;
  const r = await env.DB.prepare(
    `SELECT a.id, a.action, a.details, a.created_at, a.actor_role,
            actor.name AS actor_name, target.name AS target_name
       FROM audit_log a
       JOIN users actor ON actor.id = a.actor_id
       LEFT JOIN users target ON target.id = a.target_user
      ORDER BY a.created_at DESC LIMIT 400`
  ).all();
  return json({ log: r.results || [] }, 200, request, env);
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
  // Everyone starts as a customer; the owner promotes people by hand.
  const role = owner && email === owner ? 'owner' : 'customer';
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

    // Open this from the lounge wifi to learn the address to put in
    // LOUNGE_IP, exactly as Cloudflare sees it.
    if (url.pathname === '/whoami'){
      return json({
        ip: request.headers.get('CF-Connecting-IP'),
        note: 'Open this on the lounge wifi to get the address for off-network flagging.'
      }, 200, request, env);
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
      if (url.pathname === '/track'         && request.method === 'POST') return await handleTrack(request, env);
      if (url.pathname === '/stats'         && request.method === 'GET')  return await handleStats(request, env);

      // staff
      if (url.pathname === '/people'        && request.method === 'GET')  return await handlePeople(request, env);
      if (url.pathname === '/people/role'   && request.method === 'POST') return await handleSetRole(request, env);
      if (url.pathname === '/audit'         && request.method === 'GET')  return await handleAudit(request, env);
      if (url.pathname === '/clock/in'      && request.method === 'POST') return await handleClockIn(request, env);
      if (url.pathname === '/clock/out'     && request.method === 'POST') return await handleClockOut(request, env);
      if (url.pathname === '/me/status'     && request.method === 'GET')  return await handleMyStatus(request, env);
      if (url.pathname === '/team'          && request.method === 'GET')  return await handleTeam(request, env);
      if (url.pathname === '/team/rate'     && request.method === 'POST') return await handleSetRate(request, env);
      if (url.pathname === '/team/shift'    && request.method === 'POST') return await handleShift(request, env);
      if (url.pathname === '/team/tip'      && request.method === 'POST') return await handleTip(request, env);
      if (url.pathname === '/team/entry'    && request.method === 'POST') return await handleEditEntry(request, env);
      if (url.pathname === '/team/clocklog' && request.method === 'GET')  return await handleClockLog(request, env);
      if (url.pathname === '/team/location' && request.method === 'POST') return await handleSetLocation(request, env);
    } catch (err){
      // Detail goes to the worker log, never to the client.
      console.error('auth error', url.pathname, err && err.stack || err);
      return json({ error: 'Server error. Please try again.' }, 500, request, env);
    }

    return json({ error: 'Not found.' }, 404, request, env);
  }
};
