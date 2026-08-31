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
 *   POST /auth/reset/request {email}             -> {ok:true}   (emails a code)
 *   POST /auth/reset/confirm {email,code,password} -> {token, user}
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
async function tooManyAttempts(env, key, max, windowMin){
  const since = new Date(Date.now() - (windowMin || ATTEMPT_WINDOW_MIN) * 60000).toISOString();
  const row = await env.DB.prepare(
    'SELECT COUNT(*) AS n FROM login_attempts WHERE key = ? AND created_at > ?'
  ).bind(key, since).first();
  return (row?.n || 0) >= (max || MAX_FAILED_ATTEMPTS);
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

async function putSetting(env, key, value, userId){
  await env.DB.prepare(
    `INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value,
       updated_by = excluded.updated_by, updated_at = excluded.updated_at`
  ).bind(key, String(value), userId || null, new Date().toISOString()).run();
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
  const put = (k, v) => putSetting(env, k, v, got.user.id);

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

  /* Many shifts at once: repeating patterns, and copying a week forward.
     A shift that already exists at the same start for the same person is
     skipped, so copying a week twice cannot double-book anyone. */
  if (Array.isArray(body.bulk)){
    const items = body.bulk.slice(0, 200);
    const now = new Date().toISOString();
    const names = new Set();
    let created = 0, skipped = 0;

    for (const it of items){
      const userId = Number(it.userId);
      const starts = String(it.startsAt || '');
      const ends = String(it.endsAt || '');
      if (!userId || !starts || !ends) { skipped++; continue; }
      if (Number.isNaN(Date.parse(starts)) || Number.isNaN(Date.parse(ends))) { skipped++; continue; }
      if (Date.parse(ends) <= Date.parse(starts)) { skipped++; continue; }

      const target = await env.DB.prepare('SELECT id, name FROM users WHERE id = ?').bind(userId).first();
      if (!target) { skipped++; continue; }

      const clash = await env.DB.prepare(
        'SELECT id FROM shifts WHERE user_id = ? AND starts_at = ?'
      ).bind(userId, starts).first();
      if (clash) { skipped++; continue; }

      await env.DB.prepare(
        'INSERT INTO shifts (user_id, starts_at, ends_at, note, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)'
      ).bind(userId, starts, ends, String(it.note || '').slice(0, 200) || null, got.user.id, now).run();
      created++;
      names.add(target.name);
    }

    if (created){
      await audit(env, got.user, 'shift.bulk', null, null,
        created + ' shift' + (created === 1 ? '' : 's') + ' added for ' + [...names].join(', ') +
        (skipped ? ' (' + skipped + ' skipped as already scheduled)' : ''));
    }
    return json({ ok: true, created, skipped }, 200, request, env);
  }

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

/* ── Clover ── */

/**
 * One call to Clover for this merchant. The token is a Worker secret and
 * never leaves the server; nothing here is reachable from a browser without
 * an owner session.
 */
async function cloverFetch(env, path, params){
  const base = env.CLOVER_BASE || 'https://api.clover.com';
  const url = new URL(base + '/v3/merchants/' + env.CLOVER_MERCHANT_ID + path);
  for (const [k, v] of Object.entries(params || {})){
    // Clover takes `filter` more than once, and ANDs the conditions together.
    if (Array.isArray(v)) v.forEach(one => url.searchParams.append(k, one));
    else url.searchParams.set(k, v);
  }

  let res, text = '';
  try {
    res = await fetch(url.toString(), {
      headers: { Authorization: 'Bearer ' + env.CLOVER_TOKEN, Accept: 'application/json' }
    });
    text = await res.text();
  } catch (err){
    return { ok: false, status: 0, error: 'Could not reach Clover: ' + (err && err.message) };
  }
  let data = null;
  try { data = JSON.parse(text); } catch (e){}
  if (!res.ok){
    return { ok: false, status: res.status, error: (data && (data.message || data.error)) || text.slice(0, 200) };
  }
  return { ok: true, status: res.status, data };
}

/**
 * Checks the connection and reports what the data actually looks like, so the
 * sync can be written against the real shape rather than an assumed one.
 */
async function handleCloverTest(request, env){
  const got = await requireRole(request, env, 'owner');
  if (got.error) return got.error;

  if (!env.CLOVER_TOKEN){
    return json({ ok: false, error: 'No CLOVER_TOKEN secret is set on this worker.' }, 400, request, env);
  }
  if (!env.CLOVER_MERCHANT_ID){
    return json({ ok: false, error: 'No CLOVER_MERCHANT_ID is set.' }, 400, request, env);
  }

  const merchant = await cloverFetch(env, '');
  if (!merchant.ok){
    return json({
      ok: false, step: 'merchant', status: merchant.status, error: merchant.error,
      hint: merchant.status === 401 ? 'The token was rejected. Check it was copied whole, and created while the Clairemont lounge was the selected merchant.'
          : merchant.status === 403 ? 'The token is valid but lacks permission. It needs read access to Merchant, Orders, Payments and Inventory.'
          : 'Check the merchant id and that this Clover plan includes API access.'
    }, 200, request, env);
  }

  const orders = await cloverFetch(env, '/orders', { limit: 3, expand: 'lineItems' });
  if (!orders.ok){
    return json({
      ok: false, step: 'orders', status: orders.status, error: orders.error,
      merchantName: merchant.data && merchant.data.name,
      hint: 'The merchant call worked, so the token is good but may lack Orders read permission.'
    }, 200, request, env);
  }

  // A trimmed sample: enough to confirm the field names, no customer details.
  const sample = (orders.data.elements || []).map(o => ({
    id: o.id,
    state: o.state,
    createdTime: o.createdTime,
    total: o.total,
    lineItems: ((o.lineItems && o.lineItems.elements) || []).map(li => ({
      name: li.name, price: li.price, itemId: li.item && li.item.id
    }))
  }));

  return json({
    ok: true,
    merchantName: merchant.data && merchant.data.name,
    currency: merchant.data && merchant.data.currency,
    ordersReturned: sample.length,
    sample
  }, 200, request, env);
}

/* ── Clover sync ── */

/*
 * Every D1 call spends one of the worker's subrequests, and the free plan
 * allows fifty per invocation. So a page of orders is written as a single
 * batch rather than a statement at a time, and a run stops after eight pages
 * and reports that there is more - pressing sync again carries on.
 */
const CLOVER_PAGE = 100;        // orders per Clover request
const CLOVER_MAX_PAGES = 8;     // 800 orders a run
const CATALOG_PAGE = 500;       // menu items per Clover request
const CATALOG_MAX_PAGES = 2;
const MAX_BATCH = 800;          // statements before a batch is flushed

// Most detail first. If Clover rejects an expansion the next one is tried, and
// the one that works is remembered in settings.
const CLOVER_EXPAND = [
  'lineItems,lineItems.discounts,payments,payments.tender,payments.refunds',
  'lineItems,payments,payments.tender',
  'lineItems,payments',
  'lineItems'
];

/**
 * Units sold on a line. Clover writes one row per unit for ordinary items and
 * only sets unitQty (in thousandths) for things sold by weight or measure.
 */
function lineQty(li){
  const q = Number(li.unitQty);
  return Number.isFinite(q) && q > 0 ? q / 1000 : 1;
}

/** Hour of the day in San Diego, 0-23, so an hourly report reads like the bar felt. */
function localHour(date){
  try {
    const h = new Intl.DateTimeFormat('en-GB', {
      timeZone: 'America/Los_Angeles', hour: '2-digit', hourCycle: 'h23'
    }).format(date);
    return Number(h) % 24;
  } catch (e){
    return new Date(date.getTime() - 8 * 3600000).getUTCHours();
  }
}

/** What a line was discounted by, as a positive number. Clover signs these negative. */
function lineDiscount(li){
  const els = (li.discounts && li.discounts.elements) || li.discounts || [];
  if (!Array.isArray(els)) return 0;
  return els.reduce((t, d) => t + Math.abs(Number(d.amount) || 0), 0);
}

/** Everything refunded against one payment, as a positive number. */
function paymentRefunded(p){
  const els = (p.refunds && p.refunds.elements) || p.refunds || [];
  if (!Array.isArray(els)) return 0;
  return els.reduce((t, r) => t + Math.abs(Number(r.amount) || 0), 0);
}

/**
 * The statements that store one order and its lines. Line items are deleted
 * and rewritten rather than merged, so a voided or refunded line on a
 * re-synced order disappears instead of lingering as a phantom sale. A batch
 * runs in order, so the delete always precedes the inserts that follow it.
 */
function orderStatements(env, o, syncedAt){
  const created = Number(o.createdTime) || Number(o.modifiedTime) || Date.now();
  const at = new Date(created);
  const day = localDay(at);
  const hour = localHour(at);

  const stmts = [
    env.DB.prepare(
      `INSERT INTO sales_orders (id, day, hour, created_ms, modified_ms, state, total_cents, synced_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET day = excluded.day, hour = excluded.hour,
         created_ms = excluded.created_ms, modified_ms = excluded.modified_ms,
         state = excluded.state, total_cents = excluded.total_cents,
         synced_at = excluded.synced_at`
    ).bind(o.id, day, hour, created, Number(o.modifiedTime) || created,
           o.state || null, Number(o.total) || 0, syncedAt),
    env.DB.prepare('DELETE FROM sales_items WHERE order_id = ?').bind(o.id),
    env.DB.prepare('DELETE FROM sales_payments WHERE order_id = ?').bind(o.id)
  ];

  const lines = (o.lineItems && o.lineItems.elements) || [];
  for (const li of lines){
    stmts.push(env.DB.prepare(
      `INSERT OR REPLACE INTO sales_items
         (id, order_id, day, item_id, name, price_cents, qty, refunded, discount_cents)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(li.id, o.id, day, (li.item && li.item.id) || null,
           (li.name || 'Unnamed').trim(), Number(li.price) || 0, lineQty(li),
           (li.refunded || li.exchanged) ? 1 : 0, lineDiscount(li)));
  }

  // Tips, tax and tender are on the payment. An order can have several (a
  // split cheque), so each is stored on its own.
  const pays = (o.payments && o.payments.elements) || [];
  for (const p of pays){
    const pAt = new Date(Number(p.createdTime) || created);
    stmts.push(env.DB.prepare(
      `INSERT OR REPLACE INTO sales_payments
         (id, order_id, day, hour, created_ms, amount_cents, tip_cents, tax_cents,
          refunded_cents, tender, employee_id, result)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(p.id, o.id, localDay(pAt), localHour(pAt), pAt.getTime(),
           Number(p.amount) || 0, Number(p.tipAmount) || 0, Number(p.taxAmount) || 0,
           paymentRefunded(p),
           (p.tender && (p.tender.label || p.tender.labelKey)) || null,
           (p.employee && p.employee.id) || null,
           p.result || null));
  }

  return { stmts, lines: lines.length, payments: pays.length };
}

/** The menu as Clover holds it, so "sold nothing this month" can be answered. */
async function syncCatalog(env){
  const now = new Date().toISOString();
  let offset = 0, saved = 0;
  for (let page = 0; page < CATALOG_MAX_PAGES; page++){
    const res = await cloverFetch(env, '/items', { limit: CATALOG_PAGE, offset, expand: 'categories' });
    if (!res.ok) return { ok: false, status: res.status, error: res.error, saved };
    const batch = (res.data && res.data.elements) || [];
    if (batch.length){
      await env.DB.batch(batch.map(it => {
        const cats = (it.categories && it.categories.elements) || [];
        return env.DB.prepare(
          `INSERT INTO clover_items (id, name, price_cents, hidden, category, synced_at)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET name = excluded.name, price_cents = excluded.price_cents,
             hidden = excluded.hidden, category = excluded.category, synced_at = excluded.synced_at`
        ).bind(it.id, (it.name || 'Unnamed').trim(), Number(it.price) || 0,
               it.hidden ? 1 : 0, (cats[0] && cats[0].name) || null, now);
      }));
      saved += batch.length;
    }
    offset += batch.length;
    if (batch.length < CATALOG_PAGE) break;
  }
  return { ok: true, saved };
}

/** Register staff, so payments and tips can be reported by name. */
async function syncEmployees(env){
  const now = new Date().toISOString();
  const res = await cloverFetch(env, '/employees', { limit: CATALOG_PAGE });
  if (!res.ok) return { ok: false, status: res.status, error: res.error, saved: 0 };
  const batch = (res.data && res.data.elements) || [];
  if (batch.length){
    await env.DB.batch(batch.map(e => env.DB.prepare(
      `INSERT INTO clover_employees (id, name, role, synced_at) VALUES (?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET name = excluded.name, role = excluded.role,
         synced_at = excluded.synced_at`
    ).bind(e.id, (e.name || e.nickname || 'Unnamed').trim(), e.role || null, now)));
  }
  return { ok: true, saved: batch.length };
}

/**
 * Pulls orders changed since the last run into D1. Everything is keyed on the
 * Clover order id, so running this twice costs time and nothing else.
 */
async function handleCloverSync(request, env){
  const got = await requireRole(request, env, 'owner');
  if (got.error) return got.error;
  if (!env.CLOVER_TOKEN){
    return json({ ok: false, error: 'No CLOVER_TOKEN secret is set on this worker.' }, 400, request, env);
  }

  const body = await request.json().catch(() => ({}));
  const now = Date.now();
  let since;
  if (Number(body.days) > 0){
    since = now - Math.min(Number(body.days), 400) * 86400000;
  } else {
    const saved = Number(await getSetting(env, 'clover_synced_through'));
    // Two hours of overlap, so an order edited moments after the last run is
    // still picked up. Re-syncing an order is harmless.
    since = Number.isFinite(saved) && saved > 0 ? saved - 2 * 3600000 : now - 30 * 86400000;
  }

  const syncedAt = new Date().toISOString();
  let offset = 0, orders = 0, items = 0, payments = 0, maxModified = since, capped = false;
  const states = {};
  let pending = [];
  const flush = async () => {
    if (pending.length) await env.DB.batch(pending);
    pending = [];
  };

  // Nested expansions give tender and refund detail, but not every Clover plan
  // accepts them. The one that works is remembered, so the fallback is paid for
  // once rather than on every page.
  let expand = await getSetting(env, 'clover_expand') || CLOVER_EXPAND[0];

  for (let page = 0; page < CLOVER_MAX_PAGES; page++){
    const params = {
      filter: ['modifiedTime>=' + since, 'modifiedTime<=' + now],
      orderBy: 'modifiedTime ASC',
      limit: CLOVER_PAGE,
      offset
    };
    let res = await cloverFetch(env, '/orders', { ...params, expand });
    if (!res.ok && res.status === 400){
      for (const fallback of CLOVER_EXPAND){
        if (fallback === expand) continue;
        res = await cloverFetch(env, '/orders', { ...params, expand: fallback });
        if (res.ok){
          expand = fallback;
          await putSetting(env, 'clover_expand', fallback, got.user.id);
          break;
        }
      }
    }
    if (!res.ok){
      return json({
        ok: false, step: 'orders', status: res.status, error: res.error,
        ordersSynced: orders,
        hint: res.status === 403 ? 'The token needs read access to Orders and Payments.' : undefined
      }, 200, request, env);
    }

    const batch = (res.data && res.data.elements) || [];
    for (const o of batch){
      const built = orderStatements(env, o, syncedAt);
      pending.push(...built.stmts);
      items += built.lines;
      payments += built.payments;
      orders++;
      states[o.state || 'none'] = (states[o.state || 'none'] || 0) + 1;
      const m = Number(o.modifiedTime) || Number(o.createdTime) || 0;
      if (m > maxModified) maxModified = m;
      if (pending.length >= MAX_BATCH) await flush();
    }
    await flush();
    offset += batch.length;
    if (batch.length < CLOVER_PAGE) break;
    capped = page === CLOVER_MAX_PAGES - 1;
  }

  // Only claim to be caught up if the last page was reached. Otherwise the
  // cursor stops at the newest order stored, and the next run carries on.
  await putSetting(env, 'clover_synced_through', capped ? maxModified : now, got.user.id);
  await putSetting(env, 'clover_synced_at', new Date().toISOString(), got.user.id);

  const catalog = await syncCatalog(env);
  const staff = await syncEmployees(env);
  await audit(env, got.user, 'clover.sync', null, null,
    `${orders} order${orders === 1 ? '' : 's'}, ${items} line items`);

  return json({
    ok: true,
    ordersSynced: orders,
    itemsSynced: items,
    paymentsSynced: payments,
    menuItems: catalog.ok ? catalog.saved : null,
    catalogError: catalog.ok ? undefined : catalog.error,
    employees: staff.ok ? staff.saved : null,
    employeeError: staff.ok ? undefined : staff.error,
    orderStates: states,
    expand,
    since: new Date(since).toISOString(),
    more: capped
  }, 200, request, env);
}

/**
 * The sales report, over a range of Pacific calendar days: the money summary,
 * how it was paid, who rang it, what sold, and what did not. Refunded lines
 * are excluded from item counts; anything on the Clover menu with no sales in
 * the range comes back separately, because that is the real "slowest seller".
 */
async function handleSalesReport(request, env){
  const got = await requireRole(request, env, 'owner');
  if (got.error) return got.error;

  const url = new URL(request.url);
  const from = (url.searchParams.get('from') || daysAgo(29)).slice(0, 10);
  const to = (url.searchParams.get('to') || localDay(new Date())).slice(0, 10);

  const sold = await env.DB.prepare(
    `SELECT name,
            SUM(qty)                AS units,
            SUM(price_cents * qty)  AS revenue_cents,
            COUNT(DISTINCT order_id) AS orders,
            MAX(item_id)            AS item_id
       FROM sales_items
      WHERE day >= ? AND day <= ? AND refunded = 0
      GROUP BY LOWER(name)
      ORDER BY units DESC, revenue_cents DESC`
  ).bind(from, to).all();

  const totals = await env.DB.prepare(
    `SELECT COUNT(*) AS orders, COALESCE(SUM(total_cents), 0) AS gross_cents
       FROM sales_orders WHERE day >= ? AND day <= ?`
  ).bind(from, to).first();

  // Menu items that rang up nothing in the range. Matched on id where Clover
  // gave us one, and on name otherwise, so hand-keyed sales still count.
  const unsold = await env.DB.prepare(
    `SELECT id, name, price_cents FROM clover_items
      WHERE hidden = 0
        AND id NOT IN (
          SELECT item_id FROM sales_items
           WHERE item_id IS NOT NULL AND day >= ? AND day <= ? AND refunded = 0)
        AND LOWER(name) NOT IN (
          SELECT LOWER(name) FROM sales_items
           WHERE day >= ? AND day <= ? AND refunded = 0)
      ORDER BY name COLLATE NOCASE`
  ).bind(from, to, from, to).all();

  // Money as Clover splits it. Gross and discounts come off the ticket lines;
  // tax, tips and what was actually collected come off the payments, because
  // that is where they are recorded.
  const pay = await env.DB.prepare(
    `SELECT COUNT(*) AS n,
            COALESCE(SUM(amount_cents), 0)   AS amount_cents,
            COALESCE(SUM(tip_cents), 0)      AS tip_cents,
            COALESCE(SUM(tax_cents), 0)      AS tax_cents,
            COALESCE(SUM(refunded_cents), 0) AS refunded_cents
       FROM sales_payments WHERE day >= ? AND day <= ?`
  ).bind(from, to).first();

  const lineTotals = await env.DB.prepare(
    `SELECT COALESCE(SUM(price_cents * qty), 0) AS gross_cents,
            COALESCE(SUM(discount_cents), 0)    AS discount_cents,
            COALESCE(SUM(qty), 0)               AS units
       FROM sales_items WHERE day >= ? AND day <= ? AND refunded = 0`
  ).bind(from, to).first();

  const refundedLines = await env.DB.prepare(
    `SELECT COALESCE(SUM(price_cents * qty), 0) AS cents, COUNT(*) AS n
       FROM sales_items WHERE day >= ? AND day <= ? AND refunded = 1`
  ).bind(from, to).first();

  const tenders = await env.DB.prepare(
    `SELECT COALESCE(tender, 'Other') AS name, COUNT(*) AS n,
            COALESCE(SUM(amount_cents), 0) AS amount_cents,
            COALESCE(SUM(tip_cents), 0)    AS tip_cents
       FROM sales_payments WHERE day >= ? AND day <= ?
      GROUP BY COALESCE(tender, 'Other') ORDER BY amount_cents DESC`
  ).bind(from, to).all();

  // Grouped on the expression rather than the alias: both joined tables have
  // their own `name` column, and SQLite calls that ambiguous.
  const staff = await env.DB.prepare(
    `SELECT COALESCE(e.name, p.employee_id, 'Not recorded') AS label, COUNT(*) AS n,
            COALESCE(SUM(p.amount_cents), 0) AS amount_cents,
            COALESCE(SUM(p.tip_cents), 0)    AS tip_cents
       FROM sales_payments p LEFT JOIN clover_employees e ON e.id = p.employee_id
      WHERE p.day >= ? AND p.day <= ?
      GROUP BY COALESCE(e.name, p.employee_id, 'Not recorded')
      ORDER BY amount_cents DESC`
  ).bind(from, to).all();

  const categories = await env.DB.prepare(
    `SELECT COALESCE(c.category, 'Uncategorised') AS label,
            COALESCE(SUM(i.qty), 0) AS units,
            COALESCE(SUM(i.price_cents * i.qty), 0) AS revenue_cents
       FROM sales_items i LEFT JOIN clover_items c ON c.id = i.item_id
      WHERE i.day >= ? AND i.day <= ? AND i.refunded = 0
      GROUP BY COALESCE(c.category, 'Uncategorised')
      ORDER BY revenue_cents DESC`
  ).bind(from, to).all();

  // A single day is read hour by hour; anything longer, day by day.
  const byHour = from === to;
  const bucket = byHour ? 'hour' : 'day';
  const trendOrders = await env.DB.prepare(
    `SELECT ${bucket} AS k, COUNT(*) AS orders, COALESCE(SUM(total_cents), 0) AS total_cents
       FROM sales_orders WHERE day >= ? AND day <= ? GROUP BY k ORDER BY k`
  ).bind(from, to).all();
  const trendTips = await env.DB.prepare(
    `SELECT ${bucket} AS k, COALESCE(SUM(tip_cents), 0) AS tip_cents
       FROM sales_payments WHERE day >= ? AND day <= ? GROUP BY k ORDER BY k`
  ).bind(from, to).all();

  const tipByKey = {};
  for (const r of (trendTips.results || [])) tipByKey[r.k] = r.tip_cents;

  const gross = lineTotals?.gross_cents || 0;
  const discounts = lineTotals?.discount_cents || 0;
  const tax = pay?.tax_cents || 0;
  const tips = pay?.tip_cents || 0;
  const refunds = pay?.refunded_cents || 0;

  return json({
    ok: true,
    from, to, bucket,
    syncedAt: await getSetting(env, 'clover_synced_at'),
    totals: {
      orders: totals?.orders || 0,
      payments: pay?.n || 0,
      items: Math.round((lineTotals?.units || 0) * 100) / 100,
      grossSales: money(gross),
      discounts: money(discounts),
      netSales: money(gross - discounts),
      tax: money(tax),
      tips: money(tips),
      refunds: money(refunds),
      refundedItems: refundedLines?.n || 0,
      refundedItemValue: money(refundedLines?.cents || 0),
      collected: money((pay?.amount_cents || 0) + tips - refunds),
      orderTotal: money(totals?.gross_cents || 0),
      avgTicket: totals?.orders ? money(Math.round((totals.gross_cents || 0) / totals.orders)) : null
    },
    tenders: (tenders.results || []).map(r => ({
      name: r.name, count: r.n, amount: money(r.amount_cents), tips: money(r.tip_cents)
    })),
    staff: (staff.results || []).map(r => ({
      name: r.label, payments: r.n, sales: money(r.amount_cents), tips: money(r.tip_cents)
    })),
    categories: (categories.results || []).map(r => ({
      name: r.label, units: Math.round((r.units || 0) * 100) / 100, revenue: money(r.revenue_cents)
    })),
    trend: (trendOrders.results || []).map(r => ({
      key: r.k, orders: r.orders,
      sales: money(r.total_cents), tips: money(tipByKey[r.k] || 0)
    })),
    items: (sold.results || []).map(r => ({
      name: r.name,
      units: Math.round((r.units || 0) * 100) / 100,
      revenue: money(r.revenue_cents || 0),
      orders: r.orders
    })),
    neverSold: (unsold.results || []).map(r => ({ name: r.name, price: money(r.price_cents) }))
  }, 200, request, env);
}

/* ── payroll ── */

/** Sunday-start workweek key for a Pacific calendar day. */
function weekKey(day){
  const d = new Date(day + 'T12:00:00Z');
  d.setUTCDate(d.getUTCDate() - d.getUTCDay());
  return d.toISOString().slice(0, 10);
}

/**
 * California overtime split for ONE workweek.
 *   over 8 in a day  -> 1.5x        over 12 in a day -> 2x
 *   over 40 straight-time in a week -> 1.5x
 *   7th consecutive day worked: first 8 at 1.5x, beyond at 2x
 */
function splitWeek(days){
  const worked = days.filter(d => d.hours > 0).sort((a, b) => a.day.localeCompare(b.day));
  const seventh = worked.length === 7 ? worked[6].day : null;
  let regular = 0, ot = 0, dt = 0;

  for (const d of worked){
    if (d.day === seventh){
      ot += Math.min(d.hours, 8);
      dt += Math.max(0, d.hours - 8);
    } else {
      regular += Math.min(d.hours, 8);
      ot += Math.min(Math.max(0, d.hours - 8), 4);
      dt += Math.max(0, d.hours - 12);
    }
  }
  if (regular > 40){ ot += regular - 40; regular = 40; }
  const r = n => Math.round(n * 100) / 100;
  return { regular: r(regular), ot: r(ot), dt: r(dt) };
}

/**
 * Gross pay for a date range: hours split into regular/overtime/double time,
 * priced at the person's rate, plus tips recorded in the same period.
 * Tips are never marked up by an overtime multiplier - they are not wages.
 */
async function handlePayroll(request, env){
  const got = await requireRole(request, env, 'manager');
  if (got.error) return got.error;
  const url = new URL(request.url);
  const from = (url.searchParams.get('from') || daysAgo(13)).slice(0, 10);
  const to = (url.searchParams.get('to') || localDay(new Date())).slice(0, 10);

  const staff = await env.DB.prepare(
    `SELECT id, name, role, hourly_rate_cents FROM users
      WHERE role IN ('employee','manager','owner') ORDER BY name COLLATE NOCASE`
  ).all();

  const rows = [];
  for (const u of (staff.results || [])){
    const entries = await env.DB.prepare(
      `SELECT clock_in, clock_out FROM time_entries
        WHERE user_id = ? AND clock_out IS NOT NULL ORDER BY clock_in`
    ).bind(u.id).all();

    // Bucket completed shifts into Pacific calendar days inside the range.
    const byDay = {};
    let openShift = false;
    for (const e of (entries.results || [])){
      const day = localDay(new Date(e.clock_in));
      if (day < from || day > to) continue;
      byDay[day] = (byDay[day] || 0) + hoursBetween(e.clock_in, e.clock_out);
    }

    const stillOn = await env.DB.prepare(
      'SELECT COUNT(*) AS n FROM time_entries WHERE user_id = ? AND clock_out IS NULL'
    ).bind(u.id).first();
    openShift = (stillOn?.n || 0) > 0;

    // Split per workweek, then add the weeks together.
    const weeks = {};
    for (const [day, hours] of Object.entries(byDay)){
      (weeks[weekKey(day)] = weeks[weekKey(day)] || []).push({ day, hours });
    }
    let regular = 0, ot = 0, dt = 0;
    for (const days of Object.values(weeks)){
      const s = splitWeek(days);
      regular += s.regular; ot += s.ot; dt += s.dt;
    }

    const tips = await env.DB.prepare(
      'SELECT SUM(amount_cents) AS c FROM tips WHERE user_id = ? AND for_day BETWEEN ? AND ?'
    ).bind(u.id, from, to).first();

    const rate = u.hourly_rate_cents;
    const cents = rate ? Math.round(regular * rate + ot * rate * 1.5 + dt * rate * 2) : null;
    const tipCents = tips?.c || 0;
    const round = n => Math.round(n * 100) / 100;

    rows.push({
      id: u.id, name: u.name, role: u.role,
      hourlyRate: money(rate),
      regularHours: round(regular), otHours: round(ot), dtHours: round(dt),
      totalHours: round(regular + ot + dt),
      grossWages: money(cents),
      tips: money(tipCents),
      total: cents == null ? null : money(cents + tipCents),
      openShift,
      missingRate: !rate
    });
  }

  return json({
    from, to, workweek: 'Sunday to Saturday', timezone: 'America/Los_Angeles',
    staff: rows
  }, 200, request, env);
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

/* ── forgotten passwords ── */

const RESET_CODE_MINUTES = 15;
const RESET_MAX_ATTEMPTS = 5;    // guesses allowed against one code
const RESET_MAX_REQUESTS = 4;    // codes per email+IP per hour

/**
 * A six-digit code, drawn without modulo bias. Short enough to type from a
 * phone; the attempt limit and the fifteen-minute life are what make it safe,
 * not its length.
 */
function resetCode(){
  const buf = new Uint32Array(1);
  const limit = Math.floor(4294967296 / 1000000) * 1000000;
  do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
  return String(buf[0] % 1000000).padStart(6, '0');
}

/** Sends through Resend. The API key is a Worker secret and never reaches a browser. */
async function sendEmail(env, to, subject, text, html){
  const from = env.RESET_FROM || 'Excalibur Lounge <no-reply@excaliburloungesd.com>';
  let res, body = '';
  try {
    res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + env.RESEND_API_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ from, to: [to], subject, text, html })
    });
    body = await res.text();
  } catch (err){
    return { ok: false, status: 0, error: 'Could not reach the email service: ' + (err && err.message) };
  }
  if (!res.ok) return { ok: false, status: res.status, error: body.slice(0, 300) };
  return { ok: true };
}

function resetEmailText(name, code){
  return `Hello ${name},\n\n` +
    `Your Excalibur password reset code is ${code}\n\n` +
    `It works for the next ${RESET_CODE_MINUTES} minutes and can only be used once.\n\n` +
    `If you did not ask to reset your password, you can ignore this email — ` +
    `nothing has changed on your account.\n\n` +
    `Excalibur Cigar & Scotch Lounge`;
}

function resetEmailHtml(name, code){
  const esc = s => String(s).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  return `<div style="font-family:Helvetica,Arial,sans-serif;background:#140c05;padding:32px;color:#e8dfcc">
  <div style="max-width:440px;margin:0 auto;background:#1d1209;border:1px solid #4a3a1c;padding:32px">
    <div style="font-size:22px;color:#c9a84c;letter-spacing:.05em">Excalibur</div>
    <p style="font-size:15px;line-height:1.6">Hello ${esc(name)},</p>
    <p style="font-size:15px;line-height:1.6">Your password reset code is:</p>
    <div style="font-size:34px;letter-spacing:.35em;color:#c9a84c;font-weight:600;
                text-align:center;padding:18px 0;border:1px solid #4a3a1c;margin:20px 0">${esc(code)}</div>
    <p style="font-size:13px;line-height:1.6;color:#b3a68c">
      It works for the next ${RESET_CODE_MINUTES} minutes and can only be used once.</p>
    <p style="font-size:13px;line-height:1.6;color:#b3a68c">
      If you did not ask to reset your password, ignore this email &mdash; nothing on your
      account has changed.</p>
    <p style="font-size:12px;color:#8a7f6a;margin-top:26px">Excalibur Cigar &amp; Scotch Lounge</p>
  </div>
</div>`;
}

/**
 * Step one: email a code. The answer is the same whether or not the address
 * has an account, so this cannot be used to find out who is registered.
 */
async function handleResetRequest(request, env){
  const body = await request.json().catch(() => ({}));
  const email = normalizeEmail(body.email);
  const ip = request.headers.get('CF-Connecting-IP') || '0.0.0.0';

  if (!validEmail(email)) return json({ error: 'Please enter a valid email address.' }, 400, request, env);

  // Checked before anything is looked up, so an unconfigured service can
  // never be read as "that address has no account".
  if (!env.RESEND_API_KEY){
    return json({ error: 'Password reset by email is not set up on this site yet.' }, 503, request, env);
  }

  const key = 'reset|' + email + '|' + ip;
  if (await tooManyAttempts(env, key, RESET_MAX_REQUESTS, 60)){
    return json({ error: 'Too many reset requests. Please wait an hour and try again.' }, 429, request, env);
  }
  await recordAttempt(env, key);

  const user = await env.DB.prepare('SELECT id, name, email FROM users WHERE email = ?')
    .bind(email).first();

  if (user){
    const code = resetCode();
    const now = new Date();
    // Asking for a new code retires the old one.
    await env.DB.prepare('DELETE FROM password_resets WHERE user_id = ?').bind(user.id).run();
    await env.DB.prepare(
      'INSERT INTO password_resets (user_id, code_hash, expires_at, created_at) VALUES (?, ?, ?, ?)'
    ).bind(user.id, await sha256Hex(code),
           new Date(now.getTime() + RESET_CODE_MINUTES * 60000).toISOString(),
           now.toISOString()).run();

    const sent = await sendEmail(env, user.email,
      'Your Excalibur password reset code',
      resetEmailText(user.name, code), resetEmailHtml(user.name, code));
    // A failure is logged for the owner, never reported back: which addresses
    // exist is not something this endpoint may reveal.
    if (!sent.ok) console.error('reset email failed', sent.status, sent.error);
  }

  return json({ ok: true, expiresInMinutes: RESET_CODE_MINUTES }, 200, request, env);
}

/** Step two: check the code, set the new password, and sign the person in. */
async function handleResetConfirm(request, env){
  const body = await request.json().catch(() => ({}));
  const email = normalizeEmail(body.email);
  const code = String(body.code || '').replace(/\D/g, '');
  const password = String(body.password || '');
  const ip = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
  const key = 'resetc|' + email + '|' + ip;

  if (password.length < 10) return json({ error: 'Password must be at least 10 characters.' }, 400, request, env);
  if (password.length > 200) return json({ error: 'Password is too long.' }, 400, request, env);
  if (await tooManyAttempts(env, key, 10, 60)){
    return json({ error: 'Too many attempts. Please wait an hour and try again.' }, 429, request, env);
  }

  // One message for every way this can fail, so nothing is learned from which.
  const wrong = async () => {
    await recordAttempt(env, key);
    return json({ error: 'That code is not right, or it has expired. Ask for a new one.' },
                400, request, env);
  };

  const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  if (!user) return await wrong();

  const row = await env.DB.prepare(
    `SELECT id, code_hash, expires_at, attempts FROM password_resets
      WHERE user_id = ? ORDER BY id DESC LIMIT 1`
  ).bind(user.id).first();
  if (!row) return await wrong();

  if (Date.parse(row.expires_at) < Date.now() || row.attempts >= RESET_MAX_ATTEMPTS){
    await env.DB.prepare('DELETE FROM password_resets WHERE id = ?').bind(row.id).run();
    return await wrong();
  }

  if (!timingSafeEqual(await sha256Hex(code), row.code_hash)){
    await env.DB.prepare('UPDATE password_resets SET attempts = attempts + 1 WHERE id = ?')
      .bind(row.id).run();
    return await wrong();
  }

  const salt = randomHex(16);
  const hash = await hashPassword(password, salt, PBKDF2_ITERATIONS);
  await env.DB.prepare('UPDATE users SET pw_hash = ?, pw_salt = ?, iterations = ? WHERE id = ?')
    .bind(hash, salt, PBKDF2_ITERATIONS, user.id).run();
  await env.DB.prepare('DELETE FROM password_resets WHERE user_id = ?').bind(user.id).run();
  // Every existing session goes. If someone else had the account open, a
  // password reset is precisely when they should lose it.
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id).run();
  await clearAttempts(env, key);

  const full = await env.DB.prepare('SELECT id, name, email, role FROM users WHERE id = ?')
    .bind(user.id).first();
  await audit(env, full, 'password.reset', full.id, null, 'Password reset with an emailed code');

  const token = await createSession(env, user.id);
  return json({ token, user: full }, 200, request, env);
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
        // Whether a table or a secret exists, never its contents. Enough to
        // tell a missing secret from a missing table without reading logs.
        const tableExists = async name => {
          try {
            await env.DB.prepare('SELECT 1 FROM ' + name + ' LIMIT 1').first();
            return true;
          } catch (e){ return false; }
        };
        return json({
          ok: true,
          users: r.n,
          ownerEmailSet: !!env.OWNER_EMAIL,
          origins: env.ALLOWED_ORIGINS || null,
          resendKeySet: !!env.RESEND_API_KEY,
          resetFrom: env.RESET_FROM || null,
          resetTable: await tableExists('password_resets'),
          cloverTokenSet: !!env.CLOVER_TOKEN,
          salesTables: await tableExists('sales_payments')
        }, 200, request, env);
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
      if (url.pathname === '/auth/reset/request' && request.method === 'POST') return await handleResetRequest(request, env);
      if (url.pathname === '/auth/reset/confirm' && request.method === 'POST') return await handleResetConfirm(request, env);
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
      if (url.pathname === '/payroll'       && request.method === 'GET')  return await handlePayroll(request, env);
      if (url.pathname === '/clover/test'   && request.method === 'GET')  return await handleCloverTest(request, env);
      if (url.pathname === '/clover/sync'   && request.method === 'POST') return await handleCloverSync(request, env);
      if (url.pathname === '/sales/report'  && request.method === 'GET')  return await handleSalesReport(request, env);
      if (url.pathname === '/sales/items'   && request.method === 'GET')  return await handleSalesReport(request, env);
    } catch (err){
      // Detail goes to the worker log, never to the client.
      console.error('auth error', url.pathname, err && err.stack || err);
      return json({ error: 'Server error. Please try again.' }, 500, request, env);
    }

    return json({ error: 'Not found.' }, 404, request, env);
  }
};
