/**
 * Exercises the emailed password-reset flow against real SQLite and a stubbed
 * Resend, so the security properties are checked rather than assumed:
 * no account enumeration, codes that expire, guesses that run out, sessions
 * dropped on reset, and the old password ceasing to work.
 *
 *   node worker/test/reset.test.mjs
 *
 * No dependencies and no network. Exits non-zero if anything fails.
 */
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';

const ROOT = new URL('../..', import.meta.url).pathname.replace(/\/$/, '');

const db = new DatabaseSync(':memory:');
const schema = readFileSync(ROOT + '/worker/schema.sql', 'utf8')
  .split('\n').map(l => l.replace(/--.*$/, '')).join('\n');
for (const stmt of schema.split(';')){
  const s = stmt.trim();
  if (!s) continue;
  try { db.exec(s); } catch (e){ if (!/duplicate column/.test(e.message)) throw new Error(s.slice(0, 60) + ' :: ' + e.message); }
}

const norm = v => (v === undefined ? null : typeof v === 'boolean' ? (v ? 1 : 0) : v);
const D1 = {
  prepare(sql){
    const st = db.prepare(sql);
    let args = [];
    const api = {
      bind(...a){ args = a.map(norm); return api; },
      run(){ const m = st.run(...args); return { success: true, meta: { last_row_id: Number(m.lastInsertRowid) } }; },
      first(){ return st.get(...args) ?? null; },
      all(){ return { results: st.all(...args) }; },
      _run(){ return st.run(...args); }
    };
    return api;
  },
  batch(stmts){ return stmts.map(s => s._run()); }
};

/* ── a Resend that files the mail instead of sending it ── */
const outbox = [];
let mailFails = false;
globalThis.fetch = async (url, init) => {
  if (String(url).includes('api.resend.com')){
    if (mailFails) return new Response('{"message":"domain not verified"}', { status: 403 });
    outbox.push(JSON.parse(init.body));
    return new Response('{"id":"stub"}', { status: 200 });
  }
  return new Response('{}', { status: 404 });
};
const codeFromLastEmail = () => (outbox[outbox.length - 1].text.match(/\b(\d{6})\b/) || [])[1];

const worker = (await import(ROOT + '/worker/src/index.js')).default;
const env = {
  DB: D1, RESEND_API_KEY: 'stub', ALLOWED_ORIGINS: 'https://excaliburloungesd.com',
  OWNER_EMAIL: 'owner@excalibur.test'
};
const call = async (path, body, headers) => {
  const res = await worker.fetch(new Request('https://w.dev' + path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '1.2.3.4', ...(headers || {}) },
    body: body === undefined ? undefined : JSON.stringify(body)
  }), env);
  return { status: res.status, body: await res.json() };
};

let failures = 0;
const check = (label, cond, extra) => {
  console.log((cond ? '  ok   ' : '  FAIL ') + label + (cond ? '' : '  ' + JSON.stringify(extra)));
  if (!cond) failures++;
};

/* ── an account to reset ── */
const EMAIL = 'owner@excalibur.test';
const OLD = 'originalpassword';
const reg = await call('/auth/register', { name: 'Christian', email: EMAIL, password: OLD });
check('account created', reg.status === 201 && reg.body.user.role === 'owner', reg.body);
const firstToken = reg.body.token;

/* ── 1. asking for a code ── */
console.log('\nrequesting a code');
const ask = await call('/auth/reset/request', { email: EMAIL });
check('request accepted', ask.body.ok === true, ask.body);
check('an email went out', outbox.length === 1, outbox.length);
check('addressed to the account holder', outbox[0].to[0] === EMAIL, outbox[0].to);
const code = codeFromLastEmail();
check('a six-digit code is in the email', /^\d{6}$/.test(code || ''), code);
check('the code is not stored in the clear',
  db.prepare('SELECT COUNT(*) n FROM password_resets WHERE code_hash = ?').get(code).n === 0);

/* ── 2. an unknown address is answered identically ── */
const unknown = await call('/auth/reset/request', { email: 'nobody@nowhere.test' });
check('unknown address gets the same answer',
  unknown.status === ask.status && JSON.stringify(unknown.body) === JSON.stringify(ask.body),
  { unknown: unknown.body, known: ask.body });
check('and no email is sent for it', outbox.length === 1, outbox.length);

/* ── 3. wrong codes ── */
console.log('\nwrong codes');
const wrongCode = String((Number(code) + 1) % 1000000).padStart(6, '0');
const bad = await call('/auth/reset/confirm', { email: EMAIL, code: wrongCode, password: 'brandnewpassword' });
check('a wrong code is refused', bad.status === 400, bad.body);
check('and says nothing about why', /not right, or it has expired/.test(bad.body.error), bad.body.error);
check('the old password still works',
  (await call('/auth/login', { email: EMAIL, password: OLD })).status === 200);

for (let i = 0; i < 4; i++) await call('/auth/reset/confirm', { email: EMAIL, code: wrongCode, password: 'brandnewpassword' });
const afterBurn = await call('/auth/reset/confirm', { email: EMAIL, code, password: 'brandnewpassword' });
check('the right code is dead once the guesses run out', afterBurn.status === 400, afterBurn.body);

/* ── 4. a fresh code, and a short password ── */
console.log('\nresetting for real');
outbox.length = 0;
await call('/auth/reset/request', { email: EMAIL });
const code2 = codeFromLastEmail();
check('a new code was issued', /^\d{6}$/.test(code2 || '') && code2 !== code, { code, code2 });
check('only one code is live at a time',
  db.prepare('SELECT COUNT(*) n FROM password_resets').get().n === 1);

const short = await call('/auth/reset/confirm', { email: EMAIL, code: code2, password: 'short' });
check('a short new password is refused', short.status === 400, short.body);

const NEW = 'a-much-better-password';
const done = await call('/auth/reset/confirm', { email: EMAIL, code: code2, password: NEW });
check('the reset succeeds', done.status === 200 && !!done.body.token, done.body);
check('and signs the person straight in', done.body.user.email === EMAIL, done.body.user);

/* ── 5. what the reset did ── */
console.log('\nafter the reset');
check('the new password works', (await call('/auth/login', { email: EMAIL, password: NEW })).status === 200);
check('the old password does not',
  (await call('/auth/login', { email: EMAIL, password: OLD })).status === 401);
check('the used code is gone', db.prepare('SELECT COUNT(*) n FROM password_resets').get().n === 0);

const oldSession = await call('/auth/me', undefined, { Authorization: 'Bearer ' + firstToken });
check('sessions open before the reset were dropped', oldSession.status === 401, oldSession.body);
check('the reset is in the audit log',
  db.prepare("SELECT COUNT(*) n FROM audit_log WHERE action = 'password.reset'").get().n === 1);

/* ── 6. reusing a spent code ── */
const replay = await call('/auth/reset/confirm', { email: EMAIL, code: code2, password: 'yet-another-password' });
check('a spent code cannot be used again', replay.status === 400, replay.body);

/* ── 7. an expired code ── */
console.log('\nexpiry and throttling');
outbox.length = 0;
db.prepare('DELETE FROM login_attempts').run();
await call('/auth/reset/request', { email: EMAIL });
const code3 = codeFromLastEmail();
db.prepare('UPDATE password_resets SET expires_at = ?').run(new Date(Date.now() - 1000).toISOString());
const stale = await call('/auth/reset/confirm', { email: EMAIL, code: code3, password: 'expired-attempt-pw' });
check('an expired code is refused', stale.status === 400, stale.body);

/* ── 8. request throttling ── */
db.prepare('DELETE FROM login_attempts').run();
let limited = null;
for (let i = 0; i < 6; i++){
  const r = await call('/auth/reset/request', { email: EMAIL });
  if (r.status === 429){ limited = i; break; }
}
check('repeated requests are throttled', limited !== null && limited <= 4, limited);

/* ── 9. the service being unconfigured is not an account answer ── */
console.log('\nfailure handling');
const noKey = await worker.fetch(new Request('https://w.dev/auth/reset/request', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: EMAIL })
}), { ...env, RESEND_API_KEY: '' });
check('no API key is reported plainly, before any lookup', noKey.status === 503, noKey.status);

db.prepare('DELETE FROM login_attempts').run();
outbox.length = 0;
mailFails = true;
const sendFail = await call('/auth/reset/request', { email: EMAIL });
check('a refused send still answers ok, revealing nothing', sendFail.body.ok === true, sendFail.body);
mailFails = false;

console.log(failures ? '\n' + failures + ' FAILED' : '\nall passed');
process.exit(failures ? 1 : 0);
