/**
 * Exercises promotional email against real SQLite and a stubbed Resend. The
 * things that matter here are who receives a campaign and who provably does
 * not, that a resumed send never emails anyone twice, and that unsubscribing
 * works without signing in.
 *
 *   node worker/test/marketing.test.mjs
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

const outbox = [];
let failFor = null;          // an address the stub refuses, to test partial failure
globalThis.fetch = async (url, init) => {
  if (String(url).includes('api.resend.com')){
    const body = JSON.parse(init.body);
    if (failFor && body.to.includes(failFor)){
      return new Response('{"message":"invalid recipient"}', { status: 422 });
    }
    outbox.push(body);
    return new Response('{"id":"stub"}', { status: 200 });
  }
  return new Response('{}', { status: 404 });
};

const worker = (await import(ROOT + '/worker/src/index.js')).default;
const env = {
  DB: D1, RESEND_API_KEY: 'stub', OWNER_EMAIL: 'owner@excalibur.test',
  ALLOWED_ORIGINS: 'https://excaliburloungesd.com',
  RESET_FROM: 'Excalibur Lounge <no-reply@excaliburloungesd.com>',
  SITE_URL: 'https://excaliburloungesd.com'
};

let token = null;
const call = async (path, body, tok) => {
  const res = await worker.fetch(new Request('https://w.dev' + path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...((tok ?? token) ? { Authorization: 'Bearer ' + (tok ?? token) } : {})
    },
    body: body === undefined ? undefined : JSON.stringify(body)
  }), env);
  return { status: res.status, body: await res.json() };
};

let failures = 0;
const check = (label, cond, extra) => {
  console.log((cond ? '  ok   ' : '  FAIL ') + label + (cond ? '' : '  ' + JSON.stringify(extra)));
  if (!cond) failures++;
};

/* ── sign people up, some opting in ── */
const OPT_TEXT = 'Email me news and offers from Excalibur.';
const reg = await call('/auth/register', {
  name: 'Christian', email: 'owner@excalibur.test', password: 'ownerpassword1',
  marketingOptIn: true, marketingOptInText: OPT_TEXT
});
token = reg.body.token;
check('owner registered', reg.status === 201 && reg.body.user.role === 'owner', reg.body);

for (let i = 0; i < 7; i++){
  await call('/auth/register', {
    name: 'Guest ' + i, email: 'guest' + i + '@example.test', password: 'guestpassword1',
    // Only the even-numbered guests tick the box.
    marketingOptIn: i % 2 === 0, marketingOptInText: OPT_TEXT
  });
}
await call('/auth/register', { name: 'No Box', email: 'nobox@example.test', password: 'guestpassword1' });

const optedIn = db.prepare('SELECT COUNT(*) n FROM users WHERE marketing_opt_in = 1').get().n;
check('only those who ticked the box are opted in', optedIn === 5, optedIn);
check('a signup with no field at all defaults to off',
  db.prepare("SELECT marketing_opt_in m FROM users WHERE email = 'nobox@example.test'").get().m === 0);
check('the wording shown is stored with the consent',
  db.prepare("SELECT opt_in_text t FROM users WHERE email = 'guest0@example.test'").get().t === OPT_TEXT);

/* ── the roster the owner sees ── */
console.log('\nthe list');
const people = await call('/people');
check('people carries the opt-in flag',
  people.body.people.filter(p => p.marketing).length === 5, people.body.people.length);

const settings0 = await call('/marketing/settings');
check('subscriber count matches', settings0.body.subscribers === 5, settings0.body);

/* ── a campaign will not go out without a postal address ── */
console.log('\nbefore sending');
const draft = await call('/marketing/campaign', {
  subject: 'Scotch tasting Thursday',
  body: 'Join us Thursday at seven.\n\nTwelve pours, one table.',
  imageUrl: 'https://excaliburloungesd.com/opusx25-flyer.jpg',
  linkUrl: 'https://excaliburloungesd.com/menu.html', linkLabel: 'See The Menu'
});
check('draft saved', draft.status === 201 && draft.body.id > 0, draft.body);
const id = draft.body.id;

const noAddress = await call('/marketing/send', { id });
check('sending is refused with no postal address', noAddress.status === 400, noAddress.body);
check('and says why', /postal address/i.test(noAddress.body.error), noAddress.body.error);
check('nothing was sent', outbox.length === 0, outbox.length);

const badImg = await call('/marketing/campaign', { subject: 'x', body: 'y', imageUrl: 'javascript:alert(1)' });
check('a non-https image is refused', badImg.status === 400, badImg.body);

await call('/marketing/settings', { address: '1234 Clairemont Mesa Blvd, San Diego, CA 92111' });

/* ── a test goes only to the owner ── */
const test = await call('/marketing/test', { id });
check('test sent to the owner alone',
  test.body.ok && outbox.length === 1 && outbox[0].to[0] === 'owner@excalibur.test', outbox);
check('and is marked as a test', outbox[0].subject.startsWith('[TEST]'), outbox[0].subject);
outbox.length = 0;

/* ── the real send ── */
console.log('\nsending');
let rounds = 0, last = null;
for (;;){
  last = await call('/marketing/send', { id });
  rounds++;
  if (last.body.done || rounds > 10) break;
}
check('the send finished', last.body.done === true, last.body);
check('everyone opted in received it', outbox.length === 5, outbox.length);
check('and nobody else did',
  outbox.every(m => !m.to[0].match(/guest[135]@|nobox@/)), outbox.map(m => m.to[0]));
check('the campaign is marked sent',
  db.prepare('SELECT status FROM campaigns WHERE id = ?').get(id).status === 'sent');

const mail = outbox[0];
check('the postal address is in the body', mail.html.includes('Clairemont Mesa'), mail.html.slice(0, 120));
check('an unsubscribe link is in the body', /unsubscribe\.html\?t=/.test(mail.html));
check('and in the headers for one-click',
  mail.headers && /unsubscribe\.html/.test(mail.headers['List-Unsubscribe']), mail.headers);
check('the image is included', mail.html.includes('opusx25-flyer.jpg'));
check('a plain-text copy is sent too', typeof mail.text === 'string' && mail.text.includes('Unsubscribe:'));
check('each person gets their own link',
  new Set(outbox.map(m => m.headers['List-Unsubscribe'])).size === 5);

/* ── sending again does not repeat it ── */
const again = await call('/marketing/send', { id });
check('a finished campaign refuses to send again', again.status === 400, again.body);
check('and no extra mail went out', outbox.length === 5, outbox.length);

/* ── unsubscribing ── */
console.log('\nunsubscribing');
const link = outbox.find(m => m.to[0] === 'guest0@example.test').headers['List-Unsubscribe'];
const tok = link.match(/t=([a-f0-9]+)/)[1];

const anon = await worker.fetch(new Request('https://w.dev/unsubscribe?t=' + tok), env);
check('unsubscribe works with no sign-in at all', anon.status === 200, anon.status);
check('the person is off the list',
  db.prepare("SELECT marketing_opt_in m FROM users WHERE email = 'guest0@example.test'").get().m === 0);
check('it is recorded in the audit log',
  db.prepare("SELECT COUNT(*) n FROM audit_log WHERE action = 'marketing.unsubscribe'").get().n === 1);

const twice = await worker.fetch(new Request('https://w.dev/unsubscribe?t=' + tok), env);
check('unsubscribing twice is harmless', twice.status === 200, twice.status);
const junk = await worker.fetch(new Request('https://w.dev/unsubscribe?t=deadbeef'), env);
check('an unknown token gives nothing away', junk.status === 200, junk.status);

/* ── and they are excluded from the next one ── */
outbox.length = 0;
const second = await call('/marketing/campaign', { subject: 'Live music Friday', body: 'From eight.' });
for (rounds = 0; rounds < 10; rounds++){
  const r = await call('/marketing/send', { id: second.body.id });
  if (r.body.done) break;
}
check('the unsubscribed person is skipped next time', outbox.length === 4, outbox.length);
check('and specifically not emailed',
  !outbox.some(m => m.to[0] === 'guest0@example.test'), outbox.map(m => m.to[0]));

/* ── a partial failure is recorded, not hidden ── */
console.log('\nwhen a send fails');
outbox.length = 0;
failFor = 'guest2@example.test';
const third = await call('/marketing/campaign', { subject: 'Humidor restock', body: 'New arrivals.' });
for (rounds = 0; rounds < 10; rounds++){
  const r = await call('/marketing/send', { id: third.body.id });
  if (r.body.done) break;
}
const row = db.prepare('SELECT sent, failed FROM campaigns WHERE id = ?').get(third.body.id);
check('the failure is counted', row.failed === 1 && row.sent === 3, row);
check('and attributed to the right address',
  db.prepare("SELECT email FROM campaign_sends WHERE campaign_id = ? AND status = 'failed'")
    .get(third.body.id).email === 'guest2@example.test');
failFor = null;

/* ── a send bigger than one batch ── */
console.log('\nmore than one batch');
for (let i = 0; i < 40; i++){
  await call('/auth/register', {
    name: 'Crowd ' + i, email: 'crowd' + i + '@example.test', password: 'crowdpassword1',
    marketingOptIn: true, marketingOptInText: OPT_TEXT
  });
}
outbox.length = 0;
const big = await call('/marketing/campaign', { subject: 'Cigar night', body: 'Saturday.' });
let batches = 0, seenTotal = null;
for (rounds = 0; rounds < 20; rounds++){
  const r = await call('/marketing/send', { id: big.body.id });
  batches++;
  seenTotal = r.body.total;
  if (r.body.done) break;
}
const expected = db.prepare('SELECT COUNT(*) n FROM users WHERE marketing_opt_in = 1').get().n;
check('it took several batches', batches > 1, batches);
check('the total was reported correctly', seenTotal === expected, { seenTotal, expected });
check('everyone got exactly one', outbox.length === expected, { got: outbox.length, expected });
check('no address appears twice',
  new Set(outbox.map(m => m.to[0])).size === outbox.length,
  outbox.length - new Set(outbox.map(m => m.to[0])).size);

/* ── only the owner may do any of this ── */
console.log('\naccess');
const guest = await call('/auth/login', { email: 'guest4@example.test', password: 'guestpassword1' });
const gt = guest.body.token;
check('a customer cannot list campaigns', (await call('/marketing/campaigns', undefined, gt)).status === 403);
check('a customer cannot send', (await call('/marketing/send', { id }, gt)).status === 403);
check('a customer cannot read the settings', (await call('/marketing/settings', undefined, gt)).status === 403);
check('a customer can change their own preference',
  (await call('/me/marketing', { optIn: false }, gt)).status === 200);
check('and that took effect',
  db.prepare("SELECT marketing_opt_in m FROM users WHERE email = 'guest4@example.test'").get().m === 0);

console.log(failures ? '\n' + failures + ' FAILED' : '\nall passed');
process.exit(failures ? 1 : 0);
