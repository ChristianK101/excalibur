/**
 * Exercises the Clover sync and the sales report against real SQLite and a
 * stubbed Clover API, so the SQL, the paging, the money arithmetic and the
 * role checks are all verified before anything is deployed.
 *
 *   node worker/test/clover.test.mjs
 *
 * No dependencies and no network: node:sqlite stands in for D1 and global
 * fetch is replaced with fixtures. Exits non-zero if anything fails.
 */
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

// The repository root, two levels up from this file.
const ROOT = new URL('../..', import.meta.url).pathname.replace(/\/$/, '');

/* ── a D1-shaped wrapper over node:sqlite ── */
const db = new DatabaseSync(':memory:');
const schema = readFileSync(ROOT + '/worker/schema.sql', 'utf8')
  .split('\n').map(l => l.replace(/--.*$/, '')).join('\n');
for (const stmt of schema.split(';')){
  const s = stmt.trim();
  if (!s) continue;
  try { db.exec(s); } catch (e){ if (!/duplicate column/.test(e.message)) throw new Error(s.slice(0,60) + ' :: ' + e.message); }
}

// Every D1 call and every outbound fetch spends one of the worker's fifty
// subrequests on the free plan, so the harness counts them.
const norm = v => (v === undefined ? null : typeof v === 'boolean' ? (v ? 1 : 0) : v);
let subrequests = 0;
const D1 = {
  prepare(sql){
    const st = db.prepare(sql);
    let args = [];
    const api = {
      bind(...a){ args = a.map(norm); return api; },
      run(){ subrequests++; return { success: true, meta: st.run(...args) }; },
      first(){ subrequests++; return st.get(...args) ?? null; },
      all(){ subrequests++; return { results: st.all(...args) }; },
      _run(){ return st.run(...args); }
    };
    return api;
  },
  batch(stmts){ subrequests++; return stmts.map(s => s._run()); }
};

/* ── a Clover that answers from fixtures ── */
const DAY = 86400000;
const now = Date.now();
const MENU = ['Macallan 12', 'Blanton’s', 'Buffalo Trace', 'Hennessy VS', 'Casamigos Blanco', 'Dusty Bottle'];
const orders = [];
for (let i = 0; i < 250; i++){
  const created = now - (i % 40) * DAY - 3600000;
  const lines = [];
  // Macallan is the runaway seller; Dusty Bottle never sells at all.
  const picks = i % 3 === 0 ? ['Macallan 12', 'Macallan 12', 'Buffalo Trace']
              : i % 3 === 1 ? ['Macallan 12', 'Hennessy VS']
              : ['Casamigos Blanco'];
  picks.forEach((name, n) => lines.push({
    id: 'LI' + i + '_' + n, name, price: 1500 + n * 100,
    item: { id: 'ITEM_' + MENU.indexOf(name) },
    refunded: i === 7 && n === 0          // one refunded line, must not count
  }));
  const subtotal = lines.reduce((t, l) => t + l.price, 0);
  const tax = Math.round(subtotal * 0.0775);
  orders.push({
    id: 'ORD' + String(i).padStart(4, '0'), state: 'paid',
    createdTime: created, modifiedTime: created,
    total: subtotal + tax,
    lineItems: { elements: lines },
    payments: { elements: [{
      id: 'PAY' + i, createdTime: created,
      amount: subtotal + tax, tipAmount: 300, taxAmount: tax,
      tender: { label: i % 4 === 0 ? 'Cash' : 'Credit Card' },
      employee: { id: 'EMP' + (i % 2) },
      result: 'SUCCESS',
      refunds: { elements: i === 11 ? [{ amount: 500 }] : [] }
    }] }
  });
}
orders.sort((a, b) => a.modifiedTime - b.modifiedTime);

let cloverCalls = 0;
globalThis.fetch = async (url) => {
  cloverCalls++; subrequests++;
  const u = new URL(url);
  const send = data => new Response(JSON.stringify(data), { status: 200, headers: { 'Content-Type': 'application/json' } });
  if (/\/orders$/.test(u.pathname)){
    const filters = u.searchParams.getAll('filter');
    const from = Number((filters.find(f => f.startsWith('modifiedTime>=')) || '').slice(14));
    const to = Number((filters.find(f => f.startsWith('modifiedTime<=')) || '').slice(14));
    const limit = Number(u.searchParams.get('limit'));
    const offset = Number(u.searchParams.get('offset')) || 0;
    const hit = orders.filter(o => o.modifiedTime >= from && o.modifiedTime <= to);
    return send({ elements: hit.slice(offset, offset + limit) });
  }
  if (/\/items$/.test(u.pathname)){
    const limit = Number(u.searchParams.get('limit'));
    const offset = Number(u.searchParams.get('offset')) || 0;
    const all = MENU.map((name, i) => ({
      id: 'ITEM_' + i, name, price: 1500, hidden: false,
      categories: { elements: [{ name: i < 3 ? 'Scotch' : 'Spirits' }] }
    }));
    return send({ elements: all.slice(offset, offset + limit) });
  }
  if (/\/employees$/.test(u.pathname)){
    return send({ elements: [{ id: 'EMP0', name: 'Alex', role: 'MANAGER' },
                             { id: 'EMP1', name: 'Sam', role: 'EMPLOYEE' }] });
  }
  if (/\/merchants\/[^/]+$/.test(u.pathname)) return send({ name: 'Excalibur Lounge', currency: 'USD' });
  return new Response('{"message":"no stub"}', { status: 404 });
};

/* ── an owner with a session ── */
const token = 'testtoken';
const tokenHash = createHash('sha256').update(token).digest('hex');
db.prepare(`INSERT INTO users (id,name,email,pw_hash,pw_salt,iterations,role,created_at)
            VALUES (1,'Owner','o@x.com','x','x',1,'owner',?)`).run(new Date().toISOString());
db.prepare('INSERT INTO sessions (token_hash,user_id,expires_at,created_at) VALUES (?,1,?,?)')
  .run(tokenHash, new Date(now + DAY).toISOString(), new Date().toISOString());

const worker = (await import(ROOT + '/worker/src/index.js')).default;
const env = { DB: D1, CLOVER_TOKEN: 'fake', CLOVER_MERCHANT_ID: 'M1', ALLOWED_ORIGINS: 'https://excaliburloungesd.com' };
const call = async (path, init) => {
  const res = await worker.fetch(new Request('https://w.dev' + path, {
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }, ...init
  }), env);
  return { status: res.status, body: await res.json() };
};

let failures = 0;
const check = (label, cond, extra) => {
  console.log((cond ? '  ok   ' : '  FAIL ') + label + (cond ? '' : '  ' + JSON.stringify(extra)));
  if (!cond) failures++;
};

/* ── 1. only the owner may see any of this ── */
const anon = await worker.fetch(new Request('https://w.dev/sales/report'), env);
check('sales report rejects anonymous callers', anon.status === 401, anon.status);

const mgrToken = 'managertoken';
db.prepare(`INSERT INTO users (id,name,email,pw_hash,pw_salt,iterations,role,created_at)
            VALUES (2,'Manager','m@x.com','x','x',1,'manager',?)`).run(new Date().toISOString());
db.prepare('INSERT INTO sessions (token_hash,user_id,expires_at,created_at) VALUES (?,2,?,?)')
  .run(createHash('sha256').update(mgrToken).digest('hex'),
       new Date(now + DAY).toISOString(), new Date().toISOString());
const asManager = async (path, init) => worker.fetch(new Request('https://w.dev' + path, {
  headers: { Authorization: 'Bearer ' + mgrToken, 'Content-Type': 'application/json' }, ...init }), env);
check('a manager cannot read the sales report', (await asManager('/sales/report')).status === 403);
check('a manager cannot trigger a sync',
  (await asManager('/clover/sync', { method: 'POST', body: '{}' })).status === 403);
check('a manager can still read payroll', (await asManager('/payroll')).status === 200);

/* ── 2. first sync, backfilling 60 days ── */
console.log('\nsync (60 day backfill)');
subrequests = 0;
const s1 = await call('/clover/sync', { method: 'POST', body: JSON.stringify({ days: 60 }) });
check('sync succeeded', s1.body.ok === true, s1.body);
check('all 250 orders stored', s1.body.ordersSynced === 250, s1.body.ordersSynced);
check('paged rather than one call', cloverCalls > 3, cloverCalls);
check('menu stored', s1.body.menuItems === MENU.length, s1.body.menuItems);
check('a 250-order sync stays inside the free plan\u2019s 50 subrequests', subrequests <= 50, subrequests);

/* ── 3. the report ── */
console.log('\nreport');
const from = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Los_Angeles' })
  .format(new Date(now - 60 * DAY)).replaceAll('/', '-');
const to = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Los_Angeles' })
  .format(new Date(now + DAY)).replaceAll('/', '-');
const today0 = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Los_Angeles' }).format(new Date()).replaceAll('/', '-');
const r1 = await call('/sales/report?from=' + from + '&to=' + to);
const items = r1.body.items || [];
check('orders counted', r1.body.totals.orders === 250, r1.body.totals);
check('best seller is Macallan 12', items[0] && items[0].name === 'Macallan 12', items[0]);
check('ranked most to least', items.every((it, i) => i === 0 || items[i-1].units >= it.units), items.map(i => i.units));
const mac = items.find(i => i.name === 'Macallan 12');
// 84 orders of i%3==0 give 2 each, 83 of i%3==1 give 1 - less the one refunded line.
check('refunded line excluded', mac && mac.units === 84 * 2 + 83 - 1, mac);
// 84 tickets carry one at $15.00 and one at $16.00; 83 carry one at $15.00,
// less the single refunded line.
check('revenue matches the fixture', mac && Math.abs(mac.revenue - (84 * 31 + 83 * 15 - 15)) < 0.01, mac);
const unsold = (r1.body.neverSold || []).map(i => i.name);
// Neither ever appears on a ticket, and both are on the menu.
check('menu items with no sales are named', unsold.join('|') === 'Blanton\u2019s|Dusty Bottle', unsold);

/* ── 3b. the money summary ── */
console.log('\nmoney');
const T = r1.body.totals;
check('tips totalled', T.tips === 250 * 3, T.tips);
check('gross is line items, not order totals', Math.abs(T.grossSales - (T.orderTotal / 1.0775)) < 60, T);
check('net sales equals gross less discounts', Math.abs(T.netSales - (T.grossSales - T.discounts)) < 0.01, T);
check('tax captured', T.tax > 0, T.tax);
check('a refund is reported', T.refunds === 5, T.refunds);
check('collected is payments plus tips less refunds',
  Math.abs(T.collected - (T.orderTotal + T.tips - T.refunds)) < 0.02, T);
check('average ticket', T.avgTicket > 0, T.avgTicket);

const tenders = r1.body.tenders.map(t => t.name).sort();
check('tenders split by type', tenders.join(',') === 'Cash,Credit Card', tenders);
check('tender amounts add up to payments',
  Math.abs(r1.body.tenders.reduce((s, t) => s + t.amount, 0) - T.orderTotal) < 0.02, r1.body.tenders);

const staffRows = r1.body.staff;
check('payments attributed to named staff',
  staffRows.length === 2 && staffRows.every(s => ['Alex', 'Sam'].includes(s.name)), staffRows);
check('tips split per person',
  Math.abs(staffRows.reduce((s, r) => s + r.tips, 0) - T.tips) < 0.01, staffRows);

const cats = r1.body.categories.map(c => c.name).sort();
check('items grouped by category', cats.join(',') === 'Scotch,Spirits', cats);

check('a multi-day range is bucketed by day', r1.body.bucket === 'day', r1.body.bucket);
check('every day in the trend carries tips', r1.body.trend.every(d => d.tips > 0), r1.body.trend.slice(0, 2));

/* ── 3c. a single day reads hour by hour ── */
const oneDay = await call('/sales/report?from=' + today0 + '&to=' + today0);
check('a single day is bucketed by hour', oneDay.body.bucket === 'hour', oneDay.body.bucket);
check('hours are 0-23', (oneDay.body.trend || []).every(t => t.key >= 0 && t.key <= 23),
  (oneDay.body.trend || []).map(t => t.key));

/* ── 4. a narrow range only counts its own days ── */
const r2 = await call('/sales/report?from=' + today0 + '&to=' + today0);
check('narrow range is a subset', r2.body.totals.orders > 0 && r2.body.totals.orders < 250, r2.body.totals.orders);
check('narrow range lists more unsold items', (r2.body.neverSold || []).length >= 1, r2.body.neverSold);

/* ── 5. syncing twice must not double-count ── */
console.log('\nre-sync');
const s2 = await call('/clover/sync', { method: 'POST', body: JSON.stringify({ days: 60 }) });
const r3 = await call('/sales/report?from=' + from + '&to=' + to);
check('re-sync stored the same orders again', s2.body.ordersSynced === 250, s2.body.ordersSynced);
check('order count unchanged', r3.body.totals.orders === 250, r3.body.totals.orders);
check('unit count unchanged',
  JSON.stringify(r3.body.items) === JSON.stringify(r1.body.items),
  { before: r1.body.items[0], after: r3.body.items[0] });

/* ── 6. an incremental sync picks up an edited order ── */
console.log('\nincremental');
orders[0].total = 99999;
orders[0].modifiedTime = Date.now();
orders[0].lineItems.elements = [{ id: 'NEWLINE', name: 'Blanton’s', price: 4000, item: { id: 'ITEM_1' } }];
const s3 = await call('/clover/sync', { method: 'POST', body: JSON.stringify({}) });
// The cursor rewinds two hours, so a handful of very recent orders come
// back with the edited one. What matters is that it is not the whole history.
check('incremental run skipped the settled history', s3.body.ordersSynced > 0 && s3.body.ordersSynced < 20, s3.body.ordersSynced);
const r4 = await call('/sales/report?from=' + from + '&to=' + to);
check('replaced lines do not linger',
  (r4.body.items.find(i => i.name === 'Blanton’s') || {}).units === 1,
  r4.body.items.find(i => i.name === 'Blanton’s'));
check('order count still 250', r4.body.totals.orders === 250, r4.body.totals.orders);

/* ── 7. Clover refusing is reported, not swallowed ── */
console.log('\nfailure handling');
globalThis.fetch = async () => new Response('{"message":"401 Unauthorized"}', { status: 401 });
const s4 = await call('/clover/sync', { method: 'POST', body: JSON.stringify({ days: 5 }) });
check('a rejected token surfaces as ok:false', s4.body.ok === false && s4.status === 200, s4.body);
check('the failing step is named', s4.body.step === 'orders', s4.body);

console.log(failures ? '\n' + failures + ' FAILED' : '\nall passed');
process.exit(failures ? 1 : 0);
