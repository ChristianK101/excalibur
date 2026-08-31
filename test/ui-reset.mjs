/**
 * Walks the forgot-password screens in a real browser. The worker is mocked at
 * the network layer, so this checks the modal's own behaviour: which fields
 * show, what the buttons say, and that the code screen signs you in.
 *
 *   npm install playwright && node test/ui-reset.mjs
 *
 * Set CHROME to a browser binary if Playwright's own download is not present.
 * The worker's side of the same flow is covered by worker/test/reset.test.mjs,
 * which needs neither a browser nor a network.
 */
import { chromium } from 'playwright';
import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');
const PORT = 8931;
const TYPES = { html: 'text/html', js: 'text/javascript', css: 'text/css', jpg: 'image/jpeg', png: 'image/png' };

const server = createServer((req, res) => {
  const path = ROOT + (req.url === '/' ? '/index.html' : req.url.split('?')[0]);
  if (!existsSync(path)) { res.writeHead(404); return res.end('no'); }
  res.writeHead(200, { 'Content-Type': TYPES[path.split('.').pop()] || 'text/plain' });
  res.end(readFileSync(path));
});
await new Promise(r => server.listen(PORT, r));

let failures = 0;
const check = (label, cond, extra) => {
  console.log((cond ? '  ok   ' : '  FAIL ') + label + (cond ? '' : '  ' + JSON.stringify(extra)));
  if (!cond) failures++;
};

const browser = await chromium.launch(process.env.CHROME ? { executablePath: process.env.CHROME } : {});
const page = await browser.newPage();

const seen = [];
await page.route('**/excalibur-auth.christiankalasho.workers.dev/**', async route => {
  const url = new URL(route.request().url());
  const body = route.request().postData();
  seen.push({ path: url.pathname, body: body && JSON.parse(body) });
  const send = (status, data) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });

  if (url.pathname === '/auth/me') return send(401, { error: 'Not signed in.' });
  if (url.pathname === '/track') return send(200, { ok: true });
  if (url.pathname === '/auth/reset/request') return send(200, { ok: true, expiresInMinutes: 15 });
  if (url.pathname === '/auth/reset/confirm'){
    const b = JSON.parse(body);
    if (b.code !== '123456') return send(400, { error: 'That code is not right, or it has expired. Ask for a new one.' });
    return send(200, { token: 'tok', user: { id: 1, name: 'Christian', email: b.email, role: 'owner' } });
  }
  return send(404, { error: 'Not found.' });
});

await page.goto('http://localhost:' + PORT + '/index.html');
// The age gate stands in front of everything on the homepage.
await page.evaluate(() => sessionStorage.setItem('ageVerified', 'true'));
await page.reload();
// And the OpusX ad opens over the top of it once the age gate is past.
await page.waitForTimeout(300);
await page.evaluate(() => { if (typeof closeAdModal === 'function') closeAdModal(); });

const vis = sel => page.isVisible(sel);
const text = sel => page.textContent(sel);

await page.click('.auth-nav >> text=Sign In');
check('sign-in screen hides the code field', !(await vis('#authCodeField')));
check('sign-in offers a reset', (await text('#authSwitch')).includes('Forgot your password?'));

await page.click('#authSwitch >> text=Reset it');
check('forgot screen titled', (await text('#authTitle')) === 'Forgot Password');
check('forgot screen asks only for the email',
  await vis('#authEmail') && !(await vis('#authPasswordField')) && !(await vis('#authCodeField')));
check('button reads as sending a code', (await page.inputValue('#authEmail')) === '' &&
  (await text('#authSubmit')) === 'Email Me A Code');

await page.fill('#authEmail', 'christiankalasho@gmail.com');
await page.click('#authSubmit');
await page.waitForTimeout(400);

check('the request was sent', seen.some(s => s.path === '/auth/reset/request'), seen.map(s => s.path));
check('moved to the code screen', (await text('#authTitle')) === 'Enter Your Code');
check('the button was relabelled for the new screen',
  (await text('#authSubmit')) === 'Set New Password', await text('#authSubmit'));
check('the message says nothing about whether the account exists',
  (await text('#authMsg')).startsWith('If that address has an account'), await text('#authMsg'));
check('the email carried over', (await page.inputValue('#authEmail')) === 'christiankalasho@gmail.com');
check('code and password fields are showing',
  await vis('#authCodeField') && await vis('#authPasswordField'));
check('the password field is labelled as the new one',
  (await text('#authPasswordLabel')) === 'New Password');

// A wrong code keeps you on the screen with the reason shown.
await page.fill('#authCode', '000000');
await page.fill('#authPassword', 'a-much-better-password');
await page.click('#authSubmit');
await page.waitForTimeout(400);
check('a wrong code is reported', (await text('#authMsg')).includes('not right'), await text('#authMsg'));
check('and the screen stays put', (await text('#authTitle')) === 'Enter Your Code');
check('the button label survives a failure', (await text('#authSubmit')) === 'Set New Password');

// A short password never reaches the worker.
const before = seen.filter(s => s.path === '/auth/reset/confirm').length;
await page.fill('#authPassword', 'short');
await page.click('#authSubmit');
await page.waitForTimeout(200);
check('a short password is caught in the browser',
  seen.filter(s => s.path === '/auth/reset/confirm').length === before &&
  (await text('#authMsg')).includes('at least 10 characters'), await text('#authMsg'));

// The real thing.
await page.fill('#authCode', '123456');
await page.fill('#authPassword', 'a-much-better-password');
await page.click('#authSubmit');
await page.waitForTimeout(400);
check('a good code signs you in', (await text('#authMsg')).includes('Password changed'), await text('#authMsg'));
await page.waitForTimeout(900);
check('the modal closes', !(await page.isVisible('#authOverlay .auth-modal')));
check('the nav shows the account', (await text('.auth-nav')).includes('Christian'), await text('.auth-nav'));
check('the owner dashboard link appears', await vis('.nav-dash'));

// And back out again, without the code screen leaking into sign-in.
await page.click('.auth-nav >> text=Sign Out');
await page.waitForTimeout(200);
await page.click('.auth-nav >> text=Sign In');
check('sign-in is clean afterwards',
  !(await vis('#authCodeField')) && (await text('#authSubmit')) === 'Sign In' &&
  (await page.inputValue('#authPassword')) === '');

await browser.close();
server.close();
console.log(failures ? '\n' + failures + ' FAILED' : '\nall passed');
process.exit(failures ? 1 : 0);
