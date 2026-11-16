/**
 * Drives both menu searches in a real browser, because the unit tests prove
 * the matcher works and say nothing about the page being wired to it.
 *
 *   npm install playwright && node test/menu-search.mjs
 *
 * Set CHROME to a browser binary if Playwright's own download is absent.
 */
import { chromium } from 'playwright';
import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');
const PORT = 8942;
const TYPES = { html:'text/html', js:'text/javascript', css:'text/css', jpg:'image/jpeg', png:'image/png' };
const server = createServer((req,res) => {
  const path = ROOT + (req.url === '/' ? '/index.html' : req.url.split('?')[0]);
  if (!existsSync(path)) { res.writeHead(404); return res.end('no'); }
  res.writeHead(200, { 'Content-Type': TYPES[path.split('.').pop()] || 'text/plain' });
  res.end(readFileSync(path));
});
await new Promise(r => server.listen(PORT, r));

let failures = 0;
const check = (l,c,e) => { console.log((c?'  ok   ':'  FAIL ')+l+(c?'':'  '+JSON.stringify(e))); if(!c) failures++; };

const browser = await chromium.launch(process.env.CHROME ? { executablePath: process.env.CHROME } : {});
const page = await browser.newPage();
const errors = [];
page.on('pageerror', e => errors.push(String(e)));
await page.route('**/*.workers.dev/**', r => r.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
await page.goto('http://localhost:' + PORT + '/menu.html');
await page.waitForTimeout(500);

/* drinks */
const drinks = async q => {
  await page.fill('#searchInput', q);
  await page.waitForTimeout(150);
  return {
    title: (await page.textContent('#searchResultsTitle')).trim(),
    names: await page.$$eval('#searchResultsList .result-name', els => els.map(e => e.textContent.trim())),
    hint: await page.$$eval('#searchResultsList .search-hint', els => els.length)
  };
};

const exact = await drinks('macallan');
check('an exact drinks search still works', exact.names.length > 0, exact);
check('and is titled as results', /result/.test(exact.title), exact.title);
check('no close-match hint on an exact search', exact.hint === 0, exact.hint);

const typo = await drinks('macallen');
check('a misspelt drinks search finds something', typo.names.length > 0, typo);
check('it finds the same bottles',
  typo.names.some(n => exact.names.includes(n)), { typo: typo.names, exact: exact.names });
check('titled as close matches', /close match/.test(typo.title), typo.title);
check('and says so above the list', typo.hint === 1, typo.hint);

const nonsense = await drinks('zzzqqq');
check('real nonsense still finds nothing', nonsense.names.length === 0, nonsense);

/* cigars */
await page.evaluate(() => switchTab('cigars', document.querySelectorAll('.tab-btn')[1]));
await page.waitForTimeout(250);
const cigars = async q => {
  await page.fill('#cigarSearchInput', q);
  await page.waitForTimeout(150);
  return {
    meta: (await page.textContent('#cigarSearchMeta')).trim(),
    brands: await page.$$eval('#panel-cigars .cigars-grid .cigar-brand',
      els => els.filter(e => e.style.display !== 'none')
               .map(e => e.querySelector('.cigar-brand-name').textContent.trim()))
  };
};

const cExact = await cigars('padron');
check('an exact cigar search works', cExact.brands.includes('Padron'), cExact);
const cTypo = await cigars('padrone');
check('a misspelt cigar search finds the brand', cTypo.brands.includes('Padron'), cTypo);
check('and says it is a close match', /close/.test(cTypo.meta), cTypo.meta);

const cAccent = await cigars('esteli');
check('accents are still ignored', cAccent.brands.length > 0, cAccent);
const cTypo2 = await cigars('montecristo');
check('montecristo found', cTypo2.brands.includes('Montecristo'), cTypo2);
const cTypo3 = await cigars('montechristo');
check('and when misspelt', cTypo3.brands.includes('Montecristo'), cTypo3);

const cNone = await cigars('zzzqqq');
check('nonsense matches no cigar', cNone.brands.length === 0, cNone);
check('and says so', /No match/.test(cNone.meta), cNone.meta);

check('no javascript errors on the page', errors.length === 0, errors);

await browser.close();
server.close();
console.log(failures ? '\n' + failures + ' FAILED' : '\nall passed');
process.exit(failures ? 1 : 0);
