/**
 * Checks the fuzzy matcher behind both menu searches: that real misspellings
 * find the bottle, that exact matches still rank first, and - the part that
 * matters most - that loose matching does not start returning nonsense.
 *
 *   node test/fuzzy.test.mjs
 *
 * No dependencies and no network. Exits non-zero if anything fails.
 */
import { readFileSync } from 'node:fs';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');
const src = readFileSync(ROOT + '/fuzzy.js', 'utf8');
const { fuzzyScore, fuzzyBest, fuzzyIsApprox } =
  new Function(src + '\nreturn { fuzzyScore, fuzzyBest, fuzzyIsApprox };')();

let failures = 0;
const check = (label, cond, extra) => {
  console.log((cond ? '  ok   ' : '  FAIL ') + label + (cond ? '' : '  ' + JSON.stringify(extra)));
  if (!cond) failures++;
};
const hits = (q, t) => fuzzyScore(q, t) !== null;

/* ── exact behaviour is unchanged ── */
console.log('exact matches');
check('a full name matches', fuzzyScore('Macallan 12', 'The Macallan 12') === 0);
check('a partial word matches', fuzzyScore('macal', 'The Macallan 12') === 0);
check('case is ignored', fuzzyScore('MACALLAN', 'The Macallan 12') === 0);
check('and is not flagged as approximate', !fuzzyIsApprox(fuzzyScore('macallan', 'The Macallan 12')));
check('accents are ignored', hits('esteli', 'Serie R Estelí'), fuzzyScore('esteli', 'Serie R Estelí'));
check('an empty query matches everything', fuzzyScore('', 'anything') === 0);

/* ── the point of the exercise ── */
console.log('\nmisspellings');
const typos = [
  ['macallen', 'The Macallan 12'],
  ['mcallan',  'The Macallan 12'],        // two letters swapped
  ['macalan',  'The Macallan 12'],        // a letter dropped
  ['maccallan','The Macallan 12'],        // a letter doubled
  ['blantons', "Blanton's Single Barrel"],
  ['hennesy',  'Hennessy VS'],
  ['casamigo', 'Casamigos Blanco'],
  ['padrone',  'Padron 1964 Anniversary'],
  ['montechristo', 'Montecristo Classic Series'],
  ['opus x',   'Fuente Fuente OpusX'],
  ['opux',     'Fuente Fuente OpusX'],
  ['liga privada no 9', 'Liga Privada No. 9'],
  ['johnny walker', 'Johnnie Walker Blue Label'],
  ['glenfidich', 'Glenfiddich 18'],
  ['dom perignon', 'Dom Pérignon']
];
for (const [typed, listed] of typos){
  check(`"${typed}" finds "${listed}"`, hits(typed, listed), fuzzyScore(typed, listed));
}

/* ── and what it must NOT do ── */
console.log('\nthings that must not match');
const wrong = [
  ['rum',      'Ron Zacapa 23'],          // three letters, one edit apart
  ['gin',      'Gun Powder'],
  ['vodka',    'Vanilla Cream Ale'],
  ['macallan', 'Glenfiddich 18'],
  ['tequila',  'Tennessee Whiskey'],
  ['blue',     'Black Label'],
  ['cohiba',   'Cuba Libre']
];
for (const [typed, listed] of wrong){
  check(`"${typed}" does not match "${listed}"`, !hits(typed, listed), fuzzyScore(typed, listed));
}

// Padron and Patron are one edit apart and both real products. They never
// appear on the same menu, so the near miss is the useful answer - but it
// must be offered as a correction, never as a clean hit.
check('a one-edit neighbour is offered only as a correction',
  fuzzyIsApprox(fuzzyScore('padron', 'Patron Silver')), fuzzyScore('padron', 'Patron Silver'));
check('and loses to the real thing',
  fuzzyScore('padron', 'Padron 1964') < fuzzyScore('padron', 'Patron Silver'));

/* ── every word has to land ── */
console.log('\nmulti-word queries');
check('both words must match', !hits('blue label', 'Johnnie Walker Black Label'));
check('both words matching is enough', hits('blue label', 'Johnnie Walker Blue Label'));
check('word order does not matter', hits('label blue', 'Johnnie Walker Blue Label'));
check('one word misspelt is still found', hits('johnie blue', 'Johnnie Walker Blue Label'));
check('a word that matches nothing fails the whole query',
  !hits('blue label mezcal', 'Johnnie Walker Blue Label'));

/* ── ranking ── */
console.log('\nranking');
const rank = (q, list) => list
  .map(t => ({ t, s: fuzzyScore(q, t) }))
  .filter(r => r.s !== null)
  .sort((a, b) => a.s - b.s)
  .map(r => r.t);

const shelf = ['Macallan Rare Cask', 'The Macallan 12', 'Macallen Reserve Blend', 'Glenlivet 12'];
check('an exact hit leads', rank('macallan 12', shelf)[0] === 'The Macallan 12',
  rank('macallan 12', shelf));
check('a corrected hit ranks below every clean one',
  (() => {
    const r = rank('macallan', shelf);
    const approx = r.findIndex(t => fuzzyIsApprox(fuzzyScore('macallan', t)));
    const lastClean = r.map(t => fuzzyIsApprox(fuzzyScore('macallan', t))).lastIndexOf(false);
    return approx === -1 || approx > lastClean;
  })(), rank('macallan', shelf));
check('a glenlivet is not dragged in by a macallan search',
  !rank('macallan', shelf).includes('Glenlivet 12'));

/* ── fuzzyBest across fields ── */
console.log('\nscoring helpers');
check('the best of several fields wins',
  fuzzyBest([fuzzyScore('oak', 'Casamigos'), fuzzyScore('oak', 'oak and vanilla')]) === 0);
check('all-null stays null', fuzzyBest([null, null]) === null);
check('a correction is flagged', fuzzyIsApprox(fuzzyScore('hennesy', 'Hennessy VS')));
check('a clean hit is not', !fuzzyIsApprox(fuzzyScore('hennessy', 'Hennessy VS')));

/* ── it has to stay fast enough to run on every keystroke ── */
console.log('\nspeed');
const menu = [];
for (let i = 0; i < 600; i++) menu.push('Bottle Number ' + i + ' Reserve Cask Strength');
const t0 = Date.now();
for (let i = 0; i < 20; i++) menu.forEach(m => fuzzyScore('reserv cask', m));
const ms = Date.now() - t0;
check('600 items x 20 passes under 500ms', ms < 500, ms + 'ms');

console.log(failures ? '\n' + failures + ' FAILED' : '\nall passed');
process.exit(failures ? 1 : 0);
