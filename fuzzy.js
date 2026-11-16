/* ── FUZZY SEARCH ──
   So a misspelt search still finds the bottle. Exact matches always rank
   above approximate ones, and a query only ever matches when every word in
   it lands somewhere, so "blue label" cannot be satisfied by "blue" alone. */

/** Lowercase with accents stripped, so "esteli" reaches "Estelí". */
function fuzzNorm(s){
  return String(s == null ? '' : s).normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
}

/**
 * How far wrong a word is allowed to be before it stops counting as a typo.
 * Short words get no leeway at all: at three letters, one edit turns "rum"
 * into "run" and "gin" into "gun", and the menu fills with noise.
 */
function fuzzTolerance(len){
  if (len <= 3) return 0;
  if (len <= 6) return 1;
  return 2;
}

/**
 * Edit distance counting a swap of two neighbours as one mistake rather than
 * two, because "mcallan" for "macallan" is the single commonest way to
 * mistype a name. Capped: once every square in a row is over the cap the
 * answer cannot come back under it, so the rest is not worth computing.
 */
function fuzzDistance(a, b, cap){
  if (a === b) return 0;
  const al = a.length, bl = b.length;
  if (!al) return bl;
  if (!bl) return al;
  if (Math.abs(al - bl) > cap) return cap + 1;

  let two = null;                       // the row before last
  let one = new Array(bl + 1);
  for (let j = 0; j <= bl; j++) one[j] = j;

  for (let i = 1; i <= al; i++){
    const row = new Array(bl + 1);
    row[0] = i;
    let best = i;
    for (let j = 1; j <= bl; j++){
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(row[j - 1] + 1, one[j] + 1, one[j - 1] + cost);
      if (two && i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]){
        v = Math.min(v, two[j - 2] + 1);
      }
      row[j] = v;
      if (v < best) best = v;
    }
    if (best > cap) return cap + 1;
    two = one;
    one = row;
  }
  return one[bl];
}

/**
 * One typed word against one word from the menu. Lower is better:
 * 0 exact, 1 starts with, 2 contains, 3 and up means it took a correction.
 * null when the two are not the same word at all.
 */
function fuzzWord(q, w){
  if (w === q) return 0;
  if (w.startsWith(q)) return 1;
  if (w.includes(q)) return 2;

  const cap = fuzzTolerance(q.length);
  if (!cap) return null;

  const d = fuzzDistance(q, w, cap);
  if (d <= cap) return 2 + d;

  // Against the opening of a longer word, so a name that simply ends
  // differently still lands: "johnny" reaches "johnnie", "macalle" reaches
  // "macallan". Without this, a word only one letter short of the menu's
  // spelling can need two edits and fall outside its own tolerance.
  if (w.length > q.length){
    for (let take = q.length; take <= Math.min(q.length + cap, w.length); take++){
      if (fuzzDistance(q, w.slice(0, take), cap) <= cap) return 3 + cap;
    }
  }
  return null;
}

/**
 * Scores a whole query against a piece of menu text. Lower is better and
 * null means no match. A score of 0 is the typed phrase appearing verbatim;
 * anything from FUZZ_APPROX up needed a spelling correction somewhere.
 */
const FUZZ_APPROX = 10;

function fuzzyScore(query, text){
  const q = fuzzNorm(query).trim();
  if (!q) return 0;
  const t = fuzzNorm(text);
  if (t.includes(q)) return 0;

  const words = q.split(/\s+/).filter(Boolean);
  const candidates = t.split(/[^a-z0-9]+/).filter(Boolean);
  if (!candidates.length) return null;

  let total = 0, corrected = false;
  for (const word of words){
    let best = null;
    for (const cand of candidates){
      const s = fuzzWord(word, cand);
      if (s !== null && (best === null || s < best)) best = s;
    }
    if (best === null) return null;
    if (best > 2) corrected = true;
    total += best;
  }
  return corrected ? total + FUZZ_APPROX : total + 1;
}

/** The best score across several fields, or null if none of them matched. */
function fuzzyBest(scores){
  let best = null;
  for (const s of scores) if (s !== null && (best === null || s < best)) best = s;
  return best;
}

/** True when the match only held up after correcting a spelling. */
function fuzzyIsApprox(score){
  return score !== null && score >= FUZZ_APPROX;
}

if (typeof module !== 'undefined' && module.exports){
  module.exports = { fuzzNorm, fuzzDistance, fuzzWord, fuzzyScore, fuzzyBest, fuzzyIsApprox, FUZZ_APPROX };
}
