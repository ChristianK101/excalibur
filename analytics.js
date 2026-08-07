/* ── ANALYTICS ──
   First-party visit and search tracking for the lounge dashboard.
   No cookies: the worker derives a per-day visitor hash from the request.
   The owner's own visits are skipped so testing doesn't inflate the numbers. */

const TRACK_URL = (typeof AUTH_URL !== 'undefined')
  ? AUTH_URL
  : 'https://excalibur-auth.christiankalasho.workers.dev';

const TRACK_ROLE_KEY = 'excaliburAuthRole';

function trackIsOwner(){
  try { return localStorage.getItem(TRACK_ROLE_KEY) === 'owner'; } catch(e){ return false; }
}

function trackSend(payload){
  if (trackIsOwner()) return;
  try {
    const body = JSON.stringify(payload);
    // sendBeacon survives the page being closed mid-request; fetch is the fallback.
    if (navigator.sendBeacon){
      navigator.sendBeacon(TRACK_URL + '/track', new Blob([body], { type: 'application/json' }));
    } else {
      fetch(TRACK_URL + '/track', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
        keepalive: true
      }).catch(() => {});
    }
  } catch(e){}
}

function trackPageview(){
  let path = location.pathname;
  if (!path || path === '/') path = '/index.html';
  if (/dashboard\.html$/.test(path)) return;   // the owner's own dashboard isn't traffic
  trackSend({ type: 'pageview', path: path });
}

/* Searches fire on every keystroke, so wait until typing stops and only
   record terms of two characters or more. Repeats of the same term are
   ignored, otherwise one hesitant typist becomes ten "searches". */
function trackSearchInput(input, category, countResults){
  if (!input) return;
  let timer = null;
  let last = '';
  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      const term = input.value.trim();
      if (term.length < 2 || term.toLowerCase() === last) return;
      last = term.toLowerCase();
      let hits = null;
      try { hits = countResults(); } catch(e){}
      trackSend({ type: 'search', category: category, term: term, hits: hits });
    }, 900);
  });
}

function trackInit(){
  trackPageview();

  // Cigar search: count the brand cards still visible after filtering.
  trackSearchInput(
    document.getElementById('cigarSearchInput'),
    'cigar',
    () => Array.from(document.querySelectorAll('#panel-cigars .cigars-grid .cigar-brand'))
      .filter(el => el.style.display !== 'none').length
  );

  // Spirits search: count the rendered result rows.
  trackSearchInput(
    document.getElementById('searchInput'),
    'drink',
    () => document.querySelectorAll('#searchResultsList .search-result-item').length
  );
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', trackInit);
else trackInit();
