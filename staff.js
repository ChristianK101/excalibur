/* ── Shared helpers for the staff pages ── */

function esc(s){
  return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

const TZ = 'America/Los_Angeles';

function fmtWhen(iso){
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-US', {
    timeZone: TZ, month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit'
  });
}

function fmtTime(iso){
  if (!iso) return '—';
  return new Date(iso).toLocaleTimeString('en-US', {
    timeZone: TZ, hour: 'numeric', minute: '2-digit'
  });
}

function fmtDay(iso){
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', {
    timeZone: TZ, month: 'short', day: 'numeric', year: 'numeric'
  });
}

/** YYYY-MM-DD for an instant, in Pacific. */
function dayKey(iso){
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit'
  }).format(new Date(iso));
}

function money(n){
  return n == null ? '—' : '$' + Number(n).toFixed(2);
}

/**
 * The first 64 bits of an IPv6 address — the network, not the device.
 * Devices rotate the second half for privacy, so only this part is stable.
 * Returns null for IPv4.
 */
function ipv6Network(ip){
  if (!ip || ip.indexOf(':') === -1) return null;
  const [head, tail] = ip.split('::');
  let parts = head.split(':').filter(Boolean);
  if (tail !== undefined){
    const rest = tail.split(':').filter(Boolean);
    while (parts.length + rest.length < 8) parts.push('0');
    parts = parts.concat(rest);
  }
  // Normalise each group so 0f3d and f3d compare equal.
  return parts.slice(0, 4).map(h => parseInt(h, 16).toString(16)).join(':');
}

/** Is this punch from one of the lounge's networks? Unknown counts as yes. */
function onLoungeNetwork(ip, networks){
  if (!ip || !networks || !networks.length) return true;
  const mine = ipv6Network(ip);
  return networks.some(n => {
    const theirs = ipv6Network(n);
    return (mine && theirs) ? mine === theirs : ip === n;
  });
}

/** How far Pacific is from UTC at a given instant, in ms (PDT = -7h). */
function pacificOffsetMs(date){
  const name = new Intl.DateTimeFormat('en-US', { timeZone: TZ, timeZoneName: 'shortOffset' })
    .formatToParts(date).find(p => p.type === 'timeZoneName').value;   // "GMT-7"
  const m = /GMT([+-])(\d{1,2})(?::(\d{2}))?/.exec(name);
  if (!m) return -8 * 3600000;
  const sign = m[1] === '-' ? -1 : 1;
  return sign * ((Number(m[2]) * 60 + Number(m[3] || 0)) * 60000);
}

/**
 * Turn a wall-clock date and time *at the lounge* into a UTC instant,
 * whatever timezone the person scheduling happens to be in. Using
 * new Date('...T09:00') instead would silently shift every shift by the
 * scheduler's own offset.
 */
function pacificToInstant(dateStr, timeStr){
  if (!dateStr || !timeStr) return null;
  const naive = Date.parse(dateStr + 'T' + timeStr + ':00Z');
  if (Number.isNaN(naive)) return null;
  let off = pacificOffsetMs(new Date(naive));
  let result = naive - off;
  // Re-check at the resolved instant so shifts near a DST switch land right.
  const off2 = pacificOffsetMs(new Date(result));
  if (off2 !== off) result = naive - off2;
  return new Date(result).toISOString();
}

function flash(text, kind){
  const el = document.getElementById('msg');
  if (!el) return;
  el.textContent = text;
  el.className = 'msg show ' + (kind || 'err');
  if (kind === 'ok') setTimeout(() => { el.className = 'msg'; }, 3000);
}

function showState(title, message){
  const s = document.getElementById('state');
  if (s) s.innerHTML = '<div class="state"><h2>' + esc(title) + '</h2><p>' + esc(message) + '</p></div>';
  const b = document.getElementById('body');
  if (b) b.style.display = 'none';
  const m = document.getElementById('meta');
  if (m) m.textContent = '';
}

/**
 * Wait for auth.js to resolve the session, check the caller is senior enough,
 * then run the page's loader. The worker enforces this too - this is only so
 * the page shows something sensible instead of a wall of errors.
 */
const STAFF_RANK = { customer: 0, employee: 1, manager: 2, owner: 3 };

function staffBoot(minRole, load){
  (async function(){
    for (let i = 0; i < 40 && authToken() && !authUser; i++){
      await new Promise(r => setTimeout(r, 100));
    }
    if (!authToken() || !authUser){
      showState('Sign in required', 'Use Sign In at the top right of the page.');
      return;
    }
    if ((STAFF_RANK[authUser.role] || 0) < STAFF_RANK[minRole]){
      showState('No access', 'This page is for ' + minRole + 's. You are signed in as ' + authUser.role + '.');
      return;
    }
    document.getElementById('state').innerHTML = '';
    document.getElementById('body').style.display = '';
    try {
      await load();
    } catch (err){
      showState('Could not load', err.message || String(err));
    }
  })();
}
