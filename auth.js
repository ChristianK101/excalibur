/* ── ACCOUNTS ──
   Front-end for the Excalibur account system.
   Talks to the auth worker; see worker/README.md for deployment.
   The session token is kept in localStorage and sent as a Bearer header. */

const AUTH_URL = 'https://excalibur-auth.christiankalasho.workers.dev';
const AUTH_TOKEN_KEY = 'excaliburAuthToken';

let authUser = null;

function authToken(){ try { return localStorage.getItem(AUTH_TOKEN_KEY); } catch(e){ return null; } }
function authSetToken(t){ try { t ? localStorage.setItem(AUTH_TOKEN_KEY, t) : localStorage.removeItem(AUTH_TOKEN_KEY); } catch(e){} }

async function authApi(path, body, method){
  const opts = { method: method || (body ? 'POST' : 'GET'), headers: {} };
  if (body){ opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const t = authToken();
  if (t) opts.headers['Authorization'] = 'Bearer ' + t;
  let res;
  try {
    res = await fetch(AUTH_URL + path, opts);
  } catch(e){
    throw new Error('Could not reach the account service. Please try again.');
  }
  let data = {};
  try { data = await res.json(); } catch(e){}
  if (!res.ok) throw new Error(data.error || 'Something went wrong. Please try again.');
  return data;
}

/* Cached so analytics.js can skip the owner's own visits without waiting
   for /auth/me to come back. */
function authCacheRole(role){
  try {
    role ? localStorage.setItem('excaliburAuthRole', role)
         : localStorage.removeItem('excaliburAuthRole');
  } catch(e){}
}

/* The Dashboard link sits centred in the nav bar, owner only. */
function authRenderDash(){
  document.querySelectorAll('nav').forEach(nav => {
    const existing = nav.querySelector('.nav-dash');
    const wanted = authUser && authUser.role === 'owner' && !/dashboard\.html$/.test(location.pathname);
    if (wanted && !existing){
      const a = document.createElement('a');
      a.className = 'nav-dash';
      a.href = 'dashboard.html';
      a.innerHTML = '&#128202; Dashboard';
      nav.appendChild(a);
    } else if (!wanted && existing){
      existing.remove();
    }
  });
}

/* ── nav rendering ── */
function authRenderNav(){
  authRenderDash();
  document.querySelectorAll('.auth-nav').forEach(el => {
    if (authUser){
      const role = authUser.role && authUser.role !== 'member'
        ? '<span class="auth-user-role">' + authEsc(authUser.role) + '</span>' : '';
      el.innerHTML =
        '<span class="auth-user"><span class="auth-user-name">' + authEsc(authUser.name) + '</span>' + role + '</span>' +
        '<button class="auth-btn auth-btn-ghost" onclick="authSignOut()">Sign Out</button>';
    } else {
      el.innerHTML =
        '<button class="auth-btn auth-btn-ghost" onclick="authOpen(\'signin\')">Sign In</button>' +
        '<button class="auth-btn" onclick="authOpen(\'signup\')">Sign Up</button>';
    }
  });
}

function authEsc(s){
  return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

/* ── modal ── */
function authBuildModal(){
  if (document.getElementById('authOverlay')) return;
  const wrap = document.createElement('div');
  wrap.className = 'auth-overlay';
  wrap.id = 'authOverlay';
  wrap.onclick = e => { if (e.target === wrap) authClose(); };
  wrap.innerHTML =
    '<div class="auth-modal">' +
      '<button class="auth-close" onclick="authClose()" aria-label="Close">&#10005;</button>' +
      '<div class="auth-title" id="authTitle">Create Account</div>' +
      '<div class="auth-sub" id="authSub">Join the Excalibur roster.</div>' +
      '<div class="auth-divider"></div>' +
      '<div class="auth-msg" id="authMsg"></div>' +
      '<form id="authForm" autocomplete="on" novalidate>' +
        '<div class="auth-field" id="authNameField">' +
          '<label for="authName">Name</label>' +
          '<input type="text" id="authName" name="name" autocomplete="name" maxlength="80">' +
        '</div>' +
        '<div class="auth-field">' +
          '<label for="authEmail">Email</label>' +
          '<input type="email" id="authEmail" name="email" autocomplete="email" required maxlength="160">' +
        '</div>' +
        '<div class="auth-field">' +
          '<label for="authPassword">Password</label>' +
          '<input type="password" id="authPassword" name="password" required minlength="10" maxlength="200">' +
        '</div>' +
        '<label class="auth-check" id="authAgeCheck">' +
          '<input type="checkbox" id="authAge">' +
          '<span>I confirm I am 21 years of age or older.</span>' +
        '</label>' +
        '<button type="submit" class="auth-submit" id="authSubmit">Create Account</button>' +
      '</form>' +
      '<div class="auth-switch" id="authSwitch"></div>' +
      '<div class="auth-legal">Excalibur Cigar &amp; Scotch Lounge &middot; We never share your details.</div>' +
    '</div>';
  document.body.appendChild(wrap);
  document.getElementById('authForm').addEventListener('submit', authSubmit);
}

let authMode = 'signup';

function authOpen(mode){
  authBuildModal();
  authMode = mode === 'signin' ? 'signin' : 'signup';
  const signup = authMode === 'signup';
  document.getElementById('authTitle').textContent = signup ? 'Create Account' : 'Welcome Back';
  document.getElementById('authSub').textContent = signup
    ? 'Join the Excalibur roster.'
    : 'Sign in to your Excalibur account.';
  document.getElementById('authNameField').style.display = signup ? '' : 'none';
  document.getElementById('authAgeCheck').style.display = signup ? '' : 'none';
  document.getElementById('authName').required = signup;
  document.getElementById('authPassword').minLength = signup ? 10 : 1;
  document.getElementById('authSubmit').textContent = signup ? 'Create Account' : 'Sign In';
  document.getElementById('authSwitch').innerHTML = signup
    ? 'Already have an account? <button type="button" onclick="authOpen(\'signin\')">Sign in</button>'
    : 'New here? <button type="button" onclick="authOpen(\'signup\')">Create an account</button>';
  authMessage('');
  document.getElementById('authOverlay').classList.add('open');
  document.body.style.overflow = 'hidden';
  setTimeout(() => { document.getElementById(signup ? 'authName' : 'authEmail').focus(); }, 60);
}

function authClose(){
  const o = document.getElementById('authOverlay');
  if (!o) return;
  o.classList.remove('open');
  document.body.style.overflow = '';
}

function authMessage(text, kind){
  const el = document.getElementById('authMsg');
  if (!el) return;
  el.textContent = text || '';
  el.className = 'auth-msg' + (text ? ' show ' + (kind || 'error') : '');
}

async function authSubmit(e){
  e.preventDefault();
  const btn = document.getElementById('authSubmit');
  const signup = authMode === 'signup';
  const name = document.getElementById('authName').value.trim();
  const email = document.getElementById('authEmail').value.trim();
  const password = document.getElementById('authPassword').value;

  if (signup && !name){ authMessage('Please enter your name.'); return; }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)){
    authMessage('Please enter a valid email address.'); return;
  }
  if (!password){ authMessage('Please enter your password.'); return; }
  if (signup){
    if (password.length < 10){ authMessage('Password must be at least 10 characters.'); return; }
    if (!document.getElementById('authAge').checked){
      authMessage('You must confirm you are 21 or older.'); return;
    }
  }

  btn.disabled = true;
  const original = btn.textContent;
  btn.textContent = signup ? 'Creating…' : 'Signing in…';
  try {
    const payload = signup ? { name, email, password } : { email, password };
    const data = await authApi(signup ? '/auth/register' : '/auth/login', payload);
    authSetToken(data.token);
    authUser = data.user;
    authCacheRole(authUser.role);
    authRenderNav();
    authMessage(signup ? 'Account created. Welcome to Excalibur.' : 'Signed in.', 'ok');
    setTimeout(authClose, 700);
  } catch (err){
    authMessage(err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
}

async function authSignOut(){
  try { await authApi('/auth/logout', {}); } catch(e){}
  authSetToken(null);
  authUser = null;
  authCacheRole(null);
  authRenderNav();
}

/* ── boot ── */
async function authInit(){
  authRenderNav();
  if (!authToken()) return;
  try {
    const data = await authApi('/auth/me');
    authUser = data.user;
    authCacheRole(authUser.role);
  } catch(e){
    authSetToken(null);
    authUser = null;
    authCacheRole(null);
  }
  authRenderNav();
}

document.addEventListener('keydown', e => { if (e.key === 'Escape') authClose(); });
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', authInit);
else authInit();
