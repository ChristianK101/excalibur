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

/* One centred nav link, and which one depends on the role.
   Customers get none. */
const AUTH_ROLE_LINK = {
  owner:    { href: 'dashboard.html', label: '&#128202; Dashboard' },
  manager:  { href: 'team.html',      label: '&#128101; Team' },
  employee: { href: 'schedule.html',  label: '&#128197; Schedules' }
};

function authRenderDash(){
  const link = authUser ? AUTH_ROLE_LINK[authUser.role] : null;
  const here = location.pathname.split('/').pop();
  document.querySelectorAll('nav').forEach(nav => {
    const existing = nav.querySelector('.nav-dash');
    const wanted = link && here !== link.href;
    if (wanted){
      const a = existing || document.createElement('a');
      a.className = 'nav-dash';
      a.href = link.href;
      a.innerHTML = link.label;
      if (!existing) nav.appendChild(a);
    } else if (existing){
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
        '<div class="auth-field" id="authCodeField">' +
          '<label for="authCode">6-Digit Code</label>' +
          '<input type="text" id="authCode" name="code" inputmode="numeric" autocomplete="one-time-code" ' +
                 'maxlength="6" placeholder="000000" style="letter-spacing:.4em;text-align:center">' +
        '</div>' +
        '<div class="auth-field" id="authPasswordField">' +
          '<label for="authPassword" id="authPasswordLabel">Password</label>' +
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

/* What each screen shows. 'forgot' asks for the address; 'reset' takes the
   code that was emailed and the new password. */
const AUTH_SCREENS = {
  signup: {
    title: 'Create Account', sub: 'Join the Excalibur roster.',
    fields: ['name', 'email', 'password', 'age'], submit: 'Create Account',
    passwordLabel: 'Password', focus: 'authName'
  },
  signin: {
    title: 'Welcome Back', sub: 'Sign in to your Excalibur account.',
    fields: ['email', 'password'], submit: 'Sign In',
    passwordLabel: 'Password', focus: 'authEmail'
  },
  forgot: {
    title: 'Forgot Password', sub: 'We will email you a code to reset it.',
    fields: ['email'], submit: 'Email Me A Code', focus: 'authEmail'
  },
  reset: {
    title: 'Enter Your Code', sub: 'Check your email, then choose a new password.',
    fields: ['email', 'code', 'password'], submit: 'Set New Password',
    passwordLabel: 'New Password', focus: 'authCode'
  }
};

function authOpen(mode){
  authBuildModal();
  authMode = AUTH_SCREENS[mode] ? mode : 'signup';
  const s = AUTH_SCREENS[authMode];
  const has = f => s.fields.includes(f);

  document.getElementById('authTitle').textContent = s.title;
  document.getElementById('authSub').textContent = s.sub;
  document.getElementById('authNameField').style.display = has('name') ? '' : 'none';
  document.getElementById('authCodeField').style.display = has('code') ? '' : 'none';
  document.getElementById('authPasswordField').style.display = has('password') ? '' : 'none';
  document.getElementById('authAgeCheck').style.display = has('age') ? '' : 'none';
  document.getElementById('authName').required = has('name');
  document.getElementById('authPassword').required = has('password');
  // Sign-in accepts whatever was set before the minimum existed; the two
  // screens that set a password enforce it.
  document.getElementById('authPassword').minLength = authMode === 'signin' ? 1 : 10;
  if (s.passwordLabel) document.getElementById('authPasswordLabel').textContent = s.passwordLabel;
  document.getElementById('authSubmit').textContent = s.submit;

  document.getElementById('authSwitch').innerHTML =
    authMode === 'signup' ? 'Already have an account? <button type="button" onclick="authOpen(\'signin\')">Sign in</button>'
  : authMode === 'signin' ? 'Forgot your password? <button type="button" onclick="authOpen(\'forgot\')">Reset it</button>' +
                            '<br>New here? <button type="button" onclick="authOpen(\'signup\')">Create an account</button>'
  : authMode === 'reset'  ? 'Code not arrived? <button type="button" onclick="authOpen(\'forgot\')">Send another</button>' +
                            '<br><button type="button" onclick="authOpen(\'signin\')">Back to sign in</button>'
  : '<button type="button" onclick="authOpen(\'signin\')">Back to sign in</button>';

  // Never carry a password or a code between screens — after signing out, the
  // next person to open this must not find the last one's still typed in.
  document.getElementById('authPassword').value = '';
  document.getElementById('authCode').value = '';
  authMessage('');
  document.getElementById('authOverlay').classList.add('open');
  document.body.style.overflow = 'hidden';
  setTimeout(() => { document.getElementById(s.focus).focus(); }, 60);
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

/** Signs the person in from a register / login / reset response. */
function authAccept(data, note){
  authSetToken(data.token);
  authUser = data.user;
  authCacheRole(authUser.role);
  authRenderNav();
  authMessage(note, 'ok');
  setTimeout(authClose, 900);
}

async function authSubmit(e){
  e.preventDefault();
  const btn = document.getElementById('authSubmit');
  const mode = authMode;
  const name = document.getElementById('authName').value.trim();
  const email = document.getElementById('authEmail').value.trim();
  const password = document.getElementById('authPassword').value;
  const code = document.getElementById('authCode').value.replace(/\D/g, '');

  if (mode === 'signup' && !name){ authMessage('Please enter your name.'); return; }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)){
    authMessage('Please enter a valid email address.'); return;
  }
  if (mode === 'reset' && code.length !== 6){
    authMessage('Enter the 6-digit code from your email.'); return;
  }
  if (mode !== 'forgot'){
    if (!password){ authMessage('Please enter your password.'); return; }
    if (mode !== 'signin' && password.length < 10){
      authMessage('Password must be at least 10 characters.'); return;
    }
  }
  if (mode === 'signup' && !document.getElementById('authAge').checked){
    authMessage('You must confirm you are 21 or older.'); return;
  }

  btn.disabled = true;
  const original = btn.textContent;
  btn.textContent = mode === 'signup' ? 'Creating…'
                  : mode === 'signin' ? 'Signing in…'
                  : mode === 'forgot' ? 'Sending…' : 'Saving…';
  try {
    if (mode === 'forgot'){
      const d = await authApi('/auth/reset/request', { email });
      authOpen('reset');
      // Deliberately the same whether or not that address has an account.
      authMessage('If that address has an account, a code is on its way. ' +
                  'It lasts ' + (d.expiresInMinutes || 15) + ' minutes.', 'ok');
      return;
    }
    if (mode === 'reset'){
      authAccept(await authApi('/auth/reset/confirm', { email, code, password }),
                 'Password changed. You are signed in.');
      return;
    }
    const payload = mode === 'signup' ? { name, email, password } : { email, password };
    authAccept(await authApi(mode === 'signup' ? '/auth/register' : '/auth/login', payload),
               mode === 'signup' ? 'Account created. Welcome to Excalibur.' : 'Signed in.');
  } catch (err){
    authMessage(err.message);
  } finally {
    btn.disabled = false;
    // Moving to another screen relabels the button; only put the old label
    // back if we are still on the screen that changed it.
    if (authMode === mode) btn.textContent = original;
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
