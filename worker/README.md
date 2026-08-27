# Excalibur account service

## Deploying

Once the repo is connected under the worker's **Settings → Build**, every push
to `main` that touches this directory redeploys the worker automatically. Set
**Root directory** to `worker` so Cloudflare finds `wrangler.jsonc`.

`OWNER_EMAIL` stays a dashboard secret — secrets are not stored in this file
and survive redeploys. `ALLOWED_ORIGINS` and the `DB` binding come from
`wrangler.jsonc`, so change them there rather than in the dashboard.

To deploy by hand instead: paste `src/index.js` into the worker's editor and
click Deploy.


The Sign Up / Sign In control in the site navigation talks to this Worker.
**Until it is deployed, the buttons appear but signing up returns an error** —
the front end tells the visitor the account service can't be reached.

This is a **separate Worker** from `excalibur-cigar-proxy`. Deploying it cannot
affect the cigar-notes feature.

## One-time setup

From this `worker/` directory:

```bash
npm install -g wrangler        # if you don't have it
wrangler login

# 1. Create the database
wrangler d1 create excalibur-accounts
#    Copy the printed database_id into wrangler.jsonc (replace PASTE_DATABASE_ID_HERE)

# 2. Create the tables
wrangler d1 execute excalibur-accounts --remote --file=./schema.sql

# 3. Mark which email is the owner account (gets role "owner" on signup)
wrangler secret put OWNER_EMAIL
#    then type the address you'll register with

# 4. Deploy
wrangler deploy
```

Deploy prints the worker URL. It should be
`https://excalibur-auth.christiankalasho.workers.dev` — if it differs, update
`AUTH_URL` at the top of `../auth.js` to match.

## Verifying

```bash
curl -X POST https://excalibur-auth.christiankalasho.workers.dev/auth/register \
  -H 'Content-Type: application/json' \
  -H 'Origin: https://excaliburloungesd.com' \
  -d '{"name":"Test","email":"test@example.com","password":"testpassword123"}'
```

A JSON response containing `token` means it's working. Remove the test row with:

```bash
wrangler d1 execute excalibur-accounts --remote \
  --command="DELETE FROM users WHERE email='test@example.com'"
```

## How accounts are secured

- **Passwords** are hashed with PBKDF2-SHA256, 210,000 iterations, a unique
  16-byte salt per user. Plaintext passwords are never stored or logged.
- **Sessions** are 32 random bytes. Only the SHA-256 hash is stored, so a
  database dump yields no usable sessions. They expire after 30 days.
- **Login throttling**: 8 failed attempts per email+IP in 15 minutes returns 429.
- **Timing**: login does equivalent hashing work whether or not the account
  exists, and compares hashes in constant time, so responses don't reveal
  which emails are registered.
- **CORS** is restricted to the origins in `ALLOWED_ORIGINS`.

### Known trade-off

The session token is kept in `localStorage` and sent as a Bearer header. This is
required because the Worker is on a different origin (`workers.dev`) than the
site, where cookies are awkward. The trade-off: any cross-site-scripting bug in
the site could read the token. Routing this Worker on a path under
`excaliburloungesd.com` would allow a `HttpOnly` cookie instead, which is
stronger — worth doing if the account system grows.

## Maintenance

Expired sessions and old throttle rows are not auto-pruned. Occasionally:

```bash
wrangler d1 execute excalibur-accounts --remote \
  --command="DELETE FROM sessions WHERE expires_at < datetime('now'); DELETE FROM login_attempts WHERE created_at < datetime('now','-1 day');"
```

## Data you are now responsible for

This database holds names, email addresses, and password hashes for real
people. That carries obligations under California privacy law (CCPA) — chiefly
being able to tell someone what you hold on them and delete it on request.
Keep the account list small and delete what you don't need.
