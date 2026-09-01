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

- **Passwords** are hashed with PBKDF2-SHA256, 100,000 iterations, a unique
  16-byte salt per user. Plaintext passwords are never stored or logged. The
  count is stored per user, so it can be raised later without invalidating
  anyone's password.
- **Sessions** are 32 random bytes. Only the SHA-256 hash is stored, so a
  database dump yields no usable sessions. They expire after 30 days.
- **Login throttling**: 8 failed attempts per email+IP in 15 minutes returns 429.
- **Timing**: login does equivalent hashing work whether or not the account
  exists, and compares hashes in constant time, so responses don't reveal
  which emails are registered.
- **CORS** is restricted to the origins in `ALLOWED_ORIGINS`.

## Forgotten passwords

A password cannot be recovered — only hashes are stored, which is the point.
Instead, `Forgot your password?` on the sign-in modal emails a six-digit code.

Setup, once:

1. Create a [Resend](https://resend.com) account (free tier is ample here).
2. Add `excaliburloungesd.com` as a domain and put the DNS records it gives you
   on the domain. Without this, mail to anywhere but your own address bounces.
3. `wrangler secret put RESEND_API_KEY`, or add it as a Secret in the dashboard.

`RESET_FROM` lives in `wrangler.jsonc` and must be an address on the verified
domain. Until `RESEND_API_KEY` exists the endpoint answers 503 and says the
feature is not set up — deliberately, before any account lookup happens, so an
unconfigured service can never be mistaken for "no such account".

How it is kept safe:

- **No enumeration.** Requesting a code answers identically whether or not the
  address has an account, and a failure to send is logged, never returned.
- **Only the code's SHA-256 hash is stored**, same as session tokens.
- **One live code per person.** Asking for another retires the last.
- **Fifteen minutes, five guesses.** Either limit killing the code.
- **Four requests per email+IP per hour**, ten confirm attempts.
- **Every session is dropped on reset**, so anyone else holding that account
  loses it at exactly the moment they should.
- The reset is written to `audit_log`.

## Promotional email

Same Resend key as password resets. `/marketing/*` is owner-only; the
Promotions page off the dashboard writes and sends campaigns.

- **Only people who ticked the box receive anything.** The wording they agreed
  to is stored with the consent, because "they ticked a box" is worth little
  if nobody can say what the box said.
- **The postal address is a setting, and sending is refused until it is set** —
  CAN-SPAM requires a real one in every marketing email, so it is not left to
  whoever writes the campaign to remember.
- **Every email carries an unsubscribe link** plus `List-Unsubscribe` headers
  for the one-click control Gmail and Apple Mail show. `/unsubscribe` needs no
  sign-in: a link that asks for a password is not an unsubscribe link.
- **Sends run in batches of 30**, one per request, recorded per recipient in
  `campaign_sends`. An interrupted send resumes from whoever has not been sent
  to rather than starting again, so nobody is emailed twice.
- Image and button addresses must be `https://`, checked server-side, so a
  campaign cannot carry a `javascript:` URL into someone's inbox.

Resend's free tier is 3,000 emails a month, 100 a day. A send that exceeds it
fails per recipient and is recorded as failed, not lost.

### Known trade-off

The session token is kept in `localStorage` and sent as a Bearer header. This is
required because the Worker is on a different origin (`workers.dev`) than the
site, where cookies are awkward. The trade-off: any cross-site-scripting bug in
the site could read the token. Routing this Worker on a path under
`excaliburloungesd.com` would allow a `HttpOnly` cookie instead, which is
stronger — worth doing if the account system grows.

## Clover

Sales come from the Clover REST API and are copied into D1, so a report never
waits on Clover and nothing the site does can write back to the register.

- `CLOVER_MERCHANT_ID` is in `wrangler.jsonc`. It is an identifier, not a
  credential, and it pins reporting to the Clairemont Mesa lounge — the same
  Clover account also holds Excalibur Lounge RB and Las Villas Cigars.
- `CLOVER_TOKEN` is a **dashboard secret**. It must never appear in this repo,
  in the browser, or in a chat window. Every Clover call is made by the worker.
- The token only needs **read** on Merchant, Orders, Payments and Inventory.
  Nothing here writes to Clover, so give it nothing else.

If a token is ever exposed, revoke it in the Clover dashboard and issue a new
one; adding a replacement secret does not disable the old token.

Endpoints, all **owner-only** — a manager gets 403 on every one of them:

| Route | Does |
|---|---|
| `GET /clover/test` | Names the merchant and shows three orders, to prove the token works |
| `POST /clover/sync` | Pulls orders changed since the last run. `{"days":90}` backfills instead |
| `GET /sales/report` | The sales report for a range of Pacific days |

A sync run stops after 800 orders and answers `more: true`; run it again to
continue. That cap exists because every D1 call spends one of the worker's
fifty free-plan subrequests, so orders are written a page at a time in one
batch each.

Orders are stored under Clover's own ids, so re-syncing overwrites rather than
duplicates. Line items and payments are deleted and rewritten with their order,
so a refund or a voided line does not linger as a phantom sale.

### How the money is split

Clover records different figures in different places, and the report follows it:

- **Gross sales** and **discounts** come off the ticket lines (`sales_items`).
- **Tax**, **tips**, **refunds** and what was **collected** come off the
  payments (`sales_payments`) — an order can have several, on a split cheque.
- **Net sales** is gross less discounts, before tax.
- **Total collected** is payments plus tips less refunds, so it will not equal
  net sales.

Nested expansions (`payments.tender`, `payments.refunds`) are not on every
Clover plan. The sync asks for the richest one, falls back through simpler ones
on a 400, and remembers the one that worked in `settings.clover_expand`.

### Tests

```bash
node worker/test/clover.test.mjs     # Clover sync and the sales report
node worker/test/reset.test.mjs      # emailed password resets
node worker/test/marketing.test.mjs  # promotional email
```

No dependencies and no network — `node:sqlite` stands in for D1 and `fetch` is
replaced with fixtures. Between them they cover paging, Pacific day and hour
bucketing, the money arithmetic, refunds, re-syncing not double-counting, an
edited order replacing its old lines, the subrequest budget, that a manager is
refused, and every property listed under Forgotten passwords above.

The browser half of the reset flow needs Playwright:

```bash
npm install playwright && node test/ui-reset.mjs
```

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
