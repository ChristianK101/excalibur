-- Excalibur account service schema (Cloudflare D1)
-- Apply with:  wrangler d1 execute excalibur-accounts --remote --file=./schema.sql

CREATE TABLE IF NOT EXISTS users (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL,
  email       TEXT NOT NULL UNIQUE,
  pw_hash     TEXT NOT NULL,
  pw_salt     TEXT NOT NULL,
  iterations  INTEGER NOT NULL,
  role        TEXT NOT NULL DEFAULT 'member',
  created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash  TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at  TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS login_attempts (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  key         TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attempts_key ON login_attempts(key, created_at);

-- Emailed password reset codes. Only the SHA-256 hash of a code is stored, on
-- the same reasoning as sessions: the table itself is never enough to get in.
-- One live code per person; asking for another retires the last.
CREATE TABLE IF NOT EXISTS password_resets (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash   TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  attempts    INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_resets_user ON password_resets(user_id, created_at);

-- ═══════════════════════════════════════════════════════════════════
--  MARKETING EMAIL
-- ═══════════════════════════════════════════════════════════════════

-- Who agreed, when, and to what wording. The wording is stored with the
-- consent because "they ticked a box" is worth little if nobody can say what
-- the box said at the time.
ALTER TABLE users ADD COLUMN marketing_opt_in INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN opt_in_at TEXT;
ALTER TABLE users ADD COLUMN opt_in_text TEXT;
ALTER TABLE users ADD COLUMN unsub_token TEXT;

CREATE INDEX IF NOT EXISTS idx_users_optin ON users(marketing_opt_in);

CREATE TABLE IF NOT EXISTS campaigns (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  subject     TEXT NOT NULL,
  body        TEXT NOT NULL,          -- plain text as typed; the HTML is built at send time
  image_url   TEXT,
  link_url    TEXT,
  link_label  TEXT,
  created_by  INTEGER REFERENCES users(id),
  created_at  TEXT NOT NULL,
  started_at  TEXT,
  finished_at TEXT,
  sent        INTEGER NOT NULL DEFAULT 0,
  failed      INTEGER NOT NULL DEFAULT 0,
  status      TEXT NOT NULL DEFAULT 'draft'   -- draft | sending | sent
);

-- One row per person per campaign, so a resumed send never emails anyone
-- twice and a bounce can be traced to a recipient.
CREATE TABLE IF NOT EXISTS campaign_sends (
  campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email       TEXT NOT NULL,
  status      TEXT NOT NULL,          -- sent | failed
  error       TEXT,
  sent_at     TEXT NOT NULL,
  PRIMARY KEY (campaign_id, user_id)
);

-- Site analytics. `day` is the calendar day in America/Los_Angeles, so
-- "today" on the dashboard means today in San Diego, not UTC.
CREATE TABLE IF NOT EXISTS events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  type        TEXT NOT NULL,          -- 'pageview' | 'search'
  path        TEXT,                   -- '/menu.html' for pageviews
  category    TEXT,                   -- 'cigar' | 'drink' for searches
  term        TEXT,                   -- what was typed
  hits        INTEGER,                -- results the search returned (0 = nothing found)
  visitor     TEXT NOT NULL,          -- daily-rotating hash, no cookie, not reversible to a person
  day         TEXT NOT NULL,          -- YYYY-MM-DD, Pacific
  created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_day ON events(day);
CREATE INDEX IF NOT EXISTS idx_events_type_day ON events(type, day);
CREATE INDEX IF NOT EXISTS idx_events_search ON events(type, category, term);

-- ═══════════════════════════════════════════════════════════════════
--  STAFF: roles, time clock, schedules, pay, and the audit trail
-- ═══════════════════════════════════════════════════════════════════

-- Roles are owner | manager | employee | customer. New signups are customers;
-- only the owner can change a role. Existing 'member' rows become customers.
UPDATE users SET role = 'customer' WHERE role IS NULL OR role = '' OR role = 'member';

-- Pay rate lives on the user, in whole cents so money is never a float.
-- SQLite has no "ADD COLUMN IF NOT EXISTS" - if this errors with
-- "duplicate column name", it already ran and you can ignore it.
ALTER TABLE users ADD COLUMN hourly_rate_cents INTEGER;

-- Punches. Every timestamp is UTC ISO stamped by the worker; a device clock
-- is never trusted. clock_out IS NULL means that person is on the clock now.
CREATE TABLE IF NOT EXISTS time_entries (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  clock_in    TEXT NOT NULL,
  clock_out   TEXT,
  in_ip       TEXT,                   -- recorded so off-site punches can be flagged
  out_ip      TEXT,
  note        TEXT,
  created_by  INTEGER REFERENCES users(id),   -- set when a manager adds a missed punch
  created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entries_user ON time_entries(user_id, clock_in);
CREATE INDEX IF NOT EXISTS idx_entries_open ON time_entries(clock_out);

-- Append-only record of every change to a punch. Nothing is silently
-- overwritten - this is what protects you in a wage dispute.
CREATE TABLE IF NOT EXISTS time_edits (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  entry_id    INTEGER NOT NULL,
  editor_id   INTEGER NOT NULL REFERENCES users(id),
  field       TEXT NOT NULL,
  old_value   TEXT,
  new_value   TEXT,
  reason      TEXT,
  created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_edits_entry ON time_edits(entry_id, created_at);

-- Scheduled shifts, written by managers. UTC instants, always shown Pacific.
CREATE TABLE IF NOT EXISTS shifts (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  starts_at   TEXT NOT NULL,
  ends_at     TEXT NOT NULL,
  note        TEXT,
  created_by  INTEGER REFERENCES users(id),
  created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_shifts_user ON shifts(user_id, starts_at);
CREATE INDEX IF NOT EXISTS idx_shifts_range ON shifts(starts_at);

-- Tips are entered by hand by a manager, never calculated.
CREATE TABLE IF NOT EXISTS tips (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount_cents  INTEGER NOT NULL,
  for_day       TEXT NOT NULL,        -- YYYY-MM-DD, Pacific
  note          TEXT,
  added_by      INTEGER NOT NULL REFERENCES users(id),
  created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tips_user ON tips(user_id, for_day);

-- Every privileged action lands here: role changes, schedules, pay rates,
-- tips, punch edits. This is the owner's log of what managers did.
CREATE TABLE IF NOT EXISTS audit_log (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_id     INTEGER NOT NULL REFERENCES users(id),
  actor_role   TEXT NOT NULL,
  action       TEXT NOT NULL,         -- e.g. 'shift.create', 'rate.set'
  target_user  INTEGER REFERENCES users(id),
  entity_id    INTEGER,
  details      TEXT,                  -- human-readable summary
  created_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id, created_at);

-- Small key/value store. Holds the lounge's coordinates and the radius
-- counted as "at work", set from the Team page while standing in the lounge.
CREATE TABLE IF NOT EXISTS settings (
  key         TEXT PRIMARY KEY,
  value       TEXT NOT NULL,
  updated_by  INTEGER REFERENCES users(id),
  updated_at  TEXT NOT NULL
);

-- How far from the lounge each punch was, in metres, with the phone's own
-- estimate of how confident it is. Coordinates are deliberately NOT stored:
-- the distance answers "were they at work", without tracking anyone.
-- Ignore "duplicate column name" if you run these twice.
ALTER TABLE time_entries ADD COLUMN in_distance_m INTEGER;
ALTER TABLE time_entries ADD COLUMN in_accuracy_m INTEGER;
ALTER TABLE time_entries ADD COLUMN out_distance_m INTEGER;
ALTER TABLE time_entries ADD COLUMN out_accuracy_m INTEGER;

-- ═══════════════════════════════════════════════════════════════════
--  CLOVER: register sales, copied here so reports never wait on their API
-- ═══════════════════════════════════════════════════════════════════

-- Ids are Clover's own, so a re-sync updates a row instead of duplicating it.
-- `day` is the Pacific calendar day the order was opened.
CREATE TABLE IF NOT EXISTS sales_orders (
  id           TEXT PRIMARY KEY,
  day          TEXT NOT NULL,
  created_ms   INTEGER NOT NULL,       -- Clover epoch millis
  modified_ms  INTEGER,
  state        TEXT,
  total_cents  INTEGER,
  synced_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sales_orders_day ON sales_orders(day);

-- One row per line on a ticket. price_cents is the unit price; qty is 1 for
-- ordinary items and a fraction for anything Clover sells by measure.
CREATE TABLE IF NOT EXISTS sales_items (
  id           TEXT PRIMARY KEY,
  order_id     TEXT NOT NULL,
  day          TEXT NOT NULL,
  item_id      TEXT,                   -- Clover menu item, absent for hand-keyed lines
  name         TEXT NOT NULL,
  price_cents  INTEGER NOT NULL DEFAULT 0,
  qty          REAL NOT NULL DEFAULT 1,
  refunded     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sales_items_day ON sales_items(day);
CREATE INDEX IF NOT EXISTS idx_sales_items_order ON sales_items(order_id);
CREATE INDEX IF NOT EXISTS idx_sales_items_name ON sales_items(name);

-- The register's menu. Kept so the report can name bottles that sold nothing
-- at all in a range - a table of sales alone can never show those.
CREATE TABLE IF NOT EXISTS clover_items (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  price_cents  INTEGER,
  hidden       INTEGER NOT NULL DEFAULT 0,
  synced_at    TEXT NOT NULL
);

-- Tips, tax and tender live on the payment, not the order, which is why a
-- sales report needs both. amount_cents excludes the tip, matching Clover.
CREATE TABLE IF NOT EXISTS sales_payments (
  id              TEXT PRIMARY KEY,
  order_id        TEXT NOT NULL,
  day             TEXT NOT NULL,        -- Pacific calendar day
  hour            INTEGER,              -- 0-23 Pacific, for the hourly view
  created_ms      INTEGER NOT NULL,
  amount_cents    INTEGER NOT NULL DEFAULT 0,
  tip_cents       INTEGER NOT NULL DEFAULT 0,
  tax_cents       INTEGER NOT NULL DEFAULT 0,
  refunded_cents  INTEGER NOT NULL DEFAULT 0,
  tender          TEXT,                 -- 'Cash', 'Credit Card', ...
  employee_id     TEXT,
  result          TEXT
);

CREATE INDEX IF NOT EXISTS idx_sales_payments_day ON sales_payments(day);
CREATE INDEX IF NOT EXISTS idx_sales_payments_order ON sales_payments(order_id);

-- Names for the ids on payments, so tips can be reported per person.
CREATE TABLE IF NOT EXISTS clover_employees (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  role       TEXT,
  synced_at  TEXT NOT NULL
);

-- Added after the first sales release. Ignore "duplicate column name" if these
-- have already been run.
ALTER TABLE sales_orders ADD COLUMN hour INTEGER;
ALTER TABLE sales_items ADD COLUMN discount_cents INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clover_items ADD COLUMN category TEXT;
