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
