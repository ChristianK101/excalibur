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
