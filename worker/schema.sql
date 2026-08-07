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
