-- Postgres twin of mysql/0001. Text columns compare and sort byte-wise
-- (COLLATE "C"), as MySQL's _bin does; usernames and emails are lowercased in
-- Rust before they get here.
CREATE TABLE IF NOT EXISTS acct_users (
  id BYTEA NOT NULL PRIMARY KEY,
  username VARCHAR(32) COLLATE "C" NOT NULL UNIQUE,
  display_name VARCHAR(64) COLLATE "C" NOT NULL DEFAULT '',
  email VARCHAR(254) COLLATE "C" NULL UNIQUE,
  email_verified_at BIGINT NULL,
  email_pending VARCHAR(254) COLLATE "C" NULL,
  password_hash VARCHAR(255) COLLATE "C" NULL,
  totp_enc BYTEA NULL,
  totp_last_step BIGINT NOT NULL DEFAULT 0,
  status SMALLINT NOT NULL DEFAULT 0,
  sync_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  created_at BIGINT NOT NULL
);
