-- SQLite twin of mysql/0001. Text compares and sorts byte-wise (BINARY,
-- the default), as MySQL's _bin does; usernames and emails are lowercased in
-- Rust before they get here.
CREATE TABLE IF NOT EXISTS acct_users (
  id BLOB NOT NULL PRIMARY KEY,
  username VARCHAR(32) NOT NULL UNIQUE,
  display_name VARCHAR(64) NOT NULL DEFAULT '',
  email VARCHAR(254) NULL UNIQUE,
  email_verified_at BIGINT NULL,
  email_pending VARCHAR(254) NULL,
  password_hash VARCHAR(255) NULL,
  totp_enc BLOB NULL,
  totp_last_step BIGINT NOT NULL DEFAULT 0,
  status SMALLINT NOT NULL DEFAULT 0,
  sync_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  created_at BIGINT NOT NULL
);
