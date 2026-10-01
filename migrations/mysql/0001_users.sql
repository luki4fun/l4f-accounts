-- Usernames and emails are normalised to lowercase in Rust before they get
-- here; the _bin collation keeps the database from folding anything else.
-- email holds only a verified address; a new one waits in email_pending, so an
-- unverified claim can never squat someone else's address.
CREATE TABLE IF NOT EXISTS acct_users (
  id BINARY(16) NOT NULL,
  username VARCHAR(32) NOT NULL,
  display_name VARCHAR(64) NOT NULL DEFAULT '',
  email VARCHAR(254) NULL,
  email_verified_at BIGINT NULL,
  email_pending VARCHAR(254) NULL,
  password_hash VARCHAR(255) NULL,
  totp_enc VARBINARY(128) NULL,
  totp_last_step BIGINT NOT NULL DEFAULT 0,
  status TINYINT NOT NULL DEFAULT 0,
  sync_enabled TINYINT NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY username (username),
  UNIQUE KEY email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
