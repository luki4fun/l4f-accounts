CREATE TABLE IF NOT EXISTS acct_recovery (
  user_id BYTEA NOT NULL REFERENCES acct_users (id) ON DELETE CASCADE,
  code_hash BYTEA NOT NULL,
  used_at BIGINT NULL,
  PRIMARY KEY (user_id, code_hash)
);
