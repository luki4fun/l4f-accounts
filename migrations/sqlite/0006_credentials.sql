-- Every login method but the password, one row each; (kind, ext_id) can never
-- belong to two accounts.
CREATE TABLE IF NOT EXISTS acct_credentials (
  kind VARCHAR(24) NOT NULL,
  ext_id BLOB NOT NULL,
  user_id BLOB NOT NULL REFERENCES acct_users (id) ON DELETE CASCADE,
  public_key BLOB NULL,
  alg INTEGER NOT NULL DEFAULT 0,
  sign_count BIGINT NOT NULL DEFAULT 0,
  flags INTEGER NOT NULL DEFAULT 0,
  name VARCHAR(64) NOT NULL DEFAULT '',
  handle VARCHAR(255) NOT NULL DEFAULT '',
  email VARCHAR(254) NULL,
  public BOOLEAN NOT NULL DEFAULT FALSE,
  created_at BIGINT NOT NULL,
  last_used_at BIGINT NULL,
  PRIMARY KEY (kind, ext_id)
);
CREATE INDEX IF NOT EXISTS acct_credentials_user_id ON acct_credentials (user_id);
