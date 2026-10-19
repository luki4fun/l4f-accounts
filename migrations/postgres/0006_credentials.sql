-- Every login method but the password, one row each; (kind, ext_id) can never
-- belong to two accounts.
CREATE TABLE IF NOT EXISTS acct_credentials (
  kind VARCHAR(24) COLLATE "C" NOT NULL,
  ext_id BYTEA NOT NULL,
  user_id BYTEA NOT NULL REFERENCES acct_users (id) ON DELETE CASCADE,
  public_key BYTEA NULL,
  alg INTEGER NOT NULL DEFAULT 0,
  sign_count BIGINT NOT NULL DEFAULT 0,
  flags INTEGER NOT NULL DEFAULT 0,
  name VARCHAR(64) COLLATE "C" NOT NULL DEFAULT '',
  handle VARCHAR(255) COLLATE "C" NOT NULL DEFAULT '',
  email VARCHAR(254) COLLATE "C" NULL,
  public BOOLEAN NOT NULL DEFAULT FALSE,
  created_at BIGINT NOT NULL,
  last_used_at BIGINT NULL,
  PRIMARY KEY (kind, ext_id)
);
CREATE INDEX IF NOT EXISTS acct_credentials_user_id ON acct_credentials (user_id);
