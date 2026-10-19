-- Only SHA-256 of the token is stored: a database dump hands out no live sessions.
CREATE TABLE IF NOT EXISTS acct_sessions (
  token_hash BYTEA NOT NULL PRIMARY KEY,
  user_id BYTEA NOT NULL REFERENCES acct_users (id) ON DELETE CASCADE,
  created_at BIGINT NOT NULL,
  seen_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  auth_at BIGINT NOT NULL DEFAULT 0,
  mfa_ok BOOLEAN NOT NULL DEFAULT FALSE,
  method VARCHAR(16) COLLATE "C" NOT NULL,
  ip VARCHAR(45) COLLATE "C" NOT NULL DEFAULT '',
  ua VARCHAR(256) COLLATE "C" NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS acct_sessions_user_id ON acct_sessions (user_id);
CREATE INDEX IF NOT EXISTS acct_sessions_expires_at ON acct_sessions (expires_at);
CREATE INDEX IF NOT EXISTS acct_sessions_seen_at ON acct_sessions (seen_at);
