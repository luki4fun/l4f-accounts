-- Only SHA-256 of the cookie value is stored: a database dump hands out no
-- live sessions.
CREATE TABLE IF NOT EXISTS acct_sessions (
  token_hash BINARY(32) NOT NULL,
  user_id BINARY(16) NOT NULL,
  created_at BIGINT NOT NULL,
  seen_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  auth_at BIGINT NOT NULL DEFAULT 0,
  mfa_ok TINYINT NOT NULL DEFAULT 0,
  method VARCHAR(16) NOT NULL,
  ip VARCHAR(45) NOT NULL DEFAULT '',
  ua VARCHAR(256) NOT NULL DEFAULT '',
  PRIMARY KEY (token_hash),
  KEY user_id (user_id),
  KEY expires_at (expires_at),
  CONSTRAINT acct_sessions_user FOREIGN KEY (user_id) REFERENCES acct_users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
