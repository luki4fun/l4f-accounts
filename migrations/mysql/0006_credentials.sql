-- Every login method but the password, one row each: passkeys, SSH keys,
-- browser device keys and linked social identities. (kind, ext_id) is the
-- credential id, key fingerprint, device id or provider subject, so one of them
-- can never belong to two accounts.
CREATE TABLE IF NOT EXISTS acct_credentials (
  kind VARCHAR(24) NOT NULL,
  ext_id VARBINARY(1023) NOT NULL,
  user_id BINARY(16) NOT NULL,
  public_key VARBINARY(2048) NULL,
  alg INT NOT NULL DEFAULT 0,
  sign_count BIGINT NOT NULL DEFAULT 0,
  flags INT NOT NULL DEFAULT 0,
  name VARCHAR(64) NOT NULL DEFAULT '',
  handle VARCHAR(255) NOT NULL DEFAULT '',
  email VARCHAR(254) NULL,
  public TINYINT NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL,
  last_used_at BIGINT NULL,
  PRIMARY KEY (kind, ext_id),
  KEY user_id (user_id),
  CONSTRAINT acct_credentials_user FOREIGN KEY (user_id) REFERENCES acct_users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
