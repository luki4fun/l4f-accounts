CREATE TABLE IF NOT EXISTS acct_recovery (
  user_id BINARY(16) NOT NULL,
  code_hash BINARY(32) NOT NULL,
  used_at BIGINT NULL,
  PRIMARY KEY (user_id, code_hash),
  CONSTRAINT acct_recovery_user FOREIGN KEY (user_id) REFERENCES acct_users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
