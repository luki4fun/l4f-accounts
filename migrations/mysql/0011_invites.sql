-- Sign-up invites. Only SHA-256 of the code is stored, like a session token.
-- `username` binds an invite to one name (an admin making an account for
-- someone); NULL lets whoever holds the code choose. Used rows stay until the
-- sweep, so the admin list can say who took which.
CREATE TABLE IF NOT EXISTS acct_invites (
  code_hash BINARY(32) NOT NULL,
  created_by BINARY(16) NULL,
  username VARCHAR(32) NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  used_at BIGINT NULL,
  used_by BINARY(16) NULL,
  PRIMARY KEY (code_hash),
  KEY expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
