-- Security events, shown to the user they concern. Deleted with the account;
-- an actor who is deleted later simply stops being named.
CREATE TABLE IF NOT EXISTS acct_audit (
  id BIGINT NOT NULL AUTO_INCREMENT,
  user_id BINARY(16) NULL,
  actor_id BINARY(16) NULL,
  event VARCHAR(32) NOT NULL,
  detail VARCHAR(255) NOT NULL DEFAULT '',
  ip VARCHAR(45) NOT NULL DEFAULT '',
  at BIGINT NOT NULL,
  PRIMARY KEY (id),
  KEY user_at (user_id, at),
  KEY at (at),
  CONSTRAINT acct_audit_user FOREIGN KEY (user_id) REFERENCES acct_users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
