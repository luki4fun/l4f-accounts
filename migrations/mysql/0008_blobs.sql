-- Opt-in storage: synced store keys (ns kv), vault items and key slots, the
-- avatar. version makes every write a compare-and-set.
CREATE TABLE IF NOT EXISTS acct_blobs (
  user_id BINARY(16) NOT NULL,
  ns VARCHAR(16) NOT NULL,
  k VARCHAR(64) NOT NULL,
  v MEDIUMBLOB NOT NULL,
  version BIGINT NOT NULL DEFAULT 1,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (user_id, ns, k),
  CONSTRAINT acct_blobs_user FOREIGN KEY (user_id) REFERENCES acct_users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
