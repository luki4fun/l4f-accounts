-- Opt-in storage; version makes every write a compare-and-set.
CREATE TABLE IF NOT EXISTS acct_blobs (
  user_id BLOB NOT NULL REFERENCES acct_users (id) ON DELETE CASCADE,
  ns VARCHAR(16) NOT NULL,
  k VARCHAR(64) NOT NULL,
  v BLOB NOT NULL,
  version BIGINT NOT NULL DEFAULT 1,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (user_id, ns, k)
);
