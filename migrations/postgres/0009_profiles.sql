-- public_id NULL means the profile is off. Rotating it kills the old link.
CREATE TABLE IF NOT EXISTS acct_profiles (
  user_id BYTEA NOT NULL PRIMARY KEY REFERENCES acct_users (id) ON DELETE CASCADE,
  public_id BYTEA NULL UNIQUE,
  bio VARCHAR(1000) COLLATE "C" NOT NULL DEFAULT '',
  show_badges BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at BIGINT NOT NULL
);
