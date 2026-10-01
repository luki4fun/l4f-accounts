-- public_id NULL means the profile is off. Rotating it kills the old link.
CREATE TABLE IF NOT EXISTS acct_profiles (
  user_id BINARY(16) NOT NULL,
  public_id BINARY(16) NULL,
  bio VARCHAR(1000) NOT NULL DEFAULT '',
  show_badges TINYINT NOT NULL DEFAULT 1,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (user_id),
  UNIQUE KEY public_id (public_id),
  CONSTRAINT acct_profiles_user FOREIGN KEY (user_id) REFERENCES acct_users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
