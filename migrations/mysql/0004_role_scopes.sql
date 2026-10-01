CREATE TABLE IF NOT EXISTS acct_role_scopes (
  role_id BINARY(16) NOT NULL,
  scope VARCHAR(64) NOT NULL,
  PRIMARY KEY (role_id, scope),
  CONSTRAINT acct_role_scopes_role FOREIGN KEY (role_id) REFERENCES acct_roles (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
