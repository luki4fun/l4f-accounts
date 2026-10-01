CREATE TABLE IF NOT EXISTS acct_user_roles (
  user_id BINARY(16) NOT NULL,
  role_id BINARY(16) NOT NULL,
  granted_by BINARY(16) NULL,
  granted_at BIGINT NOT NULL,
  PRIMARY KEY (user_id, role_id),
  KEY role_id (role_id),
  CONSTRAINT acct_user_roles_user FOREIGN KEY (user_id) REFERENCES acct_users (id) ON DELETE CASCADE,
  CONSTRAINT acct_user_roles_role FOREIGN KEY (role_id) REFERENCES acct_roles (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
