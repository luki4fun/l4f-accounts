CREATE TABLE IF NOT EXISTS acct_user_roles (
  user_id BYTEA NOT NULL REFERENCES acct_users (id) ON DELETE CASCADE,
  role_id BYTEA NOT NULL REFERENCES acct_roles (id) ON DELETE CASCADE,
  granted_by BYTEA NULL,
  granted_at BIGINT NOT NULL,
  PRIMARY KEY (user_id, role_id)
);
CREATE INDEX IF NOT EXISTS acct_user_roles_role_id ON acct_user_roles (role_id);
