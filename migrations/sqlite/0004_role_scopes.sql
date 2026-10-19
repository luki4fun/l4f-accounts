CREATE TABLE IF NOT EXISTS acct_role_scopes (
  role_id BLOB NOT NULL REFERENCES acct_roles (id) ON DELETE CASCADE,
  scope VARCHAR(64) NOT NULL,
  PRIMARY KEY (role_id, scope)
);
CREATE INDEX IF NOT EXISTS acct_role_scopes_scope ON acct_role_scopes (scope);
