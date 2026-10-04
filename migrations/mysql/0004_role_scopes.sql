-- `scope` key: the last-admin guard's locking count starts from the `*` rows.
-- Without it the count scanned the whole table and locked other roles' scope
-- rows too, in role id order, so two guarded writes could deadlock on them.
CREATE TABLE IF NOT EXISTS acct_role_scopes (
  role_id BINARY(16) NOT NULL,
  scope VARCHAR(64) NOT NULL,
  PRIMARY KEY (role_id, scope),
  KEY scope (scope),
  CONSTRAINT acct_role_scopes_role FOREIGN KEY (role_id) REFERENCES acct_roles (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
