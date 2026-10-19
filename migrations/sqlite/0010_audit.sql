-- Security events, shown to the user they concern. Deleted with the account.
CREATE TABLE IF NOT EXISTS acct_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id BLOB NULL REFERENCES acct_users (id) ON DELETE CASCADE,
  actor_id BLOB NULL,
  event VARCHAR(32) NOT NULL,
  detail VARCHAR(255) NOT NULL DEFAULT '',
  ip VARCHAR(45) NOT NULL DEFAULT '',
  at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS acct_audit_user_at ON acct_audit (user_id, at);
CREATE INDEX IF NOT EXISTS acct_audit_at ON acct_audit (at);
