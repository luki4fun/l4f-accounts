-- Sign-up invites; only SHA-256 of the code is stored. `username` binds one.
CREATE TABLE IF NOT EXISTS acct_invites (
  code_hash BLOB NOT NULL PRIMARY KEY,
  created_by BLOB NULL,
  username VARCHAR(32) NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  used_at BIGINT NULL,
  used_by BLOB NULL
);
CREATE INDEX IF NOT EXISTS acct_invites_expires_at ON acct_invites (expires_at);
