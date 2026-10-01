-- The last-admin guard's locking count starts from the `*` rows. Without this
-- key it scanned the whole table and locked other roles' scope rows too, in
-- role id order, so two guarded writes could deadlock on them.
-- MySQL 8 has no ADD KEY IF NOT EXISTS: if the process dies between this
-- statement and the version bump, the next boot fails on "Duplicate key name
-- 'scope'" and needs `UPDATE acct_schema SET version = 11` by hand.
ALTER TABLE acct_role_scopes ADD KEY scope (scope)
