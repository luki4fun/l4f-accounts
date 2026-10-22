# Changelog

Migrations are append-only once a version is tagged: a host that ran them can
only move forward. **BREAKING** marks changes a host has to act on.

## v0.10.0 (2026-10-22)

For voipc 1.0's password reset with a recovery key. No migration.

- `Accounts::password_set_as_host(ctx, target, new)`: a new password from the
  host's own code, for a reset the host proved by other means. The policy, the
  per-account cap and Argon2 as for any change; every device key and every
  session goes; the audit row says `host`.
- `Accounts::second_factor_check(ctx, user, SecondFactor::Totp(code) |
  SecondFactor::Recovery(code))`: a second factor checked without a session,
  on the step-up buckets; a recovery code is spent.
- SQLite connections set `secure_delete = FAST`: a deleted account's rows
  are overwritten where that costs no extra I/O, rather than left readable in
  the file's free pages.

## v0.9.0 (2026-10-20)

Postgres and SQLite next to MySQL, for voipc's relays. New migration sets
`migrations/postgres` and `migrations/sqlite` (versions 0001–0011, the same
tables as MySQL's); `migrations/mysql` gains only 0011 (`acct_invites`), so a
v0.8.0 binary refuses a database v0.9.0 has migrated (`VersionMissing`).

### Store

- Features `postgres` and `sqlite` beside `mysql`; any of them brings the store,
  migrations and the service, and they add up: one binary serves whichever
  database its URL names (`Store::connect`). `axum`, `oauth` and `email` still
  imply `mysql`.
- **BREAKING** `Store` is an enum over the backends. `Store(pool)` is
  `Store::from(pool)`. All three are compiled from `src/store/portable.rs`;
  MySQL's is `my::Backend`, still exported as `MySqlStore`. Its statements are
  unchanged but for spellings all three take (`TRUE`/`FALSE` for 1/0,
  `LIMIT 1000 OFFSET ?`, no explicit `granted_by` NULL in `create_user`) and
  SMALLINT/BIGINT binds for `status` and limits. The last-admin guard is an
  advisory lock on Postgres and the write lock on SQLite.
- **BREAKING** `Host::delete_user` takes a `StoreConn` (the backend's
  connection in an enum) instead of `&mut MySqlConnection`; `Store::begin`
  returns a `StoreTx` (`conn()`, `commit()`, `rollback()`). That transaction
  holds the last-admin guard to its end, so every write in it goes through
  `tx`: one through the pool, `Store` or `Accounts` can wait on it and fails
  when the lock wait runs out.
- **BREAKING** `Store::set_session_mfa` is gone: `complete_session` finishes a
  pending session, with a new token.
- **BREAKING** `Store::set_password_hash` writes only while the account has no
  password, and is false otherwise; `rehash_password(id, old, new)` replaces
  one. Of two first passwords set at once (a reset link used twice), one is
  written.
- `complete_session` keeps the account's newest 50 signed-in sessions
  (`MAX_SESSIONS`), as `insert_session` does: sign-ins finished with a code or
  a passkey count too.
- `put_blob` locks the key's row too: a `delete_blob` that commits while it
  waits makes it a `Conflict` instead of bringing the key back.
  `replace_recovery` locks the account's row: two at once leave one set.
- `used_credential` takes a sign count of 0 only while the stored one is 0, so
  a cloned passkey reporting 0 is refused. False also means the credential is
  gone.
- Postgres: guarded writes, `replace_recovery` and the blob writes begin READ
  COMMITTED whatever the server's default, guarded ones with a 30 s
  `lock_timeout`. `Store::delete_user` in a host's transaction at another
  level refuses (`InvalidArgument`).
- SQLite: `Store::connect` retries `SQLITE_BUSY` for up to 5 s, for processes
  opening a new file at once.
- The data download (`Accounts::export`) gains `"profile"` (`on`, `bio`,
  `show_badges`), and `"storage"` the avatar (ns `avatar`).

### Sessions and factors

- **BREAKING** `totp_enable(ctx, user, session, sealed, code)` returns
  `(codes, Option<NewSession>)` and `passkey_add(ctx, user, session, token,
  browser_nonce, json, name)` returns `Option<NewSession>`; both answer
  Forbidden unless `session` is a full session of `user`. The account's first
  second factor ends every other session and gives the caller's a new token,
  returned as `Some`: the old one stops working (`None` if the caller was
  signed out meanwhile; the factor is on regardless). A later factor ends none. The
  web answers set the new cookie.
- **BREAKING** `password_change` answers Forbidden unless the session is fresh
  (`fresh`): a host without HTTP steps up first.
- **BREAKING** Social step-up (`Intent::Reauth`) is refused for an account with
  codes or a passkey, and next to a password for any provider but Google,
  whose `auth_time` shows it asked again: "Confirm it's you with your code,
  passkey or password instead." Checked at the start and at the callback.
- `step_up_recovery(ctx, user, session, code)`: a recovery code as a full
  step-up, which spends it, so whoever lost the factor can replace it.
  `/account/reauth` offers it while codes are left.
- Buckets per account: the second sign-in step keeps `acct-mfa-{id}:x`,
  step-up and setup by code use `acct-mfa-up-{id}:x` (5 per 15 minutes each),
  password step-up `acct-reauth-{id}:x` (`login_per_user_15min`) instead of
  the login form's. Whoever has the password can no longer lock the owner out
  of step-up or setup, and strangers' failed logins no longer block password
  step-up.
- Setting a password, by change or by reset link, is capped per account
  (`acct-pw-{id}:x`, `login_per_user_15min` per 15 minutes) before Argon2 runs.
- `mfa_totp`, `mfa_recovery` and `passkey_mfa` check the pending session
  before they spend the factor: `Closed` while accounts are off, Forbidden for
  a session that is complete, another account's, or past its 10 minutes.
- A sign-in that races the removal of its credential, sign-out everywhere or a
  password change keeps no session. SSH, device-key and social sign-ins refuse
  when `used_credential` is false; password and device-key sign-ins check the
  hash or key again after creating the session; `logout_all` and
  `set_password` revoke device keys before they delete sessions.
- Removing a passkey, an SSH key or a linked account is refused unless a
  password, a passkey or a linked account is left: SSH keys no longer count,
  as they never confirm it's you. Checked and deleted in one transaction
  (`Store::delete_credential_if_not_last`, `DeleteCredential`,
  `Store::step_up_credentials`). `totp_disable` needs one of them too.
- `passkey_add` saves a name it cannot store as "Passkey" instead of refusing
  once the authenticator holds the key.
- `passkey_options` answers Forbidden for `Login` with an account, or for the
  other ceremonies without one.

### Admin and invites

- Invites (migration 0011, `acct_invites`): `invite_create` (`users:admin` and
  every scope of the `user` role; optionally bound to one username, which is
  how an admin makes an account for someone), `invites`, `invite_revoke`, and
  `register_invite`, which signs up with a code while `registration_open` is
  off and without the PoW gate. The code is spent with the account in one
  transaction. Only its hash is stored. A wrong, used or expired code, or a
  taken name, is refused before the password is hashed (`Store::invite_open`).
  (**BREAKING** for hosts already calling them: `invite_create` needs the
  `user` role's scopes, and `register_invite` counts tries under
  `acct-inv:{address}`, was `acct-inv-{address}:x`.)
- `reset_2fa` (`users:admin`, covering the target): codes, recovery codes,
  passkeys, device keys and sessions go, for someone who lost their
  authenticator; false only when there was nothing to remove. (**BREAKING**
  for hosts already calling it: passkeys go too now, and codes being off no
  longer stops it.)
- `bootstrap_grant(ctx, user)`: `admin` for an existing account while nobody
  holds `*`, atomic under the last-admin guard. The host decides who may ask.
- `needs_2fa(user)`: holds a privileged scope that `effective_scopes` withholds.
- For the host's own shell, where no signed-in admin acts: `invite_create_as_host`,
  `grant_role_as_host`, `revoke_role_as_host` and `reset_2fa_as_host`. Same
  effects as the admin calls, with no actor in the audit row and ` (host)` at
  the end of its detail; the last holder of `*` still keeps it.
- **BREAKING** `Swept` has `invites` and `resealed` counts; the hourly sweep
  removes expired invites (and reseals, see Limiter, PoW and keys).
- **BREAKING** `grant_role` and `revoke_role` answer Forbidden when the target
  holds a scope the actor does not cover, as suspending and deleting do.
- `create_role` writes the role and its scopes in one transaction
  (`Store::create_role_with_scopes`): a grant never meets it without them.
- The `devkey_revoke` audit row of an admin's `reset_2fa` names the admin as
  actor (it named the account).
- Scope texts: `users:admin` "Suspend users, assign roles, invite, reset
  credentials and delete accounts", `roles:admin` "Create roles and edit their
  scopes". The admin's user page names the account's second factors.

### Storage and sync

- **BREAKING** `POST /account/sync` takes `_action` `on` or `off` only; anything
  else answers 400 (it turned sync off and deleted the copy).
- **BREAKING** Turning sync off keeps the `acct-sync` hint. With sync off,
  `GET /account/api/kv` answers 409 `{"error":"Sync is off."}` and clears it
  (was 400), and `sync.js` then forgets only what the server had confirmed:
  the browser keeps every value. A copy turned off and on again has a new
  epoch (`account` and `epoch` in the list, `Accounts::sync_epoch`), so the
  script pushes its values as new instead of deleting them.
- `kv_put` and `vault_put` check the key caps, and for settings the sync flag,
  under the account's row lock: racing creates stop at the cap, and a push
  racing "sync off" is refused ("Sync is off."). New
  `Store::put_blob_limited` (`PutLimited`); `put_blob` is unchanged.
- vault.js: creating checks for a vault first, deletes the new slots again
  when a write fails, and shows the recovery key once both are written. A
  passphrase change asks for the new one twice and can unlock with the
  recovery key. Slots are picked by `dek_id`, the view of a vault locked
  meanwhile is not redrawn, and password managers file the vault's
  passphrase apart. docs/vault-format.md says what a passphrase change leaves
  open.
- devkey.js keeps a new key aside until the server takes it: a failed try no
  longer forgets the key the browser held.

### Mail and OAuth

- **BREAKING** `email_confirm(ctx, user, t)` takes the signed-in `&User` and
  refuses another account's link ("That link is for another account. Sign
  out, then open it again."). `GET /account/verify-email` needs a full
  session: a signed-out visitor signs in and comes back. Both outcomes flash
  on the dashboard.
- Reset links are bound to the password hash and the address: a new or
  removed address ends them. Links mailed before the upgrade are refused.
- Confirming a new address mails the previous one "Your account's email
  address changed", and removing a confirmed address mails it too; like the
  password notice, neither is rate-limited.
- `password_forgot` answers once the limiter and the lookup are done; the
  token, the `reset_mail` audit row and the mail follow on a task of their own
  (a database error there is logged: "reset mail not sent").
- Mail caps (5 an hour per account, 3 per mailbox, 200 site-wide) are checked
  together and counted only when all pass. Resets have a site ceiling of their
  own (`acct-mail-reset:global`); `acct-mail:global` counts confirmations only.
  The per-mailbox count folds case, `+tags` and Gmail's dots.
- Mail links get the challenge tokens' strictness: one over 512 bytes, or with
  a padded or otherwise non-canonical base64url payload, is "not valid any
  more".
- Mail names the site by `base_url`'s host alone: `http://localhost:8099`
  reads `localhost`.
- Unlinking posts `id`, the identity's subject in base64url, and
  `/account/oauth/{p}/unlink` removes that identity only; without a matching
  `id` it answers "That is not linked." (**BREAKING** for a host's own unlink
  forms: they send `id`.)
- Google sign-in asks for `openid profile`, no email: the handle is the `name`
  claim alone, never the address.
- `acct-oauth:{address}` counts only callbacks with a valid flow cookie and
  state, so a cross-site image cannot spend it.
- `OAuthError::Http`, and so the `oauth_failed` warning, no longer holds the
  request URL, which carried codes, verifiers and Facebook's secret.

### Limiter, PoW and keys

- A per-address kind past 12,500 live sources evicts its least recently hit
  key (as of the last prune) instead of sharing a `{kind}:*` bucket, so a
  flood no longer refuses fresh sources. Site-wide (`…:global`) and
  per-account (`…-{id}:x`) keys are never evicted; a host's own keys keep
  these shapes.
- Single-use spends have a ceiling of 250,000 per kind instead of one shared
  million: solved proofs of work cannot crowd out challenge burns.
- `spend` caps a ttl at about 136 years instead of panicking on
  `Duration::MAX`, and a poisoned limiter lock is recovered.
- Verified SSH, device-key and passkey sign-ins of one account share
  `acct-key-{id}:x`: 3 × `login_per_user_15min` per 15 minutes (30 by
  default), then `RateLimited`. A host that signs in with a device key per
  connection may need more.
- `login_per_15min_global` defaults to 1000 (was 50): the operator's switch
  against guessing spread over many addresses, to lower while that runs.
- **BREAKING** A `pow_key` under 32 bytes (`pow::MIN_KEY_LEN`) is logged and
  dropped, so sign-up stays closed. With `ip_mode = "hash"`, an `ip_salt`
  under 32 bytes is logged at boot.
- `pow::issue` caps the ttl at 24 hours (`MAX_POW_TTL`); `verify` and
  `Gate::precheck` refuse an expiry further out, and take the official
  ALTCHA widget's base64 payload as well as raw JSON.
- Sign-up commits the gate's `Permit` right before `create_user`: a client
  hanging up cannot leave an account uncounted. A host's own gate commits
  right before its INSERT, or in the task that creates the account.
- Key rotation: while `Keys` holds an old master, `sweep` reseals the TOTP
  secrets still under it (`Swept::resealed`, `resealed=` in its log line;
  `Store::totp_rows`). The procedure is in `keys` and docs/embedding.md.

### Web

- **BREAKING** `web::router` sends `X-Frame-Options: DENY` unless the handler
  or `WebHost::page` set one; hosts add `frame-ancestors 'none'` to their CSP.
- **BREAKING** Without `Sec-Fetch-Site`, a request other than GET or HEAD whose
  `Origin` is `null` or not in `Config::origins()` is refused. Browsers
  without Fetch Metadata send `Origin: null` under `Referrer-Policy:
  no-referrer`, so a host sends `same-origin` or
  `strict-origin-when-cross-origin` on account pages, and a
  `webauthn_origins` list holds the site's own origin.
- `/account/reset` and `/account/verify-email` send `Referrer-Policy:
  strict-origin`, which the host keeps.
- Without `webauthn_origins`, `Config::origins()` is `base_url`'s scheme and
  authority, so a trailing slash no longer breaks passkeys and device keys.
  `base_url` is the site's URL without one.
- A page behind `Authed`, asked by a session that waits for its second factor,
  sends the browser to `/account/mfa?next=…` and keeps the cookie (it went to
  sign-in and cleared it); the host's pages behind `Authed` too.
- The crate's scripts are served with `X-Content-Type-Options: nosniff`.
- The public profile's title is "Profile", not the owner's display name, and
  `WebHost::page` gets its `title` as plain text to escape. Profile links
  (`Host::profile_links`) must start with `https://`, `http://` or `/`;
  others are left out.
- Display names, badges, role descriptions, bios and addresses also refuse the
  invisible U+2061–2065, U+206A–206F, U+FFF9–FFFB and U+1D173–1D17A. A passkey
  name with one becomes "Passkey", a linked account's name the provider
  label, and an SSH key is labelled by its algorithm.

### Boot

- **BREAKING** `migrate::run` and `migrate::lock` take `&Store`; `lock` returns
  a `BootLock` whose `conn()` is the `StoreConn` for a host's own tables.
  SQLite's boot lock is `<database>.lock` next to the file.
- SQLite must be a file with foreign keys on: `migrate::lock`, and so `run`
  and bootstrap, refuses an in-memory or temporary database, and
  `migrate::run` refuses foreign keys off (deletions rely on ON DELETE
  CASCADE).
- `migrate::lock` lifts its own connection's statement caps before it waits
  (MariaDB `max_statement_time = 0`, `lock_wait_timeout = 60`; Postgres
  `statement_timeout = 0`), not after: a pool's cap no longer cuts the wait
  short, and a host's DDL under the lock runs without it. The pool keeps its
  caps.
- MySQL: `GET_LOCK` answering NULL (no database in the URL) is a
  `Configuration` error, not a loop of warnings.
- `Accounts::build` refuses an app scope the crate or an earlier entry
  registered already (`InvalidArgument`).
- `.gitattributes` keeps `migrations/**` byte for byte (`-text`), so sqlx's
  checksums match on every checkout.

### Audit and logs

- An audit row that fails after its change committed no longer fails the call:
  it is logged (WARN `audit write failed`, with `error=` and `event=`) and the
  call returns its result. Sign-ins and wrong codes still fail on it.
- **BREAKING** for journal filters (`ip=` and `outcome=` stay as they were): in
  `accounts` info lines, `role=`, `how=` and `provider=` are now `detail=`
  (`detail="oauth:google"`). Password sign-ins log `detail="password"`,
  `ssh_add` the key's fingerprint, `passkey_add` its name. Role grants,
  revokes and 2FA resets by the host log no `actor=host`; their detail ends in
  ` (host)`, as the audit row's does.
- The second step's `login_ok` names both factors (`ssh+totp`,
  `oauth+passkey`), not always `password+…`.
- Refused device-key sign-ins log `devkey login refused` with `ip=` and
  `outcome=`, as SSH and password ones do. A database error behind a refusal
  is logged once (`database error`), on `POST /account/login/ssh` too.

### Docs and tests

- Tests: `L4F_TEST_DATABASE_URL` may name any of the three; the whole suite
  runs on each. `cargo test` also runs `tests/vault_vectors.mjs` and
  `tests/sync_flows.mjs` when `node` is on PATH.
- docs/embedding.md names host duties that went unsaid: a script for
  `data-confirm`, `profile_router` at `/profile`, one process, a master key
  from a CSPRNG and how to rotate it, the reserved `Keys` purposes, and the
  database link (sqlx is built with `tls-none`).

## v0.8.0 (2026-10-04)

Documentation. No code or migration changes.

- README.md, docs/embedding.md: features, host duties, cookies, scopes, calls
  without HTTP, what a SQLite store would need.

## v0.7.0 (2026-10-04)

Public profiles. No new migrations (acct_profiles existed since 0009).

- `/account/profile`, `PUT /account/api/avatar`, `assets/avatar.js`;
  `web::profile_router` for the host to nest (`/{id}`, `/{id}/avatar`).
- `Host::profile_links` (default: none); `Credential::public` for linked
  identities shown on the profile.

## v0.6.0 (2026-10-04)

Storage. No new migrations (acct_blobs existed since 0008).

- Synced settings (`/account/api/kv`, `assets/sync.js`, `/account/sync`) and the
  end-to-end encrypted vault (`/account/api/vault`, `/account/vault`,
  `assets/vault.js`), compare-and-set, under `storage_quota_bytes` (1 MiB).
- docs/vault-format.md with `tests/vault_vectors.rs` (vectors made by vault.js).
- `default_user_scopes` defaults to storage:sync, vault:use, profile:public
  (**BREAKING** for hosts that relied on the empty default).
- `migrate::lock` / `unlock` are public, for a host's own tables.

## v0.5.0 (2026-10-04)

Social sign-in. No new migrations.

- Feature `oauth` (now implies `mysql`): Discord, Google, Facebook with PKCE,
  `oauth::client` limited to `EGRESS_HOSTS`, `Accounts::with_oauth`.
- Sign-in (a first factor), sign-up for a new identity through the
  proof-of-work gate, linking (recent sign-in), unlinking, step-up with a
  forced provider prompt. Identities never matched by email.

## v0.4.0 (2026-10-04)

Mail. No new migrations.

- Feature `email` (now implies `mysql`): `email::Mailer` (SMTP, implicit TLS,
  optionally through an SNI egress forwarder), `Accounts::with_mailer`.
- Address confirmation by link, forgotten password reset by link (bound to
  the current hash: works once), password change with a recent sign-in.
- Config `smtp_host`, `smtp_port`, `smtp_user`, `smtp_from`, `egress`.
- Password policy messages are sentences (**BREAKING** for hosts matching
  the old strings).

## v0.3.0 (2026-10-04)

Signing in with a key. No new migrations.

- SSH keys: added with a signature over an enrol challenge, sign-in via
  `ssh-keygen -Y sign -n <ssh_namespace>` (default `login@<host>`); a first
  factor like the password. `sshsig::signer`.
- Remembered browsers (device keys): WebCrypto Ed25519 in IndexedDB,
  `/account/assets/devkey.js`; a full session but never a recent sign-in;
  revoked by sign-out everywhere and every second-factor change, and after
  90 days unused (`Swept::devkeys`).
- `remove_credential` for every kind; `/account/credentials/{kind}/{id}/delete`
  replaces `/account/passkey/{id}/delete` (**BREAKING** for scripts posting there).

## v0.2.0 (2026-10-04)

Two-factor sign-in. No new migrations.

- **BREAKING** `require_2fa_for_privileged` defaults to true: scopes beyond
  `default_user_scopes` count only for accounts with a second factor. The
  bootstrap admin sets one up before admin rights work.
- TOTP (sealed secret, one use per step, 5 tries per 15 minutes), ten keyed
  recovery codes, passkeys (sign-in alone with user verification, second
  factor, step-up), the second sign-in step (`PendingMfa`, `/mfa`), the
  security page, and step-up by code or passkey.
- Config `rp_id`, `webauthn_origins`, `totp_issuer`, defaulting to
  `base_url`. `User::has_passkey`.
- `/account/assets/passkey.js`.

## v0.1.0 (2026-10-04)

First version a host embeds: users, sessions, roles and password sign-in.

- Migrations `0001`-`0010` (table `acct_migrations`): `acct_users`,
  `acct_sessions`, `acct_roles`, `acct_role_scopes`, `acct_user_roles`,
  `acct_credentials`, `acct_recovery`, `acct_blobs`, `acct_profiles`,
  `acct_audit`. All `utf8mb4_bin`, InnoDB, foreign keys cascading from
  `acct_users`.
- Pure modules (no tokio, sqlx or axum): helpers, IP shaping, rate limiter
  with a single-use set, ALTCHA proof of work and the sign-up gate, QR, keys
  (HMAC subkeys, sealing), stateless challenges, scopes and username rules,
  Argon2id (plus legacy bcrypt), TOTP, recovery codes, WebAuthn, SSHSIG and
  device-key verifiers.
- `mysql`: store, migration runner with the `l4f_boot` lock, and the service
  layer: sign-up, password sign-in with per-address, per-account, site-wide
  and known-device caps, sessions, step-up, role and user administration,
  the first admin from the host's env, export, deletion, hourly sweep.
- `axum`: `/account` pages (sign-in, sign-up, sign-out, step-up, dashboard,
  sessions, display name, export, deletion, user and role administration),
  one CSRF layer, `WebHost` for the page shell.
