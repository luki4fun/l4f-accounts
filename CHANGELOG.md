# Changelog

Migrations are append-only once a version is tagged: a host that ran them can
only move forward. **BREAKING** marks changes a host has to act on.

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
