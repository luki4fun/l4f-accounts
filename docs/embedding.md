# Embedding l4f-accounts

How a host application uses this crate: what each feature brings, what the
host must do, and how a host without HTTP (voipc, later) makes the same calls.
l4f (MaxLuki) is the reference host: `src/main.rs`, `src/site_host.rs` and
`src/web.rs` there show every duty below in working code.

## Features

| feature | adds | pulls in |
|---|---|---|
| *(none)* | `util`, `ip`, `limit` (rate limiter), `pow` (ALTCHA + sign-up gate), `qr`, `keys`, `challenge`, `scope`, `password`, `totp`, `recovery`, `verify::{webauthn, sshsig, devkey}`, `model` | nothing async: usable from any server |
| `mysql` | `store`, `migrate`, `service` (`Accounts`) | sqlx (MySQL/MariaDB), tokio |
| `axum` | `web`: the `/account` router, `profile_router`, extractors, `WebHost`; `templates/`, `assets/` | `mysql`, axum, askama |
| `email` | `email::Mailer`; address confirmation, password reset, notices | `mysql`, lettre (rustls, ring) |
| `oauth` | `oauth`: Discord, Google, Facebook; social sign-in, linking, step-up | `mysql`, reqwest (rustls, ring) |
| `legacy-bcrypt` | verifies a YOURLS bcrypt hash once and rehashes it to Argon2id | bcrypt |

No feature pulls in OpenSSL or aws-lc: TLS and signatures run on ring, and a
static musl build works (`cargo tree -i openssl-sys` and `-i aws-lc-rs` find
nothing).

## Host duties

1. **A rustls provider before any client.** reqwest and lettre are built
   without one: call `rustls::crypto::ring::default_provider().install_default()`
   first thing in `main`.
2. **Migrations, then the service, then the first admin**, before serving:
   - `migrate::run(&pool)`: its own connection, the `l4f_boot` lock, table
     `acct_migrations`. A host's own tables can use the same lock
     (`migrate::lock` / `unlock`).
   - `Accounts::build(Store(pool), keys, limiter, host, app_scopes, pow_key, ip_salt)`
     seeds the built-in `admin` (`*`) and `user` roles (the latter with
     `default_user_scopes`, only when it is created).
   - `bootstrap_admin(username, hash)` while nobody holds `*`.
   - `with_mailer(...)` and `with_oauth(...)` when configured.
3. **Secrets from the environment only**: the `Keys` master
   (`Keys::new(current, old)`, at least 32 bytes; back it up, it seals TOTP
   secrets), the ALTCHA key, the IP salt, the SMTP password, OAuth secrets.
   `Config` refuses unknown keys and holds none of these.
4. **`Host`**:
   - `config()`: return the live `Config` (re-read per call, so a reload applies).
   - `export(user)`: the host's rows for the account's data download.
   - `delete_user(tx, user, delete_owned)`: runs inside the deletion
     transaction; an error rolls everything back.
   - `profile_links(user)` (optional): the host's public links on a profile.
5. **`WebHost`** (feature `axum`):
   - `page(headers, title, body)`: wrap the crate's escaped fragment in the
     site's page; account pages are noindex with no canonical link.
   - `dashboard_links(scopes)` (optional): the host's pages for this account.
6. **The client address**: insert `web::ClientIp(ip)` into every request after
   the host's own proxy check. Without it every handler that needs a `Ctx`
   answers 500 on purpose.
7. **Routes**: nest `web::router(accounts)` at `/account` (`web::BASE`;
   redirects and forms use it) and `web::profile_router(accounts)` where
   profiles should live. A host's own pages under `/account` can be merged into
   the same router; they sit outside its CSRF layer and must check
   `Sec-Fetch-Site` and `Authed::check_csrf` themselves.
8. **One rate limiter** for the whole process, shared with the host (crate keys
   start with `acct-`).
9. **An hourly `sweep(now)`**: expired sessions, old audit rows, device keys
   unused for 90 days.
10. **Static files the pages load**: `/static/js/pow.js` (the ALTCHA solver
    sign-up uses; it fills `#altcha` from `#pow-challenge`). The crate serves
    its own scripts at `/account/assets/*.js`.
11. **Headers**:
    - The crate's pages work under `default-src 'self'`, `form-action 'self'`
      and Trusted Types: no inline script or style, no HTML strings in scripts.
      Social sign-in starts from a GET link for that reason.
    - Keep a `Cache-Control` and a `Content-Security-Policy` a handler set: the
      crate sends `private, no-store` on account pages, `no-cache` on its
      scripts, and serves avatars under `default-src 'none'; sandbox`.
12. **Settings sync** (optional): where the host keeps local settings in
    `localStorage` under `l4f:`, load the script only while the hint cookie is
    set, and let it wrap the store:
    ```js
    const on = /(?:^|;\s*)(?:__Host-)?acct-sync=1(?:;|$)/.test(document.cookie);
    if (on || localStorage.getItem('l4f-sync:acked'))
      import('/account/assets/sync.js').then((m) => (on ? m.attach(store) : m.cleanup()));
    ```
    `store` needs `get(k, fallback)`, `set(k, v) -> bool` and `del(k)`.
13. **Outbound connections** (mail, OAuth) through a forwarder when the service
    may not reach the internet: `Config::egress` names it; connections go there
    while TLS names and verifies the real server (l4f: an nginx `stream` block
    with `ssl_preread`, `deploy/nginx-l4f-egress.conf`). Every OAuth host is in
    `oauth::EGRESS_HOSTS`.

### Cookies

| name (`__Host-` when `cookie_secure`) | what | HttpOnly |
|---|---|---|
| `acct` | session token | yes |
| `acct-dev` | known device (own sign-in bucket) | yes |
| `acct-ch` | browser nonce of a passkey, SSH or device-key challenge, 10 min | yes |
| `acct-oauth`, `acct-oauth-signup` | sealed OAuth flow and pending sign-up, 10 min | yes |
| `acct-sync` | "sync is on", for the host's script | **no** |

### Scopes

The crate registers `users:read`, `users:admin`, `roles:admin`,
`storage:sync`, `vault:use`, `profile:public`; a host adds its own (`app_scopes`,
l4f: `links:admin`, `links:own`). `default_user_scopes` (default: the last three
crate scopes) are not privileged; anything else counts only for accounts with a
second factor while `require_2fa_for_privileged` is on.

## Without HTTP

The service layer takes no HTTP types. A `Ctx` is the peer address, a client
name for the session list, and `sec_fetch_site: ""`. Sessions are opaque tokens
the client keeps and presents on every connection.

- **Password**: `login_password(ctx, name, password, None)` → `LoginStep::Done`
  or `NeedMfa`; for the latter `mfa_totp(ctx, user, &pending.info, code)` or
  `mfa_recovery(...)`. Then `session_from_token(token, now)` per connection,
  `logout(token)` at the end.
- **SSH key**: `ssh_challenge(None, nonce)` where `nonce` is at least 16
  random bytes bound to the connection; the client signs the returned text with
  `ssh-keygen -Y sign -n <ssh_namespace>` (or the same SSHSIG format in code);
  `ssh_login(ctx, token, nonce, signature)`.
- **Device key**: `devkey_challenge(None, nonce)`; the client signs
  `devkey::message(origin, device_id, challenge_bytes(token))` with its Ed25519
  key; `devkey_login(ctx, token, nonce, device_id, signature)`. `origin` must be
  one of `Config::origins()`: give a non-browser client its own fixed string
  there (say `voipc://client`).
- **Step-up**: `step_up` (password), `step_up_totp`, `passkey_step_up`; check
  `fresh(&session, now)` before a sensitive action.
- **Roles and scopes**: `effective_scopes(user)` and `service::require(scopes,
  "x:y")`, or the admin calls with an `Actor`.

## A SQLite store, later

`Store` is the only MySQL-specific part; a SQLite one would offer the same
methods behind an exclusive feature. What has to change:

- `migrations/mysql` → a sqlite set (no `ENGINE`, `COLLATE`; `BLOB` for
  `BINARY(16)`/`VARBINARY`; no foreign key names).
- The boot lock (`GET_LOCK`) → SQLite's own write lock, or a lock file.
- `READ COMMITTED` and `SELECT … FOR UPDATE` (the last-admin guard, the storage
  quota) → `BEGIN IMMEDIATE`.
- `INSERT … ON DUPLICATE KEY UPDATE` → `INSERT … ON CONFLICT DO UPDATE`.
- `DELETE … LIMIT` batches → `DELETE … WHERE rowid IN (SELECT … LIMIT ?)`.
- The `utf8mb4_bin` byte-wise comparisons → SQLite's default `BINARY`
  collation already compares bytes.
