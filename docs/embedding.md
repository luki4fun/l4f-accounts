# Embedding l4f-accounts

How a host application uses this crate: what each feature brings, what the
host must do, and how a host without HTTP (voipc, later) makes the same calls.
l4f (MaxLuki) is the reference host: `src/main.rs`, `src/site_host.rs` and
`src/web.rs` there show every duty below in working code.

## Features

| feature | adds | pulls in |
|---|---|---|
| *(none)* | `util`, `ip`, `limit` (rate limiter), `pow` (ALTCHA + sign-up gate), `qr`, `keys`, `challenge`, `scope`, `password`, `totp`, `recovery`, `verify::{webauthn, sshsig, devkey}`, `model` | nothing async: usable from any server |
| `mysql` | `store`, `migrate`, `service` (`Accounts`) on MySQL/MariaDB | sqlx (MySQL), tokio |
| `postgres` | the same on Postgres | sqlx (Postgres), tokio |
| `sqlite` | the same on SQLite (bundled, so a static build keeps working) | sqlx (SQLite), tokio |
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
   - `Store::connect(url)` (or `Store::from(pool)`): the backend follows the
     URL's scheme, among those the build has features for. SQLite needs a
     file with foreign keys on; `migrate::run` refuses anything else.
   - The crate builds sqlx with `tls-none`: the link to the database is
     plaintext, and asking for TLS in the URL (`sslmode=require`,
     `ssl-mode=REQUIRED`) fails. Keep the database on the same machine or a
     private network, or enable a sqlx TLS feature in the host's own
     `Cargo.toml` (`tls-rustls-ring-webpki` keeps to ring); Cargo turns it on
     for this crate's sqlx too.
   - `migrate::run(&store)`: its own connection, the boot lock (`GET_LOCK` on
     MySQL, an advisory lock on Postgres, `<database>.lock` on SQLite), table
     `acct_migrations`. A host's own tables can use the same lock
     (`migrate::lock` / `unlock`; `BootLock::conn` is the `StoreConn`, free
     of the pool's statement caps).
   - `Accounts::build(store, keys, limiter, host, app_scopes, pow_key, ip_salt)`
     seeds the built-in `admin` (`*`) and `user` roles (the latter with
     `default_user_scopes`, only when it is created). It refuses an app scope
     the crate or an earlier entry already registered.
   - `bootstrap_admin(username, hash)` while nobody holds `*`.
   - `with_mailer(...)` and `with_oauth(...)` when configured.
3. **Secrets from the environment only**: the `Keys` master, the ALTCHA key
   (at least 32 bytes: a shorter one is logged and dropped, and sign-up stays
   closed), the IP salt (at least 32 bytes for `ip_mode = "hash"`), the SMTP
   password, OAuth secrets. `Config` refuses unknown keys and holds none of
   these.
   - The master (`Keys::new(current, old)`) is at least 32 bytes of CSPRNG
     output, never a passphrase: say the text of `openssl rand -hex 32`,
     passed as is. Back it up, it seals TOTP secrets. Changing how that text
     becomes bytes (starting to decode it) changes the master: do it as a
     rotation.
   - To rotate, pass the new master and the old one as `old`. The hourly
     sweep reseals every TOTP secret still under the old one
     (`Swept::resealed`). Drop the old one once a sweep reseals none and a
     day has passed (mail links live that long). Recovery codes issued
     before the rotation match under the old master only: keep it as long as
     they must work, or have each account with a second factor make a new
     set. Known-device cookies made under it are forgotten then, until the
     next sign-in.
   - The crate's `Keys` purposes are reserved: `challenge`, `csrf`, `device`,
     `notice`, `email-verify`, `reset`, `totp`, `totp-setup`, `recovery`,
     `oauth-flow`, `oauth-signup`. `subkey(p)` is the very key `sign(p)` and
     `seal(p)` use, so a host that derives keys of its own from
     `Accounts::keys` prefixes its purposes (`host/…`).
4. **`Host`**:
   - `config()`: return the live `Config` (re-read per call, so a reload
     applies), with `base_url` the site's URL without a trailing slash.
   - `export(user)`: the host's rows for the account's data download.
   - `delete_user(tx, user, delete_owned)`: runs inside the deletion
     transaction (`tx` is a `StoreConn`: match the backend you run on); an
     error rolls everything back. The transaction holds the last-admin guard
     to its end, so every write goes through `tx`: one through a pool,
     `Store` or `Accounts` can wait on it and fails after a timeout.
   - `profile_links(user)` (optional): the host's public links on a profile.
     Only those starting with `https://`, `http://` or `/` are shown.
5. **`WebHost`** (feature `axum`):
   - `page(headers, title, body)`: wrap the crate's escaped fragment in the
     site's page. `title` is plain text: escape it like any value. Account
     pages are noindex with no canonical link.
   - `dashboard_links(scopes)` (optional): the host's pages for this account.
6. **The client address**: insert `web::ClientIp(ip)` into every request after
   the host's own proxy check. Without it every handler that needs a `Ctx`
   answers 500 on purpose.
7. **Routes**: nest `web::router(accounts)` at `/account` (`web::BASE`;
   redirects and forms use it) and `web::profile_router(accounts)` at
   `/profile`, where the profile settings link to. A host's own pages under
   `/account` can be merged into the same router; they sit outside its CSRF
   layer and must check `Sec-Fetch-Site` and `Authed::check_csrf` themselves.
8. **One process, one rate limiter**, shared with the host (crate keys start
   with `acct-`). Single use and every cap hold per process: a second
   instance accepts a burned challenge or a solved proof of work once more,
   and counts every cap from zero. Run one instance, or move spends and
   counters to shared storage first. A host's own keys take the crate's
   shapes: `kind:source` per address (past 12,500 sources a kind forgets its
   least recently hit ones), `kind-{id}:x` per account and `kind:global`
   site-wide, which are never evicted.
9. **An hourly `sweep(now)`**: expired sessions, old audit rows, device keys
   unused for 90 days, expired invites, and during a key rotation the TOTP
   secrets still under the old master (3 above).
10. **Static files and scripts the pages need**:
    - `/static/js/pow.js`, the ALTCHA solver sign-up uses: it fills `#altcha`
      from `#pow-challenge`, with the JSON payload or its base64 (as the
      official widget sends it). The crate serves its own scripts at
      `/account/assets/*.js`.
    - A script for `data-confirm`, which no crate script handles: without
      one, turning codes off, a new set of recovery codes or deleting the
      account takes a single click.
      ```js
      document.addEventListener('submit', (e) => {
        const ask = e.target.dataset.confirm;
        if (ask && !confirm(ask)) e.preventDefault();
      });
      ```
11. **Headers**:
    - The crate's pages work under `default-src 'self'`, `form-action 'self'`
      and Trusted Types: no inline script or style, no HTML strings in scripts.
      Social sign-in starts from a GET link for that reason.
    - Framing: `web::router` sends `X-Frame-Options: DENY` unless a handler or
      `page` set one. Add `frame-ancestors 'none'` to the CSP too; it also
      covers the profile pages, which get no `X-Frame-Options` from the crate.
    - `Referrer-Policy`: `same-origin` or `strict-origin-when-cross-origin` on
      account pages, not `no-referrer`. Under that a browser without Fetch
      Metadata posts every form with `Origin: null`, and the CSRF layer
      refuses a post without `Sec-Fetch-Site` whose `Origin` is `null` or not
      one of `Config::origins()`. Those are `webauthn_origins` when it is
      set, so that list holds the site's own origin. The reset and
      confirmation pages send `strict-origin` themselves.
    - Keep a `Cache-Control`, `Content-Security-Policy`, `X-Frame-Options` or
      `Referrer-Policy` a handler set: the crate sends `private, no-store` on
      account pages, `no-cache` on its scripts, and serves avatars under
      `default-src 'none'; sandbox`.
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
| `acct-sync` | "sync is on", or was turned off since this browser last pulled; for the host's script | **no** |

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
  `mfa_recovery(...)` within 10 minutes (later: Forbidden, sign in again).
  Then `session_from_token(token, now)` per connection, `logout(token)` at the
  end. `session_from_token` also returns a session still waiting for its
  second factor, with `mfa_ok` false and no scopes: check `mfa_ok` before
  treating the account as signed in.
- **SSH key**: `ssh_challenge(None, nonce)` where `nonce` is at least 16
  random bytes bound to the connection; the client signs the returned text with
  `ssh-keygen -Y sign -n <ssh_namespace>` (or the same SSHSIG format in code);
  `ssh_login(ctx, token, nonce, signature)`.
- **Device key**: `devkey_challenge(None, nonce)`; the client signs
  `devkey::message(origin, device_id, challenge_bytes(token))` with its Ed25519
  key; `devkey_login(ctx, token, nonce, device_id, signature)`. `origin` must be
  one of `Config::origins()`: give a non-browser client its own fixed string
  there (say `voipc://client`). Verified key sign-ins of one account share
  `3 × login_per_user_15min` per 15 minutes: a client that signs in per
  connection may need a higher `login_per_user_15min`.
- **Step-up**: `step_up` (password), `step_up_totp`, `step_up_recovery`
  (spends a recovery code), `passkey_step_up`; check `fresh(&session, now)`
  before a sensitive action. `password_change` checks it itself.
- **A first second factor**: `totp_enable` and `passkey_add` take the calling
  session. For the account's first second factor they end every other
  session and return the caller's with a new token (`Some(NewSession)`): the
  old token stops working, so the client keeps the new one.
- **Invites**: `invite_create(ctx, actor, username, days)` returns the code
  (shown once); `register_invite(ctx, InviteForm { code, … })` signs up with it
  whatever `registration_open` says, with no PoW gate.
- **Second factor for privileged roles**: `needs_2fa(user)` says the account
  holds a scope it cannot use until it enrols one (`totp_setup` /
  `totp_enable`); `reset_2fa` is the admin's way back for a lost phone.
- **First admin without a hash in the environment**: `bootstrap_grant(ctx,
  user)` makes an existing account the admin while nobody holds `*`.
- **Roles and scopes**: `effective_scopes(user)` and `service::require(scopes,
  "x:y")`, or the admin calls with an `Actor`.
- **The host's own shell**, where no signed-in admin acts:
  `invite_create_as_host`, `grant_role_as_host`, `revoke_role_as_host` and
  `reset_2fa_as_host`. The same effects as the admin calls; the audit row has
  no actor and its detail ends in ` (host)`. The last holder of `*` still
  keeps it.

## Backends

`Store` is an enum over the backends, all compiled from one source,
`src/store/portable.rs`: `my::Backend` (also `MySqlStore`), `pg::Backend` and
`lite::Backend`. A query is written once, in MySQL's `?` dialect (`sql!` numbers
the placeholders for Postgres), with `if MY` / `if PG` at the dialect points, and
the suite runs on all three databases (README). Where the dialects part:

- `ON DUPLICATE KEY UPDATE`, `INSERT IGNORE` and `CAST(… AS SIGNED)` on MySQL;
  `ON CONFLICT` and `CAST(… AS BIGINT)` on the others.
- Batch deletes: `DELETE … LIMIT n` on MySQL. Postgres and SQLite have no
  `DELETE … LIMIT`, so there batches are picked by key (`… WHERE key IN (SELECT
  key … LIMIT n)`).
- The last-admin guard: MySQL relies on READ COMMITTED and `FOR UPDATE` on the
  `*` rows. Postgres has no `FOR UPDATE` on an aggregate, so every guarded
  write takes one advisory lock (`pg_advisory_xact_lock`) first, in a
  transaction begun READ COMMITTED with a 30 s `lock_timeout`;
  `Store::delete_user` in a host's own transaction at another level refuses
  (`InvalidArgument`). SQLite starts every writing transaction with
  `BEGIN IMMEDIATE`, its database-wide write lock. Either way the guarded
  writes run one after another and each count sees the one before it.
- Text compares byte-wise like MySQL's `_bin` (Postgres: `COLLATE "C"` on every
  text column; SQLite: its default), without the PAD SPACE quirk. So there the
  admin search ignores case in display names for ASCII letters only: a search
  for `ä` or `Ä` misses a display name spelled with `Ä`.
- On Postgres and SQLite `status` is SMALLINT and the flags are BOOLEAN; the
  store converts.
