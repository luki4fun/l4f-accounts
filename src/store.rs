//! Every SQL statement on the `acct_*` tables. Methods take and return crate
//! types only, so each backend is the same set of methods: `store/portable.rs`,
//! compiled once for MySQL (`my`, also `MySqlStore`), once for Postgres (`pg`)
//! and once for SQLite (`lite`). `Store` (`store/backend.rs`) is whichever of
//! them runs.
//!
//! Writes that could take `*` away from the last account holding it refuse
//! here, inside their own transaction, rather than in the service: a check
//! before the write would let two admins revoking each other both pass.

use crate::model::AccountId;

mod backend;
pub use backend::{Store, StoreConn, StoreTx};

#[cfg(feature = "mysql")]
pub mod my {
    pub(super) type Db = sqlx::MySql;
    const PG: bool = false;
    const MY: bool = true;
    include!("store/portable.rs");
}

/// The MySQL backend under its name from before there were others.
#[cfg(feature = "mysql")]
pub use my::Backend as MySqlStore;

#[cfg(feature = "postgres")]
pub mod pg {
    pub(super) type Db = sqlx::Postgres;
    const PG: bool = true;
    const MY: bool = false;
    include!("store/portable.rs");
}

#[cfg(feature = "sqlite")]
pub mod lite {
    pub(super) type Db = sqlx::Sqlite;
    const PG: bool = false;
    const MY: bool = false;
    include!("store/portable.rs");
}

#[derive(Debug)]
pub enum CreateUserError {
    UsernameTaken,
    Db(sqlx::Error),
}

impl From<sqlx::Error> for CreateUserError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

/// A write the store refused, or a database failure. Either way nothing changed.
#[derive(Debug)]
pub enum WriteError {
    /// It would leave no active account holding `*`, and nobody could
    /// administer the site again short of editing the database.
    LastAdmin,
    /// Built-in roles can be edited but never deleted.
    Builtin,
    Db(sqlx::Error),
}

impl From<sqlx::Error> for WriteError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

/// One stored value: a synced setting, a vault item or slot, an avatar.
#[derive(Clone, Debug)]
pub struct Blob {
    pub k: String,
    pub v: Vec<u8>,
    pub version: i64,
    pub updated_at: i64,
}

/// How `Store::put_blob` went.
#[derive(Debug, PartialEq, Eq)]
pub enum PutBlob {
    /// Written; the new version.
    Done(i64),
    /// Someone wrote it since `expect` (or it exists and `expect` was 0).
    Conflict,
    /// The account's storage would go over its quota.
    Quota,
}

/// How `Store::put_blob_limited` went: `put_blob`'s answer, or one of the two
/// refusals only it has. Nothing changed unless `Put(PutBlob::Done(_))`.
#[derive(Debug, PartialEq, Eq)]
pub enum PutLimited {
    Put(PutBlob),
    /// A new key, and the namespace holds `max_keys` already.
    Full,
    /// `need_sync`, and the account has sync off.
    SyncOff,
}

/// An account's profile settings. `public_id` `None`: the profile is off.
#[derive(Clone, Debug, Default)]
pub struct Profile {
    pub public_id: Option<[u8; 16]>,
    pub bio: String,
    pub show_badges: bool,
}

/// How `Store::create_user_with_invite` went. Nothing changed unless `Done`.
#[derive(Debug, PartialEq, Eq)]
pub enum InviteSignup {
    Done,
    /// Unknown, used, expired, or bound to another name.
    BadInvite,
    UsernameTaken,
}

/// How `Store::delete_credential_if_not_last` went. Nothing changed unless `Done`.
#[derive(Debug, PartialEq, Eq)]
pub enum DeleteCredential {
    Done,
    /// The account has no such credential.
    NotFound,
    /// It would leave no password, passkey or social identity: nothing that
    /// both signs in and makes a session recent.
    LastWayIn,
}

/// How `Store::confirm_email` went.
#[derive(Debug, PartialEq, Eq)]
pub enum EmailConfirm {
    Done,
    /// The pending address changed or was removed since the link was sent.
    Stale,
    /// Another account verified it first.
    Taken,
}

/// `seen_at` is written at most this often: a write per request would turn every
/// page view into a row lock and a binlog entry.
pub const TOUCH_SECS: i64 = 600;

const USER_COLS: &str = "id, username, display_name, email, email_pending, password_hash IS NOT NULL, \
     totp_enc IS NOT NULL, status, sync_enabled, created_at, \
     EXISTS (SELECT 1 FROM acct_credentials c WHERE c.user_id = acct_users.id AND c.kind = 'passkey')";

const CRED_COLS: &str = "kind, ext_id, user_id, public_key, alg, sign_count, flags, name, created_at, last_used_at, public";

const SESSION_COLS: &str = "token_hash, user_id, created_at, seen_at, expires_at, auth_at, mfa_ok, method, ip, ua";
/// Signed-in sessions kept per account; the oldest go first.
pub const MAX_SESSIONS: u32 = 50;
/// Sessions waiting for a second factor kept per account.
pub const MAX_PENDING: u32 = 10;
/// The export holds the newest this many audit rows, so one request cannot
/// pull an unbounded trail into memory.
const EXPORT_AUDIT_ROWS: u32 = 10_000;

/// One row per scope, ordered by role then scope; a role without scopes still
/// gets one row (NULL scope) from the LEFT JOIN.
const ROLE_COLS: &str = "r.id, r.name, r.description, r.badge, r.builtin, s.scope";

fn is_dup(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(d) if d.is_unique_violation())
}

fn id(b: Vec<u8>) -> sqlx::Result<AccountId> {
    AccountId::from_slice(&b).ok_or_else(|| sqlx::Error::Decode("account id is not 16 bytes".into()))
}

fn opt_id(b: Option<Vec<u8>>) -> sqlx::Result<Option<AccountId>> {
    b.map(id).transpose()
}

/// At most `max` characters, cut on a character boundary. For the free-form
/// columns (user agent, audit detail): an over-long value must not fail the
/// login or the event that carries it.
fn clip(s: &str, max: usize) -> &str {
    s.char_indices().nth(max).map_or(s, |(i, _)| &s[..i])
}

/// `%`, `_` and the escape itself are literal in a search box.
fn like_pattern(q: &str) -> String {
    let mut p = String::from("%");
    for c in q.to_lowercase().chars() {
        if matches!(c, '!' | '%' | '_') {
            p.push('!');
        }
        p.push(c);
    }
    p.push('%');
    p
}

/// A LIMIT or OFFSET as every backend binds it.
fn lim(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// The `?` placeholders numbered `$1`, `$2`… in order, as Postgres takes them.
/// A `?` inside a '…' literal is text, not a placeholder.
fn numbered(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len() + 16);
    let (mut n, mut quoted) = (0, false);
    for c in sql.chars() {
        match c {
            '\'' => quoted = !quoted,
            '?' if !quoted => {
                n += 1;
                out.push_str(&format!("${n}"));
                continue;
            }
            _ => {}
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::backend::each;
    use super::*;
    use crate::migrate;
    use crate::model::{NewUser, SessionInfo, User, UserStatus};
    use crate::util;
    use sqlx::AssertSqlSafe;

    /// The shared test database. Tests run in parallel against it, so every
    /// name carries a random suffix, nothing grants `*`, and nothing counts
    /// rows across the whole schema. `L4F_TEST_DATABASE_URL` picks the backend
    /// (`mysql://`, `postgres://`, `sqlite://`); unset, the tests pass vacuously.
    pub(crate) async fn shared() -> Option<Store> {
        let url = std::env::var("L4F_TEST_DATABASE_URL").ok()?;
        let store = Store::connect(&url).await.expect("L4F_TEST_DATABASE_URL does not connect");
        migrate::run(&store).await.unwrap();
        Some(store)
    }

    /// A database of its own (`l4f_test_<hex>`), for tests about global state:
    /// who holds `*`, how many rows a sweep removes. `done` drops it; a failed
    /// test leaves it behind on the throwaway server (or in the temp dir).
    pub(crate) struct Fresh {
        pub(crate) store: Store,
        name: String,
        #[cfg_attr(not(any(feature = "mysql", feature = "postgres")), allow(dead_code))]
        url: String,
    }

    pub(crate) async fn fresh() -> Option<Fresh> {
        let url = std::env::var("L4F_TEST_DATABASE_URL").ok()?;
        let name = format!("l4f_test_{}", hex::encode(util::random::<6>()));
        let store = match url.split_once(':').map_or("", |(s, _)| s) {
            #[cfg(feature = "mysql")]
            "mysql" | "mariadb" => {
                use sqlx::Connection;
                let opts: sqlx::mysql::MySqlConnectOptions = url.parse().expect("L4F_TEST_DATABASE_URL does not parse");
                let mut c = sqlx::MySqlConnection::connect_with(&opts).await.unwrap();
                sqlx::raw_sql(AssertSqlSafe(format!("CREATE DATABASE `{name}`"))).execute(&mut c).await.unwrap();
                let _ = c.close().await;
                Store::from(sqlx::MySqlPool::connect_with(opts.database(&name)).await.unwrap())
            }
            #[cfg(feature = "postgres")]
            "postgres" | "postgresql" => {
                use sqlx::Connection;
                let opts: sqlx::postgres::PgConnectOptions = url.parse().expect("L4F_TEST_DATABASE_URL does not parse");
                let mut c = sqlx::PgConnection::connect_with(&opts).await.unwrap();
                sqlx::raw_sql(AssertSqlSafe(format!("CREATE DATABASE \"{name}\""))).execute(&mut c).await.unwrap();
                let _ = c.close().await;
                Store::from(sqlx::PgPool::connect_with(opts.database(&name)).await.unwrap())
            }
            #[cfg(feature = "sqlite")]
            "sqlite" => Store::connect(&format!("sqlite://{}", sqlite_path(&name).display())).await.unwrap(),
            other => panic!("no backend for {other:?} in this build"),
        };
        migrate::run(&store).await.unwrap();
        Some(Fresh { store, name, url })
    }

    #[cfg(feature = "sqlite")]
    fn sqlite_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("{name}.db"))
    }

    impl Fresh {
        pub(crate) async fn done(self) {
            self.store.close().await;
            match &self.store {
                #[cfg(feature = "mysql")]
                Store::My(_) => {
                    use sqlx::Connection;
                    let opts: sqlx::mysql::MySqlConnectOptions = self.url.parse().unwrap();
                    let mut c = sqlx::MySqlConnection::connect_with(&opts).await.unwrap();
                    sqlx::raw_sql(AssertSqlSafe(format!("DROP DATABASE `{}`", self.name))).execute(&mut c).await.unwrap();
                    let _ = c.close().await;
                }
                #[cfg(feature = "postgres")]
                Store::Pg(_) => {
                    use sqlx::Connection;
                    let mut c = sqlx::PgConnection::connect(&self.url).await.unwrap();
                    sqlx::raw_sql(AssertSqlSafe(format!("DROP DATABASE \"{}\"", self.name))).execute(&mut c).await.unwrap();
                    let _ = c.close().await;
                }
                #[cfg(feature = "sqlite")]
                Store::Lite(_) => {
                    let path = sqlite_path(&self.name);
                    for suffix in ["", "-wal", "-shm", ".lock"] {
                        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
                    }
                }
            }
        }
    }

    /// A value for `exec`/`scalar`.
    pub(crate) enum Arg {
        B(Vec<u8>),
        I(i64),
        S(String),
    }

    /// Test SQL is written with `?`, like the store's; Postgres numbers them.
    fn dialect(store: &Store, sql: &str) -> String {
        match store {
            #[cfg(feature = "postgres")]
            Store::Pg(_) => numbered(sql),
            #[allow(unreachable_patterns)]
            _ => sql.to_string(),
        }
    }

    macro_rules! run_on {
        ($store:expr, $sql:expr, $args:expr, $make:path, $fetch:ident $(, $post:ident)?) => {{
            let sql = dialect($store, $sql);
            each!($store, Store(b) => {
                let mut q = $make(AssertSqlSafe(sql));
                for a in $args {
                    q = match a { Arg::B(v) => q.bind(v), Arg::I(v) => q.bind(v), Arg::S(v) => q.bind(v) };
                }
                q.$fetch(&b.0).await.unwrap()$(.$post())?
            })
        }};
    }

    /// A raw statement on whichever backend the tests run on: rows affected.
    pub(crate) async fn exec(store: &Store, sql: &str, args: Vec<Arg>) -> u64 {
        run_on!(store, sql, args, sqlx::query, execute, rows_affected)
    }

    /// A raw `SELECT COUNT(*)`-style query: its one integer.
    pub(crate) async fn scalar(store: &Store, sql: &str, args: Vec<Arg>) -> i64 {
        run_on!(store, sql, args, sqlx::query_scalar, fetch_one)
    }

    /// `exec` on a connection a host was handed (`Host::delete_user`).
    pub(crate) async fn exec_conn(conn: StoreConn<'_>, sql: &str, args: Vec<Arg>) -> u64 {
        macro_rules! on {
            ($c:expr, $sql:expr) => {{
                let mut q = sqlx::query(AssertSqlSafe($sql));
                for a in args {
                    q = match a { Arg::B(v) => q.bind(v), Arg::I(v) => q.bind(v), Arg::S(v) => q.bind(v) };
                }
                q.execute($c).await.unwrap().rows_affected()
            }};
        }
        match conn {
            #[cfg(feature = "mysql")]
            StoreConn::My(c) => on!(c, sql.to_string()),
            #[cfg(feature = "postgres")]
            StoreConn::Pg(c) => on!(c, numbered(sql)),
            #[cfg(feature = "sqlite")]
            StoreConn::Lite(c) => on!(c, sql.to_string()),
        }
    }

    /// `delete_user` on a pool connection of its own, outside any transaction.
    pub(crate) async fn delete(s: &Store, id: AccountId) -> Result<bool, WriteError> {
        match s {
            #[cfg(feature = "mysql")]
            Store::My(b) => MySqlStore::delete_user(&mut b.0.acquire().await.unwrap(), id).await,
            #[cfg(feature = "postgres")]
            Store::Pg(b) => pg::Backend::delete_user(&mut b.0.acquire().await.unwrap(), id).await,
            #[cfg(feature = "sqlite")]
            Store::Lite(b) => lite::Backend::delete_user(&mut b.0.acquire().await.unwrap(), id).await,
        }
    }

    fn unique(prefix: &str) -> String {
        format!("{prefix}{}", hex::encode(util::random::<6>()))
    }

    fn new_user(username: &str) -> NewUser {
        NewUser {
            id: AccountId::new(),
            username: username.to_string(),
            display_name: String::new(),
            email_pending: None,
            password_hash: None,
            created_at: util::now(),
        }
    }

    async fn make_user(s: &Store, role: Option<&str>) -> AccountId {
        let u = new_user(&unique("u"));
        s.create_user(&u, role).await.unwrap();
        u.id
    }

    async fn make_role(s: &Store, scopes: &[&str]) -> (AccountId, String) {
        let name = unique("r");
        let id = s.create_role(&name, "", None).await.unwrap().unwrap();
        s.set_role_scopes(id, &strings(scopes)).await.unwrap();
        (id, name)
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn sess(user: AccountId, created: i64, seen: i64, expires: i64) -> SessionInfo {
        SessionInfo {
            token_hash: util::random(),
            user_id: user,
            created_at: created,
            seen_at: seen,
            expires_at: expires,
            auth_at: 0,
            mfa_ok: false,
            method: "password".into(),
            ip: "203.0.113.0".into(),
            ua: "test".into(),
        }
    }

    /// Ten recovery code hashes, as `replace_recovery` takes them.
    fn codes() -> Vec<[u8; 32]> {
        (0..10).map(|_| util::random()).collect()
    }

    /// A credential of `kind` with a random id: all a removal reads.
    async fn add_credential(s: &Store, user: AccountId, kind: &str) -> [u8; 16] {
        let ext = util::random();
        let sql = "INSERT INTO acct_credentials (kind, ext_id, user_id, created_at) VALUES (?, ?, ?, 1)";
        exec(s, sql, vec![Arg::S(kind.into()), Arg::B(ext.to_vec()), Arg::B(user.0.to_vec())]).await;
        ext
    }

    async fn rows_for(s: &Store, table: &str, id: AccountId) -> i64 {
        scalar(s, &format!("SELECT COUNT(*) FROM {table} WHERE user_id = ?"), vec![Arg::B(id.0.to_vec())]).await
    }

    #[test]
    fn clip_cuts_on_characters_and_like_pattern_escapes() {
        assert_eq!(clip("abc", 5), "abc");
        assert_eq!(clip("ééé", 2), "éé");
        assert_eq!(clip("", 0), "");
        assert_eq!(like_pattern("A_b%c!"), "%a!_b!%c!!%");
    }

    #[test]
    fn numbered_counts_placeholders_in_order_outside_literals() {
        assert_eq!(numbered("UPDATE t SET a = ?, b = ? WHERE c IN (?, ?)"), "UPDATE t SET a = $1, b = $2 WHERE c IN ($3, $4)");
        assert_eq!(
            numbered("SELECT '?', 'it''s ?', '' FROM t WHERE a LIKE ? ESCAPE '!' AND b = ?"),
            "SELECT '?', 'it''s ?', '' FROM t WHERE a LIKE $1 ESCAPE '!' AND b = $2",
            "a `?` in a literal is text, and numbering goes on after it"
        );
        let plain = "SELECT COUNT(*) FROM t WHERE s = '*'";
        assert_eq!(numbered(plain), plain, "no placeholder, no `$`");
    }

    #[tokio::test]
    async fn users_round_trip_and_update() {
        let Some(s) = shared().await else { return };
        let mut u = new_user(&unique("u"));
        u.display_name = "Dee".into();
        u.email_pending = Some("dee@example.com".into());
        u.password_hash = Some("h1".into());
        s.create_user(&u, None).await.unwrap();

        let got = s.user_by_id(u.id).await.unwrap().expect("created user is found by id");
        assert_eq!(got.username, u.username);
        assert_eq!(got.display_name, "Dee");
        assert_eq!(got.email, None, "a new address is pending, never verified");
        assert_eq!(got.email_pending.as_deref(), Some("dee@example.com"));
        assert!(got.has_password && !got.totp_enabled && !got.sync_enabled);
        assert_eq!(got.status, UserStatus::Active);
        assert_eq!(s.user_by_username(&u.username).await.unwrap().map(|x| x.id), Some(u.id));
        assert!(s.user_by_username(&unique("nobody")).await.unwrap().is_none());
        assert!(s.user_by_id(AccountId::new()).await.unwrap().is_none());

        assert_eq!(s.password_hash_of(u.id).await.unwrap().as_deref(), Some("h1"));
        assert!(!s.set_password_hash(u.id, "h2").await.unwrap(), "a first password, and this account has one");
        assert!(s.rehash_password(u.id, "h1", "h2").await.unwrap());
        assert!(!s.rehash_password(u.id, "h1", "h3").await.unwrap(), "a stale rehash must not overwrite a new password");
        assert_eq!(s.password_hash_of(u.id).await.unwrap().as_deref(), Some("h2"));
        assert!(s.rehash_password(u.id, "h2", "h3").await.unwrap());
        assert_eq!(s.password_hash_of(u.id).await.unwrap().as_deref(), Some("h3"));

        assert!(s.set_display_name(u.id, "Dee Two").await.unwrap());
        assert!(s.set_sync_enabled(u.id, true).await.unwrap());
        assert!(s.set_status(u.id, UserStatus::Disabled).await.unwrap());
        let got = s.user_by_id(u.id).await.unwrap().unwrap();
        assert_eq!((got.display_name.as_str(), got.sync_enabled, got.status), ("Dee Two", true, UserStatus::Disabled));
        assert!(!s.set_status(AccountId::new(), UserStatus::Disabled).await.unwrap(), "unknown id changes nothing");
        assert!(!s.set_password_hash(AccountId::new(), "x").await.unwrap());

        let nopw = make_user(&s, None).await;
        assert!(!s.user_by_id(nopw).await.unwrap().unwrap().has_password);
        assert_eq!(s.password_hash_of(nopw).await.unwrap(), None);
        assert_eq!(s.password_hash_of(AccountId::new()).await.unwrap(), None);
        assert!(s.set_password_hash(nopw, "p1").await.unwrap());
        assert!(!s.set_password_hash(nopw, "p2").await.unwrap(), "two first passwords: only one is written");
        assert_eq!(s.password_hash_of(nopw).await.unwrap().as_deref(), Some("p1"));

        assert!(delete(&s, u.id).await.unwrap());
        assert!(!delete(&s, u.id).await.unwrap(), "second delete finds nothing");
        assert!(delete(&s, nopw).await.unwrap());
    }

    #[tokio::test]
    async fn same_username_race_has_exactly_one_winner() {
        let Some(s) = shared().await else { return };
        let name = unique("u");
        let (a, b) = (new_user(&name), new_user(&name));
        let (ra, rb) = tokio::join!(s.create_user(&a, None), s.create_user(&b, None));
        let winner = match (ra, rb) {
            (Ok(()), Err(CreateUserError::UsernameTaken)) => a.id,
            (Err(CreateUserError::UsernameTaken), Ok(())) => b.id,
            other => panic!("expected one winner and one UsernameTaken, got {other:?}"),
        };
        assert!(matches!(s.create_user(&new_user(&name), None).await, Err(CreateUserError::UsernameTaken)));
        assert_eq!(s.user_by_username(&name).await.unwrap().unwrap().id, winner);
        delete(&s, winner).await.unwrap();
    }

    #[tokio::test]
    async fn create_user_grants_its_role_or_nothing() {
        let Some(s) = shared().await else { return };
        let (role, role_name) = make_role(&s, &["t:one"]).await;
        let u = make_user(&s, Some(&role_name)).await;
        assert_eq!(s.user_roles(u).await.unwrap().iter().map(|r| r.id).collect::<Vec<_>>(), [role]);

        let orphan = new_user(&unique("u"));
        assert!(matches!(s.create_user(&orphan, Some(&unique("missing"))).await, Err(CreateUserError::Db(_))));
        assert!(s.user_by_id(orphan.id).await.unwrap().is_none(), "the user insert rolls back with the failed grant");

        delete(&s, u).await.unwrap();
        s.delete_role(role).await.unwrap();
    }

    #[tokio::test]
    async fn list_users_searches_pages_and_takes_wildcards_literally() {
        let Some(s) = shared().await else { return };
        let p = unique("l");
        let mut ids = Vec::new();
        let now = util::now();
        for (age, name, display) in [(30, "_one", "Alpha"), (20, "xone", "Beta"), (10, "_two", "Gamma")] {
            let mut u = new_user(&format!("{p}{name}"));
            u.display_name = format!("{display} {p}");
            u.created_at = now - age;
            s.create_user(&u, None).await.unwrap();
            ids.push(u.id);
        }
        let ids_of = |users: &[User]| users.iter().map(|u| u.id).collect::<Vec<_>>();

        let (all, n) = s.list_users(Some(&p), 10, 0).await.unwrap();
        assert_eq!((ids_of(&all), n), (vec![ids[2], ids[1], ids[0]], 3), "newest first");
        let (under, n) = s.list_users(Some(&format!("{p}_")), 10, 0).await.unwrap();
        assert_eq!(n, 2, "`_` is literal, so {p}xone must not match");
        assert!(under.iter().all(|u| u.username.contains('_')));
        let (page, n) = s.list_users(Some(&p), 1, 1).await.unwrap();
        assert_eq!((ids_of(&page), n), (vec![ids[1]], 3), "limit and offset page, the count does not");
        let (by_display, n) = s.list_users(Some(&format!("BETA {p}")), 10, 0).await.unwrap();
        assert_eq!((n, by_display[0].id), (1, ids[1]), "display names match case-insensitively");
        let mail = unique("m");
        exec(&s, "UPDATE acct_users SET email = ? WHERE id = ?", vec![Arg::S(format!("{mail}@example.org")), Arg::B(ids[0].0.to_vec())]).await;
        let (by_mail, n) = s.list_users(Some(&mail.to_uppercase()), 10, 0).await.unwrap();
        assert_eq!((ids_of(&by_mail), n), (vec![ids[0]], 1), "the verified address matches too");
        let (_, n) = s.list_users(Some(&format!("{p}%")), 10, 0).await.unwrap();
        assert_eq!(n, 0, "`%` is literal too");
        let (_, everyone) = s.list_users(Some("  "), 1, 0).await.unwrap();
        assert!(everyone >= 3, "a blank search lists everyone");

        for id in ids {
            delete(&s, id).await.unwrap();
        }
    }

    #[tokio::test]
    async fn sessions_are_capped_and_never_land_on_a_disabled_account() {
        let Some(s) = shared().await else { return };
        let u = make_user(&s, None).await;
        let now = util::now();
        let mut full = Vec::new();
        for i in 0..MAX_SESSIONS as i64 + 3 {
            let mut x = sess(u, now - 1000 + i, now - 1000 + i, now + 100);
            x.mfa_ok = true;
            s.insert_session(&x).await.unwrap();
            full.push(x.token_hash);
        }
        for i in 0..MAX_PENDING as i64 + 3 {
            s.insert_session(&sess(u, now + i, now + i, now + 100)).await.unwrap();
        }
        let left = s.sessions_of(u).await.unwrap();
        assert_eq!(left.iter().filter(|x| x.mfa_ok).count(), MAX_SESSIONS as usize, "the oldest signed-in ones went");
        assert_eq!(left.iter().filter(|x| !x.mfa_ok).count(), MAX_PENDING as usize, "pending ones did not push them out");
        assert!(left.iter().any(|x| x.token_hash == full[full.len() - 1]) && !left.iter().any(|x| x.token_hash == full[0]));

        assert!(s.set_status(u, UserStatus::Disabled).await.unwrap());
        let late = sess(u, now, now, now + 100);
        assert!(matches!(s.insert_session(&late).await, Err(sqlx::Error::RowNotFound)), "a login in flight gets no session");
        assert!(s.session_by_hash(&late.token_hash, now).await.unwrap().is_none());
    }

    /// Logins with a second factor sign in through a pending session: they
    /// count against the same cap.
    #[tokio::test]
    async fn sessions_completed_by_a_second_factor_are_capped_too() {
        let Some(s) = shared().await else { return };
        let u = make_user(&s, None).await;
        let now = util::now();
        let mut done = Vec::new();
        for i in 0..MAX_SESSIONS as i64 + 3 {
            let pending = sess(u, now - 1000 + i, now - 1000 + i, now + 100);
            s.insert_session(&pending).await.unwrap();
            let new: [u8; 32] = util::random();
            assert!(s.complete_session(&pending.token_hash, &new, now, now + 100).await.unwrap());
            done.push(new);
        }
        let left = s.sessions_of(u).await.unwrap();
        assert_eq!(left.len(), MAX_SESSIONS as usize, "the oldest went");
        assert!(left.iter().all(|x| x.mfa_ok));
        assert!(left.iter().any(|x| x.token_hash == done[done.len() - 1]) && !left.iter().any(|x| x.token_hash == done[0]));
        delete(&s, u).await.unwrap();
    }

    #[tokio::test]
    async fn sessions_expire_touch_rotate_and_delete() {
        let Some(s) = shared().await else { return };
        let (u, other) = (make_user(&s, None).await, make_user(&s, None).await);
        let now = util::now();
        let mut live = sess(u, now, now, now + 100);
        live.ua = "é".repeat(300);
        let mut expired = sess(u, now - 50, now - 50, now - 1);
        let mut keep = sess(u, now, now, now + 100);
        // Hashes ascend against the order sessions_of promises, so the primary
        // key's order cannot pass for it.
        (expired.token_hash[0], keep.token_hash[0]) = (0x10, 0x20);
        for x in [&live, &expired, &keep] {
            s.insert_session(x).await.unwrap();
        }

        let got = s.session_by_hash(&live.token_hash, now).await.unwrap().expect("live session");
        assert_eq!((got.user_id, got.expires_at, got.method.as_str()), (u, now + 100, "password"));
        assert_eq!(got.ua.chars().count(), 256, "user agent cut to the column");
        assert!(s.session_by_hash(&expired.token_hash, now).await.unwrap().is_none(), "past expires_at");
        assert!(s.session_by_hash(&live.token_hash, now + 100).await.unwrap().is_none(), "expiry is exclusive");

        assert!(!s.touch_session(&live.token_hash, now + TOUCH_SECS).await.unwrap(), "not older than 600 s yet");
        assert!(s.touch_session(&live.token_hash, now + TOUCH_SECS + 1).await.unwrap());
        assert_eq!(s.session_by_hash(&live.token_hash, now).await.unwrap().unwrap().seen_at, now + TOUCH_SECS + 1);
        assert!(!s.touch_session(&live.token_hash, now + TOUCH_SECS + 60).await.unwrap(), "just written");

        let done: [u8; 32] = util::random();
        assert!(s.complete_session(&live.token_hash, &done, now + 5, now + 200).await.unwrap());
        assert!(s.session_by_hash(&live.token_hash, now).await.unwrap().is_none(), "the pending token is dead");
        let got = s.session_by_hash(&done, now).await.unwrap().unwrap();
        assert!(got.mfa_ok);
        assert_eq!((got.auth_at, got.expires_at), (now + 5, now + 200));
        assert!(!s.complete_session(&done, &util::random(), now + 6, now + 300).await.unwrap(), "only once");

        let rotated: [u8; 32] = util::random();
        assert!(s.rotate_session(&done, &rotated).await.unwrap());
        assert!(s.session_by_hash(&done, now).await.unwrap().is_none(), "old token dead after rotation");
        assert!(s.session_by_hash(&rotated, now).await.unwrap().unwrap().mfa_ok, "rotation keeps the session");
        assert!(!s.rotate_session(&done, &util::random()).await.unwrap());

        assert!(!s.delete_session(&rotated, other).await.unwrap(), "someone else's hash deletes nothing");
        assert!(s.delete_session(&rotated, u).await.unwrap());
        assert!(s.session_by_hash(&rotated, now).await.unwrap().is_none());

        let (mut tie, mut newer) = (sess(u, now + 1, now, now + 100), sess(u, now - 5, now + 7, now + 100));
        (tie.token_hash[0], newer.token_hash[0]) = (0x30, 0x40);
        for x in [&tie, &newer, &sess(other, now, now, now + 100)] {
            s.insert_session(x).await.unwrap();
        }
        let order: Vec<_> = s.sessions_of(u).await.unwrap().iter().map(|x| x.token_hash).collect();
        let want = [newer.token_hash, tie.token_hash, keep.token_hash, expired.token_hash];
        assert_eq!(order, want, "last seen first, then newest; expired rows stay until the sweep");
        assert_eq!(s.delete_sessions_of(u, Some(&keep.token_hash)).await.unwrap(), 3);
        let left = s.sessions_of(u).await.unwrap();
        assert_eq!(left.iter().map(|x| x.token_hash).collect::<Vec<_>>(), [keep.token_hash]);
        assert_eq!(s.sessions_of(other).await.unwrap().len(), 1, "other accounts untouched");
        assert_eq!(s.delete_sessions_of(u, None).await.unwrap(), 1);
        assert!(s.sessions_of(u).await.unwrap().is_empty());

        delete(&s, u).await.unwrap();
        delete(&s, other).await.unwrap();
    }

    #[tokio::test]
    async fn sweep_removes_expired_and_idle_sessions_in_batches() {
        let Some(f) = fresh().await else { return };
        let s = &f.store;
        let u = make_user(s, None).await;
        let now = util::now();
        let idle = 1000;
        for _ in 0..5 {
            s.insert_session(&sess(u, now - 10, now - 10, now - 1)).await.unwrap();
        }
        for _ in 0..3 {
            s.insert_session(&sess(u, now - 2000, now - idle - 1, now + 100)).await.unwrap();
        }
        let live = [sess(u, now, now, now + 100), sess(u, now - 2000, now - idle + 1, now + 100)];
        for x in &live {
            s.insert_session(x).await.unwrap();
        }
        let mut swept = Vec::new();
        loop {
            let n = s.delete_expired_sessions(now, idle, 3).await.unwrap();
            swept.push(n);
            if n < 3 {
                break;
            }
        }
        assert_eq!(swept, [3, 3, 2]);
        let mut left: Vec<_> = s.sessions_of(u).await.unwrap().iter().map(|x| x.token_hash).collect();
        let mut want: Vec<_> = live.iter().map(|x| x.token_hash).collect();
        left.sort();
        want.sort();
        assert_eq!(left, want, "live and recently seen sessions survive");
        f.done().await;
    }

    /// New codes asked for twice at once (a double submit): one set stays
    /// valid, never both.
    #[tokio::test]
    async fn racing_recovery_replacements_leave_one_set() {
        let Some(s) = shared().await else { return };
        let u = make_user(&s, None).await;
        for round in 0..3 {
            let (a, b) = (codes(), codes());
            let (ra, rb) = tokio::join!(s.replace_recovery(u, &a), s.replace_recovery(u, &b));
            ra.unwrap();
            rb.unwrap();
            assert_eq!(s.recovery_left(u).await.unwrap(), 10, "round {round}");
        }
        delete(&s, u).await.unwrap();
    }

    /// A delete that lands while a write waits for the key's row: the write
    /// finds the key gone and conflicts, rather than putting it back.
    #[tokio::test]
    async fn a_blob_deleted_under_a_waiting_write_stays_deleted() {
        let Some(s) = shared().await else { return };
        let u = make_user(&s, None).await;
        assert_eq!(s.put_blob(u, "kv", "k", b"1", 0, 1000).await.unwrap(), PutBlob::Done(1));
        let sql = dialect(&s, "DELETE FROM acct_blobs WHERE user_id = ? AND ns = 'kv' AND k = 'k'");
        each!(&s, Store(b) => {
            let mut tx = b.0.begin().await.unwrap();
            sqlx::query(AssertSqlSafe(sql)).bind(&u.0[..]).execute(&mut *tx).await.unwrap();
            let put = tokio::spawn({
                let s = s.clone();
                async move { s.put_blob(u, "kv", "k", b"2", 1, 1000).await }
            });
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            tx.commit().await.unwrap();
            assert_eq!(put.await.unwrap().unwrap(), PutBlob::Conflict);
        });
        assert!(s.blob(u, "kv", "k").await.unwrap().is_none(), "the delete stands");
        delete(&s, u).await.unwrap();
    }

    /// Creates racing at the key cap queue on the account's row and count
    /// after each other: the cap fills and holds. The sync switch is read
    /// there too (ADMIN-9, store-data-6).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capped_writes_count_under_the_accounts_lock() {
        let Some(s) = shared().await else { return };
        let u = make_user(&s, None).await;
        assert_eq!(s.put_blob_limited(u, "kv", "k0", b"1", 0, 1000, Some(5), true).await.unwrap(), PutLimited::SyncOff);
        assert!(s.set_sync_enabled(u, true).await.unwrap());
        let puts: Vec<_> = (0..8)
            .map(|i| {
                let s = s.clone();
                tokio::spawn(async move { s.put_blob_limited(u, "kv", &format!("k{i}"), b"1", 0, 1000, Some(5), true).await.unwrap() })
            })
            .collect();
        let mut got = Vec::new();
        for p in puts {
            got.push(p.await.unwrap());
        }
        assert_eq!(got.iter().filter(|r| **r == PutLimited::Put(PutBlob::Done(1))).count(), 5, "{got:?}");
        assert_eq!(got.iter().filter(|r| **r == PutLimited::Full).count(), 3, "{got:?}");
        assert_eq!(s.blob_count(u, "kv").await.unwrap(), 5);
        let kept = s.blobs(u, "kv").await.unwrap().remove(0).k;
        let update = s.put_blob_limited(u, "kv", &kept, b"2", 1, 1000, Some(5), true).await.unwrap();
        assert_eq!(update, PutLimited::Put(PutBlob::Done(2)), "a full set still updates");
        assert!(s.set_sync_enabled(u, false).await.unwrap());
        assert_eq!(s.put_blob_limited(u, "kv", &kept, b"3", 2, 1000, Some(5), true).await.unwrap(), PutLimited::SyncOff);
        assert_eq!(s.put_blob_limited(u, "vault", "v", b"3", 0, 1000, None, false).await.unwrap(), PutLimited::Put(PutBlob::Done(1)));
        delete(&s, u).await.unwrap();
    }

    #[tokio::test]
    async fn a_used_counter_never_falls_back_to_zero() {
        let Some(s) = shared().await else { return };
        let u = make_user(&s, None).await;
        let (zero, counting): ([u8; 16], [u8; 16]) = (util::random(), util::random());
        for ext in [zero, counting] {
            let sql = "INSERT INTO acct_credentials (kind, ext_id, user_id, created_at) VALUES ('passkey', ?, ?, 1)";
            exec(&s, sql, vec![Arg::B(ext.to_vec()), Arg::B(u.0.to_vec())]).await;
        }
        assert!(s.used_credential("passkey", &zero, 0, 10).await.unwrap(), "an authenticator that stays at 0");
        assert!(s.used_credential("passkey", &zero, 0, 11).await.unwrap());
        assert!(s.used_credential("passkey", &counting, 7, 10).await.unwrap());
        assert!(!s.used_credential("passkey", &counting, 7, 11).await.unwrap(), "the same count again");
        assert!(!s.used_credential("passkey", &counting, 0, 12).await.unwrap(), "a clone reporting 0");
        assert!(s.used_credential("passkey", &counting, 8, 13).await.unwrap());
        let c = s.credential("passkey", &counting).await.unwrap().unwrap();
        assert_eq!((c.sign_count, c.last_used_at), (8, Some(13)));
        delete(&s, u).await.unwrap();
    }

    /// Without a password, an account keeps a passkey or a social identity.
    /// Two removals at once queue on the account's row, so the second counts
    /// what the first left and they cannot both go; from the second round on
    /// the pool has a connection for each, so they really overlap. An SSH key
    /// does not count: it never makes a session recent (store-data-8, FAC-4).
    #[tokio::test]
    async fn racing_removals_keep_a_way_to_step_up() {
        let Some(s) = shared().await else { return };
        for round in 0..3 {
            let u = make_user(&s, None).await;
            let (pk, sub) = (add_credential(&s, u, "passkey").await, add_credential(&s, u, "oauth:google").await);
            let (a, b) = tokio::join!(s.delete_credential_if_not_last(u, "passkey", &pk), s.delete_credential_if_not_last(u, "oauth:google", &sub));
            let mut got = [a.unwrap(), b.unwrap()];
            got.sort_by_key(|r| *r != DeleteCredential::Done);
            assert_eq!(got, [DeleteCredential::Done, DeleteCredential::LastWayIn], "round {round}");
            assert_eq!(s.step_up_credentials(u).await.unwrap(), 1, "round {round}: one of them stays");
            delete(&s, u).await.unwrap();
        }
        let u = make_user(&s, None).await;
        let (pk, ssh) = (add_credential(&s, u, "passkey").await, add_credential(&s, u, "ssh").await);
        assert_eq!(s.delete_credential_if_not_last(u, "passkey", &pk).await.unwrap(), DeleteCredential::LastWayIn, "SSH alone");
        assert_eq!(s.delete_credential_if_not_last(u, "ssh", &ssh).await.unwrap(), DeleteCredential::Done);
        assert_eq!(s.delete_credential_if_not_last(u, "ssh", &ssh).await.unwrap(), DeleteCredential::NotFound);
        assert!(s.set_password_hash(u, "stand-in").await.unwrap());
        assert_eq!(s.delete_credential_if_not_last(u, "passkey", &pk).await.unwrap(), DeleteCredential::Done, "a password stays");
        delete(&s, u).await.unwrap();
    }

    #[tokio::test]
    async fn builtin_roles_are_seeded_once_and_never_regrow() {
        let Some(f) = fresh().await else { return };
        let s = &f.store;
        // A bad default scope from config stops the boot rather than being stored.
        assert!(matches!(s.ensure_builtin_roles(&strings(&["links:own", "* "])).await, Err(sqlx::Error::InvalidArgument(_))));
        assert!(s.role_by_name("user").await.unwrap().is_none(), "the refused role is not half-made");
        s.ensure_builtin_roles(&strings(&["links:own", "storage:sync", "links:own"])).await.unwrap();
        let admin = s.role_by_name("admin").await.unwrap().unwrap();
        let user = s.role_by_name("user").await.unwrap().unwrap();
        assert!(admin.builtin && user.builtin);
        assert_eq!(admin.scopes, ["*"]);
        assert_eq!(user.scopes, ["links:own", "storage:sync"], "deduplicated and sorted");

        s.set_role_scopes(user.id, &strings(&["links:own"])).await.unwrap();
        s.ensure_builtin_roles(&strings(&["links:own", "storage:sync", "vault:use"])).await.unwrap();
        let roles = s.roles().await.unwrap();
        assert_eq!(roles.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["admin", "user"]);
        assert_eq!(roles[1].id, user.id, "the existing row is kept");
        assert_eq!(roles[1].scopes, ["links:own"], "a trimmed role must not grow back on restart");
        assert_eq!(roles[0].scopes, ["*"]);

        assert!(matches!(s.delete_role(admin.id).await, Err(WriteError::Builtin)));
        assert!(matches!(s.delete_role(user.id).await, Err(WriteError::Builtin)));
        assert!(s.role_by_name("user").await.unwrap().is_some());
        f.done().await;
    }

    #[tokio::test]
    async fn custom_roles_edit_and_replace_scopes_atomically() {
        let Some(s) = shared().await else { return };
        let name = unique("r");
        let id = s.create_role(&name, "first", Some("B")).await.unwrap().expect("new name");
        assert_eq!(s.create_role(&name, "again", None).await.unwrap(), None, "taken name");
        let r = s.role_by_name(&name).await.unwrap().unwrap();
        assert_eq!((r.id, r.description.as_str(), r.badge.as_deref(), r.builtin), (id, "first", Some("B"), false));
        assert!(r.scopes.is_empty());

        assert!(s.update_role(id, "second", None).await.unwrap());
        s.set_role_scopes(id, &strings(&["t:b", "t:*", "t:b"])).await.unwrap();
        let r = s.role_by_name(&name).await.unwrap().unwrap();
        assert_eq!((r.description.as_str(), r.badge.as_deref()), ("second", None));
        assert_eq!(r.scopes, ["t:*", "t:b"]);

        // `* ` and `t:b ` compare equal to `*` and `t:b` in the PAD SPACE column.
        let too_long = "t".repeat(65);
        for bad in [&["t:new", &too_long][..], &["* "], &["t:b", "t:b "], &["T:b"], &["t*"]] {
            let r = s.set_role_scopes(id, &strings(bad)).await;
            assert!(matches!(r, Err(WriteError::Db(sqlx::Error::InvalidArgument(_)))), "{bad:?} must be refused, got {r:?}");
        }
        assert_eq!(s.role_by_name(&name).await.unwrap().unwrap().scopes, ["t:*", "t:b"], "failed replace keeps the old set");
        assert!(s.roles().await.unwrap().iter().any(|r| r.id == id));

        s.set_role_scopes(id, &[]).await.unwrap();
        assert!(s.role_by_name(&name).await.unwrap().unwrap().scopes.is_empty());
        assert!(s.delete_role(id).await.unwrap());
        assert!(s.role_by_name(&name).await.unwrap().is_none());
        assert!(!s.delete_role(id).await.unwrap(), "already gone");
        assert!(!s.update_role(id, "x", None).await.unwrap());
    }

    /// The role and its scopes appear together or not at all: an empty one
    /// would pass a grant's check that the granter covers it (ADMIN-3).
    #[tokio::test]
    async fn a_role_is_created_with_its_scopes_in_one_go() {
        let Some(s) = shared().await else { return };
        let name = unique("r");
        assert!(s.create_role_with_scopes(&name, "", None, &strings(&["t:a", "* "])).await.is_err());
        assert!(s.role_by_name(&name).await.unwrap().is_none(), "no role left without its scopes");
        let id = s.create_role_with_scopes(&name, "d", Some("B"), &strings(&["t:b", "t:a"])).await.unwrap().expect("new name");
        let r = s.role_by_name(&name).await.unwrap().unwrap();
        assert_eq!((r.id, r.description.as_str(), r.badge.as_deref(), r.scopes), (id, "d", Some("B"), strings(&["t:a", "t:b"])));
        assert_eq!(s.create_role_with_scopes(&name, "", None, &strings(&["*"])).await.unwrap(), None, "taken name");
        assert_eq!(s.role_by_name(&name).await.unwrap().unwrap().scopes, ["t:a", "t:b"], "and the scopes it had");
        assert!(s.delete_role(id).await.unwrap());
    }

    #[tokio::test]
    async fn user_scopes_join_every_role() {
        let Some(s) = shared().await else { return };
        let (r1, _) = make_role(&s, &["t:one", "t:shared"]).await;
        let (r2, _) = make_role(&s, &["t:shared", "t:two"]).await;
        let (u, by) = (make_user(&s, None).await, make_user(&s, None).await);
        assert!(s.user_scopes(u).await.unwrap().is_empty());
        assert!(s.grant_role(u, r1, Some(by)).await.unwrap());
        assert!(!s.grant_role(u, r1, None).await.unwrap(), "second grant is a no-op");
        assert!(s.grant_role(u, r2, None).await.unwrap());
        assert!(s.grant_role(AccountId::new(), r1, None).await.is_err(), "unknown user is an error, not a silent no-op");

        let mut want = vec![r1, r2];
        let mut got: Vec<_> = s.user_roles(u).await.unwrap().iter().map(|r| r.id).collect();
        want.sort_by_key(|r| r.0);
        got.sort_by_key(|r| r.0);
        assert_eq!(got, want);
        assert_eq!(s.user_scopes(u).await.unwrap(), ["t:one", "t:shared", "t:two"]);

        assert!(s.revoke_role(u, r1).await.unwrap());
        assert!(!s.revoke_role(u, r1).await.unwrap());
        assert_eq!(s.user_scopes(u).await.unwrap(), ["t:shared", "t:two"]);
        s.set_role_scopes(r2, &strings(&["t:three"])).await.unwrap();
        assert_eq!(s.user_scopes(u).await.unwrap(), ["t:three"], "scopes are read live from the role");

        for id in [u, by] {
            delete(&s, id).await.unwrap();
        }
        for r in [r1, r2] {
            s.delete_role(r).await.unwrap();
        }
    }

    #[tokio::test]
    async fn the_last_star_holder_cannot_be_removed() {
        let Some(f) = fresh().await else { return };
        let s = &f.store;
        s.ensure_builtin_roles(&strings(&["profile:public"])).await.unwrap();
        assert_eq!(s.holders_of_scope_star().await.unwrap(), 0);
        let admin = s.role_by_name("admin").await.unwrap().unwrap().id;
        let plain = make_user(s, Some("user")).await;
        assert!(delete(s, plain).await.unwrap(), "nothing to protect before bootstrap");

        let a1 = make_user(s, Some("admin")).await;
        assert_eq!(s.holders_of_scope_star().await.unwrap(), 1);
        assert!(matches!(s.revoke_role(a1, admin).await, Err(WriteError::LastAdmin)));
        assert!(matches!(s.set_status(a1, UserStatus::Disabled).await, Err(WriteError::LastAdmin)));
        assert!(matches!(delete(s, a1).await, Err(WriteError::LastAdmin)));
        assert!(matches!(s.set_role_scopes(admin, &strings(&["users:read"])).await, Err(WriteError::LastAdmin)));
        assert_eq!(s.holders_of_scope_star().await.unwrap(), 1, "every refusal rolled back");
        assert_eq!(s.role_by_name("admin").await.unwrap().unwrap().scopes, ["*"]);
        assert_eq!(s.user_by_id(a1).await.unwrap().unwrap().status, UserStatus::Active);

        // A second holder through a custom role frees the first.
        let (root, _) = make_role(s, &["*"]).await;
        let a2 = make_user(s, None).await;
        s.grant_role(a2, root, Some(a1)).await.unwrap();
        assert_eq!(s.holders_of_scope_star().await.unwrap(), 2);
        assert!(s.revoke_role(a1, admin).await.unwrap());
        assert!(matches!(s.delete_role(root).await, Err(WriteError::LastAdmin)));
        assert!(matches!(s.set_status(a2, UserStatus::Disabled).await, Err(WriteError::LastAdmin)));

        // Disabled accounts do not count.
        let off = make_user(s, Some("admin")).await;
        assert_eq!(s.holders_of_scope_star().await.unwrap(), 2);
        assert!(s.set_status(off, UserStatus::Disabled).await.unwrap());
        assert_eq!(s.holders_of_scope_star().await.unwrap(), 1);
        assert!(matches!(delete(s, a2).await, Err(WriteError::LastAdmin)));

        // Inside a caller's transaction a refusal undoes only its own delete.
        let other = make_user(s, None).await;
        let mut tx = s.begin().await.unwrap();
        assert!(Store::delete_user(tx.conn(), other).await.unwrap());
        assert!(matches!(Store::delete_user(tx.conn(), a2).await, Err(WriteError::LastAdmin)));
        tx.commit().await.unwrap();
        assert!(s.user_by_id(other).await.unwrap().is_none(), "the caller's earlier work commits");
        assert!(s.user_by_id(a2).await.unwrap().is_some());
        f.done().await;
    }

    /// Two admins removed at the same moment, for real: two threads, a barrier,
    /// and a pool that is warm after the first round. `low` is a scoped role
    /// whose id sorts before `admin`'s; random ids decide that order on a real
    /// install, and with it a scan of acct_role_scopes deadlocked.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn racing_admin_removals_leave_exactly_one_and_never_deadlock() {
        let Some(f) = fresh().await else { return };
        let s = &f.store;
        s.ensure_builtin_roles(&strings(&["links:own", "profile:public"])).await.unwrap();
        let low = AccountId([0; 16]);
        exec(s, "INSERT INTO acct_roles (id, name, created_at) VALUES (?, 'low', 1)", vec![Arg::B(low.0.to_vec())]).await;
        s.set_role_scopes(low, &strings(&["links:own", "profile:public"])).await.unwrap();
        let admin = s.role_by_name("admin").await.unwrap().unwrap().id;

        let mut keep = make_user(s, Some("admin")).await;
        for round in 0..30 {
            let other = make_user(s, Some("admin")).await;
            let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
            let go = |how: usize, u: AccountId| {
                let (s, b) = (s.clone(), barrier.clone());
                tokio::spawn(async move {
                    b.wait().await;
                    match how {
                        0 => s.revoke_role(u, admin).await,
                        1 => delete(&s, u).await,
                        _ => s.set_status(u, UserStatus::Disabled).await,
                    }
                })
            };
            let (h1, h2) = [(0, 0), (1, 1), (2, 0)][round % 3];
            let (j1, j2) = (go(h1, keep), go(h2, other));
            let (r1, r2) = (j1.await.unwrap(), j2.await.unwrap());
            keep = match (&r1, &r2) {
                (Ok(true), Err(WriteError::LastAdmin)) => other,
                (Err(WriteError::LastAdmin), Ok(true)) => keep,
                x => panic!("round {round} ({h1}, {h2}): expected one removal and one LastAdmin, got {x:?}"),
            };
            assert_eq!(s.holders_of_scope_star().await.unwrap(), 1, "round {round}");
        }
        f.done().await;
    }

    /// A server whose default is REPEATABLE READ, where a statement after a
    /// lock wait would read a snapshot from before it: the store's own
    /// transactions name READ COMMITTED (the guarded ones also a bound on the
    /// wait), and a host's transaction at another level is refused.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn postgres_transactions_run_at_read_committed() {
        let Some(Store::Pg(_)) = shared().await else { return };
        let opts: sqlx::postgres::PgConnectOptions = std::env::var("L4F_TEST_DATABASE_URL").unwrap().parse().unwrap();
        let pool = sqlx::PgPool::connect_with(opts.options([("default_transaction_isolation", "repeatable read")])).await.unwrap();
        let s = Store::from(pool.clone());
        let u = make_user(&s, None).await;
        let (a, b) = (codes(), codes());
        let (ra, rb) = tokio::join!(s.replace_recovery(u, &a), s.replace_recovery(u, &b));
        ra.unwrap();
        rb.unwrap();
        assert_eq!(s.recovery_left(u).await.unwrap(), 10, "the second DELETE saw the first one's codes");
        assert!(s.set_status(u, UserStatus::Disabled).await.unwrap(), "a guarded write");

        let mut host = pool.begin().await.unwrap();
        let r = Store::delete_user(StoreConn::Pg(&mut host), u).await;
        assert!(matches!(r, Err(WriteError::Db(sqlx::Error::InvalidArgument(_)))), "got {r:?}");
        drop(host);

        let mut tx = s.begin().await.unwrap();
        let (level, wait): (String, String) = match &mut tx {
            StoreTx::Pg(t) => sqlx::query_as("SELECT current_setting('transaction_isolation'), current_setting('lock_timeout')")
                .fetch_one(&mut **t)
                .await
                .unwrap(),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        };
        assert_eq!((level.as_str(), wait.as_str()), ("read committed", "30s"));
        assert!(Store::delete_user(tx.conn(), u).await.unwrap());
        tx.commit().await.unwrap();
        s.close().await;
    }

    #[tokio::test]
    async fn audit_lists_newest_first_and_ages_out_in_batches() {
        let Some(f) = fresh().await else { return };
        let s = &f.store;
        let (u, actor) = (make_user(s, None).await, make_user(s, None).await);
        s.audit(Some(u), None, "login_ok", "first", "203.0.113.0").await.unwrap();
        s.audit(Some(u), Some(actor), "role_grant", &"x".repeat(300), "198.51.100.77").await.unwrap();
        s.audit(Some(u), Some(u), "display_name", "", "203.0.113.9").await.unwrap();
        s.audit(None, Some(actor), "bootstrap", "", "").await.unwrap();

        let log = s.audit_of(u, 10).await.unwrap();
        assert_eq!(log.iter().map(|e| e.event.as_str()).collect::<Vec<_>>(), ["display_name", "role_grant", "login_ok"]);
        assert_eq!((log[1].user_id, log[1].actor_id), (Some(u), Some(actor)));
        assert_eq!(log[1].detail.len(), 255, "detail cut to the column");
        assert_eq!(log[1].ip, "", "the acting admin's address is not the user's to see");
        assert_eq!(log[0].ip, "203.0.113.9", "the user's own action keeps it");
        assert_eq!((log[2].detail.as_str(), log[2].ip.as_str(), log[2].actor_id), ("first", "203.0.113.0", None));
        assert!(log[0].at >= util::now() - 60);
        assert_eq!(s.audit_of(u, 1).await.unwrap().len(), 1);

        for at in 1..=7 {
            exec(s, "INSERT INTO acct_audit (user_id, event, at) VALUES (?, 'old', ?)", vec![Arg::B(u.0.to_vec()), Arg::I(at)]).await;
        }
        assert_eq!(s.delete_audit_before(100, 3).await.unwrap(), 3);
        assert_eq!(s.delete_audit_before(100, 3).await.unwrap(), 3);
        assert_eq!(s.delete_audit_before(100, 3).await.unwrap(), 1);
        assert_eq!(s.delete_audit_before(100, 3).await.unwrap(), 0);
        assert_eq!(s.audit_of(u, 100).await.unwrap().len(), 3, "recent rows stay");
        f.done().await;
    }

    #[tokio::test]
    async fn deleting_a_user_takes_every_row_with_it() {
        let Some(s) = shared().await else { return };
        let (role, _) = make_role(&s, &["t:x"]).await;
        let (u, bystander) = (make_user(&s, None).await, make_user(&s, None).await);
        let now = util::now();
        s.grant_role(u, role, None).await.unwrap();
        s.insert_session(&sess(u, now, now, now + 100)).await.unwrap();
        s.audit(Some(u), None, "login_ok", "", "").await.unwrap();
        s.audit(Some(bystander), Some(u), "role_grant", "", "").await.unwrap();
        for (sql, extra) in [
            // ext_id = the user id: unique, and the key is global across test runs.
            ("INSERT INTO acct_credentials (kind, ext_id, user_id, created_at) SELECT 'ssh', id, id, 1 FROM acct_users WHERE id = ?", None),
            ("INSERT INTO acct_recovery (user_id, code_hash) VALUES (?, ?)", Some(vec![b'a'; 32])),
            ("INSERT INTO acct_blobs (user_id, ns, k, v, updated_at) VALUES (?, 'kv', 'k', ?, 1)", Some(b"v".to_vec())),
            ("INSERT INTO acct_profiles (user_id, updated_at) VALUES (?, 1)", None),
        ] {
            let mut args = vec![Arg::B(u.0.to_vec())];
            args.extend(extra.map(Arg::B));
            exec(&s, sql, args).await;
        }
        let tables = [
            "acct_sessions",
            "acct_user_roles",
            "acct_credentials",
            "acct_recovery",
            "acct_blobs",
            "acct_profiles",
            "acct_audit",
        ];
        for t in tables {
            assert_eq!(rows_for(&s, t, u).await, 1, "{t} seeded");
        }

        // Inside a caller's transaction the delete is undone with it.
        let mut tx = s.begin().await.unwrap();
        assert!(Store::delete_user(tx.conn(), u).await.unwrap());
        tx.rollback().await.unwrap();
        assert!(s.user_by_id(u).await.unwrap().is_some());

        assert!(delete(&s, u).await.unwrap());
        assert!(s.user_by_id(u).await.unwrap().is_none());
        for t in tables {
            assert_eq!(rows_for(&s, t, u).await, 0, "{t} must cascade");
        }
        assert_eq!(s.audit_of(bystander, 10).await.unwrap().len(), 1, "others' audit rows naming the actor stay");
        assert!(s.roles().await.unwrap().iter().any(|r| r.id == role), "the role itself stays");

        delete(&s, bystander).await.unwrap();
        s.delete_role(role).await.unwrap();
    }

    #[tokio::test]
    async fn export_holds_the_account_but_no_secrets() {
        let Some(s) = shared().await else { return };
        let (role, role_name) = make_role(&s, &["t:x"]).await;
        let mut nu = new_user(&unique("u"));
        nu.password_hash = Some("$argon2id$v=19$m=19456,t=2,p=1$SALTSALTSALT$SECRETHASHSECRETHASH".into());
        s.create_user(&nu, Some(&role_name)).await.unwrap();
        let u = nu.id;
        let totp = [0xc3u8; 40];
        let public_key = [0x99u8; 65];
        let recovery = [0x55u8; 32];
        let ext: [u8; 16] = util::random();
        exec(&s, "UPDATE acct_users SET totp_enc = ? WHERE id = ?", vec![Arg::B(totp.to_vec()), Arg::B(u.0.to_vec())]).await;
        exec(
            &s,
            "INSERT INTO acct_credentials (kind, ext_id, user_id, public_key, alg, name, created_at)
             VALUES ('passkey', ?, ?, ?, -7, 'Laptop', 5)",
            vec![Arg::B(ext.to_vec()), Arg::B(u.0.to_vec()), Arg::B(public_key.to_vec())],
        )
        .await;
        exec(&s, "INSERT INTO acct_recovery (user_id, code_hash) VALUES (?, ?)", vec![Arg::B(u.0.to_vec()), Arg::B(recovery.to_vec())]).await;
        let now = util::now();
        let session = sess(u, now, now, now + 100);
        s.insert_session(&session).await.unwrap();
        let admin = make_user(&s, None).await;
        s.audit(Some(u), Some(admin), "role_revoke", "", "198.51.100.77").await.unwrap();
        s.audit(Some(u), None, "register", "", "203.0.113.0").await.unwrap();
        let avatar = b"\x89PNG the avatar";
        assert_eq!(s.put_blob(u, "avatar", "a", avatar, 0, 1000).await.unwrap(), PutBlob::Done(1));
        let profile = Profile { public_id: Some(util::random()), bio: "Hi, it's me".into(), show_badges: false };
        s.save_profile(u, &profile, now).await.unwrap();

        let v = s.export_user(u).await.unwrap().expect("account exists");
        assert_eq!(v["profile"], serde_json::json!({ "on": true, "bio": "Hi, it's me", "show_badges": false }));
        let stored = v["storage"].as_array().unwrap();
        assert!(stored.iter().any(|b| b["ns"] == "avatar" && b["value"] == util::b64u(avatar).as_str()), "{stored:?}");
        assert_eq!(v["user"]["username"], nu.username.as_str());
        assert_eq!(v["user"]["id"], u.hex().as_str());
        assert_eq!(v["user"]["has_password"], true);
        assert_eq!(v["user"]["totp_enabled"], true);
        assert!(v["user"].get("email_verified_at").is_some());
        assert_eq!(v["roles"][0]["name"], role_name.as_str());
        assert_eq!(v["sessions"][0]["method"], "password");
        assert_eq!(v["credentials"][0]["kind"], "passkey");
        assert_eq!(v["credentials"][0]["name"], "Laptop");
        assert_eq!(v["audit"][0]["event"], "register");
        assert_eq!(v["audit"][1]["event"], "role_revoke");

        let text = v.to_string();
        assert!(!text.contains("198.51.100.77"), "export hands out the acting admin's address");
        let b64 = |b: &[u8]| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(b)
        };
        for secret in [&totp[..], &public_key[..], &recovery[..], &session.token_hash[..], &ext[..]] {
            for form in [hex::encode(secret), util::b64u(secret), b64(secret)] {
                assert!(!text.contains(&form), "export leaks {form}");
            }
        }
        for field in ["SECRETHASH", "argon2", "password_hash", "totp_enc", "token_hash", "public_key", "code_hash", "ext_id"] {
            assert!(!text.contains(field), "export leaks {field}");
        }
        assert!(s.export_user(AccountId::new()).await.unwrap().is_none());

        delete(&s, u).await.unwrap();
        delete(&s, admin).await.unwrap();
        s.delete_role(role).await.unwrap();
    }

    /// Processes booting at once on a new file: each of them gets its store.
    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sqlite_connects_racing_on_a_new_file_all_succeed() {
        let path = sqlite_path(&unique("l4f_race_"));
        let url = format!("sqlite://{}", path.display());
        let racers: Vec<_> = (0..8)
            .map(|_| {
                let url = url.clone();
                tokio::spawn(async move { Store::connect(&url).await })
            })
            .collect();
        for r in racers {
            r.await.unwrap().expect("a racing connect gets its store").close().await;
        }
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
