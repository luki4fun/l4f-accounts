// The store, one source for every backend: `store.rs` `include!`s it once per
// database with `Db` set to `sqlx::MySql`, `sqlx::Postgres` or `sqlx::Sqlite`
// and `MY` or `PG` saying which (neither: SQLite). What each method promises is
// documented on its `Store` twin (`store/backend.rs`); this file notes how each
// database gets there.
//
// One statement serves all three where they all take it: MySQL's text, with `?`
// placeholders bound in order (`sql!` numbers them for Postgres), and spellings
// MySQL takes too (`TRUE`/`FALSE`, `LIMIT n OFFSET m`). Where the dialects part,
// a const or an `if MY` holds each spelling, MySQL's first.
// The last-admin guard is one lock per database: MySQL's locking count under
// READ COMMITTED (`BEGIN_RC`, `star_holders`), a Postgres advisory lock held to
// the end of the transaction (it cannot lock an aggregate), or SQLite's own
// write lock (`BEGIN IMMEDIATE`). Each serialises every write that could take
// `*` away, so the count each of them runs sees the one before it committed.

use sqlx::{AssertSqlSafe, Connection, Pool, Row, Transaction};

use super::{
    Blob, CRED_COLS, CreateUserError, DeleteCredential, EXPORT_AUDIT_ROWS, EmailConfirm, InviteSignup, MAX_PENDING, MAX_SESSIONS,
    Profile, PutBlob, PutLimited, ROLE_COLS, SESSION_COLS, TOUCH_SECS, USER_COLS, WriteError, clip, id, is_dup, like_pattern, lim,
    opt_id,
};
use crate::model::{AccountId, AuditEntry, Credential, Invite, NewUser, Role, SessionInfo, User, UserStatus};
use crate::util;

type Conn = <Db as sqlx::Database>::Connection;
type DbRow = <Db as sqlx::Database>::Row;

#[derive(Clone)]
pub struct Backend(pub Pool<Db>);

/// A statement as this backend takes it: Postgres numbers the `?` placeholders
/// (`$1`, `$2`…), MySQL and SQLite bind them in order. Built once per call site
/// from constants only (the closure captures nothing), so no value a caller
/// passes can reach SQL text.
macro_rules! sql {
    ($($f:tt)+) => {{
        static Q: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
            let s = format!($($f)+);
            debug_assert!(!s.contains('$'), "a `$` placeholder in shared SQL: {s}");
            if PG { super::numbered(&s) } else { s }
        });
        Q.as_str()
    }};
}

/// The guard's advisory lock key ("l4f_star"); Postgres scopes it per database.
const GUARD_KEY: i64 = 0x6c34_665f_7374_6172;

/// Active accounts holding `*` through any role. On MySQL, STRAIGHT_JOIN and
/// FORCE INDEX pin the plan to start from the `*` rows through the `scope` key:
/// as a locking read, a plan that began with acct_users would lock every
/// account, and a scan of acct_role_scopes (the cheapest plan on a tiny table)
/// locks other roles' rows in id order and deadlocks two guarded writes. The
/// others count under a lock of their own and lock no rows.
const STAR_HOLDERS: &str = if MY {
    "SELECT STRAIGHT_JOIN COUNT(DISTINCT ur.user_id) FROM acct_role_scopes s FORCE INDEX (scope) \
     JOIN acct_user_roles ur ON ur.role_id = s.role_id \
     JOIN acct_users u ON u.id = ur.user_id AND u.status = 0 \
     WHERE s.scope = '*'"
} else {
    "SELECT COUNT(DISTINCT ur.user_id) FROM acct_role_scopes s \
     JOIN acct_user_roles ur ON ur.role_id = s.role_id \
     JOIN acct_users u ON u.id = ur.user_id AND u.status = 0 \
     WHERE s.scope = '*'"
};

/// The guard's count locks what it reads on MySQL only: Postgres cannot lock
/// an aggregate, and SQLite has no row locks.
const STAR_LOCK: &str = if MY { " FOR UPDATE" } else { "" };

/// A row lock (the account in the blob writes, `replace_recovery` and
/// `delete_credential_if_not_last`, the key in the blob writes, `delete_role`'s
/// role). SQLite has none to ask for: the transaction already holds the
/// database's write lock.
const FOR_UPDATE: &str = if MY || PG { " FOR UPDATE" } else { "" };

/// `CAST(… AS I64)`: MySQL has no BIGINT to cast to.
const I64: &str = if MY { "SIGNED" } else { "BIGINT" };

/// The credentials that sign in and can also make a session recent.
const STEPS_UP: &str = "(kind = 'passkey' OR kind LIKE 'oauth:%')";

/// An invite a sign-up can claim, binding the code's hash, now, and the name:
/// one text for the claim and for `invite_open`, so the two cannot drift.
const INVITE_OPEN: &str = "code_hash = ? AND used_at IS NULL AND expires_at > ? AND (username IS NULL OR username = ?)";

const UPSERT_BLOB: &str = if MY {
    "ON DUPLICATE KEY UPDATE v = VALUES(v), version = VALUES(version), updated_at = VALUES(updated_at)"
} else {
    "ON CONFLICT (user_id, ns, k) DO UPDATE SET v = excluded.v, version = excluded.version, updated_at = excluded.updated_at"
};

/// MySQL's ON DUPLICATE KEY meets either unique key (user_id or public_id);
/// ON CONFLICT meets user_id only, so a taken public_id is an error there.
const UPSERT_PROFILE: &str = if MY {
    "ON DUPLICATE KEY UPDATE public_id = VALUES(public_id), bio = VALUES(bio), show_badges = VALUES(show_badges), updated_at = VALUES(updated_at)"
} else {
    "ON CONFLICT (user_id) DO UPDATE SET public_id = excluded.public_id, bio = excluded.bio, \
     show_badges = excluded.show_badges, updated_at = excluded.updated_at"
};

/// READ COMMITTED, for the guarded writes (`begin_guarded`),
/// `replace_recovery`, the blob writes and `delete_credential_if_not_last`. On
/// MySQL, under READ COMMITTED the locking count holds record locks only on
/// what it counts: the `*` scope rows, those roles' grants and the holders'
/// user rows. Under REPEATABLE READ it would also take gap locks, which never
/// conflict with each other: two guarded writes on a table without `*` rows
/// both pass the count and then deadlock on each other's inserts. RC also keeps
/// MariaDB's snapshot isolation (an RR check) out of the way. Postgres: named,
/// not left to the server's default (the advisory lock is the guard): under
/// REPEATABLE READ the snapshot is taken as the lock statement starts, before
/// the lock is granted, so the count would miss the write it waited for.
/// SQLite: the write lock, as in `begin_write`.
const BEGIN_RC: &str = if MY {
    "SET TRANSACTION ISOLATION LEVEL READ COMMITTED; START TRANSACTION"
} else if PG {
    "BEGIN ISOLATION LEVEL READ COMMITTED"
} else {
    "BEGIN IMMEDIATE"
};

/// `BEGIN_RC`, with a bound on Postgres's wait for the guard: a guarded write
/// through the pool from inside `Store::begin`'s transaction waits on that
/// transaction, which would otherwise be forever. MySQL's
/// `innodb_lock_wait_timeout` and SQLite's busy timeout bound it there.
const BEGIN_GUARDED: &str = if PG { "BEGIN ISOLATION LEVEL READ COMMITTED; SET LOCAL lock_timeout = '30s'" } else { BEGIN_RC };

/// A transaction that writes. SQLite takes the write lock at BEGIN: a deferred
/// one that reads first and then writes fails with BUSY when another writer
/// got in between, instead of waiting. MySQL keeps its default isolation here.
async fn begin_write(pool: &Pool<Db>) -> sqlx::Result<Transaction<'static, Db>> {
    if MY || PG { pool.begin().await } else { pool.begin_with("BEGIN IMMEDIATE").await }
}

async fn begin_rc(pool: &Pool<Db>) -> sqlx::Result<Transaction<'static, Db>> {
    pool.begin_with(BEGIN_RC).await
}

/// Postgres: the guard's lock, until this transaction ends. It guards only
/// under READ COMMITTED (see `BEGIN_RC`), so a transaction at another level,
/// such as a host's own one around `delete_user`, is refused. MySQL locks rows
/// in `star_holders` instead, and on SQLite the write lock is the guard.
async fn guard(c: &mut Conn) -> sqlx::Result<()> {
    if PG {
        let level: String =
            sqlx::query_scalar(sql!("SELECT current_setting('transaction_isolation') FROM (SELECT pg_advisory_xact_lock(?)) l"))
                .bind(GUARD_KEY)
                .fetch_one(c)
                .await?;
        if level != "read committed" {
            return Err(sqlx::Error::InvalidArgument(format!("the last-admin guard needs READ COMMITTED, not {level}")));
        }
    }
    Ok(())
}

/// How every write in `WriteError::LastAdmin`'s reach starts.
async fn begin_guarded(pool: &Pool<Db>) -> sqlx::Result<Transaction<'static, Db>> {
    let mut tx = pool.begin_with(BEGIN_GUARDED).await?;
    guard(&mut tx).await?;
    Ok(tx)
}

/// The count every guarded write runs first. On MySQL a locking read: two of
/// them queue on the first `*` row of the `scope` key, so the second one counts
/// after the first has committed.
async fn star_holders(c: &mut Conn) -> sqlx::Result<i64> {
    sqlx::query_scalar(sql!("{STAR_HOLDERS}{STAR_LOCK}")).fetch_one(c).await
}

/// Runs after the change, in its transaction; an error drops (rolls back) it.
/// `before == 0` is a database nobody administers yet (before bootstrap), where
/// there is nothing to protect.
async fn keep_an_admin(c: &mut Conn, before: i64) -> Result<(), WriteError> {
    if before > 0 && star_holders(c).await? == 0 {
        return Err(WriteError::LastAdmin);
    }
    Ok(())
}

/// Refuses anything `scope::valid_grant` does not accept. Beyond keeping junk
/// out: MySQL's column is PAD SPACE, so a stored `* ` would count as `*` in the
/// last-admin guard while granting nothing.
async fn insert_scopes(c: &mut Conn, role: AccountId, scopes: &[String]) -> sqlx::Result<()> {
    if let Some(bad) = scopes.iter().find(|s| !crate::scope::valid_grant(s)) {
        return Err(sqlx::Error::InvalidArgument(format!("not a valid scope grant: {bad:?}")));
    }
    let mut scopes: Vec<&str> = scopes.iter().map(String::as_str).collect();
    scopes.sort_unstable();
    scopes.dedup();
    if scopes.is_empty() {
        return Ok(());
    }
    // The one statement built at run time: a row of placeholders per scope.
    let values = vec!["(?, ?)"; scopes.len()].join(", ");
    let sql = format!("INSERT INTO acct_role_scopes (role_id, scope) VALUES {values}");
    let mut q = sqlx::query(AssertSqlSafe(if PG { super::numbered(&sql) } else { sql }));
    for s in scopes {
        q = q.bind(&role.0[..]).bind(s);
    }
    q.execute(c).await.map(|_| ())
}

/// The account row and its `role`, in the caller's transaction. False when
/// the name is taken; `InvalidArgument` when there is no such role.
async fn insert_user(c: &mut Conn, u: &NewUser, role: Option<&str>) -> sqlx::Result<bool> {
    let inserted = sqlx::query(sql!(
        "INSERT INTO acct_users (id, username, display_name, email_pending, password_hash, created_at)
         VALUES (?, ?, ?, ?, ?, ?)"
    ))
    .bind(&u.id.0[..])
    .bind(&u.username)
    .bind(&u.display_name)
    .bind(&u.email_pending)
    .bind(&u.password_hash)
    .bind(u.created_at)
    .execute(&mut *c)
    .await;
    match inserted {
        Err(e) if is_dup(&e) => return Ok(false),
        Err(e) => return Err(e),
        Ok(_) => {}
    }
    if let Some(role) = role {
        let n = sqlx::query(sql!("INSERT INTO acct_user_roles (user_id, role_id, granted_at) SELECT ?, id, ? FROM acct_roles WHERE name = ?"))
            .bind(&u.id.0[..])
            .bind(u.created_at)
            .bind(role)
            .execute(&mut *c)
            .await?
            .rows_affected();
        if n != 1 {
            return Err(sqlx::Error::InvalidArgument(format!("no role named {role:?}")));
        }
    }
    Ok(true)
}

/// A blob write in `tx`, which holds the account's row: the quota and the
/// compare-and-set, then the upsert, committed only if it was written. The
/// key's row is locked too: `delete_blob` takes no account lock, and a delete
/// landing between a plain read and the upsert would be undone by it.
async fn put_locked(
    mut tx: Transaction<'static, Db>,
    user: AccountId,
    ns: &str,
    k: &str,
    v: &[u8],
    expect: i64,
    quota: i64,
) -> sqlx::Result<PutBlob> {
    let used: i64 = sqlx::query_scalar(sql!("SELECT CAST(COALESCE(SUM(LENGTH(v)), 0) AS {I64}) FROM acct_blobs WHERE user_id = ?"))
        .bind(&user.0[..])
        .fetch_one(&mut *tx)
        .await?;
    let current: Option<(i64, i64)> =
        sqlx::query_as(sql!("SELECT version, CAST(LENGTH(v) AS {I64}) FROM acct_blobs WHERE user_id = ? AND ns = ? AND k = ?{FOR_UPDATE}"))
            .bind(&user.0[..])
            .bind(ns)
            .bind(k)
            .fetch_optional(&mut *tx)
            .await?;
    let (old_len, version) = match current {
        Some((ver, _)) if ver != expect => return Ok(PutBlob::Conflict),
        None if expect != 0 => return Ok(PutBlob::Conflict),
        Some((ver, len)) => (len, ver + 1),
        None => (0, 1),
    };
    if used - old_len + v.len() as i64 > quota {
        return Ok(PutBlob::Quota);
    }
    sqlx::query(sql!(
        "INSERT INTO acct_blobs (user_id, ns, k, v, version, updated_at) VALUES (?, ?, ?, ?, ?, ?)
         {UPSERT_BLOB}"
    ))
    .bind(&user.0[..])
    .bind(ns)
    .bind(k)
    .bind(v)
    .bind(version)
    .bind(util::now())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(PutBlob::Done(version))
}

/// `status` is SMALLINT on Postgres (no one-byte integer there); MySQL's TINYINT
/// decodes into an i16 too.
fn status(v: i16) -> UserStatus {
    UserStatus::from_db(i8::from(v != 0))
}

fn user(r: &DbRow) -> sqlx::Result<User> {
    Ok(User {
        id: id(r.try_get(0)?)?,
        username: r.try_get(1)?,
        display_name: r.try_get(2)?,
        email: r.try_get(3)?,
        email_pending: r.try_get(4)?,
        has_password: r.try_get(5)?,
        totp_enabled: r.try_get(6)?,
        status: status(r.try_get(7)?),
        sync_enabled: r.try_get(8)?,
        created_at: r.try_get(9)?,
        has_passkey: r.try_get(10)?,
    })
}

fn credential(r: &DbRow) -> sqlx::Result<Credential> {
    Ok(Credential {
        kind: r.try_get(0)?,
        ext_id: r.try_get(1)?,
        user_id: id(r.try_get(2)?)?,
        public_key: r.try_get(3)?,
        alg: r.try_get::<i32, _>(4)?.into(),
        sign_count: r.try_get(5)?,
        flags: r.try_get::<i32, _>(6)?.into(),
        name: r.try_get(7)?,
        created_at: r.try_get(8)?,
        last_used_at: r.try_get(9)?,
        public: r.try_get(10)?,
    })
}

fn session(r: &DbRow) -> sqlx::Result<SessionInfo> {
    let hash: Vec<u8> = r.try_get(0)?;
    Ok(SessionInfo {
        token_hash: hash.try_into().map_err(|_| sqlx::Error::Decode("token hash is not 32 bytes".into()))?,
        user_id: id(r.try_get(1)?)?,
        created_at: r.try_get(2)?,
        seen_at: r.try_get(3)?,
        expires_at: r.try_get(4)?,
        auth_at: r.try_get(5)?,
        mfa_ok: r.try_get(6)?,
        method: r.try_get(7)?,
        ip: r.try_get(8)?,
        ua: r.try_get(9)?,
    })
}

fn roles_from(rows: Vec<DbRow>) -> sqlx::Result<Vec<Role>> {
    let mut out: Vec<Role> = Vec::new();
    for r in rows {
        let rid = id(r.try_get(0)?)?;
        if out.last().is_none_or(|l| l.id != rid) {
            out.push(Role {
                id: rid,
                name: r.try_get(1)?,
                description: r.try_get(2)?,
                badge: r.try_get(3)?,
                builtin: r.try_get(4)?,
                scopes: Vec::new(),
            });
        }
        if let (Some(scope), Some(role)) = (r.try_get::<Option<String>, _>(5)?, out.last_mut()) {
            role.scopes.push(scope);
        }
    }
    Ok(out)
}

fn invite(r: &DbRow) -> sqlx::Result<Invite> {
    Ok(Invite {
        id: hex::encode(r.try_get::<Vec<u8>, _>(0)?),
        created_by: opt_id(r.try_get(1)?)?,
        username: r.try_get(2)?,
        created_at: r.try_get(3)?,
        expires_at: r.try_get(4)?,
        used_at: r.try_get(5)?,
        used_by: opt_id(r.try_get(6)?)?,
    })
}

fn audit_entry(r: &DbRow) -> sqlx::Result<AuditEntry> {
    Ok(AuditEntry {
        id: r.try_get(0)?,
        user_id: opt_id(r.try_get(1)?)?,
        actor_id: opt_id(r.try_get(2)?)?,
        event: r.try_get(3)?,
        detail: r.try_get(4)?,
        ip: r.try_get(5)?,
        at: r.try_get(6)?,
    })
}

impl Backend {
    /// The guard's locks from the start: Postgres's advisory lock, SQLite's
    /// write lock, and on MySQL the locking count's row locks.
    pub async fn begin(&self) -> sqlx::Result<Transaction<'static, Db>> {
        let mut tx = begin_guarded(&self.0).await?;
        if MY {
            star_holders(&mut tx).await?;
        }
        Ok(tx)
    }

    // ------------------------------------------------------------------ users

    pub async fn create_user(&self, u: &NewUser, role: Option<&str>) -> Result<(), CreateUserError> {
        let mut tx = begin_write(&self.0).await?;
        if !insert_user(&mut tx, u, role).await? {
            return Err(CreateUserError::UsernameTaken);
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn user_by_id(&self, id: AccountId) -> sqlx::Result<Option<User>> {
        sqlx::query(sql!("SELECT {USER_COLS} FROM acct_users WHERE id = ?"))
            .bind(&id.0[..])
            .fetch_optional(&self.0)
            .await?
            .as_ref()
            .map(user)
            .transpose()
    }

    pub async fn user_by_username(&self, username: &str) -> sqlx::Result<Option<User>> {
        sqlx::query(sql!("SELECT {USER_COLS} FROM acct_users WHERE username = ?"))
            .bind(username)
            .fetch_optional(&self.0)
            .await?
            .as_ref()
            .map(user)
            .transpose()
    }

    pub async fn user_by_email(&self, email: &str) -> sqlx::Result<Option<User>> {
        sqlx::query(sql!("SELECT {USER_COLS} FROM acct_users WHERE email = ?"))
            .bind(email)
            .fetch_optional(&self.0)
            .await?
            .as_ref()
            .map(user)
            .transpose()
    }

    pub async fn set_email_pending(&self, id: AccountId, email: Option<&str>) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!("UPDATE acct_users SET email_pending = ? WHERE id = ?")).bind(email).bind(&id.0[..]).execute(&self.0).await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn confirm_email(&self, id: AccountId, email: &str, now: i64) -> sqlx::Result<EmailConfirm> {
        let r = sqlx::query(sql!(
            "UPDATE acct_users SET email = email_pending, email_pending = NULL, email_verified_at = ?
              WHERE id = ? AND email_pending = ?"
        ))
        .bind(now)
        .bind(&id.0[..])
        .bind(email)
        .execute(&self.0)
        .await;
        match r {
            Ok(r) if r.rows_affected() == 1 => Ok(EmailConfirm::Done),
            Ok(_) => Ok(EmailConfirm::Stale),
            Err(e) if is_dup(&e) => Ok(EmailConfirm::Taken),
            Err(e) => Err(e),
        }
    }

    pub async fn clear_email(&self, id: AccountId) -> sqlx::Result<()> {
        sqlx::query(sql!("UPDATE acct_users SET email = NULL, email_pending = NULL, email_verified_at = NULL WHERE id = ?"))
            .bind(&id.0[..])
            .execute(&self.0)
            .await
            .map(|_| ())
    }

    pub async fn password_hash_of(&self, id: AccountId) -> sqlx::Result<Option<String>> {
        let h: Option<Option<String>> = sqlx::query_scalar(sql!("SELECT password_hash FROM acct_users WHERE id = ?"))
            .bind(&id.0[..])
            .fetch_optional(&self.0)
            .await?;
        Ok(h.flatten())
    }

    pub async fn set_password_hash(&self, id: AccountId, hash: &str) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!("UPDATE acct_users SET password_hash = ? WHERE id = ? AND password_hash IS NULL"))
            .bind(hash)
            .bind(&id.0[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn rehash_password(&self, id: AccountId, old: &str, new: &str) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!("UPDATE acct_users SET password_hash = ? WHERE id = ? AND password_hash = ?"))
            .bind(new)
            .bind(&id.0[..])
            .bind(old)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn set_status(&self, id: AccountId, status: UserStatus) -> Result<bool, WriteError> {
        let mut tx = begin_guarded(&self.0).await?;
        let before = star_holders(&mut tx).await?;
        let n = sqlx::query(sql!("UPDATE acct_users SET status = ? WHERE id = ?"))
            .bind(status as i16)
            .bind(&id.0[..])
            .execute(&mut *tx)
            .await?
            .rows_affected();
        keep_an_admin(&mut tx, before).await?;
        tx.commit().await?;
        Ok(n == 1)
    }

    pub async fn set_display_name(&self, id: AccountId, name: &str) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!("UPDATE acct_users SET display_name = ? WHERE id = ?"))
            .bind(name)
            .bind(&id.0[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn set_sync_enabled(&self, id: AccountId, on: bool) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!("UPDATE acct_users SET sync_enabled = ? WHERE id = ?"))
            .bind(on)
            .bind(&id.0[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn list_users(&self, search: Option<&str>, limit: u32, offset: u32) -> sqlx::Result<(Vec<User>, i64)> {
        const SEARCH: &str = "WHERE username LIKE ? ESCAPE '!' OR LOWER(display_name) LIKE ? ESCAPE '!' \
             OR COALESCE(email, '') LIKE ? ESCAPE '!'";
        let like = search.map(str::trim).filter(|s| !s.is_empty()).map(like_pattern);
        let mut rows = sqlx::query(if like.is_some() {
            sql!("SELECT {USER_COLS} FROM acct_users {SEARCH} ORDER BY created_at DESC, id LIMIT ? OFFSET ?")
        } else {
            sql!("SELECT {USER_COLS} FROM acct_users ORDER BY created_at DESC, id LIMIT ? OFFSET ?")
        });
        let mut count = sqlx::query_scalar::<_, i64>(if like.is_some() {
            sql!("SELECT COUNT(*) FROM acct_users {SEARCH}")
        } else {
            "SELECT COUNT(*) FROM acct_users"
        });
        if let Some(l) = &like {
            rows = rows.bind(l).bind(l).bind(l);
            count = count.bind(l).bind(l).bind(l);
        }
        let users = rows
            .bind(i64::from(limit))
            .bind(i64::from(offset))
            .fetch_all(&self.0)
            .await?
            .iter()
            .map(user)
            .collect::<sqlx::Result<_>>()?;
        Ok((users, count.fetch_one(&self.0).await?))
    }

    pub async fn delete_user(conn: &mut Conn, id: AccountId) -> Result<bool, WriteError> {
        let mut tx = if conn.is_in_transaction() { conn.begin().await? } else { conn.begin_with(BEGIN_GUARDED).await? };
        guard(&mut tx).await?;
        let before = star_holders(&mut tx).await?;
        let n = sqlx::query(sql!("DELETE FROM acct_users WHERE id = ?"))
            .bind(&id.0[..])
            .execute(&mut *tx)
            .await?
            .rows_affected();
        keep_an_admin(&mut tx, before).await?;
        tx.commit().await?;
        Ok(n == 1)
    }

    // --------------------------------------------------------------- sessions

    pub async fn insert_session(&self, s: &SessionInfo) -> sqlx::Result<()> {
        let n = sqlx::query(sql!(
            "INSERT INTO acct_sessions ({SESSION_COLS})
             SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ? FROM acct_users WHERE id = ? AND status = ?"
        ))
        .bind(&s.token_hash[..])
        .bind(&s.user_id.0[..])
        .bind(s.created_at)
        .bind(s.seen_at)
        .bind(s.expires_at)
        .bind(s.auth_at)
        .bind(s.mfa_ok)
        .bind(&s.method)
        .bind(&s.ip)
        .bind(clip(&s.ua, 256))
        .bind(&s.user_id.0[..])
        .bind(UserStatus::Active as i16)
        .execute(&self.0)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(sqlx::Error::RowNotFound);
        }
        self.trim_sessions(s.user_id, s.mfa_ok).await
    }

    /// Deletes the account's oldest sessions of one kind past `MAX_SESSIONS`
    /// (signed in) or `MAX_PENDING`. Found by a plain read and deleted by
    /// primary key: on MySQL a DELETE ranging over the user_id index takes gap
    /// locks that deadlock with other accounts' logins. Two racing logins may
    /// leave one extra row until the next one.
    async fn trim_sessions(&self, user: AccountId, mfa_ok: bool) -> sqlx::Result<()> {
        let over: Vec<Vec<u8>> = sqlx::query_scalar(sql!(
            "SELECT token_hash FROM acct_sessions WHERE user_id = ? AND mfa_ok = ?
              ORDER BY seen_at DESC, created_at DESC LIMIT 1000 OFFSET ?"
        ))
        .bind(&user.0[..])
        .bind(mfa_ok)
        .bind(i64::from(if mfa_ok { MAX_SESSIONS } else { MAX_PENDING }))
        .fetch_all(&self.0)
        .await?;
        for h in over {
            sqlx::query(sql!("DELETE FROM acct_sessions WHERE token_hash = ?")).bind(h).execute(&self.0).await?;
        }
        Ok(())
    }

    pub async fn session_by_hash(&self, hash: &[u8; 32], now: i64) -> sqlx::Result<Option<SessionInfo>> {
        sqlx::query(sql!("SELECT {SESSION_COLS} FROM acct_sessions WHERE token_hash = ? AND expires_at > ?"))
            .bind(&hash[..])
            .bind(now)
            .fetch_optional(&self.0)
            .await?
            .as_ref()
            .map(session)
            .transpose()
    }

    pub async fn touch_session(&self, hash: &[u8; 32], now: i64) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!("UPDATE acct_sessions SET seen_at = ? WHERE token_hash = ? AND seen_at < ?"))
            .bind(now)
            .bind(&hash[..])
            .bind(now - TOUCH_SECS)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn rotate_session(&self, old: &[u8; 32], new: &[u8; 32]) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!("UPDATE acct_sessions SET token_hash = ? WHERE token_hash = ?"))
            .bind(&new[..])
            .bind(&old[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn complete_session(&self, old: &[u8; 32], new: &[u8; 32], auth_at: i64, expires_at: i64) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!(
            "UPDATE acct_sessions SET token_hash = ?, mfa_ok = TRUE, auth_at = ?, expires_at = ? WHERE token_hash = ? AND mfa_ok = FALSE"
        ))
        .bind(&new[..])
        .bind(auth_at)
        .bind(expires_at)
        .bind(&old[..])
        .execute(&self.0)
        .await?;
        if r.rows_affected() != 1 {
            return Ok(false);
        }
        // Signed in now: it counts against `MAX_SESSIONS` like a login without
        // a second factor.
        let user: Option<Vec<u8>> =
            sqlx::query_scalar(sql!("SELECT user_id FROM acct_sessions WHERE token_hash = ?")).bind(&new[..]).fetch_optional(&self.0).await?;
        if let Some(user) = user {
            self.trim_sessions(id(user)?, true).await?;
        }
        Ok(true)
    }

    pub async fn refresh_session(&self, old: &[u8; 32], new: &[u8; 32], auth_at: i64) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!("UPDATE acct_sessions SET token_hash = ?, auth_at = ? WHERE token_hash = ? AND mfa_ok = TRUE"))
            .bind(&new[..])
            .bind(auth_at)
            .bind(&old[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn delete_session(&self, hash: &[u8; 32], user: AccountId) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!("DELETE FROM acct_sessions WHERE token_hash = ? AND user_id = ?"))
            .bind(&hash[..])
            .bind(&user.0[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn delete_sessions_of(&self, user: AccountId, except: Option<&[u8; 32]>) -> sqlx::Result<u64> {
        let q = match except {
            Some(h) => sqlx::query(sql!("DELETE FROM acct_sessions WHERE user_id = ? AND token_hash <> ?"))
                .bind(&user.0[..])
                .bind(&h[..]),
            None => sqlx::query(sql!("DELETE FROM acct_sessions WHERE user_id = ?")).bind(&user.0[..]),
        };
        Ok(q.execute(&self.0).await?.rows_affected())
    }

    pub async fn sessions_of(&self, user: AccountId) -> sqlx::Result<Vec<SessionInfo>> {
        sqlx::query(sql!("SELECT {SESSION_COLS} FROM acct_sessions WHERE user_id = ? ORDER BY seen_at DESC, created_at DESC"))
            .bind(&user.0[..])
            .fetch_all(&self.0)
            .await?
            .iter()
            .map(session)
            .collect()
    }

    /// The batch deletes: MySQL takes `DELETE … LIMIT` and rejects LIMIT inside
    /// an IN subquery; Postgres and SQLite have no `DELETE … LIMIT`, so there
    /// the batch is picked by key.
    pub async fn delete_expired_sessions(&self, now: i64, idle_secs: i64, batch: u64) -> sqlx::Result<u64> {
        // Two statements, one index each: an OR across both columns scanned and
        // locked the whole table on every batch.
        let expired = sqlx::query(if MY {
            sql!("DELETE FROM acct_sessions WHERE expires_at < ? LIMIT ?")
        } else {
            sql!("DELETE FROM acct_sessions WHERE token_hash IN (SELECT token_hash FROM acct_sessions WHERE expires_at < ? LIMIT ?)")
        })
        .bind(now)
        .bind(lim(batch))
        .execute(&self.0)
        .await?
        .rows_affected();
        if expired >= batch {
            return Ok(expired);
        }
        let idle = sqlx::query(if MY {
            sql!("DELETE FROM acct_sessions WHERE seen_at < ? LIMIT ?")
        } else {
            sql!("DELETE FROM acct_sessions WHERE token_hash IN (SELECT token_hash FROM acct_sessions WHERE seen_at < ? LIMIT ?)")
        })
        .bind(now - idle_secs)
        .bind(lim(batch - expired))
        .execute(&self.0)
        .await?
        .rows_affected();
        Ok(expired + idle)
    }

    // ------------------------------------------------------- second factors

    pub async fn totp_of(&self, user: AccountId) -> sqlx::Result<Option<(Vec<u8>, i64)>> {
        let row: Option<(Option<Vec<u8>>, i64)> = sqlx::query_as(sql!("SELECT totp_enc, totp_last_step FROM acct_users WHERE id = ?"))
            .bind(&user.0[..])
            .fetch_optional(&self.0)
            .await?;
        Ok(row.and_then(|(enc, step)| enc.map(|e| (e, step))))
    }

    pub async fn set_totp(&self, user: AccountId, sealed: Option<&[u8]>, last_step: i64) -> sqlx::Result<bool> {
        let q = match sealed {
            Some(s) => sqlx::query(sql!("UPDATE acct_users SET totp_enc = ?, totp_last_step = ? WHERE id = ? AND totp_enc IS NULL")).bind(s),
            None => sqlx::query(sql!("UPDATE acct_users SET totp_enc = NULL, totp_last_step = ? WHERE id = ? AND totp_enc IS NOT NULL")),
        };
        Ok(q.bind(last_step).bind(&user.0[..]).execute(&self.0).await?.rows_affected() == 1)
    }

    pub async fn advance_totp(&self, user: AccountId, step: i64) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!("UPDATE acct_users SET totp_last_step = ? WHERE id = ? AND totp_enc IS NOT NULL AND totp_last_step < ?"))
            .bind(step)
            .bind(&user.0[..])
            .bind(step)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn reseal_totp(&self, user: AccountId, old: &[u8], new: &[u8]) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!("UPDATE acct_users SET totp_enc = ? WHERE id = ? AND totp_enc = ?"))
            .bind(new)
            .bind(&user.0[..])
            .bind(old)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Each database orders the 16-byte ids by their bytes.
    pub async fn totp_rows(&self, after: AccountId, limit: u64) -> sqlx::Result<Vec<(AccountId, Vec<u8>)>> {
        let rows: Vec<(Vec<u8>, Vec<u8>)> =
            sqlx::query_as(sql!("SELECT id, totp_enc FROM acct_users WHERE totp_enc IS NOT NULL AND id > ? ORDER BY id LIMIT ?"))
                .bind(&after.0[..])
                .bind(lim(limit))
                .fetch_all(&self.0)
                .await?;
        rows.into_iter().map(|(u, sealed)| Ok((id(u)?, sealed))).collect()
    }

    /// Under READ COMMITTED on MySQL (`BEGIN_RC`): the DELETE's gap locks under
    /// REPEATABLE READ deadlock with another account's codes going in next to them.
    /// The account's row is locked first, so two replacements run one after the
    /// other: otherwise the second one's DELETE can miss the first one's new
    /// codes, and both sets stay valid.
    pub async fn replace_recovery(&self, user: AccountId, hashes: &[[u8; 32]]) -> sqlx::Result<()> {
        let mut tx = begin_rc(&self.0).await?;
        sqlx::query(sql!("SELECT id FROM acct_users WHERE id = ?{FOR_UPDATE}")).bind(&user.0[..]).execute(&mut *tx).await?;
        sqlx::query(sql!("DELETE FROM acct_recovery WHERE user_id = ?")).bind(&user.0[..]).execute(&mut *tx).await?;
        for h in hashes {
            sqlx::query(sql!("INSERT INTO acct_recovery (user_id, code_hash) VALUES (?, ?)"))
                .bind(&user.0[..])
                .bind(&h[..])
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await
    }

    pub async fn use_recovery(&self, user: AccountId, hash: &[u8; 32], now: i64) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!("UPDATE acct_recovery SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL"))
            .bind(now)
            .bind(&user.0[..])
            .bind(&hash[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn recovery_left(&self, user: AccountId) -> sqlx::Result<i64> {
        sqlx::query_scalar(sql!("SELECT COUNT(*) FROM acct_recovery WHERE user_id = ? AND used_at IS NULL"))
            .bind(&user.0[..])
            .fetch_one(&self.0)
            .await
    }

    pub async fn delete_recovery(&self, user: AccountId) -> sqlx::Result<()> {
        sqlx::query(sql!("DELETE FROM acct_recovery WHERE user_id = ?")).bind(&user.0[..]).execute(&self.0).await.map(|_| ())
    }

    // ---------------------------------------------------------------- blobs

    pub async fn blobs(&self, user: AccountId, ns: &str) -> sqlx::Result<Vec<Blob>> {
        let rows: Vec<(String, Vec<u8>, i64, i64)> =
            sqlx::query_as(sql!("SELECT k, v, version, updated_at FROM acct_blobs WHERE user_id = ? AND ns = ? ORDER BY k"))
                .bind(&user.0[..])
                .bind(ns)
                .fetch_all(&self.0)
                .await?;
        Ok(rows.into_iter().map(|(k, v, version, updated_at)| Blob { k, v, version, updated_at }).collect())
    }

    pub async fn blob(&self, user: AccountId, ns: &str, k: &str) -> sqlx::Result<Option<Blob>> {
        let row: Option<(String, Vec<u8>, i64, i64)> =
            sqlx::query_as(sql!("SELECT k, v, version, updated_at FROM acct_blobs WHERE user_id = ? AND ns = ? AND k = ?"))
                .bind(&user.0[..])
                .bind(ns)
                .bind(k)
                .fetch_optional(&self.0)
                .await?;
        Ok(row.map(|(k, v, version, updated_at)| Blob { k, v, version, updated_at }))
    }

    pub async fn blob_count(&self, user: AccountId, ns: &str) -> sqlx::Result<i64> {
        sqlx::query_scalar(sql!("SELECT COUNT(*) FROM acct_blobs WHERE user_id = ? AND ns = ?"))
            .bind(&user.0[..])
            .bind(ns)
            .fetch_one(&self.0)
            .await
    }

    /// Under READ COMMITTED on MySQL, like `replace_recovery`; SQLite holds
    /// the write lock instead of the row locks.
    pub async fn put_blob(&self, user: AccountId, ns: &str, k: &str, v: &[u8], expect: i64, quota: i64) -> sqlx::Result<PutBlob> {
        let mut tx = begin_rc(&self.0).await?;
        sqlx::query(sql!("SELECT id FROM acct_users WHERE id = ?{FOR_UPDATE}")).bind(&user.0[..]).execute(&mut *tx).await?;
        put_locked(tx, user, ns, k, v, expect, quota).await
    }

    /// `put_blob`, reading the flag and the count once the account's row is
    /// locked: every write of the account waits there, so the count holds a
    /// key a racing create just added, and a write that waited on `sync_set`
    /// turning sync off reads it off.
    #[allow(clippy::too_many_arguments)]
    pub async fn put_blob_limited(
        &self,
        user: AccountId,
        ns: &str,
        k: &str,
        v: &[u8],
        expect: i64,
        quota: i64,
        max_keys: Option<i64>,
        need_sync: bool,
    ) -> sqlx::Result<PutLimited> {
        let mut tx = begin_rc(&self.0).await?;
        let sync: Option<bool> = sqlx::query_scalar(sql!("SELECT sync_enabled FROM acct_users WHERE id = ?{FOR_UPDATE}"))
            .bind(&user.0[..])
            .fetch_optional(&mut *tx)
            .await?;
        if need_sync && sync != Some(true) {
            return Ok(PutLimited::SyncOff);
        }
        if let Some(max) = max_keys
            && expect == 0
        {
            let n: i64 = sqlx::query_scalar(sql!("SELECT COUNT(*) FROM acct_blobs WHERE user_id = ? AND ns = ?"))
                .bind(&user.0[..])
                .bind(ns)
                .fetch_one(&mut *tx)
                .await?;
            if n >= max {
                return Ok(PutLimited::Full);
            }
        }
        Ok(PutLimited::Put(put_locked(tx, user, ns, k, v, expect, quota).await?))
    }

    pub async fn delete_blob(&self, user: AccountId, ns: &str, k: &str, expect: i64) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!("DELETE FROM acct_blobs WHERE user_id = ? AND ns = ? AND k = ? AND (? = 0 OR version = ?)"))
            .bind(&user.0[..])
            .bind(ns)
            .bind(k)
            .bind(expect)
            .bind(expect)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn delete_blobs(&self, user: AccountId, ns: &str) -> sqlx::Result<u64> {
        let r = sqlx::query(sql!("DELETE FROM acct_blobs WHERE user_id = ? AND ns = ?")).bind(&user.0[..]).bind(ns).execute(&self.0).await?;
        Ok(r.rows_affected())
    }

    // -------------------------------------------------------------- profile

    pub async fn profile(&self, user: AccountId) -> sqlx::Result<Profile> {
        let row: Option<(Option<Vec<u8>>, String, bool)> =
            sqlx::query_as(sql!("SELECT public_id, bio, show_badges FROM acct_profiles WHERE user_id = ?"))
                .bind(&user.0[..])
                .fetch_optional(&self.0)
                .await?;
        Ok(match row {
            Some((id, bio, show_badges)) => Profile { public_id: id.and_then(|b| b.try_into().ok()), bio, show_badges },
            None => Profile { public_id: None, bio: String::new(), show_badges: true },
        })
    }

    pub async fn save_profile(&self, user: AccountId, p: &Profile, now: i64) -> sqlx::Result<()> {
        sqlx::query(sql!(
            "INSERT INTO acct_profiles (user_id, public_id, bio, show_badges, updated_at) VALUES (?, ?, ?, ?, ?)
             {UPSERT_PROFILE}"
        ))
        .bind(&user.0[..])
        .bind(p.public_id.as_ref().map(|b| &b[..]))
        .bind(clip(&p.bio, 1000))
        .bind(p.show_badges)
        .bind(now)
        .execute(&self.0)
        .await
        .map(|_| ())
    }

    pub async fn profile_owner(&self, public_id: &[u8; 16]) -> sqlx::Result<Option<AccountId>> {
        let owner: Option<Vec<u8>> =
            sqlx::query_scalar(sql!("SELECT user_id FROM acct_profiles WHERE public_id = ?")).bind(&public_id[..]).fetch_optional(&self.0).await?;
        owner.map(id).transpose()
    }

    pub async fn set_credential_public(&self, user: AccountId, kind: &str, ext_id: &[u8], public: bool) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!("UPDATE acct_credentials SET public = ? WHERE user_id = ? AND kind = ? AND ext_id = ?"))
            .bind(public)
            .bind(&user.0[..])
            .bind(kind)
            .bind(ext_id)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn public_identities(&self, user: AccountId) -> sqlx::Result<Vec<(String, String)>> {
        sqlx::query_as(sql!("SELECT kind, name FROM acct_credentials WHERE user_id = ? AND public = TRUE AND kind LIKE 'oauth:%' ORDER BY kind"))
            .bind(&user.0[..])
            .fetch_all(&self.0)
            .await
    }

    // ---------------------------------------------------------- credentials

    pub async fn insert_credential(&self, c: &Credential) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!(
            "INSERT INTO acct_credentials (kind, ext_id, user_id, public_key, alg, sign_count, flags, name, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ))
        .bind(&c.kind)
        .bind(&c.ext_id)
        .bind(&c.user_id.0[..])
        .bind(&c.public_key)
        .bind(c.alg)
        .bind(c.sign_count)
        .bind(c.flags)
        .bind(clip(&c.name, 64))
        .bind(c.created_at)
        .execute(&self.0)
        .await;
        match r {
            Ok(_) => Ok(true),
            Err(e) if is_dup(&e) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub async fn credential(&self, kind: &str, ext_id: &[u8]) -> sqlx::Result<Option<Credential>> {
        sqlx::query(sql!("SELECT {CRED_COLS} FROM acct_credentials WHERE kind = ? AND ext_id = ?"))
            .bind(kind)
            .bind(ext_id)
            .fetch_optional(&self.0)
            .await?
            .as_ref()
            .map(credential)
            .transpose()
    }

    pub async fn credentials_of(&self, user: AccountId, kind: &str) -> sqlx::Result<Vec<Credential>> {
        sqlx::query(sql!("SELECT {CRED_COLS} FROM acct_credentials WHERE user_id = ? AND kind = ? ORDER BY created_at, ext_id"))
            .bind(&user.0[..])
            .bind(kind)
            .fetch_all(&self.0)
            .await?
            .iter()
            .map(credential)
            .collect()
    }

    pub async fn delete_credential(&self, user: AccountId, kind: &str, ext_id: &[u8]) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!("DELETE FROM acct_credentials WHERE user_id = ? AND kind = ? AND ext_id = ?"))
            .bind(&user.0[..])
            .bind(kind)
            .bind(ext_id)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn delete_credentials_of(&self, user: AccountId, kind: &str) -> sqlx::Result<u64> {
        let r = sqlx::query(sql!("DELETE FROM acct_credentials WHERE user_id = ? AND kind = ?"))
            .bind(&user.0[..])
            .bind(kind)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected())
    }

    /// A batch delete, as in `delete_expired_sessions`; by key, `kind` goes in twice.
    pub async fn delete_stale_credentials(&self, kind: &str, before: i64, batch: u64) -> sqlx::Result<u64> {
        let q = if MY {
            sqlx::query(sql!("DELETE FROM acct_credentials WHERE kind = ? AND COALESCE(last_used_at, created_at) < ? LIMIT ?")).bind(kind)
        } else {
            sqlx::query(sql!(
                "DELETE FROM acct_credentials WHERE kind = ? AND ext_id IN
                   (SELECT ext_id FROM acct_credentials WHERE kind = ? AND COALESCE(last_used_at, created_at) < ? LIMIT ?)"
            ))
            .bind(kind)
            .bind(kind)
        };
        let r = q.bind(before).bind(lim(batch)).execute(&self.0).await?;
        Ok(r.rows_affected())
    }

    pub async fn login_credentials(&self, user: AccountId) -> sqlx::Result<i64> {
        sqlx::query_scalar(sql!(
            "SELECT COUNT(*) FROM acct_credentials WHERE user_id = ? AND (kind IN ('passkey', 'ssh') OR kind LIKE 'oauth:%')"
        ))
        .bind(&user.0[..])
        .fetch_one(&self.0)
        .await
    }

    pub async fn step_up_credentials(&self, user: AccountId) -> sqlx::Result<i64> {
        sqlx::query_scalar(sql!("SELECT COUNT(*) FROM acct_credentials WHERE user_id = ? AND {STEPS_UP}"))
            .bind(&user.0[..])
            .fetch_one(&self.0)
            .await
    }

    /// Under READ COMMITTED on MySQL, like `replace_recovery`, with the
    /// account's row locked first: a second removal waits on it, then counts
    /// what the first one left. The count runs after the DELETE; a refusal
    /// drops (rolls back) the transaction.
    pub async fn delete_credential_if_not_last(&self, user: AccountId, kind: &str, ext_id: &[u8]) -> sqlx::Result<DeleteCredential> {
        let mut tx = begin_rc(&self.0).await?;
        let password: Option<bool> = sqlx::query_scalar(sql!("SELECT password_hash IS NOT NULL FROM acct_users WHERE id = ?{FOR_UPDATE}"))
            .bind(&user.0[..])
            .fetch_optional(&mut *tx)
            .await?;
        let Some(password) = password else { return Ok(DeleteCredential::NotFound) };
        let r = sqlx::query(sql!("DELETE FROM acct_credentials WHERE user_id = ? AND kind = ? AND ext_id = ?"))
            .bind(&user.0[..])
            .bind(kind)
            .bind(ext_id)
            .execute(&mut *tx)
            .await?;
        if r.rows_affected() != 1 {
            return Ok(DeleteCredential::NotFound);
        }
        let left: i64 = sqlx::query_scalar(sql!("SELECT COUNT(*) FROM acct_credentials WHERE user_id = ? AND {STEPS_UP}"))
            .bind(&user.0[..])
            .fetch_one(&mut *tx)
            .await?;
        if !password && left == 0 {
            return Ok(DeleteCredential::LastWayIn);
        }
        tx.commit().await?;
        Ok(DeleteCredential::Done)
    }

    pub async fn used_credential(&self, kind: &str, ext_id: &[u8], sign_count: i64, now: i64) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!(
            "UPDATE acct_credentials SET sign_count = ?, last_used_at = ?
              WHERE kind = ? AND ext_id = ? AND ((? = 0 AND sign_count = 0) OR sign_count < ?)"
        ))
        .bind(sign_count)
        .bind(now)
        .bind(kind)
        .bind(ext_id)
        .bind(sign_count)
        .bind(sign_count)
        .execute(&self.0)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    // ------------------------------------------------------------------ roles

    pub async fn ensure_builtin_roles(&self, user_scopes: &[String]) -> sqlx::Result<()> {
        let star = ["*".to_string()];
        for (name, description, scopes) in [("admin", "Full access", &star[..]), ("user", "Every account", user_scopes)] {
            let mut tx = begin_write(&self.0).await?;
            let role = AccountId::new();
            // IGNORE (or DO NOTHING) only ever meets the name key: every other
            // value is a constant. MySQL 8 has no ON CONFLICT.
            let fresh = sqlx::query(if MY {
                sql!("INSERT IGNORE INTO acct_roles (id, name, description, builtin, created_at) VALUES (?, ?, ?, TRUE, ?)")
            } else {
                sql!("INSERT INTO acct_roles (id, name, description, builtin, created_at) VALUES (?, ?, ?, TRUE, ?) ON CONFLICT DO NOTHING")
            })
            .bind(&role.0[..])
            .bind(name)
            .bind(description)
            .bind(util::now())
            .execute(&mut *tx)
            .await?
            .rows_affected()
                == 1;
            if fresh {
                insert_scopes(&mut tx, role, scopes).await?;
            }
            tx.commit().await?;
        }
        Ok(())
    }

    pub async fn roles(&self) -> sqlx::Result<Vec<Role>> {
        let rows = sqlx::query(sql!(
            "SELECT {ROLE_COLS} FROM acct_roles r LEFT JOIN acct_role_scopes s ON s.role_id = r.id ORDER BY r.name, s.scope"
        ))
        .fetch_all(&self.0)
        .await?;
        roles_from(rows)
    }

    pub async fn role_by_name(&self, name: &str) -> sqlx::Result<Option<Role>> {
        let rows = sqlx::query(sql!(
            "SELECT {ROLE_COLS} FROM acct_roles r LEFT JOIN acct_role_scopes s ON s.role_id = r.id
              WHERE r.name = ? ORDER BY s.scope"
        ))
        .bind(name)
        .fetch_all(&self.0)
        .await?;
        Ok(roles_from(rows)?.into_iter().next())
    }

    pub async fn create_role(&self, name: &str, description: &str, badge: Option<&str>) -> sqlx::Result<Option<AccountId>> {
        self.create_role_with_scopes(name, description, badge, &[]).await
    }

    /// No guard: nobody holds a new role, so its scopes take `*` from no one.
    /// An error drops (rolls back) the transaction, the role with it.
    pub async fn create_role_with_scopes(
        &self,
        name: &str,
        description: &str,
        badge: Option<&str>,
        scopes: &[String],
    ) -> sqlx::Result<Option<AccountId>> {
        let role = AccountId::new();
        let mut tx = begin_write(&self.0).await?;
        let r = sqlx::query(sql!("INSERT INTO acct_roles (id, name, description, badge, builtin, created_at) VALUES (?, ?, ?, ?, FALSE, ?)"))
            .bind(&role.0[..])
            .bind(name)
            .bind(description)
            .bind(badge)
            .bind(util::now())
            .execute(&mut *tx)
            .await;
        match r {
            Ok(_) => {}
            Err(e) if is_dup(&e) => return Ok(None),
            Err(e) => return Err(e),
        }
        insert_scopes(&mut tx, role, scopes).await?;
        tx.commit().await?;
        Ok(Some(role))
    }

    pub async fn update_role(&self, role: AccountId, description: &str, badge: Option<&str>) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!("UPDATE acct_roles SET description = ?, badge = ? WHERE id = ?"))
            .bind(description)
            .bind(badge)
            .bind(&role.0[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn set_role_scopes(&self, role: AccountId, scopes: &[String]) -> Result<(), WriteError> {
        let mut tx = begin_guarded(&self.0).await?;
        let before = star_holders(&mut tx).await?;
        sqlx::query(sql!("DELETE FROM acct_role_scopes WHERE role_id = ?"))
            .bind(&role.0[..])
            .execute(&mut *tx)
            .await?;
        insert_scopes(&mut tx, role, scopes).await?;
        keep_an_admin(&mut tx, before).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn delete_role(&self, role: AccountId) -> Result<bool, WriteError> {
        let mut tx = begin_guarded(&self.0).await?;
        let before = star_holders(&mut tx).await?;
        let builtin: Option<bool> = sqlx::query_scalar(sql!("SELECT builtin FROM acct_roles WHERE id = ?{FOR_UPDATE}"))
            .bind(&role.0[..])
            .fetch_optional(&mut *tx)
            .await?;
        match builtin {
            None => return Ok(false),
            Some(true) => return Err(WriteError::Builtin),
            Some(false) => {}
        }
        sqlx::query(sql!("DELETE FROM acct_roles WHERE id = ?")).bind(&role.0[..]).execute(&mut *tx).await?;
        keep_an_admin(&mut tx, before).await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn user_roles(&self, user: AccountId) -> sqlx::Result<Vec<Role>> {
        let rows = sqlx::query(sql!(
            "SELECT {ROLE_COLS} FROM acct_user_roles ur JOIN acct_roles r ON r.id = ur.role_id
               LEFT JOIN acct_role_scopes s ON s.role_id = r.id
              WHERE ur.user_id = ? ORDER BY r.name, s.scope"
        ))
        .bind(&user.0[..])
        .fetch_all(&self.0)
        .await?;
        roles_from(rows)
    }

    pub async fn user_scopes(&self, user: AccountId) -> sqlx::Result<Vec<String>> {
        sqlx::query_scalar(sql!(
            "SELECT DISTINCT s.scope FROM acct_user_roles ur JOIN acct_role_scopes s ON s.role_id = ur.role_id
              WHERE ur.user_id = ? ORDER BY s.scope"
        ))
        .bind(&user.0[..])
        .fetch_all(&self.0)
        .await
    }

    pub async fn grant_role(&self, user: AccountId, role: AccountId, by: Option<AccountId>) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!("INSERT INTO acct_user_roles (user_id, role_id, granted_by, granted_at) VALUES (?, ?, ?, ?)"))
            .bind(&user.0[..])
            .bind(&role.0[..])
            .bind(by.as_ref().map(|b| &b.0[..]))
            .bind(util::now())
            .execute(&self.0)
            .await;
        match r {
            Ok(_) => Ok(true),
            Err(e) if is_dup(&e) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub async fn revoke_role(&self, user: AccountId, role: AccountId) -> Result<bool, WriteError> {
        let mut tx = begin_guarded(&self.0).await?;
        let before = star_holders(&mut tx).await?;
        let n = sqlx::query(sql!("DELETE FROM acct_user_roles WHERE user_id = ? AND role_id = ?"))
            .bind(&user.0[..])
            .bind(&role.0[..])
            .execute(&mut *tx)
            .await?
            .rows_affected();
        keep_an_admin(&mut tx, before).await?;
        tx.commit().await?;
        Ok(n == 1)
    }

    pub async fn holders_of_scope_star(&self) -> sqlx::Result<i64> {
        sqlx::query_scalar(STAR_HOLDERS).fetch_one(&self.0).await
    }

    // ------------------------------------------------------------------ audit

    pub async fn audit(&self, user: Option<AccountId>, actor: Option<AccountId>, event: &str, detail: &str, ip: &str) -> sqlx::Result<()> {
        sqlx::query(sql!("INSERT INTO acct_audit (user_id, actor_id, event, detail, ip, at) VALUES (?, ?, ?, ?, ?, ?)"))
            .bind(user.as_ref().map(|u| &u.0[..]))
            .bind(actor.as_ref().map(|a| &a.0[..]))
            .bind(event)
            .bind(clip(detail, 255))
            .bind(ip)
            .bind(util::now())
            .execute(&self.0)
            .await
            .map(|_| ())
    }

    pub async fn audit_of(&self, user: AccountId, limit: u32) -> sqlx::Result<Vec<AuditEntry>> {
        sqlx::query(sql!(
            "SELECT id, user_id, actor_id, event, detail,
                    CASE WHEN actor_id IS NULL OR actor_id = user_id THEN ip ELSE '' END, at
               FROM acct_audit WHERE user_id = ? ORDER BY at DESC, id DESC LIMIT ?"
        ))
        .bind(&user.0[..])
        .bind(i64::from(limit))
        .fetch_all(&self.0)
        .await?
        .iter()
        .map(audit_entry)
        .collect()
    }

    /// A batch delete, as in `delete_expired_sessions`.
    pub async fn delete_audit_before(&self, ts: i64, batch: u64) -> sqlx::Result<u64> {
        let r = sqlx::query(if MY {
            sql!("DELETE FROM acct_audit WHERE at < ? LIMIT ?")
        } else {
            sql!("DELETE FROM acct_audit WHERE id IN (SELECT id FROM acct_audit WHERE at < ? LIMIT ?)")
        })
        .bind(ts)
        .bind(lim(batch))
        .execute(&self.0)
        .await?;
        Ok(r.rows_affected())
    }

    // ---------------------------------------------------------------- invites

    pub async fn insert_invite(&self, code_hash: &[u8; 32], by: Option<AccountId>, username: Option<&str>, expires_at: i64) -> sqlx::Result<()> {
        sqlx::query(sql!("INSERT INTO acct_invites (code_hash, created_by, username, created_at, expires_at) VALUES (?, ?, ?, ?, ?)"))
            .bind(&code_hash[..])
            .bind(by.as_ref().map(|b| &b.0[..]))
            .bind(username)
            .bind(util::now())
            .bind(expires_at)
            .execute(&self.0)
            .await
            .map(|_| ())
    }

    pub async fn invites(&self, now: i64) -> sqlx::Result<Vec<Invite>> {
        sqlx::query(sql!(
            "SELECT code_hash, created_by, username, created_at, expires_at, used_at, used_by FROM acct_invites
              WHERE expires_at > ? ORDER BY created_at DESC, code_hash LIMIT 1000"
        ))
        .bind(now)
        .fetch_all(&self.0)
        .await?
        .iter()
        .map(invite)
        .collect()
    }

    pub async fn delete_invite(&self, code_hash: &[u8; 32]) -> sqlx::Result<bool> {
        let r = sqlx::query(sql!("DELETE FROM acct_invites WHERE code_hash = ?")).bind(&code_hash[..]).execute(&self.0).await?;
        Ok(r.rows_affected() == 1)
    }

    /// A batch delete, as in `delete_expired_sessions`.
    pub async fn delete_expired_invites(&self, now: i64, batch: u64) -> sqlx::Result<u64> {
        let r = sqlx::query(if MY {
            sql!("DELETE FROM acct_invites WHERE expires_at < ? LIMIT ?")
        } else {
            sql!("DELETE FROM acct_invites WHERE code_hash IN (SELECT code_hash FROM acct_invites WHERE expires_at < ? LIMIT ?)")
        })
        .bind(now)
        .bind(lim(batch))
        .execute(&self.0)
        .await?;
        Ok(r.rows_affected())
    }

    pub async fn invite_open(&self, code_hash: &[u8; 32], username: &str, now: i64) -> sqlx::Result<bool> {
        let n: i64 = sqlx::query_scalar(sql!("SELECT COUNT(*) FROM acct_invites WHERE {INVITE_OPEN}"))
            .bind(&code_hash[..])
            .bind(now)
            .bind(username)
            .fetch_one(&self.0)
            .await?;
        Ok(n > 0)
    }

    /// A taken name returns before the commit: dropping the transaction rolls
    /// the claim back (Postgres has aborted it anyway).
    pub async fn create_user_with_invite(&self, u: &NewUser, role: &str, code_hash: &[u8; 32], now: i64) -> sqlx::Result<InviteSignup> {
        let mut tx = begin_write(&self.0).await?;
        let claimed = sqlx::query(sql!(
            "UPDATE acct_invites SET used_at = ?, used_by = ?
              WHERE {INVITE_OPEN}"
        ))
        .bind(now)
        .bind(&u.id.0[..])
        .bind(&code_hash[..])
        .bind(now)
        .bind(&u.username)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if claimed != 1 {
            return Ok(InviteSignup::BadInvite);
        }
        if !insert_user(&mut tx, u, Some(role)).await? {
            return Ok(InviteSignup::UsernameTaken);
        }
        tx.commit().await?;
        Ok(InviteSignup::Done)
    }

    pub async fn grant_admin_if_none(&self, user: AccountId) -> Result<bool, WriteError> {
        let mut tx = begin_guarded(&self.0).await?;
        if star_holders(&mut tx).await? > 0 {
            return Ok(false);
        }
        let n = sqlx::query(sql!(
            "INSERT INTO acct_user_roles (user_id, role_id, granted_at)
             SELECT u.id, r.id, ? FROM acct_users u JOIN acct_roles r ON r.name = 'admin' WHERE u.id = ? AND u.status = ?"
        ))
        .bind(util::now())
        .bind(&user.0[..])
        .bind(UserStatus::Active as i16)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        Ok(n == 1)
    }

    // ----------------------------------------------------------------- export

    pub async fn export_user(&self, id: AccountId) -> sqlx::Result<Option<serde_json::Value>> {
        let Some(user) = self.user_by_id(id).await? else { return Ok(None) };
        let verified_at: Option<i64> = sqlx::query_scalar(sql!("SELECT email_verified_at FROM acct_users WHERE id = ?"))
            .bind(&id.0[..])
            .fetch_one(&self.0)
            .await?;
        let credentials = sqlx::query(sql!(
            "SELECT kind, name, handle, email, public, created_at, last_used_at FROM acct_credentials
              WHERE user_id = ? ORDER BY created_at"
        ))
        .bind(&id.0[..])
        .fetch_all(&self.0)
        .await?
        .iter()
        .map(|r| {
            Ok(serde_json::json!({
                "kind": r.try_get::<String, _>(0)?,
                "name": r.try_get::<String, _>(1)?,
                "handle": r.try_get::<String, _>(2)?,
                "email": r.try_get::<Option<String>, _>(3)?,
                "public": r.try_get::<bool, _>(4)?,
                "created_at": r.try_get::<i64, _>(5)?,
                "last_used_at": r.try_get::<Option<i64>, _>(6)?,
            }))
        })
        .collect::<sqlx::Result<Vec<_>>>()?;
        // Synced settings as they are; vault entries as the ciphertext they
        // are, which only the owner's keys open; the avatar as its bytes.
        let blobs: Vec<(String, String, Vec<u8>, i64, i64)> = sqlx::query_as(sql!(
            "SELECT ns, k, v, version, updated_at FROM acct_blobs WHERE user_id = ? AND ns IN ('avatar', 'kv', 'vault', 'vault_slot') ORDER BY ns, k"
        ))
        .bind(&id.0[..])
        .fetch_all(&self.0)
        .await?;
        let blobs: Vec<serde_json::Value> = blobs
            .into_iter()
            .map(|(ns, k, v, version, updated_at)| {
                let value = match ns.as_str() {
                    "kv" | "vault_slot" => serde_json::from_slice(&v).unwrap_or(serde_json::Value::Null),
                    _ => serde_json::Value::String(util::b64u(&v)),
                };
                serde_json::json!({ "ns": ns, "k": k, "value": value, "version": version, "updated_at": updated_at })
            })
            .collect();
        // When each recovery code was used; never the hashes.
        let recovery: Vec<Option<i64>> =
            sqlx::query_scalar(sql!("SELECT used_at FROM acct_recovery WHERE user_id = ? ORDER BY used_at IS NULL, used_at"))
                .bind(&id.0[..])
                .fetch_all(&self.0)
                .await?;
        let profile = self.profile(id).await?;
        let mut user = serde_json::json!(user);
        user["email_verified_at"] = serde_json::json!(verified_at);
        Ok(Some(serde_json::json!({
            "user": user,
            "roles": self.user_roles(id).await?,
            "sessions": self.sessions_of(id).await?,
            "credentials": credentials,
            "recovery_codes": recovery.iter().map(|u| serde_json::json!({ "used_at": u })).collect::<Vec<_>>(),
            "profile": { "on": profile.public_id.is_some(), "bio": profile.bio, "show_badges": profile.show_badges },
            "storage": blobs,
            "audit": self.audit_of(id, EXPORT_AUDIT_ROWS).await?,
        })))
    }
}
