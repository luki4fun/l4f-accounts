// The store on Postgres and on SQLite: one source, `include!`d once per
// backend by `store.rs` with `Db` set to `sqlx::Postgres` or `sqlx::Sqlite` and
// `PG` saying which. The method set and every doc comment that matters are the
// MySQL store's (`MySqlStore`); this file only notes where it differs.
//
// SQL here is the dialect both understand: `$N` placeholders (SQLite binds them
// by number too), `ON CONFLICT`, `TRUE`/`FALSE`, `CAST(.. AS BIGINT)`. What
// MySQL does with row and gap locks is done here with one lock per database:
// a Postgres advisory lock held to the end of the transaction, or SQLite's own
// write lock (`BEGIN IMMEDIATE`). Both serialise every write that could take
// `*` away, so the count each of them runs sees the one before it committed.

use sqlx::{AssertSqlSafe, Connection, Pool, Row, Transaction};

use super::{
    Blob, CRED_COLS, CreateUserError, EXPORT_AUDIT_ROWS, EmailConfirm, InviteSignup, MAX_PENDING, MAX_SESSIONS, Profile,
    PutBlob, ROLE_COLS, SESSION_COLS, TOUCH_SECS, USER_COLS, WriteError, clip, id, is_dup, like_pattern, opt_id,
};
use crate::model::{AccountId, AuditEntry, Credential, Invite, NewUser, Role, SessionInfo, User, UserStatus};
use crate::util;

type Conn = <Db as sqlx::Database>::Connection;
type DbRow = <Db as sqlx::Database>::Row;

#[derive(Clone)]
pub struct Backend(pub Pool<Db>);

/// The guard's advisory lock key ("l4f_star"); Postgres scopes it per database.
const GUARD_KEY: i64 = 0x6c34_665f_7374_6172;

/// The `*` holders, without MySQL's join hints: here the count runs under a
/// lock of its own and locks no rows.
const STAR_HOLDERS: &str = "SELECT COUNT(DISTINCT ur.user_id) FROM acct_role_scopes s \
     JOIN acct_user_roles ur ON ur.role_id = s.role_id \
     JOIN acct_users u ON u.id = ur.user_id AND u.status = 0 \
     WHERE s.scope = '*'";

/// SQLite has no row locks to ask for: the transaction already holds the
/// database's write lock.
const FOR_UPDATE: &str = if PG { " FOR UPDATE" } else { "" };

/// A transaction that writes. SQLite takes the write lock at BEGIN: a deferred
/// one that reads first and then writes fails with BUSY when another writer
/// got in between, instead of waiting.
async fn begin_write(pool: &Pool<Db>) -> sqlx::Result<Transaction<'static, Db>> {
    if PG { pool.begin().await } else { pool.begin_with("BEGIN IMMEDIATE").await }
}

/// Postgres: the guard's lock, until this transaction ends. SQLite: nothing,
/// the write lock is the guard.
async fn guard(c: &mut Conn) -> sqlx::Result<()> {
    if PG {
        sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(GUARD_KEY).execute(c).await?;
    }
    Ok(())
}

async fn begin_guarded(pool: &Pool<Db>) -> sqlx::Result<Transaction<'static, Db>> {
    let mut tx = begin_write(pool).await?;
    guard(&mut tx).await?;
    Ok(tx)
}

async fn star_holders(c: &mut Conn) -> sqlx::Result<i64> {
    sqlx::query_scalar(STAR_HOLDERS).fetch_one(c).await
}

async fn keep_an_admin(c: &mut Conn, before: i64) -> Result<(), WriteError> {
    if before > 0 && star_holders(c).await? == 0 {
        return Err(WriteError::LastAdmin);
    }
    Ok(())
}

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
    let values: Vec<String> = (0..scopes.len()).map(|i| format!("(${}, ${})", 2 * i + 1, 2 * i + 2)).collect();
    let mut q = sqlx::query(AssertSqlSafe(format!("INSERT INTO acct_role_scopes (role_id, scope) VALUES {}", values.join(", "))));
    for s in scopes {
        q = q.bind(&role.0[..]).bind(s);
    }
    q.execute(c).await.map(|_| ())
}

/// `status` is SMALLINT here (Postgres has no one-byte integer).
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
    pub async fn begin(&self) -> sqlx::Result<Transaction<'static, Db>> {
        begin_guarded(&self.0).await
    }

    // ------------------------------------------------------------------ users

    pub async fn create_user(&self, u: &NewUser, role: Option<&str>) -> Result<(), CreateUserError> {
        let mut tx = begin_write(&self.0).await?;
        let inserted = sqlx::query(
            "INSERT INTO acct_users (id, username, display_name, email_pending, password_hash, created_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&u.id.0[..])
        .bind(&u.username)
        .bind(&u.display_name)
        .bind(&u.email_pending)
        .bind(&u.password_hash)
        .bind(u.created_at)
        .execute(&mut *tx)
        .await;
        match inserted {
            Err(e) if is_dup(&e) => return Err(CreateUserError::UsernameTaken),
            Err(e) => return Err(e.into()),
            Ok(_) => {}
        }
        if let Some(role) = role {
            let n = sqlx::query(
                "INSERT INTO acct_user_roles (user_id, role_id, granted_at)
                 SELECT $1, id, $2 FROM acct_roles WHERE name = $3",
            )
            .bind(&u.id.0[..])
            .bind(u.created_at)
            .bind(role)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if n != 1 {
                return Err(sqlx::Error::InvalidArgument(format!("no role named {role:?}")).into());
            }
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn user_by_id(&self, id: AccountId) -> sqlx::Result<Option<User>> {
        sqlx::query(AssertSqlSafe(format!("SELECT {USER_COLS} FROM acct_users WHERE id = $1")))
            .bind(&id.0[..])
            .fetch_optional(&self.0)
            .await?
            .as_ref()
            .map(user)
            .transpose()
    }

    pub async fn user_by_username(&self, username: &str) -> sqlx::Result<Option<User>> {
        sqlx::query(AssertSqlSafe(format!("SELECT {USER_COLS} FROM acct_users WHERE username = $1")))
            .bind(username)
            .fetch_optional(&self.0)
            .await?
            .as_ref()
            .map(user)
            .transpose()
    }

    pub async fn user_by_email(&self, email: &str) -> sqlx::Result<Option<User>> {
        sqlx::query(AssertSqlSafe(format!("SELECT {USER_COLS} FROM acct_users WHERE email = $1")))
            .bind(email)
            .fetch_optional(&self.0)
            .await?
            .as_ref()
            .map(user)
            .transpose()
    }

    pub async fn set_email_pending(&self, id: AccountId, email: Option<&str>) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_users SET email_pending = $1 WHERE id = $2").bind(email).bind(&id.0[..]).execute(&self.0).await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn confirm_email(&self, id: AccountId, email: &str, now: i64) -> sqlx::Result<EmailConfirm> {
        let r = sqlx::query(
            "UPDATE acct_users SET email = email_pending, email_pending = NULL, email_verified_at = $1
              WHERE id = $2 AND email_pending = $3",
        )
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
        sqlx::query("UPDATE acct_users SET email = NULL, email_pending = NULL, email_verified_at = NULL WHERE id = $1")
            .bind(&id.0[..])
            .execute(&self.0)
            .await
            .map(|_| ())
    }

    pub async fn password_hash_of(&self, id: AccountId) -> sqlx::Result<Option<String>> {
        let h: Option<Option<String>> = sqlx::query_scalar("SELECT password_hash FROM acct_users WHERE id = $1")
            .bind(&id.0[..])
            .fetch_optional(&self.0)
            .await?;
        Ok(h.flatten())
    }

    pub async fn set_password_hash(&self, id: AccountId, hash: &str) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_users SET password_hash = $1 WHERE id = $2")
            .bind(hash)
            .bind(&id.0[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn rehash_password(&self, id: AccountId, old: &str, new: &str) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_users SET password_hash = $1 WHERE id = $2 AND password_hash = $3")
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
        let n = sqlx::query("UPDATE acct_users SET status = $1 WHERE id = $2")
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
        let r = sqlx::query("UPDATE acct_users SET display_name = $1 WHERE id = $2")
            .bind(name)
            .bind(&id.0[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn set_sync_enabled(&self, id: AccountId, on: bool) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_users SET sync_enabled = $1 WHERE id = $2")
            .bind(on)
            .bind(&id.0[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    /// The search pattern is bound once and used three times (`$1`).
    pub async fn list_users(&self, search: Option<&str>, limit: u32, offset: u32) -> sqlx::Result<(Vec<User>, i64)> {
        let like = search.map(str::trim).filter(|s| !s.is_empty()).map(like_pattern);
        let (filter, page) = if like.is_some() {
            (
                "WHERE username LIKE $1 ESCAPE '!' OR LOWER(display_name) LIKE $1 ESCAPE '!' \
                 OR COALESCE(email, '') LIKE $1 ESCAPE '!'",
                "LIMIT $2 OFFSET $3",
            )
        } else {
            ("", "LIMIT $1 OFFSET $2")
        };
        let mut rows = sqlx::query(AssertSqlSafe(format!(
            "SELECT {USER_COLS} FROM acct_users {filter} ORDER BY created_at DESC, id {page}"
        )));
        let mut count = sqlx::query_scalar::<_, i64>(AssertSqlSafe(format!("SELECT COUNT(*) FROM acct_users {filter}")));
        if let Some(l) = &like {
            rows = rows.bind(l);
            count = count.bind(l);
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
        // Inside a transaction this nests as a savepoint, as on MySQL.
        let mut tx = if conn.is_in_transaction() || PG { conn.begin().await? } else { conn.begin_with("BEGIN IMMEDIATE").await? };
        guard(&mut tx).await?;
        let before = star_holders(&mut tx).await?;
        let n = sqlx::query("DELETE FROM acct_users WHERE id = $1")
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
        let n = sqlx::query(AssertSqlSafe(format!(
            "INSERT INTO acct_sessions ({SESSION_COLS})
             SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10 FROM acct_users WHERE id = $2 AND status = $11"
        )))
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
        .bind(UserStatus::Active as i16)
        .execute(&self.0)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(sqlx::Error::RowNotFound);
        }
        let over: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT token_hash FROM acct_sessions WHERE user_id = $1 AND mfa_ok = $2
              ORDER BY seen_at DESC, created_at DESC LIMIT 1000 OFFSET $3",
        )
        .bind(&s.user_id.0[..])
        .bind(s.mfa_ok)
        .bind(i64::from(if s.mfa_ok { MAX_SESSIONS } else { MAX_PENDING }))
        .fetch_all(&self.0)
        .await?;
        for h in over {
            sqlx::query("DELETE FROM acct_sessions WHERE token_hash = $1").bind(h).execute(&self.0).await?;
        }
        Ok(())
    }

    pub async fn session_by_hash(&self, hash: &[u8; 32], now: i64) -> sqlx::Result<Option<SessionInfo>> {
        sqlx::query(AssertSqlSafe(format!(
            "SELECT {SESSION_COLS} FROM acct_sessions WHERE token_hash = $1 AND expires_at > $2"
        )))
        .bind(&hash[..])
        .bind(now)
        .fetch_optional(&self.0)
        .await?
        .as_ref()
        .map(session)
        .transpose()
    }

    pub async fn touch_session(&self, hash: &[u8; 32], now: i64) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_sessions SET seen_at = $1 WHERE token_hash = $2 AND seen_at < $3")
            .bind(now)
            .bind(&hash[..])
            .bind(now - TOUCH_SECS)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn set_session_mfa(&self, hash: &[u8; 32], mfa_ok: bool, auth_at: i64) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_sessions SET mfa_ok = $1, auth_at = $2 WHERE token_hash = $3")
            .bind(mfa_ok)
            .bind(auth_at)
            .bind(&hash[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn rotate_session(&self, old: &[u8; 32], new: &[u8; 32]) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_sessions SET token_hash = $1 WHERE token_hash = $2")
            .bind(&new[..])
            .bind(&old[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn complete_session(&self, old: &[u8; 32], new: &[u8; 32], auth_at: i64, expires_at: i64) -> sqlx::Result<bool> {
        let r = sqlx::query(
            "UPDATE acct_sessions SET token_hash = $1, mfa_ok = TRUE, auth_at = $2, expires_at = $3
              WHERE token_hash = $4 AND mfa_ok = FALSE",
        )
        .bind(&new[..])
        .bind(auth_at)
        .bind(expires_at)
        .bind(&old[..])
        .execute(&self.0)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn refresh_session(&self, old: &[u8; 32], new: &[u8; 32], auth_at: i64) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_sessions SET token_hash = $1, auth_at = $2 WHERE token_hash = $3 AND mfa_ok = TRUE")
            .bind(&new[..])
            .bind(auth_at)
            .bind(&old[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn delete_session(&self, hash: &[u8; 32], user: AccountId) -> sqlx::Result<bool> {
        let r = sqlx::query("DELETE FROM acct_sessions WHERE token_hash = $1 AND user_id = $2")
            .bind(&hash[..])
            .bind(&user.0[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn delete_sessions_of(&self, user: AccountId, except: Option<&[u8; 32]>) -> sqlx::Result<u64> {
        let q = match except {
            Some(h) => sqlx::query("DELETE FROM acct_sessions WHERE user_id = $1 AND token_hash <> $2")
                .bind(&user.0[..])
                .bind(&h[..]),
            None => sqlx::query("DELETE FROM acct_sessions WHERE user_id = $1").bind(&user.0[..]),
        };
        Ok(q.execute(&self.0).await?.rows_affected())
    }

    pub async fn sessions_of(&self, user: AccountId) -> sqlx::Result<Vec<SessionInfo>> {
        sqlx::query(AssertSqlSafe(format!(
            "SELECT {SESSION_COLS} FROM acct_sessions WHERE user_id = $1 ORDER BY seen_at DESC, created_at DESC"
        )))
        .bind(&user.0[..])
        .fetch_all(&self.0)
        .await?
        .iter()
        .map(session)
        .collect()
    }

    /// Neither backend has `DELETE … LIMIT`: the batch is picked by key.
    pub async fn delete_expired_sessions(&self, now: i64, idle_secs: i64, batch: u64) -> sqlx::Result<u64> {
        let batch = i64::try_from(batch).unwrap_or(i64::MAX);
        let expired = sqlx::query(
            "DELETE FROM acct_sessions WHERE token_hash IN
               (SELECT token_hash FROM acct_sessions WHERE expires_at < $1 LIMIT $2)",
        )
        .bind(now)
        .bind(batch)
        .execute(&self.0)
        .await?
        .rows_affected();
        if expired as i64 >= batch {
            return Ok(expired);
        }
        let idle = sqlx::query(
            "DELETE FROM acct_sessions WHERE token_hash IN
               (SELECT token_hash FROM acct_sessions WHERE seen_at < $1 LIMIT $2)",
        )
        .bind(now - idle_secs)
        .bind(batch - expired as i64)
        .execute(&self.0)
        .await?
        .rows_affected();
        Ok(expired + idle)
    }

    // ------------------------------------------------------- second factors

    pub async fn totp_of(&self, user: AccountId) -> sqlx::Result<Option<(Vec<u8>, i64)>> {
        let row: Option<(Option<Vec<u8>>, i64)> = sqlx::query_as("SELECT totp_enc, totp_last_step FROM acct_users WHERE id = $1")
            .bind(&user.0[..])
            .fetch_optional(&self.0)
            .await?;
        Ok(row.and_then(|(enc, step)| enc.map(|e| (e, step))))
    }

    pub async fn set_totp(&self, user: AccountId, sealed: Option<&[u8]>, last_step: i64) -> sqlx::Result<bool> {
        let q = match sealed {
            Some(s) => sqlx::query("UPDATE acct_users SET totp_enc = $1, totp_last_step = $2 WHERE id = $3 AND totp_enc IS NULL")
                .bind(s),
            None => sqlx::query("UPDATE acct_users SET totp_enc = NULL, totp_last_step = $1 WHERE id = $2 AND totp_enc IS NOT NULL"),
        };
        Ok(q.bind(last_step).bind(&user.0[..]).execute(&self.0).await?.rows_affected() == 1)
    }

    pub async fn advance_totp(&self, user: AccountId, step: i64) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_users SET totp_last_step = $1 WHERE id = $2 AND totp_enc IS NOT NULL AND totp_last_step < $1")
            .bind(step)
            .bind(&user.0[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn reseal_totp(&self, user: AccountId, old: &[u8], new: &[u8]) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_users SET totp_enc = $1 WHERE id = $2 AND totp_enc = $3")
            .bind(new)
            .bind(&user.0[..])
            .bind(old)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn replace_recovery(&self, user: AccountId, hashes: &[[u8; 32]]) -> sqlx::Result<()> {
        let mut tx = begin_write(&self.0).await?;
        sqlx::query("DELETE FROM acct_recovery WHERE user_id = $1").bind(&user.0[..]).execute(&mut *tx).await?;
        for h in hashes {
            sqlx::query("INSERT INTO acct_recovery (user_id, code_hash) VALUES ($1, $2)")
                .bind(&user.0[..])
                .bind(&h[..])
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await
    }

    pub async fn use_recovery(&self, user: AccountId, hash: &[u8; 32], now: i64) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_recovery SET used_at = $1 WHERE user_id = $2 AND code_hash = $3 AND used_at IS NULL")
            .bind(now)
            .bind(&user.0[..])
            .bind(&hash[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn recovery_left(&self, user: AccountId) -> sqlx::Result<i64> {
        sqlx::query_scalar("SELECT COUNT(*) FROM acct_recovery WHERE user_id = $1 AND used_at IS NULL")
            .bind(&user.0[..])
            .fetch_one(&self.0)
            .await
    }

    pub async fn delete_recovery(&self, user: AccountId) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM acct_recovery WHERE user_id = $1").bind(&user.0[..]).execute(&self.0).await.map(|_| ())
    }

    // ---------------------------------------------------------------- blobs

    pub async fn blobs(&self, user: AccountId, ns: &str) -> sqlx::Result<Vec<Blob>> {
        let rows: Vec<(String, Vec<u8>, i64, i64)> =
            sqlx::query_as("SELECT k, v, version, updated_at FROM acct_blobs WHERE user_id = $1 AND ns = $2 ORDER BY k")
                .bind(&user.0[..])
                .bind(ns)
                .fetch_all(&self.0)
                .await?;
        Ok(rows.into_iter().map(|(k, v, version, updated_at)| Blob { k, v, version, updated_at }).collect())
    }

    pub async fn blob(&self, user: AccountId, ns: &str, k: &str) -> sqlx::Result<Option<Blob>> {
        let row: Option<(String, Vec<u8>, i64, i64)> =
            sqlx::query_as("SELECT k, v, version, updated_at FROM acct_blobs WHERE user_id = $1 AND ns = $2 AND k = $3")
                .bind(&user.0[..])
                .bind(ns)
                .bind(k)
                .fetch_optional(&self.0)
                .await?;
        Ok(row.map(|(k, v, version, updated_at)| Blob { k, v, version, updated_at }))
    }

    pub async fn blob_count(&self, user: AccountId, ns: &str) -> sqlx::Result<i64> {
        sqlx::query_scalar("SELECT COUNT(*) FROM acct_blobs WHERE user_id = $1 AND ns = $2")
            .bind(&user.0[..])
            .bind(ns)
            .fetch_one(&self.0)
            .await
    }

    /// Postgres locks the account's row; SQLite already holds the write lock.
    pub async fn put_blob(&self, user: AccountId, ns: &str, k: &str, v: &[u8], expect: i64, quota: i64) -> sqlx::Result<PutBlob> {
        let now = util::now();
        let mut tx = begin_write(&self.0).await?;
        sqlx::query(AssertSqlSafe(format!("SELECT id FROM acct_users WHERE id = $1{FOR_UPDATE}")))
            .bind(&user.0[..])
            .execute(&mut *tx)
            .await?;
        let used: i64 = sqlx::query_scalar("SELECT CAST(COALESCE(SUM(LENGTH(v)), 0) AS BIGINT) FROM acct_blobs WHERE user_id = $1")
            .bind(&user.0[..])
            .fetch_one(&mut *tx)
            .await?;
        let current: Option<(i64, i64)> =
            sqlx::query_as("SELECT version, CAST(LENGTH(v) AS BIGINT) FROM acct_blobs WHERE user_id = $1 AND ns = $2 AND k = $3")
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
        sqlx::query(
            "INSERT INTO acct_blobs (user_id, ns, k, v, version, updated_at) VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (user_id, ns, k) DO UPDATE SET v = excluded.v, version = excluded.version, updated_at = excluded.updated_at",
        )
        .bind(&user.0[..])
        .bind(ns)
        .bind(k)
        .bind(v)
        .bind(version)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(PutBlob::Done(version))
    }

    pub async fn delete_blob(&self, user: AccountId, ns: &str, k: &str, expect: i64) -> sqlx::Result<bool> {
        let r = sqlx::query("DELETE FROM acct_blobs WHERE user_id = $1 AND ns = $2 AND k = $3 AND ($4 = 0 OR version = $4)")
            .bind(&user.0[..])
            .bind(ns)
            .bind(k)
            .bind(expect)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn delete_blobs(&self, user: AccountId, ns: &str) -> sqlx::Result<u64> {
        let r = sqlx::query("DELETE FROM acct_blobs WHERE user_id = $1 AND ns = $2").bind(&user.0[..]).bind(ns).execute(&self.0).await?;
        Ok(r.rows_affected())
    }

    // -------------------------------------------------------------- profile

    pub async fn profile(&self, user: AccountId) -> sqlx::Result<Profile> {
        let row: Option<(Option<Vec<u8>>, String, bool)> = sqlx::query_as("SELECT public_id, bio, show_badges FROM acct_profiles WHERE user_id = $1")
            .bind(&user.0[..])
            .fetch_optional(&self.0)
            .await?;
        Ok(match row {
            Some((id, bio, show_badges)) => Profile { public_id: id.and_then(|b| b.try_into().ok()), bio, show_badges },
            None => Profile { public_id: None, bio: String::new(), show_badges: true },
        })
    }

    pub async fn save_profile(&self, user: AccountId, p: &Profile, now: i64) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO acct_profiles (user_id, public_id, bio, show_badges, updated_at) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (user_id) DO UPDATE SET public_id = excluded.public_id, bio = excluded.bio,
               show_badges = excluded.show_badges, updated_at = excluded.updated_at",
        )
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
            sqlx::query_scalar("SELECT user_id FROM acct_profiles WHERE public_id = $1").bind(&public_id[..]).fetch_optional(&self.0).await?;
        owner.map(id).transpose()
    }

    pub async fn set_credential_public(&self, user: AccountId, kind: &str, ext_id: &[u8], public: bool) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_credentials SET public = $1 WHERE user_id = $2 AND kind = $3 AND ext_id = $4")
            .bind(public)
            .bind(&user.0[..])
            .bind(kind)
            .bind(ext_id)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn public_identities(&self, user: AccountId) -> sqlx::Result<Vec<(String, String)>> {
        sqlx::query_as("SELECT kind, name FROM acct_credentials WHERE user_id = $1 AND public = TRUE AND kind LIKE 'oauth:%' ORDER BY kind")
            .bind(&user.0[..])
            .fetch_all(&self.0)
            .await
    }

    // ---------------------------------------------------------- credentials

    pub async fn insert_credential(&self, c: &Credential) -> sqlx::Result<bool> {
        let r = sqlx::query(
            "INSERT INTO acct_credentials (kind, ext_id, user_id, public_key, alg, sign_count, flags, name, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
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
        sqlx::query(AssertSqlSafe(format!("SELECT {CRED_COLS} FROM acct_credentials WHERE kind = $1 AND ext_id = $2")))
            .bind(kind)
            .bind(ext_id)
            .fetch_optional(&self.0)
            .await?
            .as_ref()
            .map(credential)
            .transpose()
    }

    pub async fn credentials_of(&self, user: AccountId, kind: &str) -> sqlx::Result<Vec<Credential>> {
        sqlx::query(AssertSqlSafe(format!(
            "SELECT {CRED_COLS} FROM acct_credentials WHERE user_id = $1 AND kind = $2 ORDER BY created_at, ext_id"
        )))
        .bind(&user.0[..])
        .bind(kind)
        .fetch_all(&self.0)
        .await?
        .iter()
        .map(credential)
        .collect()
    }

    pub async fn delete_credential(&self, user: AccountId, kind: &str, ext_id: &[u8]) -> sqlx::Result<bool> {
        let r = sqlx::query("DELETE FROM acct_credentials WHERE user_id = $1 AND kind = $2 AND ext_id = $3")
            .bind(&user.0[..])
            .bind(kind)
            .bind(ext_id)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn delete_credentials_of(&self, user: AccountId, kind: &str) -> sqlx::Result<u64> {
        let r = sqlx::query("DELETE FROM acct_credentials WHERE user_id = $1 AND kind = $2")
            .bind(&user.0[..])
            .bind(kind)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected())
    }

    pub async fn delete_stale_credentials(&self, kind: &str, before: i64, batch: u64) -> sqlx::Result<u64> {
        let r = sqlx::query(
            "DELETE FROM acct_credentials WHERE kind = $1 AND ext_id IN
               (SELECT ext_id FROM acct_credentials WHERE kind = $1 AND COALESCE(last_used_at, created_at) < $2 LIMIT $3)",
        )
        .bind(kind)
        .bind(before)
        .bind(i64::try_from(batch).unwrap_or(i64::MAX))
        .execute(&self.0)
        .await?;
        Ok(r.rows_affected())
    }

    pub async fn login_credentials(&self, user: AccountId) -> sqlx::Result<i64> {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM acct_credentials WHERE user_id = $1 AND (kind IN ('passkey', 'ssh') OR kind LIKE 'oauth:%')",
        )
        .bind(&user.0[..])
        .fetch_one(&self.0)
        .await
    }

    pub async fn used_credential(&self, kind: &str, ext_id: &[u8], sign_count: i64, now: i64) -> sqlx::Result<bool> {
        let r = sqlx::query(
            "UPDATE acct_credentials SET sign_count = $1, last_used_at = $2
              WHERE kind = $3 AND ext_id = $4 AND ($1 = 0 OR sign_count < $1)",
        )
        .bind(sign_count)
        .bind(now)
        .bind(kind)
        .bind(ext_id)
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
            let fresh = sqlx::query(
                "INSERT INTO acct_roles (id, name, description, builtin, created_at) VALUES ($1, $2, $3, TRUE, $4)
                 ON CONFLICT DO NOTHING",
            )
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
        let rows = sqlx::query(AssertSqlSafe(format!(
            "SELECT {ROLE_COLS} FROM acct_roles r LEFT JOIN acct_role_scopes s ON s.role_id = r.id ORDER BY r.name, s.scope"
        )))
        .fetch_all(&self.0)
        .await?;
        roles_from(rows)
    }

    pub async fn role_by_name(&self, name: &str) -> sqlx::Result<Option<Role>> {
        let rows = sqlx::query(AssertSqlSafe(format!(
            "SELECT {ROLE_COLS} FROM acct_roles r LEFT JOIN acct_role_scopes s ON s.role_id = r.id
              WHERE r.name = $1 ORDER BY s.scope"
        )))
        .bind(name)
        .fetch_all(&self.0)
        .await?;
        Ok(roles_from(rows)?.into_iter().next())
    }

    pub async fn create_role(&self, name: &str, description: &str, badge: Option<&str>) -> sqlx::Result<Option<AccountId>> {
        let role = AccountId::new();
        let r = sqlx::query("INSERT INTO acct_roles (id, name, description, badge, builtin, created_at) VALUES ($1, $2, $3, $4, FALSE, $5)")
            .bind(&role.0[..])
            .bind(name)
            .bind(description)
            .bind(badge)
            .bind(util::now())
            .execute(&self.0)
            .await;
        match r {
            Ok(_) => Ok(Some(role)),
            Err(e) if is_dup(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn update_role(&self, role: AccountId, description: &str, badge: Option<&str>) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_roles SET description = $1, badge = $2 WHERE id = $3")
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
        sqlx::query("DELETE FROM acct_role_scopes WHERE role_id = $1")
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
        let builtin: Option<bool> = sqlx::query_scalar("SELECT builtin FROM acct_roles WHERE id = $1")
            .bind(&role.0[..])
            .fetch_optional(&mut *tx)
            .await?;
        match builtin {
            None => return Ok(false),
            Some(true) => return Err(WriteError::Builtin),
            Some(false) => {}
        }
        sqlx::query("DELETE FROM acct_roles WHERE id = $1").bind(&role.0[..]).execute(&mut *tx).await?;
        keep_an_admin(&mut tx, before).await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn user_roles(&self, user: AccountId) -> sqlx::Result<Vec<Role>> {
        let rows = sqlx::query(AssertSqlSafe(format!(
            "SELECT {ROLE_COLS} FROM acct_user_roles ur JOIN acct_roles r ON r.id = ur.role_id
               LEFT JOIN acct_role_scopes s ON s.role_id = r.id
              WHERE ur.user_id = $1 ORDER BY r.name, s.scope"
        )))
        .bind(&user.0[..])
        .fetch_all(&self.0)
        .await?;
        roles_from(rows)
    }

    pub async fn user_scopes(&self, user: AccountId) -> sqlx::Result<Vec<String>> {
        sqlx::query_scalar(
            "SELECT DISTINCT s.scope FROM acct_user_roles ur JOIN acct_role_scopes s ON s.role_id = ur.role_id
              WHERE ur.user_id = $1 ORDER BY s.scope",
        )
        .bind(&user.0[..])
        .fetch_all(&self.0)
        .await
    }

    pub async fn grant_role(&self, user: AccountId, role: AccountId, by: Option<AccountId>) -> sqlx::Result<bool> {
        let r = sqlx::query("INSERT INTO acct_user_roles (user_id, role_id, granted_by, granted_at) VALUES ($1, $2, $3, $4)")
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
        let n = sqlx::query("DELETE FROM acct_user_roles WHERE user_id = $1 AND role_id = $2")
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
        sqlx::query("INSERT INTO acct_audit (user_id, actor_id, event, detail, ip, at) VALUES ($1, $2, $3, $4, $5, $6)")
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
        sqlx::query(
            "SELECT id, user_id, actor_id, event, detail,
                    CASE WHEN actor_id IS NULL OR actor_id = user_id THEN ip ELSE '' END, at
               FROM acct_audit WHERE user_id = $1 ORDER BY at DESC, id DESC LIMIT $2",
        )
        .bind(&user.0[..])
        .bind(i64::from(limit))
        .fetch_all(&self.0)
        .await?
        .iter()
        .map(audit_entry)
        .collect()
    }

    pub async fn delete_audit_before(&self, ts: i64, batch: u64) -> sqlx::Result<u64> {
        let r = sqlx::query("DELETE FROM acct_audit WHERE id IN (SELECT id FROM acct_audit WHERE at < $1 LIMIT $2)")
            .bind(ts)
            .bind(i64::try_from(batch).unwrap_or(i64::MAX))
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected())
    }

    // ---------------------------------------------------------------- invites

    pub async fn insert_invite(&self, code_hash: &[u8; 32], by: Option<AccountId>, username: Option<&str>, expires_at: i64) -> sqlx::Result<()> {
        sqlx::query("INSERT INTO acct_invites (code_hash, created_by, username, created_at, expires_at) VALUES ($1, $2, $3, $4, $5)")
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
        sqlx::query(
            "SELECT code_hash, created_by, username, created_at, expires_at, used_at, used_by FROM acct_invites
              WHERE expires_at > $1 ORDER BY created_at DESC, code_hash LIMIT 1000",
        )
        .bind(now)
        .fetch_all(&self.0)
        .await?
        .iter()
        .map(invite)
        .collect()
    }

    pub async fn delete_invite(&self, code_hash: &[u8; 32]) -> sqlx::Result<bool> {
        let r = sqlx::query("DELETE FROM acct_invites WHERE code_hash = $1").bind(&code_hash[..]).execute(&self.0).await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn delete_expired_invites(&self, now: i64, batch: u64) -> sqlx::Result<u64> {
        let r = sqlx::query("DELETE FROM acct_invites WHERE code_hash IN (SELECT code_hash FROM acct_invites WHERE expires_at < $1 LIMIT $2)")
            .bind(now)
            .bind(i64::try_from(batch).unwrap_or(i64::MAX))
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected())
    }

    /// A taken name returns before the commit: dropping the transaction rolls
    /// the claim back (Postgres has aborted it anyway).
    pub async fn create_user_with_invite(&self, u: &NewUser, role: &str, code_hash: &[u8; 32], now: i64) -> sqlx::Result<InviteSignup> {
        let mut tx = begin_write(&self.0).await?;
        let claimed = sqlx::query(
            "UPDATE acct_invites SET used_at = $1, used_by = $2
              WHERE code_hash = $3 AND used_at IS NULL AND expires_at > $1 AND (username IS NULL OR username = $4)",
        )
        .bind(now)
        .bind(&u.id.0[..])
        .bind(&code_hash[..])
        .bind(&u.username)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if claimed != 1 {
            return Ok(InviteSignup::BadInvite);
        }
        let inserted = sqlx::query(
            "INSERT INTO acct_users (id, username, display_name, email_pending, password_hash, created_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&u.id.0[..])
        .bind(&u.username)
        .bind(&u.display_name)
        .bind(&u.email_pending)
        .bind(&u.password_hash)
        .bind(u.created_at)
        .execute(&mut *tx)
        .await;
        match inserted {
            Err(e) if is_dup(&e) => return Ok(InviteSignup::UsernameTaken),
            Err(e) => return Err(e),
            Ok(_) => {}
        }
        let n = sqlx::query("INSERT INTO acct_user_roles (user_id, role_id, granted_at) SELECT $1, id, $2 FROM acct_roles WHERE name = $3")
            .bind(&u.id.0[..])
            .bind(u.created_at)
            .bind(role)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n != 1 {
            return Err(sqlx::Error::InvalidArgument(format!("no role named {role:?}")));
        }
        tx.commit().await?;
        Ok(InviteSignup::Done)
    }

    pub async fn grant_admin_if_none(&self, user: AccountId) -> Result<bool, WriteError> {
        let mut tx = begin_guarded(&self.0).await?;
        if star_holders(&mut tx).await? > 0 {
            return Ok(false);
        }
        let n = sqlx::query(
            "INSERT INTO acct_user_roles (user_id, role_id, granted_at)
             SELECT u.id, r.id, $1 FROM acct_users u JOIN acct_roles r ON r.name = 'admin' WHERE u.id = $2 AND u.status = $3",
        )
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
        let verified_at: Option<i64> = sqlx::query_scalar("SELECT email_verified_at FROM acct_users WHERE id = $1")
            .bind(&id.0[..])
            .fetch_one(&self.0)
            .await?;
        let credentials = sqlx::query(
            "SELECT kind, name, handle, email, public, created_at, last_used_at FROM acct_credentials
              WHERE user_id = $1 ORDER BY created_at",
        )
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
        let blobs: Vec<(String, String, Vec<u8>, i64, i64)> = sqlx::query_as(
            "SELECT ns, k, v, version, updated_at FROM acct_blobs WHERE user_id = $1 AND ns IN ('kv', 'vault', 'vault_slot') ORDER BY ns, k",
        )
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
        let recovery: Vec<Option<i64>> = sqlx::query_scalar("SELECT used_at FROM acct_recovery WHERE user_id = $1 ORDER BY used_at IS NULL, used_at")
            .bind(&id.0[..])
            .fetch_all(&self.0)
            .await?;
        let mut user = serde_json::json!(user);
        user["email_verified_at"] = serde_json::json!(verified_at);
        Ok(Some(serde_json::json!({
            "user": user,
            "roles": self.user_roles(id).await?,
            "sessions": self.sessions_of(id).await?,
            "credentials": credentials,
            "recovery_codes": recovery.iter().map(|u| serde_json::json!({ "used_at": u })).collect::<Vec<_>>(),
            "storage": blobs,
            "audit": self.audit_of(id, EXPORT_AUDIT_ROWS).await?,
        })))
    }
}
