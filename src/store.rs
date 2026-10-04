//! Every SQL statement on the `acct_*` tables. Methods take and return crate
//! types only, so a second backend later is the same set of methods.
//!
//! Writes that could take `*` away from the last account holding it refuse
//! here, inside their own transaction, rather than in the service: a check
//! before the write would let two admins revoking each other both pass.

use sqlx::{AssertSqlSafe, Connection, MySql, MySqlConnection, MySqlPool, Row, Transaction, mysql::MySqlRow};

use crate::model::{AccountId, AuditEntry, Credential, NewUser, Role, SessionInfo, User, UserStatus};
use crate::util;

#[derive(Clone)]
pub struct Store(pub MySqlPool);

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

const CRED_COLS: &str = "kind, ext_id, user_id, public_key, alg, sign_count, flags, name, created_at, last_used_at";

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

/// Active accounts holding `*` through any role. STRAIGHT_JOIN and FORCE INDEX
/// pin the plan to start from the `*` rows through the `scope` key: as a
/// locking read, a plan that began with acct_users would lock every account,
/// and a scan of acct_role_scopes (the cheapest plan on a tiny table) locks
/// other roles' rows in id order and deadlocks two guarded writes.
const STAR_HOLDERS: &str = "SELECT STRAIGHT_JOIN COUNT(DISTINCT ur.user_id) FROM acct_role_scopes s FORCE INDEX (scope) \
     JOIN acct_user_roles ur ON ur.role_id = s.role_id \
     JOIN acct_users u ON u.id = ur.user_id AND u.status = 0 \
     WHERE s.scope = '*'";

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

fn user(r: &MySqlRow) -> sqlx::Result<User> {
    Ok(User {
        id: id(r.try_get(0)?)?,
        username: r.try_get(1)?,
        display_name: r.try_get(2)?,
        email: r.try_get(3)?,
        email_pending: r.try_get(4)?,
        has_password: r.try_get(5)?,
        totp_enabled: r.try_get(6)?,
        status: UserStatus::from_db(r.try_get(7)?),
        sync_enabled: r.try_get(8)?,
        created_at: r.try_get(9)?,
        has_passkey: r.try_get(10)?,
    })
}

fn credential(r: &MySqlRow) -> sqlx::Result<Credential> {
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
    })
}

fn session(r: &MySqlRow) -> sqlx::Result<SessionInfo> {
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

fn roles_from(rows: Vec<MySqlRow>) -> sqlx::Result<Vec<Role>> {
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

fn audit_entry(r: &MySqlRow) -> sqlx::Result<AuditEntry> {
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

/// How every write in `WriteError::LastAdmin`'s reach starts. Under READ
/// COMMITTED the locking count holds record locks only on what it counts: the
/// `*` scope rows, those roles' grants and the holders' user rows. Under
/// REPEATABLE READ it would also take gap locks, which never
/// conflict with each other: two guarded writes on a table without `*` rows
/// both pass the count and then deadlock on each other's inserts. RC also
/// keeps MariaDB's snapshot isolation (an RR check) out of the way.
const BEGIN_GUARDED: &str = "SET TRANSACTION ISOLATION LEVEL READ COMMITTED; START TRANSACTION";

/// The locking count every guarded write runs first: two of them queue on the
/// first `*` row of the `scope` key, so the second one counts after the first
/// has committed.
async fn star_holders_locked(c: &mut MySqlConnection) -> sqlx::Result<i64> {
    sqlx::query_scalar(AssertSqlSafe(format!("{STAR_HOLDERS} FOR UPDATE"))).fetch_one(c).await
}

/// Runs after the change, in its transaction; an error drops (rolls back) it.
/// `before == 0` is a database nobody administers yet (before bootstrap), where
/// there is nothing to protect.
async fn keep_an_admin(c: &mut MySqlConnection, before: i64) -> Result<(), WriteError> {
    if before > 0 && star_holders_locked(c).await? == 0 {
        return Err(WriteError::LastAdmin);
    }
    Ok(())
}

/// Refuses anything `scope::valid_grant` does not accept. Beyond keeping junk
/// out: the column is PAD SPACE, so a stored `* ` would count as `*` in the
/// last-admin guard while granting nothing.
async fn insert_scopes(c: &mut MySqlConnection, role: AccountId, scopes: &[String]) -> sqlx::Result<()> {
    if let Some(bad) = scopes.iter().find(|s| !crate::scope::valid_grant(s)) {
        return Err(sqlx::Error::InvalidArgument(format!("not a valid scope grant: {bad:?}")));
    }
    let mut scopes: Vec<&str> = scopes.iter().map(String::as_str).collect();
    scopes.sort_unstable();
    scopes.dedup();
    if scopes.is_empty() {
        return Ok(());
    }
    let values = vec!["(?, ?)"; scopes.len()].join(", ");
    let mut q = sqlx::query(AssertSqlSafe(format!("INSERT INTO acct_role_scopes (role_id, scope) VALUES {values}")));
    for s in scopes {
        q = q.bind(&role.0[..]).bind(s);
    }
    q.execute(c).await.map(|_| ())
}

impl Store {
    /// A transaction for composing with `delete_user`, isolated the way the
    /// last-admin guard needs (see `BEGIN_GUARDED`), and holding the guard's
    /// locks from the start. The caller's own writes come before
    /// `delete_user`'s count; had they locked an admin's row first, two admins
    /// deleting each other would each hold a row the other's count waits on.
    pub async fn begin(&self) -> sqlx::Result<Transaction<'static, MySql>> {
        let mut tx = self.0.begin_with(BEGIN_GUARDED).await?;
        star_holders_locked(&mut tx).await?;
        Ok(tx)
    }

    // ------------------------------------------------------------------ users

    /// Plain INSERT: the unique key settles a race for a name, not a SELECT
    /// first. `role`, when given, is granted in the same transaction, so an
    /// account never exists without the role it was made for. For bootstrap's
    /// admin that matters: a half-made one would hold the name and refuse the
    /// next boot.
    pub async fn create_user(&self, u: &NewUser, role: Option<&str>) -> Result<(), CreateUserError> {
        let mut tx = self.0.begin().await?;
        let inserted = sqlx::query(
            "INSERT INTO acct_users (id, username, display_name, email_pending, password_hash, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
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
                "INSERT INTO acct_user_roles (user_id, role_id, granted_by, granted_at)
                 SELECT ?, id, NULL, ? FROM acct_roles WHERE name = ?",
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
        sqlx::query(AssertSqlSafe(format!("SELECT {USER_COLS} FROM acct_users WHERE id = ?")))
            .bind(&id.0[..])
            .fetch_optional(&self.0)
            .await?
            .as_ref()
            .map(user)
            .transpose()
    }

    /// `username` as `scope::normalize_username` returns it. The column is
    /// `_bin`, so case is not folded, but it is PAD SPACE: `"name "` finds
    /// `name`. Never pass a raw string here.
    pub async fn user_by_username(&self, username: &str) -> sqlx::Result<Option<User>> {
        sqlx::query(AssertSqlSafe(format!("SELECT {USER_COLS} FROM acct_users WHERE username = ?")))
            .bind(username)
            .fetch_optional(&self.0)
            .await?
            .as_ref()
            .map(user)
            .transpose()
    }

    /// A verified address only: a pending one belongs to nobody yet.
    pub async fn user_by_email(&self, email: &str) -> sqlx::Result<Option<User>> {
        sqlx::query(AssertSqlSafe(format!("SELECT {USER_COLS} FROM acct_users WHERE email = ?")))
            .bind(email)
            .fetch_optional(&self.0)
            .await?
            .as_ref()
            .map(user)
            .transpose()
    }

    pub async fn set_email_pending(&self, id: AccountId, email: Option<&str>) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_users SET email_pending = ? WHERE id = ?").bind(email).bind(&id.0[..]).execute(&self.0).await?;
        Ok(r.rows_affected() == 1)
    }

    /// The pending address becomes the verified one, if it is still the one
    /// the link was for.
    pub async fn confirm_email(&self, id: AccountId, email: &str, now: i64) -> sqlx::Result<EmailConfirm> {
        let r = sqlx::query(
            "UPDATE acct_users SET email = email_pending, email_pending = NULL, email_verified_at = ?
              WHERE id = ? AND email_pending = ?",
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
        sqlx::query("UPDATE acct_users SET email = NULL, email_pending = NULL, email_verified_at = NULL WHERE id = ?")
            .bind(&id.0[..])
            .execute(&self.0)
            .await
            .map(|_| ())
    }

    pub async fn password_hash_of(&self, id: AccountId) -> sqlx::Result<Option<String>> {
        let h: Option<Option<String>> = sqlx::query_scalar("SELECT password_hash FROM acct_users WHERE id = ?")
            .bind(&id.0[..])
            .fetch_optional(&self.0)
            .await?;
        Ok(h.flatten())
    }

    pub async fn set_password_hash(&self, id: AccountId, hash: &str) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_users SET password_hash = ? WHERE id = ?")
            .bind(hash)
            .bind(&id.0[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    /// The upgrade after a login whose hash `needs_rehash`: only while `old` is
    /// still the stored hash. A password change that lands while the login is
    /// verifying would otherwise be overwritten with the old password.
    pub async fn rehash_password(&self, id: AccountId, old: &str, new: &str) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_users SET password_hash = ? WHERE id = ? AND password_hash = ?")
            .bind(new)
            .bind(&id.0[..])
            .bind(old)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Refuses to disable the last active holder of `*`. The caller still
    /// deletes the sessions of an account it disables.
    pub async fn set_status(&self, id: AccountId, status: UserStatus) -> Result<bool, WriteError> {
        let mut tx = self.0.begin_with(BEGIN_GUARDED).await?;
        let before = star_holders_locked(&mut tx).await?;
        let n = sqlx::query("UPDATE acct_users SET status = ? WHERE id = ?")
            .bind(status as i8)
            .bind(&id.0[..])
            .execute(&mut *tx)
            .await?
            .rows_affected();
        keep_an_admin(&mut tx, before).await?;
        tx.commit().await?;
        Ok(n == 1)
    }

    pub async fn set_display_name(&self, id: AccountId, name: &str) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_users SET display_name = ? WHERE id = ?")
            .bind(name)
            .bind(&id.0[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn set_sync_enabled(&self, id: AccountId, on: bool) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_users SET sync_enabled = ? WHERE id = ?")
            .bind(on)
            .bind(&id.0[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Newest first, with the total for paging. `search` matches username,
    /// display name and verified email, case-insensitively (the columns are
    /// `_bin`, so LIKE alone would not be).
    pub async fn list_users(&self, search: Option<&str>, limit: u32, offset: u32) -> sqlx::Result<(Vec<User>, i64)> {
        let like = search.map(str::trim).filter(|s| !s.is_empty()).map(like_pattern);
        let filter = if like.is_some() {
            "WHERE username LIKE ? ESCAPE '!' OR LOWER(display_name) LIKE ? ESCAPE '!' \
             OR COALESCE(email, '') LIKE ? ESCAPE '!'"
        } else {
            ""
        };
        let mut rows = sqlx::query(AssertSqlSafe(format!(
            "SELECT {USER_COLS} FROM acct_users {filter} ORDER BY created_at DESC, id LIMIT ? OFFSET ?"
        )));
        let mut count = sqlx::query_scalar::<_, i64>(AssertSqlSafe(format!("SELECT COUNT(*) FROM acct_users {filter}")));
        if let Some(l) = &like {
            rows = rows.bind(l).bind(l).bind(l);
            count = count.bind(l).bind(l).bind(l);
        }
        let users = rows.bind(limit).bind(offset).fetch_all(&self.0).await?.iter().map(user).collect::<sqlx::Result<_>>()?;
        Ok((users, count.fetch_one(&self.0).await?))
    }

    /// One DELETE; the foreign keys take sessions, grants, credentials,
    /// recovery codes, blobs, the profile and the audit rows with it.
    ///
    /// Takes a connection, not `&self`: the service runs it inside the
    /// transaction (from `Store::begin`) that also removes the host's rows for
    /// the account. Inside one, this nests as a savepoint, so a refusal (last
    /// `*` holder) rolls back only this part and leaves the rest to the caller.
    pub async fn delete_user(conn: &mut MySqlConnection, id: AccountId) -> Result<bool, WriteError> {
        let mut tx = if conn.is_in_transaction() { conn.begin().await? } else { conn.begin_with(BEGIN_GUARDED).await? };
        let before = star_holders_locked(&mut tx).await?;
        let n = sqlx::query("DELETE FROM acct_users WHERE id = ?")
            .bind(&id.0[..])
            .execute(&mut *tx)
            .await?
            .rows_affected();
        keep_an_admin(&mut tx, before).await?;
        tx.commit().await?;
        Ok(n == 1)
    }

    // --------------------------------------------------------------- sessions

    /// Inserts only for an active account: a login still in flight when the
    /// account is disabled or deleted gets `RowNotFound`, not a session. Keeps
    /// the newest `MAX_SESSIONS` signed-in sessions per account (and
    /// `MAX_PENDING` waiting for a second factor), so a script that logs in in a
    /// loop cannot grow the table without bound. Pending sessions never push
    /// out signed-in ones: knowing the password alone must not sign the owner out.
    pub async fn insert_session(&self, s: &SessionInfo) -> sqlx::Result<()> {
        let n = sqlx::query(AssertSqlSafe(format!(
            "INSERT INTO acct_sessions ({SESSION_COLS})
             SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ? FROM acct_users WHERE id = ? AND status = ?"
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
        .bind(&s.user_id.0[..])
        .bind(UserStatus::Active as i8)
        .execute(&self.0)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(sqlx::Error::RowNotFound);
        }
        // Found by a plain read and deleted by primary key: a DELETE ranging
        // over the user_id index takes gap locks that deadlock with other
        // accounts' logins. Two racing logins may leave one extra row until
        // the next one.
        let over: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT token_hash FROM acct_sessions WHERE user_id = ? AND mfa_ok = ?
              ORDER BY seen_at DESC, created_at DESC LIMIT ?, 1000",
        )
        .bind(&s.user_id.0[..])
        .bind(s.mfa_ok)
        .bind(if s.mfa_ok { MAX_SESSIONS } else { MAX_PENDING })
        .fetch_all(&self.0)
        .await?;
        for h in over {
            sqlx::query("DELETE FROM acct_sessions WHERE token_hash = ?").bind(h).execute(&self.0).await?;
        }
        Ok(())
    }

    /// Absolute expiry only; the idle limit is config, so the service checks
    /// `seen_at` itself.
    pub async fn session_by_hash(&self, hash: &[u8; 32], now: i64) -> sqlx::Result<Option<SessionInfo>> {
        sqlx::query(AssertSqlSafe(format!(
            "SELECT {SESSION_COLS} FROM acct_sessions WHERE token_hash = ? AND expires_at > ?"
        )))
        .bind(&hash[..])
        .bind(now)
        .fetch_optional(&self.0)
        .await?
        .as_ref()
        .map(session)
        .transpose()
    }

    /// True when it wrote, i.e. `seen_at` was more than `TOUCH_SECS` old.
    pub async fn touch_session(&self, hash: &[u8; 32], now: i64) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_sessions SET seen_at = ? WHERE token_hash = ? AND seen_at < ?")
            .bind(now)
            .bind(&hash[..])
            .bind(now - TOUCH_SECS)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn set_session_mfa(&self, hash: &[u8; 32], mfa_ok: bool, auth_at: i64) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_sessions SET mfa_ok = ?, auth_at = ? WHERE token_hash = ?")
            .bind(mfa_ok)
            .bind(auth_at)
            .bind(&hash[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    /// New token, same session: a token seen before a privilege change (login,
    /// MFA, step-up, role change) stops working after it.
    pub async fn rotate_session(&self, old: &[u8; 32], new: &[u8; 32]) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_sessions SET token_hash = ? WHERE token_hash = ?")
            .bind(&new[..])
            .bind(&old[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    /// The second factor is done: a new token, `mfa_ok`, the full lifetime.
    /// Only a pending session completes, and only once.
    pub async fn complete_session(&self, old: &[u8; 32], new: &[u8; 32], auth_at: i64, expires_at: i64) -> sqlx::Result<bool> {
        let r = sqlx::query(
            "UPDATE acct_sessions SET token_hash = ?, mfa_ok = 1, auth_at = ?, expires_at = ? WHERE token_hash = ? AND mfa_ok = 0",
        )
        .bind(&new[..])
        .bind(auth_at)
        .bind(expires_at)
        .bind(&old[..])
        .execute(&self.0)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Step-up: a new token and a fresh `auth_at`, on a complete session only.
    pub async fn refresh_session(&self, old: &[u8; 32], new: &[u8; 32], auth_at: i64) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_sessions SET token_hash = ?, auth_at = ? WHERE token_hash = ? AND mfa_ok = 1")
            .bind(&new[..])
            .bind(auth_at)
            .bind(&old[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Scoped to the owner: the revoke button posts a hash from a URL, and a
    /// hash belonging to someone else must delete nothing.
    pub async fn delete_session(&self, hash: &[u8; 32], user: AccountId) -> sqlx::Result<bool> {
        let r = sqlx::query("DELETE FROM acct_sessions WHERE token_hash = ? AND user_id = ?")
            .bind(&hash[..])
            .bind(&user.0[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    /// "Sign out everywhere" keeps `except`, the session asking.
    pub async fn delete_sessions_of(&self, user: AccountId, except: Option<&[u8; 32]>) -> sqlx::Result<u64> {
        let q = match except {
            Some(h) => sqlx::query("DELETE FROM acct_sessions WHERE user_id = ? AND token_hash <> ?")
                .bind(&user.0[..])
                .bind(&h[..]),
            None => sqlx::query("DELETE FROM acct_sessions WHERE user_id = ?").bind(&user.0[..]),
        };
        Ok(q.execute(&self.0).await?.rows_affected())
    }

    /// Most recently used first. Includes rows the sweep has not reached yet;
    /// the caller knows the idle limit and filters.
    pub async fn sessions_of(&self, user: AccountId) -> sqlx::Result<Vec<SessionInfo>> {
        sqlx::query(AssertSqlSafe(format!(
            "SELECT {SESSION_COLS} FROM acct_sessions WHERE user_id = ? ORDER BY seen_at DESC, created_at DESC"
        )))
        .bind(&user.0[..])
        .fetch_all(&self.0)
        .await?
        .iter()
        .map(session)
        .collect()
    }

    /// One batch; the sweeper loops while a call returns a full one. Small
    /// batches keep each lock short.
    pub async fn delete_expired_sessions(&self, now: i64, idle_secs: i64, batch: u64) -> sqlx::Result<u64> {
        // Two statements, one index each: an OR across both columns scanned and
        // locked the whole table on every batch.
        let expired = sqlx::query("DELETE FROM acct_sessions WHERE expires_at < ? LIMIT ?")
            .bind(now)
            .bind(batch)
            .execute(&self.0)
            .await?
            .rows_affected();
        if expired >= batch {
            return Ok(expired);
        }
        let idle = sqlx::query("DELETE FROM acct_sessions WHERE seen_at < ? LIMIT ?")
            .bind(now - idle_secs)
            .bind(batch - expired)
            .execute(&self.0)
            .await?
            .rows_affected();
        Ok(expired + idle)
    }

    // ------------------------------------------------------- second factors

    /// The sealed TOTP secret and the last step a code was accepted for.
    pub async fn totp_of(&self, user: AccountId) -> sqlx::Result<Option<(Vec<u8>, i64)>> {
        let row: Option<(Option<Vec<u8>>, i64)> =
            sqlx::query_as("SELECT totp_enc, totp_last_step FROM acct_users WHERE id = ?").bind(&user.0[..]).fetch_optional(&self.0).await?;
        Ok(row.and_then(|(enc, step)| enc.map(|e| (e, step))))
    }

    /// Turns codes on (only while off, so two setups cannot race) or off.
    pub async fn set_totp(&self, user: AccountId, sealed: Option<&[u8]>, last_step: i64) -> sqlx::Result<bool> {
        let q = match sealed {
            Some(s) => sqlx::query("UPDATE acct_users SET totp_enc = ?, totp_last_step = ? WHERE id = ? AND totp_enc IS NULL").bind(s),
            None => sqlx::query("UPDATE acct_users SET totp_enc = NULL, totp_last_step = ? WHERE id = ? AND totp_enc IS NOT NULL"),
        };
        Ok(q.bind(last_step).bind(&user.0[..]).execute(&self.0).await?.rows_affected() == 1)
    }

    /// Accepts a code's step once: false when this step or a later one was
    /// already used, so a code read over a shoulder is worth nothing after.
    pub async fn advance_totp(&self, user: AccountId, step: i64) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_users SET totp_last_step = ? WHERE id = ? AND totp_enc IS NOT NULL AND totp_last_step < ?")
            .bind(step)
            .bind(&user.0[..])
            .bind(step)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    /// The same secret under the current key, unless it changed meanwhile.
    pub async fn reseal_totp(&self, user: AccountId, old: &[u8], new: &[u8]) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_users SET totp_enc = ? WHERE id = ? AND totp_enc = ?")
            .bind(new)
            .bind(&user.0[..])
            .bind(old)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    /// A fresh set of recovery code hashes in place of the old one. Under READ
    /// COMMITTED (see `BEGIN_GUARDED`): the DELETE's gap locks under REPEATABLE
    /// READ deadlock with another account's codes going in next to them.
    pub async fn replace_recovery(&self, user: AccountId, hashes: &[[u8; 32]]) -> sqlx::Result<()> {
        let mut tx = self.0.begin_with(BEGIN_GUARDED).await?;
        sqlx::query("DELETE FROM acct_recovery WHERE user_id = ?").bind(&user.0[..]).execute(&mut *tx).await?;
        for h in hashes {
            sqlx::query("INSERT INTO acct_recovery (user_id, code_hash) VALUES (?, ?)")
                .bind(&user.0[..])
                .bind(&h[..])
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await
    }

    /// Spends one code: false when it is unknown or already spent.
    pub async fn use_recovery(&self, user: AccountId, hash: &[u8; 32], now: i64) -> sqlx::Result<bool> {
        let r = sqlx::query("UPDATE acct_recovery SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL")
            .bind(now)
            .bind(&user.0[..])
            .bind(&hash[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn recovery_left(&self, user: AccountId) -> sqlx::Result<i64> {
        sqlx::query_scalar("SELECT COUNT(*) FROM acct_recovery WHERE user_id = ? AND used_at IS NULL")
            .bind(&user.0[..])
            .fetch_one(&self.0)
            .await
    }

    pub async fn delete_recovery(&self, user: AccountId) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM acct_recovery WHERE user_id = ?").bind(&user.0[..]).execute(&self.0).await.map(|_| ())
    }

    // ---------------------------------------------------------- credentials

    /// A plain INSERT: false when `(kind, ext_id)` already exists, so a key can
    /// never be moved to a second account by registering it again.
    pub async fn insert_credential(&self, c: &Credential) -> sqlx::Result<bool> {
        let r = sqlx::query(
            "INSERT INTO acct_credentials (kind, ext_id, user_id, public_key, alg, sign_count, flags, name, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        sqlx::query(AssertSqlSafe(format!("SELECT {CRED_COLS} FROM acct_credentials WHERE kind = ? AND ext_id = ?")))
            .bind(kind)
            .bind(ext_id)
            .fetch_optional(&self.0)
            .await?
            .as_ref()
            .map(credential)
            .transpose()
    }

    /// Oldest first.
    pub async fn credentials_of(&self, user: AccountId, kind: &str) -> sqlx::Result<Vec<Credential>> {
        sqlx::query(AssertSqlSafe(format!(
            "SELECT {CRED_COLS} FROM acct_credentials WHERE user_id = ? AND kind = ? ORDER BY created_at, ext_id"
        )))
        .bind(&user.0[..])
        .bind(kind)
        .fetch_all(&self.0)
        .await?
        .iter()
        .map(credential)
        .collect()
    }

    /// Scoped to the owner, like `delete_session`.
    pub async fn delete_credential(&self, user: AccountId, kind: &str, ext_id: &[u8]) -> sqlx::Result<bool> {
        let r = sqlx::query("DELETE FROM acct_credentials WHERE user_id = ? AND kind = ? AND ext_id = ?")
            .bind(&user.0[..])
            .bind(kind)
            .bind(ext_id)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Every credential of one kind an account has, e.g. its device keys when a
    /// second factor changes.
    pub async fn delete_credentials_of(&self, user: AccountId, kind: &str) -> sqlx::Result<u64> {
        let r = sqlx::query("DELETE FROM acct_credentials WHERE user_id = ? AND kind = ?")
            .bind(&user.0[..])
            .bind(kind)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected())
    }

    /// One batch of credentials of `kind` unused since `before`.
    pub async fn delete_stale_credentials(&self, kind: &str, before: i64, batch: u64) -> sqlx::Result<u64> {
        let r = sqlx::query("DELETE FROM acct_credentials WHERE kind = ? AND COALESCE(last_used_at, created_at) < ? LIMIT ?")
            .bind(kind)
            .bind(before)
            .bind(batch)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected())
    }

    /// Credentials that sign in on their own: passkeys, SSH keys, social
    /// identities. Device keys only stand in for one of these, so they do not
    /// count as a way in.
    pub async fn login_credentials(&self, user: AccountId) -> sqlx::Result<i64> {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM acct_credentials WHERE user_id = ? AND (kind IN ('passkey', 'ssh') OR kind LIKE 'oauth:%')",
        )
        .bind(&user.0[..])
        .fetch_one(&self.0)
        .await
    }

    /// Records a use. The counter only moves forward (authenticators that keep
    /// it at 0 aside): false means another use raced this one or the
    /// authenticator went backwards, and the caller refuses.
    pub async fn used_credential(&self, kind: &str, ext_id: &[u8], sign_count: i64, now: i64) -> sqlx::Result<bool> {
        let r = sqlx::query(
            "UPDATE acct_credentials SET sign_count = ?, last_used_at = ?
              WHERE kind = ? AND ext_id = ? AND (? = 0 OR sign_count < ?)",
        )
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

    /// Seeds `admin` (`*`) and `user` (`user_scopes`) on first boot. Scopes are
    /// written only when the role row is new: an admin who later trimmed the
    /// `user` role must not see it grow back on every restart.
    pub async fn ensure_builtin_roles(&self, user_scopes: &[String]) -> sqlx::Result<()> {
        let star = ["*".to_string()];
        for (name, description, scopes) in [("admin", "Full access", &star[..]), ("user", "Every account", user_scopes)] {
            let mut tx = self.0.begin().await?;
            let role = AccountId::new();
            // IGNORE only ever meets the name key: every other value is a constant.
            let fresh = sqlx::query(
                "INSERT IGNORE INTO acct_roles (id, name, description, builtin, created_at) VALUES (?, ?, ?, 1, ?)",
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
              WHERE r.name = ? ORDER BY s.scope"
        )))
        .bind(name)
        .fetch_all(&self.0)
        .await?;
        Ok(roles_from(rows)?.into_iter().next())
    }

    /// `None` when the name is taken. Scopes come after, via `set_role_scopes`.
    pub async fn create_role(&self, name: &str, description: &str, badge: Option<&str>) -> sqlx::Result<Option<AccountId>> {
        let role = AccountId::new();
        let r = sqlx::query("INSERT INTO acct_roles (id, name, description, badge, builtin, created_at) VALUES (?, ?, ?, ?, 0, ?)")
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
        let r = sqlx::query("UPDATE acct_roles SET description = ?, badge = ? WHERE id = ?")
            .bind(description)
            .bind(badge)
            .bind(&role.0[..])
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Replaces the whole set in one transaction: a failure half-way leaves the
    /// old set, never an empty or partial one.
    pub async fn set_role_scopes(&self, role: AccountId, scopes: &[String]) -> Result<(), WriteError> {
        let mut tx = self.0.begin_with(BEGIN_GUARDED).await?;
        let before = star_holders_locked(&mut tx).await?;
        sqlx::query("DELETE FROM acct_role_scopes WHERE role_id = ?")
            .bind(&role.0[..])
            .execute(&mut *tx)
            .await?;
        insert_scopes(&mut tx, role, scopes).await?;
        keep_an_admin(&mut tx, before).await?;
        tx.commit().await?;
        Ok(())
    }

    /// False when there is no such role. Its scopes and grants go with it.
    pub async fn delete_role(&self, role: AccountId) -> Result<bool, WriteError> {
        let mut tx = self.0.begin_with(BEGIN_GUARDED).await?;
        let before = star_holders_locked(&mut tx).await?;
        let builtin: Option<bool> = sqlx::query_scalar("SELECT builtin FROM acct_roles WHERE id = ? FOR UPDATE")
            .bind(&role.0[..])
            .fetch_optional(&mut *tx)
            .await?;
        match builtin {
            None => return Ok(false),
            Some(true) => return Err(WriteError::Builtin),
            Some(false) => {}
        }
        sqlx::query("DELETE FROM acct_roles WHERE id = ?").bind(&role.0[..]).execute(&mut *tx).await?;
        keep_an_admin(&mut tx, before).await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn user_roles(&self, user: AccountId) -> sqlx::Result<Vec<Role>> {
        let rows = sqlx::query(AssertSqlSafe(format!(
            "SELECT {ROLE_COLS} FROM acct_user_roles ur JOIN acct_roles r ON r.id = ur.role_id
               LEFT JOIN acct_role_scopes s ON s.role_id = r.id
              WHERE ur.user_id = ? ORDER BY r.name, s.scope"
        )))
        .bind(&user.0[..])
        .fetch_all(&self.0)
        .await?;
        roles_from(rows)
    }

    /// Every scope of every role the account holds, deduplicated and sorted.
    pub async fn user_scopes(&self, user: AccountId) -> sqlx::Result<Vec<String>> {
        sqlx::query_scalar(
            "SELECT DISTINCT s.scope FROM acct_user_roles ur JOIN acct_role_scopes s ON s.role_id = ur.role_id
              WHERE ur.user_id = ? ORDER BY s.scope",
        )
        .bind(&user.0[..])
        .fetch_all(&self.0)
        .await
    }

    /// False when the account already held the role. Plain INSERT, not IGNORE:
    /// IGNORE would also swallow a missing user or role.
    pub async fn grant_role(&self, user: AccountId, role: AccountId, by: Option<AccountId>) -> sqlx::Result<bool> {
        let r = sqlx::query("INSERT INTO acct_user_roles (user_id, role_id, granted_by, granted_at) VALUES (?, ?, ?, ?)")
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

    /// False when the account did not hold the role.
    pub async fn revoke_role(&self, user: AccountId, role: AccountId) -> Result<bool, WriteError> {
        let mut tx = self.0.begin_with(BEGIN_GUARDED).await?;
        let before = star_holders_locked(&mut tx).await?;
        let n = sqlx::query("DELETE FROM acct_user_roles WHERE user_id = ? AND role_id = ?")
            .bind(&user.0[..])
            .bind(&role.0[..])
            .execute(&mut *tx)
            .await?
            .rows_affected();
        keep_an_admin(&mut tx, before).await?;
        tx.commit().await?;
        Ok(n == 1)
    }

    /// Active accounts holding `*`. Zero means nobody can administer the site:
    /// bootstrap runs then. A disabled admin does not count, since they cannot
    /// sign in.
    pub async fn holders_of_scope_star(&self) -> sqlx::Result<i64> {
        sqlx::query_scalar(STAR_HOLDERS).fetch_one(&self.0).await
    }

    // ------------------------------------------------------------------ audit

    /// `ip` is already shaped (`ip::shape_ip`); `detail` is cut to the column.
    pub async fn audit(
        &self,
        user: Option<AccountId>,
        actor: Option<AccountId>,
        event: &str,
        detail: &str,
        ip: &str,
    ) -> sqlx::Result<()> {
        sqlx::query("INSERT INTO acct_audit (user_id, actor_id, event, detail, ip, at) VALUES (?, ?, ?, ?, ?, ?)")
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

    /// Newest first. `ip` is blanked on rows another account acted on (an
    /// admin's grant or disable): it is the admin's address, not the user's,
    /// and this is what the user's dashboard and export show.
    pub async fn audit_of(&self, user: AccountId, limit: u32) -> sqlx::Result<Vec<AuditEntry>> {
        sqlx::query(
            "SELECT id, user_id, actor_id, event, detail,
                    CASE WHEN actor_id IS NULL OR actor_id = user_id THEN ip ELSE '' END, at
               FROM acct_audit WHERE user_id = ? ORDER BY at DESC, id DESC LIMIT ?",
        )
        .bind(&user.0[..])
        .bind(limit)
        .fetch_all(&self.0)
        .await?
        .iter()
        .map(audit_entry)
        .collect()
    }

    /// One batch of rows older than `ts`; loop like `delete_expired_sessions`.
    pub async fn delete_audit_before(&self, ts: i64, batch: u64) -> sqlx::Result<u64> {
        let r = sqlx::query("DELETE FROM acct_audit WHERE at < ? LIMIT ?")
            .bind(ts)
            .bind(batch)
            .execute(&self.0)
            .await?;
        Ok(r.rows_affected())
    }

    // ----------------------------------------------------------------- export

    /// The GDPR download: the account row, roles, sessions, sign-in methods
    /// and the newest audit rows about the account (as `audit_of` shows them). No
    /// secrets and nothing that works as a credential: no password hash, TOTP
    /// secret, session hashes, recovery hashes or public keys. Not in it: audit
    /// rows where this account acted on another one, which sit in that
    /// account's log. TODO: blobs (phase 6)
    /// and the profile (phase 7) join this when something writes them. `None`
    /// when the account does not exist.
    pub async fn export_user(&self, id: AccountId) -> sqlx::Result<Option<serde_json::Value>> {
        let Some(user) = self.user_by_id(id).await? else { return Ok(None) };
        let verified_at: Option<i64> = sqlx::query_scalar("SELECT email_verified_at FROM acct_users WHERE id = ?")
            .bind(&id.0[..])
            .fetch_one(&self.0)
            .await?;
        let credentials = sqlx::query(
            "SELECT kind, name, handle, email, public, created_at, last_used_at FROM acct_credentials
              WHERE user_id = ? ORDER BY created_at",
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
        // When each recovery code was used; never the hashes.
        let recovery: Vec<Option<i64>> =
            sqlx::query_scalar("SELECT used_at FROM acct_recovery WHERE user_id = ? ORDER BY used_at IS NULL, used_at")
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
            "audit": self.audit_of(id, EXPORT_AUDIT_ROWS).await?,
        })))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::migrate;
    use sqlx::mysql::MySqlConnectOptions;

    /// The shared test database. Tests run in parallel against it, so every
    /// name carries a random suffix, nothing grants `*`, and nothing counts
    /// rows across the whole schema.
    pub(crate) async fn shared() -> Option<Store> {
        let url = std::env::var("L4F_TEST_DATABASE_URL").ok()?;
        let pool = MySqlPool::connect(&url).await.expect("L4F_TEST_DATABASE_URL does not connect");
        migrate::run(&pool).await.unwrap();
        Some(Store(pool))
    }

    /// A database of its own (`l4f_test_<hex>`), for tests about global state:
    /// who holds `*`, how many rows a sweep removes. `done` drops it; a failed
    /// test leaves it behind on the throwaway server.
    pub(crate) struct Fresh {
        pub(crate) store: Store,
        name: String,
        opts: MySqlConnectOptions,
    }

    pub(crate) async fn fresh() -> Option<Fresh> {
        let url = std::env::var("L4F_TEST_DATABASE_URL").ok()?;
        let opts: MySqlConnectOptions = url.parse().expect("L4F_TEST_DATABASE_URL does not parse");
        let name = format!("l4f_test_{}", hex::encode(util::random::<6>()));
        let mut c = MySqlConnection::connect_with(&opts).await.unwrap();
        sqlx::raw_sql(AssertSqlSafe(format!("CREATE DATABASE `{name}`"))).execute(&mut c).await.unwrap();
        let _ = c.close().await;
        let pool = MySqlPool::connect_with(opts.clone().database(&name)).await.unwrap();
        migrate::run(&pool).await.unwrap();
        Some(Fresh { store: Store(pool), name, opts })
    }

    impl Fresh {
        pub(crate) async fn done(self) {
            self.store.0.close().await;
            let mut c = MySqlConnection::connect_with(&self.opts).await.unwrap();
            sqlx::raw_sql(AssertSqlSafe(format!("DROP DATABASE `{}`", self.name))).execute(&mut c).await.unwrap();
            let _ = c.close().await;
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

    async fn delete(s: &Store, id: AccountId) -> Result<bool, WriteError> {
        Store::delete_user(&mut s.0.acquire().await.unwrap(), id).await
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

    async fn rows_for(s: &Store, table: &str, id: AccountId) -> i64 {
        sqlx::query_scalar(AssertSqlSafe(format!("SELECT COUNT(*) FROM {table} WHERE user_id = ?")))
            .bind(&id.0[..])
            .fetch_one(&s.0)
            .await
            .unwrap()
    }

    #[test]
    fn clip_cuts_on_characters_and_like_pattern_escapes() {
        assert_eq!(clip("abc", 5), "abc");
        assert_eq!(clip("ééé", 2), "éé");
        assert_eq!(clip("", 0), "");
        assert_eq!(like_pattern("A_b%c!"), "%a!_b!%c!!%");
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
        assert!(s.set_password_hash(u.id, "h2").await.unwrap());
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
        sqlx::query("UPDATE acct_users SET email = ? WHERE id = ?")
            .bind(format!("{mail}@example.org"))
            .bind(&ids[0].0[..])
            .execute(&s.0)
            .await
            .unwrap();
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

        assert!(s.set_session_mfa(&live.token_hash, true, now + 5).await.unwrap());
        let got = s.session_by_hash(&live.token_hash, now).await.unwrap().unwrap();
        assert!(got.mfa_ok);
        assert_eq!(got.auth_at, now + 5);

        let rotated: [u8; 32] = util::random();
        assert!(s.rotate_session(&live.token_hash, &rotated).await.unwrap());
        assert!(s.session_by_hash(&live.token_hash, now).await.unwrap().is_none(), "old token dead after rotation");
        assert!(s.session_by_hash(&rotated, now).await.unwrap().unwrap().mfa_ok, "rotation keeps the session");
        assert!(!s.rotate_session(&live.token_hash, &util::random()).await.unwrap());

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
        assert!(Store::delete_user(&mut tx, other).await.unwrap());
        assert!(matches!(Store::delete_user(&mut tx, a2).await, Err(WriteError::LastAdmin)));
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
        sqlx::query("INSERT INTO acct_roles (id, name, created_at) VALUES (?, 'low', 1)").bind(&low.0[..]).execute(&s.0).await.unwrap();
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
            sqlx::query("INSERT INTO acct_audit (user_id, event, at) VALUES (?, 'old', ?)")
                .bind(&u.0[..])
                .bind(at)
                .execute(&s.0)
                .await
                .unwrap();
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
        let b = &u.0[..];
        for sql in [
            // ext_id = the user id: unique, and the key is global across test runs.
            "INSERT INTO acct_credentials (kind, ext_id, user_id, created_at) SELECT 'ssh', id, id, 1 FROM acct_users WHERE id = ?",
            "INSERT INTO acct_recovery (user_id, code_hash) VALUES (?, REPEAT('a', 32))",
            "INSERT INTO acct_blobs (user_id, ns, k, v, updated_at) VALUES (?, 'kv', 'k', 'v', 1)",
            "INSERT INTO acct_profiles (user_id, updated_at) VALUES (?, 1)",
        ] {
            sqlx::query(sql).bind(b).execute(&s.0).await.unwrap();
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
        assert!(Store::delete_user(&mut tx, u).await.unwrap());
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
        sqlx::query("UPDATE acct_users SET totp_enc = ? WHERE id = ?").bind(&totp[..]).bind(&u.0[..]).execute(&s.0).await.unwrap();
        sqlx::query(
            "INSERT INTO acct_credentials (kind, ext_id, user_id, public_key, alg, name, created_at)
             VALUES ('passkey', ?, ?, ?, -7, 'Laptop', 5)",
        )
        .bind(&ext[..])
        .bind(&u.0[..])
        .bind(&public_key[..])
        .execute(&s.0)
        .await
        .unwrap();
        sqlx::query("INSERT INTO acct_recovery (user_id, code_hash) VALUES (?, ?)")
            .bind(&u.0[..])
            .bind(&recovery[..])
            .execute(&s.0)
            .await
            .unwrap();
        let now = util::now();
        let session = sess(u, now, now, now + 100);
        s.insert_session(&session).await.unwrap();
        let admin = make_user(&s, None).await;
        s.audit(Some(u), Some(admin), "role_revoke", "", "198.51.100.77").await.unwrap();
        s.audit(Some(u), None, "register", "", "203.0.113.0").await.unwrap();

        let v = s.export_user(u).await.unwrap().expect("account exists");
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
}
