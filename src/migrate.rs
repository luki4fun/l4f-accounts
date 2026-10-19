//! Schema migrations: every `migrations/<backend>/<version>_<desc>.sql`, embedded
//! at compile time by sqlx, one set per backend (`mysql`, `postgres`, `sqlite`)
//! with the same versions. Append only: add the next-numbered file to every
//! set. A shipped file is never edited, renumbered or removed; sqlx checksums
//! each one and refuses to boot on a mismatch.
//!
//! The database is shared with YOURLS's own tables, so the bookkeeping table is
//! `acct_migrations`, not sqlx's `_sqlx_migrations`. MySQL commits DDL
//! implicitly: a step that fails half-way is left marked dirty and the next boot
//! refuses until someone repairs it by hand. Keep one DDL statement per file.

use sqlx::migrate::{MigrateError, Migrator};
#[cfg(any(feature = "mysql", feature = "postgres"))]
use sqlx::Connection;

use crate::store::{Store, StoreConn};

/// Bring the schema up to date. Concurrent boots wait on the boot lock. An
/// older binary against a newer schema fails with `VersionMissing`.
///
/// Runs on a connection taken out of the pool for good: the pool may cap every
/// statement, which would also cut off DDL on a big table, and the lifted caps
/// must not leak into a connection a request reuses.
pub async fn run(store: &Store) -> Result<(), MigrateError> {
    let mut held = lock(store).await?;
    let r = match held.conn() {
        #[cfg(feature = "mysql")]
        StoreConn::My(conn) => {
            // MariaDB only; MySQL has no such variable and the default there is no cap.
            let _ = sqlx::query("SET SESSION max_statement_time = 0").execute(&mut *conn).await;
            // An ALTER waiting on a metadata lock blocks every later query on its table;
            // the server default lets that last a year.
            let _ = sqlx::query("SET SESSION lock_wait_timeout = 60").execute(&mut *conn).await;
            ours(sqlx::migrate!("migrations/mysql")).run(conn).await
        }
        #[cfg(feature = "postgres")]
        StoreConn::Pg(conn) => ours(sqlx::migrate!("migrations/postgres")).run(conn).await,
        #[cfg(feature = "sqlite")]
        StoreConn::Lite(conn) => ours(sqlx::migrate!("migrations/sqlite")).run(conn).await,
    };
    unlock(held).await;
    r
}

/// Our table name, and our own lock instead of sqlx's: its MySQL one is
/// `GET_LOCK(name, -1)` with the result ignored, and MariaDB answers a negative
/// timeout with NULL at once, so it locks nothing there.
fn ours(mut m: Migrator) -> Migrator {
    m.dangerous_set_table_name("acct_migrations");
    m.set_locking(false);
    m
}

/// The boot lock, held while it lives: migrations, and other steps two
/// processes starting at once must not interleave (the bootstrap admin, a
/// host's own tables). `conn` is a connection out of the pool for good, so on
/// MySQL and Postgres the lock dies with it whatever happens.
pub enum BootLock {
    #[cfg(feature = "mysql")]
    My(sqlx::MySqlConnection),
    #[cfg(feature = "postgres")]
    Pg(sqlx::PgConnection),
    /// SQLite has no named locks: an exclusive lock on `<database>.lock` next
    /// to the file (none for an in-memory database, which one process owns).
    #[cfg(feature = "sqlite")]
    Lite(sqlx::SqliteConnection, Option<std::fs::File>),
}

impl BootLock {
    /// For a host's own migrations while the lock is held.
    pub fn conn(&mut self) -> StoreConn<'_> {
        match self {
            #[cfg(feature = "mysql")]
            BootLock::My(c) => StoreConn::My(c),
            #[cfg(feature = "postgres")]
            BootLock::Pg(c) => StoreConn::Pg(c),
            #[cfg(feature = "sqlite")]
            BootLock::Lite(c, _) => StoreConn::Lite(c),
        }
    }
}

/// The Postgres advisory lock key ("l4f_boot"); Postgres scopes it per database.
#[cfg(feature = "postgres")]
const PG_BOOT_KEY: i64 = 0x6c34_665f_626f_6f74;

/// Waits as long as the holder needs: a long migration on another instance is
/// not an error. Named per database: GET_LOCK names are server-wide, and a test
/// database on the same server must not wait for production's boot.
pub async fn lock(store: &Store) -> sqlx::Result<BootLock> {
    match store {
        #[cfg(feature = "mysql")]
        Store::My(s) => {
            let mut conn = s.0.acquire().await?.detach();
            loop {
                let got: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(CONCAT(DATABASE(), '.l4f_boot'), 30)")
                    .fetch_one(&mut conn)
                    .await?;
                if got == Some(1) {
                    return Ok(BootLock::My(conn));
                }
                tracing::warn!(target: "accounts", "another process holds the boot lock; still waiting");
            }
        }
        #[cfg(feature = "postgres")]
        Store::Pg(s) => {
            let mut conn = s.0.acquire().await?.detach();
            let mut waited = 0u32;
            loop {
                let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)").bind(PG_BOOT_KEY).fetch_one(&mut conn).await?;
                if got {
                    return Ok(BootLock::Pg(conn));
                }
                waited += 1;
                if waited.is_multiple_of(30) {
                    tracing::warn!(target: "accounts", "another process holds the boot lock; still waiting");
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
        #[cfg(feature = "sqlite")]
        Store::Lite(s) => {
            let path = s.0.connect_options().get_filename().to_path_buf();
            let file = if path.as_os_str().is_empty() || path.to_string_lossy().starts_with("file:") || path.as_os_str() == ":memory:" {
                None
            } else {
                let mut lock_path = path.into_os_string();
                lock_path.push(".lock");
                let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&lock_path)?;
                let f = tokio::task::spawn_blocking(move || f.lock().map(|()| f))
                    .await
                    .map_err(|e| sqlx::Error::Io(std::io::Error::other(e)))??;
                Some(f)
            };
            let conn = s.0.acquire().await?.detach();
            Ok(BootLock::Lite(conn, file))
        }
    }
}

pub async fn unlock(held: BootLock) {
    match held {
        #[cfg(feature = "mysql")]
        BootLock::My(mut conn) => {
            let _ = sqlx::query("SELECT RELEASE_LOCK(CONCAT(DATABASE(), '.l4f_boot'))").execute(&mut conn).await;
            let _ = conn.close().await;
        }
        #[cfg(feature = "postgres")]
        BootLock::Pg(mut conn) => {
            let _ = sqlx::query("SELECT pg_advisory_unlock($1)").bind(PG_BOOT_KEY).execute(&mut conn).await;
            let _ = conn.close().await;
        }
        #[cfg(feature = "sqlite")]
        BootLock::Lite(conn, file) => {
            use sqlx::Connection;
            let _ = conn.close().await;
            // Closing the file releases the lock; unlock first all the same.
            if let Some(f) = file {
                let _ = f.unlock();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::{scalar, shared};

    #[tokio::test]
    async fn schema_applies_once() {
        let Some(store) = shared().await else { return };
        run(&store).await.unwrap();
        run(&store).await.unwrap();
        let versions = scalar(&store, "SELECT COUNT(*) FROM acct_migrations WHERE success", vec![]).await;
        assert!(versions >= 10, "every migration recorded once, got {versions}");
    }

    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn mysql_tables_use_a_binary_collation() {
        let Some(Store::My(s)) = shared().await else { return };
        let non_bin: Vec<(String, String)> = sqlx::query_as(
            "SELECT TABLE_NAME, TABLE_COLLATION FROM information_schema.TABLES
              WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE 'acct\\_%' AND TABLE_COLLATION NOT LIKE '%\\_bin'
                AND TABLE_NAME <> 'acct_migrations'",
        )
        .fetch_all(&s.0)
        .await
        .unwrap();
        assert!(non_bin.is_empty(), "case-folding collation on {non_bin:?}");
    }

    #[tokio::test]
    async fn boot_lock_is_exclusive() {
        let Some(store) = shared().await else { return };
        let held = lock(&store).await.unwrap();
        let second = tokio::time::timeout(std::time::Duration::from_millis(1500), lock(&store)).await;
        assert!(second.is_err(), "a second process must not get the lock while it is held");
        unlock(held).await;
        let again = tokio::time::timeout(std::time::Duration::from_secs(5), lock(&store)).await;
        unlock(again.expect("free again after unlock").unwrap()).await;
    }
}
