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
/// Runs on the boot lock's connection, without the pool's statement caps (see
/// `lock`). SQLite must enforce foreign keys, or this refuses: deleting an
/// account or a role is one DELETE that relies on ON DELETE CASCADE, which
/// SQLite skips without a word when a pool turned them off.
pub async fn run(store: &Store) -> Result<(), MigrateError> {
    let mut held = lock(store).await?;
    let r = match held.conn() {
        #[cfg(feature = "mysql")]
        StoreConn::My(conn) => ours(sqlx::migrate!("migrations/mysql")).run(conn).await,
        #[cfg(feature = "postgres")]
        StoreConn::Pg(conn) => ours(sqlx::migrate!("migrations/postgres")).run(conn).await,
        #[cfg(feature = "sqlite")]
        StoreConn::Lite(conn) => match sqlx::query_scalar::<_, i64>("PRAGMA foreign_keys").fetch_one(&mut *conn).await {
            Ok(1) => ours(sqlx::migrate!("migrations/sqlite")).run(conn).await,
            Ok(_) => Err(MigrateError::Execute(sqlx::Error::Configuration(
                "SQLite foreign keys are off, and deleting an account or a role relies on ON DELETE CASCADE".into(),
            ))),
            Err(e) => Err(e.into()),
        },
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
    /// to the file. Always `Some`: an in-memory or temporary database, which
    /// had none, is refused (it would die with the lock's connection).
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
///
/// The connection leaves the pool for good, with the pool's statement caps
/// lifted before the wait: a cap would cut off the wait and the DDL under the
/// lock (a migration, a host's own tables), and the lifted caps must not leak
/// into a connection a request reuses.
pub async fn lock(store: &Store) -> sqlx::Result<BootLock> {
    match store {
        #[cfg(feature = "mysql")]
        Store::My(s) => {
            let mut conn = s.0.acquire().await?.detach();
            // MariaDB only; MySQL has no such variable and the default there is no cap.
            let _ = sqlx::query("SET SESSION max_statement_time = 0").execute(&mut conn).await;
            // An ALTER waiting on a metadata lock blocks every later query on its table;
            // the server default lets that last a year.
            let _ = sqlx::query("SET SESSION lock_wait_timeout = 60").execute(&mut conn).await;
            loop {
                let got: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(CONCAT(DATABASE(), '.l4f_boot'), 30)")
                    .fetch_one(&mut conn)
                    .await?;
                match got {
                    Some(1) => return Ok(BootLock::My(conn)),
                    Some(_) => tracing::warn!(target: "accounts", "another process holds the boot lock; still waiting"),
                    // Not a wait: MariaDB answers a NULL name (no database
                    // selected) with NULL at once, and looping would spin.
                    None => {
                        return Err(sqlx::Error::Configuration(
                            "the boot lock's GET_LOCK answered NULL: no database selected (none in the URL?)".into(),
                        ));
                    }
                }
            }
        }
        #[cfg(feature = "postgres")]
        Store::Pg(s) => {
            let mut conn = s.0.acquire().await?.detach();
            sqlx::query("SET statement_timeout = 0").execute(&mut conn).await?;
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
            // SQLite's own answer, whatever the URL or options said: the full
            // path, or "" for an in-memory or temporary database.
            let path: String = sqlx::query_scalar("SELECT file FROM pragma_database_list WHERE name = 'main'").fetch_one(&s.0).await?;
            if path.is_empty() {
                return Err(sqlx::Error::Configuration(
                    "in-memory and temporary SQLite databases are not supported: the boot lock takes a connection \
                     out of the pool for good, and such a database dies with it"
                        .into(),
                ));
            }
            let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(format!("{path}.lock"))?;
            // Polled, not a blocking wait: a caller that gives up (a timeout)
            // leaves no thread behind to take the lock later.
            let mut waited = 0u32;
            loop {
                match f.try_lock() {
                    Ok(()) => break,
                    Err(std::fs::TryLockError::WouldBlock) => {}
                    Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
                }
                waited += 1;
                if waited.is_multiple_of(30) {
                    tracing::warn!(target: "accounts", "another process holds the boot lock; still waiting");
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            let conn = s.0.acquire().await?.detach();
            Ok(BootLock::Lite(conn, Some(f)))
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

    /// A pool that caps every statement, as the l4f host's does: the lock's
    /// connection runs without the cap, the wait included, and the pool
    /// keeps it.
    #[tokio::test]
    async fn the_boot_lock_lifts_the_pools_statement_cap() {
        let Some(store) = shared().await else { return };
        match store {
            #[cfg(feature = "mysql")]
            Store::My(_) => {
                let pool = sqlx::mysql::MySqlPoolOptions::new()
                    .after_connect(|c, _| Box::pin(async move { sqlx::query("SET SESSION max_statement_time = 10").execute(c).await.map(|_| ()) }))
                    .connect(&std::env::var("L4F_TEST_DATABASE_URL").unwrap())
                    .await
                    .unwrap();
                let cap = "SELECT CAST(@@max_statement_time AS SIGNED)";
                let mut held = lock(&Store::from(pool.clone())).await.unwrap();
                let lifted: i64 = match held.conn() {
                    StoreConn::My(c) => sqlx::query_scalar(cap).fetch_one(c).await.unwrap(),
                    #[allow(unreachable_patterns)]
                    _ => unreachable!(),
                };
                unlock(held).await;
                assert_eq!(lifted, 0);
                assert_eq!(sqlx::query_scalar::<_, i64>(cap).fetch_one(&pool).await.unwrap(), 10, "the pool keeps its cap");
                pool.close().await;
            }
            #[cfg(feature = "postgres")]
            Store::Pg(_) => {
                let opts: sqlx::postgres::PgConnectOptions = std::env::var("L4F_TEST_DATABASE_URL").unwrap().parse().unwrap();
                let pool = sqlx::PgPool::connect_with(opts.options([("statement_timeout", "10s")])).await.unwrap();
                let cap = "SELECT current_setting('statement_timeout')";
                let mut held = lock(&Store::from(pool.clone())).await.unwrap();
                let lifted: String = match held.conn() {
                    StoreConn::Pg(c) => sqlx::query_scalar(cap).fetch_one(c).await.unwrap(),
                    #[allow(unreachable_patterns)]
                    _ => unreachable!(),
                };
                unlock(held).await;
                assert_eq!(lifted, "0");
                assert_eq!(sqlx::query_scalar::<_, String>(cap).fetch_one(&pool).await.unwrap(), "10s", "the pool keeps its cap");
                pool.close().await;
            }
            // SQLite has no statement cap to lift.
            #[allow(unreachable_patterns)]
            _ => {}
        }
    }

    /// Without a database in the URL, MariaDB answers GET_LOCK with NULL at
    /// once: an error, not a wait that spins.
    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn mysql_boot_lock_without_a_database_is_an_error() {
        let Some(Store::My(_)) = shared().await else { return };
        let url = std::env::var("L4F_TEST_DATABASE_URL").unwrap();
        let (server, _db) = url.split('?').next().unwrap().rsplit_once('/').unwrap();
        let store = Store::connect(server).await.unwrap();
        let r = tokio::time::timeout(std::time::Duration::from_secs(5), lock(&store)).await.expect("an answer, not a wait");
        let Err(e) = r else { panic!("a lock without a database") };
        assert!(matches!(e, sqlx::Error::Configuration(_)), "{e}");
        store.close().await;
    }

    /// What SQLite cannot keep: an in-memory or temporary database dies with
    /// the lock's connection, and with foreign keys off a deletion leaves the
    /// account's rows behind.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_without_a_file_or_foreign_keys_is_refused() {
        for url in ["sqlite::memory:", "sqlite://?mode=memory", "sqlite://"] {
            let store = Store::connect(url).await.unwrap();
            let e = run(&store).await.unwrap_err();
            assert!(e.to_string().contains("in-memory and temporary"), "{url}: {e}");
            store.close().await;
        }
        let path = std::env::temp_dir().join(format!("l4f_fk_{}.db", hex::encode(crate::util::random::<6>())));
        let opts = sqlx::sqlite::SqliteConnectOptions::new().filename(&path).create_if_missing(true).foreign_keys(false);
        let store = Store::from(sqlx::SqlitePool::connect_with(opts).await.unwrap());
        let e = run(&store).await.unwrap_err();
        assert!(e.to_string().contains("foreign keys are off"), "{e}");
        store.close().await;
        for suffix in ["", "-wal", "-shm", ".lock"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
