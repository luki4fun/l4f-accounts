//! Schema migrations: every `migrations/mysql/<version>_<desc>.sql`, embedded at
//! compile time by sqlx. Append only: add the next-numbered file. A shipped file
//! is never edited, renumbered or removed; sqlx checksums each one and refuses
//! to boot on a mismatch.
//!
//! The database is shared with YOURLS's own tables, so the bookkeeping table is
//! `acct_migrations`, not sqlx's `_sqlx_migrations`. MySQL commits DDL
//! implicitly: a step that fails half-way is left marked dirty and the next boot
//! refuses until someone repairs it by hand. Keep one DDL statement per file.

use sqlx::{Connection, MySqlConnection, MySqlPool, migrate::MigrateError};

/// Bring the schema up to date. Concurrent boots wait on the boot lock. An
/// older binary against a newer schema fails with `VersionMissing`.
///
/// Runs on a connection taken out of the pool for good: the pool may cap every
/// statement, which would also cut off DDL on a big table, and the lifted caps
/// must not leak into a connection a request reuses.
pub async fn run(pool: &MySqlPool) -> Result<(), MigrateError> {
    let mut m = sqlx::migrate!("migrations/mysql");
    m.dangerous_set_table_name("acct_migrations");
    // sqlx's own lock is `GET_LOCK(name, -1)` with the result ignored; MariaDB
    // answers a negative timeout with NULL at once, so it locks nothing there.
    m.set_locking(false);
    let mut conn = lock(pool).await?;
    // MariaDB only; MySQL has no such variable and the default there is no cap.
    let _ = sqlx::query("SET SESSION max_statement_time = 0").execute(&mut conn).await;
    // An ALTER waiting on a metadata lock blocks every later query on its table;
    // the server default lets that last a year.
    let _ = sqlx::query("SET SESSION lock_wait_timeout = 60").execute(&mut conn).await;
    let r = m.run(&mut conn).await;
    unlock(conn).await;
    r
}

/// The boot lock: migrations, and other steps two processes starting at once
/// must not interleave (the bootstrap admin). On a connection out of the pool
/// for good, so the lock dies with it whatever happens. Waits as long as the
/// holder needs: a long migration on another instance is not an error. Named
/// per database: GET_LOCK names are server-wide, and a test database on the
/// same server must not wait for production's boot.
pub(crate) async fn lock(pool: &MySqlPool) -> sqlx::Result<MySqlConnection> {
    let mut conn = pool.acquire().await?.detach();
    loop {
        let got: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(CONCAT(DATABASE(), '.l4f_boot'), 30)")
            .fetch_one(&mut conn)
            .await?;
        if got == Some(1) {
            return Ok(conn);
        }
        tracing::warn!(target: "accounts", "another process holds the boot lock; still waiting");
    }
}

pub(crate) async fn unlock(mut conn: MySqlConnection) {
    let _ = sqlx::query("SELECT RELEASE_LOCK(CONCAT(DATABASE(), '.l4f_boot'))").execute(&mut conn).await;
    let _ = conn.close().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Store tests need a disposable MariaDB: `L4F_TEST_DATABASE_URL`, never the
    /// real one. Without it they pass vacuously, so a plain `cargo test` works.
    async fn test_pool() -> Option<MySqlPool> {
        let url = std::env::var("L4F_TEST_DATABASE_URL").ok()?;
        Some(MySqlPool::connect(&url).await.expect("L4F_TEST_DATABASE_URL does not connect"))
    }

    #[tokio::test]
    async fn schema_applies_once_with_binary_collation() {
        let Some(pool) = test_pool().await else { return };
        run(&pool).await.unwrap();
        run(&pool).await.unwrap();
        let non_bin: Vec<(String, String)> = sqlx::query_as(
            "SELECT TABLE_NAME, TABLE_COLLATION FROM information_schema.TABLES
              WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE 'acct\\_%' AND TABLE_COLLATION NOT LIKE '%\\_bin'
                AND TABLE_NAME <> 'acct_migrations'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(non_bin.is_empty(), "case-folding collation on {non_bin:?}");
    }

    #[tokio::test]
    async fn boot_lock_is_exclusive() {
        let Some(pool) = test_pool().await else { return };
        let held = lock(&pool).await.unwrap();
        let mut other = pool.acquire().await.unwrap();
        let got: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(CONCAT(DATABASE(), '.l4f_boot'), 0)")
            .fetch_one(&mut *other)
            .await
            .unwrap();
        assert_eq!(got, Some(0), "a second process must not get the lock");
        unlock(held).await;
    }
}
