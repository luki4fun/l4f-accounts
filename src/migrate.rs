//! Schema migrations, small enough to read in one go.
//!
//! The database is shared with YOURLS's own tables, so nothing here may assume
//! it owns the schema. Each app (or crate) passes a namespace and an append-only
//! list of single statements; the namespace's `<ns>_schema` row records how many
//! have run. One statement per step because MySQL commits DDL implicitly: a step
//! that fails half-way leaves the version at the last step that finished, and
//! `CREATE TABLE IF NOT EXISTS` makes rerunning it harmless.
//!
//! Not sqlx's `migrate!`: that adds a `_sqlx_migrations` table and checksums
//! every file, so editing a comment in a shipped migration would stop the boot.

use sqlx::{Connection, MySqlPool};

/// The crate's own schema, in order. Append only: a shipped step is never
/// edited or removed, or databases that already ran it drift from the code.
pub const ACCOUNTS: &[&str] = &[
    include_str!("../migrations/mysql/0001_users.sql"),
    include_str!("../migrations/mysql/0002_sessions.sql"),
    include_str!("../migrations/mysql/0003_roles.sql"),
    include_str!("../migrations/mysql/0004_role_scopes.sql"),
    include_str!("../migrations/mysql/0005_user_roles.sql"),
    include_str!("../migrations/mysql/0006_credentials.sql"),
    include_str!("../migrations/mysql/0007_recovery.sql"),
    include_str!("../migrations/mysql/0008_blobs.sql"),
    include_str!("../migrations/mysql/0009_profiles.sql"),
    include_str!("../migrations/mysql/0010_audit.sql"),
];

#[derive(Debug)]
pub enum MigrateError {
    BadNamespace,
    /// Another process held the migration lock for 30 seconds.
    Locked,
    /// The database ran steps this binary does not know: an older binary after a
    /// newer one. Booting would run old code against a schema it never saw.
    TooNew { database: i64, known: i64 },
    Db(sqlx::Error),
}

impl std::fmt::Display for MigrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadNamespace => write!(f, "migration namespace must be [a-z0-9_]+"),
            Self::Locked => write!(f, "another process is migrating this database"),
            Self::TooNew { database, known } => write!(
                f,
                "database schema is at step {database}, this binary only knows {known}: refusing to run older code against it"
            ),
            Self::Db(e) => write!(f, "migration failed: {e}"),
        }
    }
}

impl std::error::Error for MigrateError {}

impl From<sqlx::Error> for MigrateError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

/// Bring namespace `ns` up to `steps.len()`. Returns the version now in place.
///
/// Runs on a connection taken out of the pool for good: the pool caps every
/// statement at 10 seconds, which would also cut off DDL on a big table, and the
/// lock and the lifted cap must not leak into a connection a request reuses.
pub async fn run(pool: &MySqlPool, ns: &str, steps: &[&str]) -> Result<i64, MigrateError> {
    if ns.is_empty() || !ns.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
        return Err(MigrateError::BadNamespace);
    }
    let mut conn = pool.acquire().await?.detach();
    // MariaDB only; MySQL has no such variable and the default there is no cap.
    let _ = sqlx::query("SET SESSION max_statement_time = 0").execute(&mut conn).await;

    // Named per database: GET_LOCK names are server-wide, and a test database on
    // the same server must not wait for production's migration.
    let got: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(CONCAT(DATABASE(), '.l4f_migrate'), 30)")
        .fetch_one(&mut conn)
        .await?;
    if got != Some(1) {
        return Err(MigrateError::Locked);
    }
    let result = run_locked(&mut conn, ns, steps).await;
    let _ = sqlx::query("SELECT RELEASE_LOCK(CONCAT(DATABASE(), '.l4f_migrate'))").execute(&mut conn).await;
    let _ = conn.close().await;
    result
}

async fn run_locked(conn: &mut sqlx::MySqlConnection, ns: &str, steps: &[&str]) -> Result<i64, MigrateError> {
    let table = format!("{ns}_schema");
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE TABLE IF NOT EXISTS `{table}` (id TINYINT NOT NULL PRIMARY KEY, version BIGINT NOT NULL) \
         ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin"
    )))
    .execute(&mut *conn)
    .await?;
    sqlx::query(sqlx::AssertSqlSafe(format!("INSERT IGNORE INTO `{table}` (id, version) VALUES (1, 0)")))
        .execute(&mut *conn)
        .await?;
    let mut version: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT version FROM `{table}` WHERE id = 1")))
        .fetch_one(&mut *conn)
        .await?;
    let known = steps.len() as i64;
    if version > known {
        return Err(MigrateError::TooNew { database: version, known });
    }
    while version < known {
        let step = steps[version as usize];
        sqlx::raw_sql(sqlx::AssertSqlSafe(step)).execute(&mut *conn).await?;
        version += 1;
        sqlx::query(sqlx::AssertSqlSafe(format!("UPDATE `{table}` SET version = ? WHERE id = 1")))
            .bind(version)
            .execute(&mut *conn)
            .await?;
        tracing::info!(target: "accounts", ns, version, "schema step applied");
    }
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Store tests need a disposable MariaDB: `L4F_TEST_DATABASE_URL`, never the
    /// real one. Without it they pass vacuously, so a plain `cargo test` works.
    pub(crate) async fn test_pool() -> Option<MySqlPool> {
        let url = std::env::var("L4F_TEST_DATABASE_URL").ok()?;
        Some(MySqlPool::connect(&url).await.expect("L4F_TEST_DATABASE_URL does not connect"))
    }

    #[tokio::test]
    async fn runs_once_then_is_a_no_op_and_refuses_newer_schemas() {
        let Some(pool) = test_pool().await else { return };
        let ns = "t_migrate";
        sqlx::raw_sql("DROP TABLE IF EXISTS t_migrate_schema, t_migrate_a, t_migrate_b").execute(&pool).await.unwrap();
        let steps = ["CREATE TABLE IF NOT EXISTS t_migrate_a (x INT)", "CREATE TABLE IF NOT EXISTS t_migrate_b (y INT)"];
        assert_eq!(run(&pool, ns, &steps[..1]).await.unwrap(), 1);
        assert_eq!(run(&pool, ns, &steps).await.unwrap(), 2, "only the new step runs");
        assert_eq!(run(&pool, ns, &steps).await.unwrap(), 2, "idempotent");
        assert!(matches!(run(&pool, ns, &steps[..1]).await, Err(MigrateError::TooNew { database: 2, known: 1 })));
        assert!(matches!(run(&pool, "bad-ns", &steps).await, Err(MigrateError::BadNamespace)));
        sqlx::raw_sql("DROP TABLE t_migrate_schema, t_migrate_a, t_migrate_b").execute(&pool).await.unwrap();
    }

    #[tokio::test]
    async fn accounts_schema_applies_with_binary_collation() {
        let Some(pool) = test_pool().await else { return };
        run(&pool, "acct", ACCOUNTS).await.unwrap();
        let non_bin: Vec<(String, String)> = sqlx::query_as(
            "SELECT TABLE_NAME, TABLE_COLLATION FROM information_schema.TABLES
              WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE 'acct\\_%' AND TABLE_COLLATION NOT LIKE '%\\_bin'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(non_bin.is_empty(), "case-folding collation on {non_bin:?}");
    }
}
