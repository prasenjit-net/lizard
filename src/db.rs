//! The SQLite-backed store for ACME state (accounts, orders,
//! authorizations, challenges, certificates). Nonces are deliberately not
//! here — see `crate::acme::nonce` (added in a later milestone) — losing
//! them on restart is harmless, so they stay in memory.
#![allow(dead_code)]

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::Connection;

use crate::error::AppResult;

const SCHEMA: &str = include_str!("schema.sql");

/// A single connection behind a mutex — SQLite serializes writes anyway,
/// and this app's request volume doesn't warrant a connection pool.
pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    /// Opens (creating if needed) the database at `path` and applies the
    /// schema. `CREATE TABLE IF NOT EXISTS` makes this idempotent, so it's
    /// safe to call on every startup.
    pub fn open(path: &Path) -> AppResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    /// Locks the connection for a query or transaction. The lock is only
    /// ever held for the duration of one call site's queries, so a
    /// poisoned-mutex panic here means an earlier query already panicked —
    /// propagating that panic is correct, not something to paper over.
    pub fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn open_test_db(dir: &TempDir) -> Db {
        Db::open(&dir.path().join("lizard.db")).unwrap()
    }

    #[test]
    fn creates_the_database_file_and_all_tables() {
        let dir = TempDir::new().unwrap();
        let db = open_test_db(&dir);

        assert!(dir.path().join("lizard.db").exists());

        let conn = db.conn();
        for table in [
            "accounts",
            "orders",
            "authorizations",
            "challenges",
            "certificates",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "missing table {table}");
        }
    }

    #[test]
    fn reopening_an_existing_database_does_not_lose_data() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("lizard.db");

        {
            let db = Db::open(&path).unwrap();
            db.conn()
                .execute(
                    "INSERT INTO accounts (id, jwk_thumbprint, jwk_json, status, created_at) \
                     VALUES ('acct-1', 'thumb-1', '{}', 'valid', '2026-01-01T00:00:00Z')",
                    [],
                )
                .unwrap();
        }

        let db = Db::open(&path).unwrap();
        let count: i64 = db
            .conn()
            .query_row("SELECT count(*) FROM accounts", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn a_full_order_lifecycle_round_trips_through_every_table() {
        let dir = TempDir::new().unwrap();
        let db = open_test_db(&dir);
        let conn = db.conn();

        conn.execute(
            "INSERT INTO accounts (id, jwk_thumbprint, jwk_json, status, created_at) \
             VALUES ('acct-1', 'thumb-1', '{}', 'valid', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO orders \
             (id, account_id, status, identifiers_json, expires, created_at) \
             VALUES ('order-1', 'acct-1', 'pending', '[]', '2026-01-02T00:00:00Z', \
                     '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO authorizations \
             (id, order_id, identifier_type, identifier_value, status, expires) \
             VALUES ('authz-1', 'order-1', 'dns', 'service.internal.example', 'pending', \
                     '2026-01-02T00:00:00Z')",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO challenges (id, authorization_id, type, token, status) \
             VALUES ('chal-1', 'authz-1', 'http-01', 'tok-1', 'pending')",
            [],
        )
        .unwrap();

        // A certificate can only reference an order that already exists,
        // and only afterward does the order get pointed back at it.
        conn.execute(
            "INSERT INTO certificates (id, order_id, serial, pem_chain, issued_at) \
             VALUES ('cert-1', 'order-1', 'aa:bb:cc', 'PEM', '2026-01-01T01:00:00Z')",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE orders SET status = 'valid', certificate_id = 'cert-1' WHERE id = 'order-1'",
            [],
        )
        .unwrap();

        let (status, certificate_id): (String, Option<String>) = conn
            .query_row(
                "SELECT status, certificate_id FROM orders WHERE id = 'order-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(status, "valid");
        assert_eq!(certificate_id.as_deref(), Some("cert-1"));
    }

    #[test]
    fn duplicate_jwk_thumbprint_is_rejected() {
        let dir = TempDir::new().unwrap();
        let db = open_test_db(&dir);
        let conn = db.conn();

        let insert = "INSERT INTO accounts (id, jwk_thumbprint, jwk_json, status, created_at) \
                      VALUES (?1, 'same-thumbprint', '{}', 'valid', '2026-01-01T00:00:00Z')";
        conn.execute(insert, ["acct-1"]).unwrap();

        let err = conn.execute(insert, ["acct-2"]).unwrap_err();
        assert!(matches!(
            err,
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error {
                    code: rusqlite::ErrorCode::ConstraintViolation,
                    ..
                },
                _
            )
        ));
    }

    #[test]
    fn foreign_keys_are_enforced() {
        let dir = TempDir::new().unwrap();
        let db = open_test_db(&dir);

        let err = db
            .conn()
            .execute(
                "INSERT INTO orders \
                 (id, account_id, status, identifiers_json, expires, created_at) \
                 VALUES ('order-1', 'no-such-account', 'pending', '[]', \
                         '2026-01-02T00:00:00Z', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap_err();
        assert!(matches!(
            err,
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error {
                    code: rusqlite::ErrorCode::ConstraintViolation,
                    ..
                },
                _
            )
        ));
    }
}
