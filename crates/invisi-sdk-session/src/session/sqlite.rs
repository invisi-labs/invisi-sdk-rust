//! Optional persistent ciphertext records. Financial JSON is encrypted by EncryptedWalletStore.
use super::{AtomicRecords, EncryptedRecord, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::{path::Path, sync::Mutex, time::Duration};

pub struct SQLiteRecords {
    connection: Mutex<Connection>,
}
impl SQLiteRecords {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(path) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        let connection = Connection::open(path).map_err(|e| e.to_string())?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        connection.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS invisi_wallet_records(scope TEXT PRIMARY KEY NOT NULL, revision INTEGER NOT NULL CHECK(revision > 0), ciphertext BLOB NOT NULL);").map_err(|e|e.to_string())?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }
}
impl AtomicRecords for SQLiteRecords {
    fn read(&self, scope: &str) -> Result<Option<EncryptedRecord>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "wallet database lock poisoned")?;
        connection
            .query_row(
                "SELECT revision,ciphertext FROM invisi_wallet_records WHERE scope=?1",
                params![scope],
                |row| {
                    let revision: i64 = row.get(0)?;
                    if revision <= 0 {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                    Ok(EncryptedRecord {
                        revision: revision as u64,
                        data: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(|e| e.to_string())
    }
    fn compare_and_swap(
        &self,
        scope: &str,
        expected_revision: u64,
        next: &EncryptedRecord,
    ) -> Result<bool> {
        if scope.is_empty()
            || next.revision
                != expected_revision
                    .checked_add(1)
                    .ok_or("wallet record revision overflow")?
        {
            return Err("invalid wallet record revision or scope".into());
        }
        let revision = i64::try_from(next.revision)
            .map_err(|_| "SQLite wallet record revision exceeds int64")?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| "wallet database lock poisoned")?;
        // An immediate transaction serializes CAS across connections and processes.
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let previous: Option<i64> = tx
            .query_row(
                "SELECT revision FROM invisi_wallet_records WHERE scope=?1",
                params![scope],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if previous.map_or(0, |v| v as u64) != expected_revision {
            return Ok(false);
        }
        tx.execute("INSERT INTO invisi_wallet_records(scope,revision,ciphertext) VALUES(?1,?2,?3) ON CONFLICT(scope) DO UPDATE SET revision=excluded.revision,ciphertext=excluded.ciphertext",params![scope,revision,&next.data]).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }
    fn persistent(&self) -> bool {
        true
    }
}
