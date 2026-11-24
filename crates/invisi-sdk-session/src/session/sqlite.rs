//! Optional persistent ciphertext records. Financial JSON is encrypted by EncryptedWalletStore.
use super::{AtomicRecords, EncryptedRecord, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::{path::Path, sync::Mutex, time::Duration};

pub struct SQLiteRecords {
    connection: Mutex<Connection>,
    mutation_identity: usize,
    table: &'static str,
}
impl SQLiteRecords {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_table(path, "invisi_wallet_records")
    }
    pub fn open_public(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_table(path, "invisi_public_history_records")
    }
    fn open_table(path: impl AsRef<Path>, table: &'static str) -> Result<Self> {
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
        connection.execute_batch(&format!("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS {table}(scope TEXT PRIMARY KEY NOT NULL, revision INTEGER NOT NULL CHECK(revision > 0), ciphertext BLOB NOT NULL);")).map_err(|e|e.to_string())?;
        // Independent connections to the same database/table represent one wallet store.
        use std::hash::{DefaultHasher, Hash, Hasher};
        let mut identity = DefaultHasher::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let file = path.metadata().map_err(|e| e.to_string())?;
            (file.dev(), file.ino()).hash(&mut identity);
        }
        #[cfg(not(unix))]
        path.canonicalize()
            .map_err(|e| e.to_string())?
            .hash(&mut identity);
        table.hash(&mut identity);
        Ok(Self {
            connection: Mutex::new(connection),
            mutation_identity: identity.finish() as usize,
            table,
        })
    }
}
impl AtomicRecords for SQLiteRecords {
    fn mutation_identity(&self) -> usize {
        self.mutation_identity
    }
    fn read(&self, scope: &str) -> Result<Option<EncryptedRecord>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "wallet database lock poisoned")?;
        connection
            .query_row(
                &format!(
                    "SELECT revision,ciphertext FROM {} WHERE scope=?1",
                    self.table
                ),
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
                &format!("SELECT revision FROM {} WHERE scope=?1", self.table),
                params![scope],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if previous.map_or(0, |v| v as u64) != expected_revision {
            return Ok(false);
        }
        tx.execute(&format!("INSERT INTO {}(scope,revision,ciphertext) VALUES(?1,?2,?3) ON CONFLICT(scope) DO UPDATE SET revision=excluded.revision,ciphertext=excluded.ciphertext",self.table),params![scope,revision,&next.data]).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }
    fn supports_batches(&self) -> bool {
        true
    }
    fn compare_and_swap_batch(
        &self,
        scope: &str,
        expected: u64,
        next: &EncryptedRecord,
        writes: &[(String, Option<EncryptedRecord>)],
    ) -> Result<bool> {
        super::store::validate_batch(scope, expected, next, writes)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| "wallet database lock poisoned")?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let previous: Option<i64> = tx
            .query_row(
                &format!("SELECT revision FROM {} WHERE scope=?1", self.table),
                params![scope],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if previous.map_or(0, |n| n as u64) != expected {
            return Ok(false);
        }
        let insert=format!("INSERT INTO {}(scope,revision,ciphertext) VALUES(?1,?2,?3) ON CONFLICT(scope) DO UPDATE SET revision=excluded.revision,ciphertext=excluded.ciphertext",self.table);
        for (key, value) in writes {
            if let Some(value) = value {
                let revision =
                    i64::try_from(value.revision).map_err(|_| "SQLite record revision overflow")?;
                tx.execute(&insert, params![key, revision, &value.data])
                    .map_err(|e| e.to_string())?;
            } else {
                tx.execute(
                    &format!("DELETE FROM {} WHERE scope=?1", self.table),
                    params![key],
                )
                .map_err(|e| e.to_string())?;
            }
        }
        let revision =
            i64::try_from(next.revision).map_err(|_| "SQLite record revision overflow")?;
        tx.execute(&insert, params![scope, revision, &next.data])
            .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }
    fn count(&self, prefix: &str) -> Result<u64> {
        super::store::validate_page(prefix, None, 1)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| "wallet database lock poisoned")?;
        connection
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM {} WHERE scope>=?1 AND scope<?2",
                    self.table
                ),
                params![prefix, format!("{prefix}{}", char::MAX)],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|e| e.to_string())
            .and_then(|n| u64::try_from(n).map_err(|_| "invalid record count".into()))
    }
    fn list(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(String, EncryptedRecord)>> {
        super::store::validate_page(prefix, after, limit)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| "wallet database lock poisoned")?;
        let mut statement=connection.prepare(&format!("SELECT scope,revision,ciphertext FROM {} WHERE scope>=?1 AND scope<?2 AND scope>?3 ORDER BY scope LIMIT ?4",self.table)).map_err(|e|e.to_string())?;
        let upper = format!("{prefix}{}", char::MAX);
        let rows = statement
            .query_map(
                params![prefix, upper, after.unwrap_or(""), limit as i64],
                |row| {
                    let revision: i64 = row.get(1)?;
                    if revision <= 0 {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                    Ok((
                        row.get(0)?,
                        EncryptedRecord {
                            revision: revision as u64,
                            data: row.get(2)?,
                        },
                    ))
                },
            )
            .map_err(|e| e.to_string())?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }
    fn persistent(&self) -> bool {
        true
    }
}
