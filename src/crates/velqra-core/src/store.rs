// SPDX-License-Identifier: GPL-3.0-only
//! Durable record store. `MemStore` for simulation, `SqliteStore` for the product.

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use thiserror::Error;
use velqra_protocol::TaskState;

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum StoreError {
    #[error("storage error: {0}")]
    Io(String),
    #[error("record already exists")]
    Conflict,
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Io(e.to_string())
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        StoreError::Io(e.to_string())
    }
}

/// What the engine needs to reconstruct a download after a restart (no secrets here).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRequest {
    pub download_key: String,
    pub url: String,
    pub filename: String,
}

impl std::fmt::Debug for StoredRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoredRequest { <redacted> }")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub task_id: u64,
    pub request_id: String,
    pub generation: u32,
    pub fingerprint: String,
    pub state: TaskState,
    pub history: Vec<TaskState>,
    pub dispatch_attempt: Option<String>,
    pub aborted_at: Option<u64>,
    /// The accepted request, kept so a restarted core can still run the task.
    #[serde(default)]
    pub request: Option<StoredRequest>,
    /// Reference to the protected context (cookies, headers) in the secret vault.
    #[serde(default)]
    pub context_ref: Option<String>,
    /// Why a task failed or was held (never contains secrets).
    #[serde(default)]
    pub fail_reason: Option<String>,
    /// A tombstone whose payload was dropped after retention; it still fences the request id.
    #[serde(default)]
    pub compacted: bool,
}

impl Record {
    pub fn new(
        task_id: u64,
        request_id: &str,
        generation: u32,
        fingerprint: &str,
        state: TaskState,
    ) -> Self {
        Self {
            task_id,
            request_id: request_id.to_string(),
            generation,
            fingerprint: fingerprint.to_string(),
            state,
            history: vec![state],
            dispatch_attempt: None,
            aborted_at: None,
            request: None,
            context_ref: None,
            fail_reason: None,
            compacted: false,
        }
    }
}

pub trait Store {
    fn get_by_request(&self, request_id: &str) -> Result<Option<Record>, StoreError>;
    fn get_by_task(&self, task_id: u64) -> Result<Option<Record>, StoreError>;
    /// Atomic upsert of an EXISTING task. On error nothing is written.
    fn put(&mut self, record: &Record) -> Result<(), StoreError>;
    /// Atomic insert of a NEW task: fails with `Conflict` (writing nothing) if the task id or
    /// request id already exists, so two writers can never overwrite each other.
    fn insert(&mut self, record: &Record) -> Result<(), StoreError>;
    /// Monotonic: never reuses an id, even after `remove`.
    fn next_task_id(&self) -> Result<u64, StoreError>;
    fn all(&self) -> Result<Vec<Record>, StoreError>;
    fn remove(&mut self, task_id: u64) -> Result<(), StoreError>;
}

#[derive(Default, Clone)]
pub struct MemStore {
    map: BTreeMap<u64, Record>,
    next: u64,
    /// Number of upcoming `put` calls that fail without writing.
    pub fail_puts: usize,
}

impl Store for MemStore {
    fn get_by_request(&self, request_id: &str) -> Result<Option<Record>, StoreError> {
        Ok(self
            .map
            .values()
            .find(|r| r.request_id == request_id)
            .cloned())
    }
    fn get_by_task(&self, task_id: u64) -> Result<Option<Record>, StoreError> {
        Ok(self.map.get(&task_id).cloned())
    }
    fn put(&mut self, record: &Record) -> Result<(), StoreError> {
        if self.fail_puts > 0 {
            self.fail_puts -= 1;
            return Err(StoreError::Io("injected put failure".into()));
        }
        self.next = self.next.max(record.task_id + 1);
        self.map.insert(record.task_id, record.clone());
        Ok(())
    }
    fn insert(&mut self, record: &Record) -> Result<(), StoreError> {
        if self.map.contains_key(&record.task_id)
            || self.map.values().any(|r| r.request_id == record.request_id)
        {
            return Err(StoreError::Conflict);
        }
        self.put(record)
    }
    fn next_task_id(&self) -> Result<u64, StoreError> {
        Ok(self.next.max(1))
    }
    fn all(&self) -> Result<Vec<Record>, StoreError> {
        Ok(self.map.values().cloned().collect())
    }
    fn remove(&mut self, task_id: u64) -> Result<(), StoreError> {
        self.map.remove(&task_id);
        Ok(())
    }
}

pub struct SqliteStore {
    conn: Connection,
}

impl SqliteStore {
    /// Opens (creating if needed) a database with WAL and `synchronous=FULL`.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.pragma_update_and_check(None, "journal_mode", "WAL", |_row| Ok(()))?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS records(
                task_id INTEGER PRIMARY KEY,
                request_id TEXT NOT NULL UNIQUE,
                json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS meta(
                id INTEGER PRIMARY KEY CHECK(id = 1),
                next INTEGER NOT NULL);
             INSERT OR IGNORE INTO meta(id, next) VALUES(1, 1);",
        )?;
        Ok(Self { conn })
    }

    fn decode(json: String) -> Result<Record, StoreError> {
        Ok(serde_json::from_str(&json)?)
    }
}

impl Store for SqliteStore {
    fn get_by_request(&self, request_id: &str) -> Result<Option<Record>, StoreError> {
        let json: Option<String> = self
            .conn
            .query_row(
                "SELECT json FROM records WHERE request_id = ?1",
                [request_id],
                |r| r.get(0),
            )
            .optional()?;
        json.map(Self::decode).transpose()
    }
    fn get_by_task(&self, task_id: u64) -> Result<Option<Record>, StoreError> {
        let json: Option<String> = self
            .conn
            .query_row(
                "SELECT json FROM records WHERE task_id = ?1",
                [task_id as i64],
                |r| r.get(0),
            )
            .optional()?;
        json.map(Self::decode).transpose()
    }
    fn put(&mut self, record: &Record) -> Result<(), StoreError> {
        let json = serde_json::to_string(record)?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT OR REPLACE INTO records(task_id, request_id, json) VALUES(?1, ?2, ?3)",
            params![record.task_id as i64, record.request_id, json],
        )?;
        tx.execute(
            "UPDATE meta SET next = MAX(next, ?1) WHERE id = 1",
            params![record.task_id as i64 + 1],
        )?;
        tx.commit()?;
        Ok(())
    }
    fn insert(&mut self, record: &Record) -> Result<(), StoreError> {
        let json = serde_json::to_string(record)?;
        let tx = self.conn.transaction()?;
        match tx.execute(
            "INSERT INTO records(task_id, request_id, json) VALUES(?1, ?2, ?3)",
            params![record.task_id as i64, record.request_id, json],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err(StoreError::Conflict)
            }
            Err(e) => return Err(e.into()),
        }
        tx.execute(
            "UPDATE meta SET next = MAX(next, ?1) WHERE id = 1",
            params![record.task_id as i64 + 1],
        )?;
        tx.commit()?;
        Ok(())
    }
    fn next_task_id(&self) -> Result<u64, StoreError> {
        let next: i64 = self
            .conn
            .query_row("SELECT next FROM meta WHERE id = 1", [], |r| r.get(0))?;
        Ok(next as u64)
    }
    fn all(&self) -> Result<Vec<Record>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT json FROM records ORDER BY task_id")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(Self::decode(row?)?);
        }
        Ok(out)
    }
    fn remove(&mut self, task_id: u64) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM records WHERE task_id = ?1", [task_id as i64])?;
        Ok(())
    }
}
