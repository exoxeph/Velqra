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

/// What the engine needs to reconstruct a download after a restart. The URL can carry signed
/// tokens, so it is held in the secret vault and only its reference is stored here. A record from
/// before this change has no reference (empty) and is failed visibly at dispatch.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRequest {
    pub download_key: String,
    pub filename: String,
    #[serde(default)]
    pub url_ref: String,
}

impl std::fmt::Debug for StoredRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoredRequest { <redacted> }")
    }
}

/// The file a task will write, chosen and held at Prepare so two tasks can never collide on a name.
/// `key` is the case- and normalisation-folded form that the uniqueness index compares.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reservation {
    pub path: String,
    pub key: String,
    /// An aborted task gives its name back; nothing on disk is touched.
    pub released: bool,
}

impl Reservation {
    /// The key the uniqueness index sees: none once released.
    pub fn active_key(&self) -> Option<&str> {
        (!self.released).then_some(self.key.as_str())
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
    /// The reserved destination file, when the core was given a destination policy.
    #[serde(default)]
    pub destination: Option<Reservation>,
    /// The engine's answer to the last submit was lost: the task may or may not exist there.
    #[serde(default)]
    pub engine_ambiguous: bool,
    /// Questions about that task the engine could not answer.
    #[serde(default)]
    pub engine_queries: u32,
    /// Times the core submitted again after proving the engine did not know the task.
    #[serde(default)]
    pub engine_resubmits: u32,
    /// Identity could not be proven; the core stops touching the task and says why.
    #[serde(default)]
    pub held: bool,
    /// Times the engine forgot a running task and it was submitted again.
    #[serde(default)]
    pub engine_redispatches: u32,
    /// Higher starts first; ties go to the older task.
    #[serde(default)]
    pub priority: i32,
    /// Why a committed task is not running yet (a fixed phrase), shown to the user.
    #[serde(default)]
    pub queued_reason: Option<String>,
    #[serde(default)]
    pub paused: bool,
    #[serde(default)]
    pub pause_reason: Option<String>,
    /// Attempts started again after a transient failure.
    #[serde(default)]
    pub retries: u32,
    /// Seconds (the core's clock) before which a retry must not start; 0 when none is waiting.
    #[serde(default)]
    pub retry_at: u64,
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
            destination: None,
            engine_ambiguous: false,
            engine_queries: 0,
            engine_resubmits: 0,
            held: false,
            engine_redispatches: 0,
            priority: 0,
            queued_reason: None,
            paused: false,
            pause_reason: None,
            retries: 0,
            retry_at: 0,
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
    /// True when an unreleased reservation holds this folded key.
    fn is_reserved(&self, key: &str) -> Result<bool, StoreError>;
}

#[derive(Default, Clone)]
pub struct MemStore {
    map: BTreeMap<u64, Record>,
    next: u64,
    /// Number of upcoming `put` calls that fail without writing.
    pub fail_puts: usize,
}

impl MemStore {
    fn key_taken_by_other(&self, record: &Record) -> bool {
        let Some(key) = record.destination.as_ref().and_then(|d| d.active_key()) else {
            return false;
        };
        self.map.values().any(|r| {
            r.task_id != record.task_id
                && r.destination.as_ref().and_then(|d| d.active_key()) == Some(key)
        })
    }
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
        if self.key_taken_by_other(record) {
            return Err(StoreError::Conflict);
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
    fn is_reserved(&self, key: &str) -> Result<bool, StoreError> {
        Ok(self
            .map
            .values()
            .any(|r| r.destination.as_ref().and_then(|d| d.active_key()) == Some(key)))
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
                json TEXT NOT NULL,
                dest_key TEXT);
             CREATE TABLE IF NOT EXISTS meta(
                id INTEGER PRIMARY KEY CHECK(id = 1),
                next INTEGER NOT NULL);
             INSERT OR IGNORE INTO meta(id, next) VALUES(1, 1);",
        )?;
        // databases created before reservations existed get the column in place; NULL keys never collide
        let has_column = conn
            .prepare("SELECT 1 FROM pragma_table_info('records') WHERE name = 'dest_key'")?
            .exists([])?;
        if !has_column {
            conn.execute("ALTER TABLE records ADD COLUMN dest_key TEXT", [])?;
        }
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS records_dest_key ON records(dest_key)",
            [],
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
        let dest_key = record
            .destination
            .as_ref()
            .and_then(|d| d.active_key().map(str::to_string));
        let tx = self.conn.transaction()?;
        // an upsert on the task id only: REPLACE would silently delete another row that holds the
        // same reservation or request id, so those collisions are errors instead
        match tx.execute(
            "INSERT INTO records(task_id, request_id, json, dest_key) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(task_id) DO UPDATE SET
                request_id = excluded.request_id, json = excluded.json, dest_key = excluded.dest_key",
            params![record.task_id as i64, record.request_id, json, dest_key],
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
    fn insert(&mut self, record: &Record) -> Result<(), StoreError> {
        let json = serde_json::to_string(record)?;
        let dest_key = record
            .destination
            .as_ref()
            .and_then(|d| d.active_key().map(str::to_string));
        let tx = self.conn.transaction()?;
        match tx.execute(
            "INSERT INTO records(task_id, request_id, json, dest_key) VALUES(?1, ?2, ?3, ?4)",
            params![record.task_id as i64, record.request_id, json, dest_key],
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
    fn is_reserved(&self, key: &str) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .prepare("SELECT 1 FROM records WHERE dest_key = ?1")?
            .exists([key])?)
    }
}
