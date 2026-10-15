// SPDX-License-Identifier: GPL-3.0-only
//! The ownership state machine (spec section 4), app side.

use crate::destination::DestinationPolicy;
use crate::settings::{Loaded, Settings};
use crate::store::{Record, Store, StoreError, StoredRequest};
use crate::vault::{MemVault, SecretVault};
use velqra_protocol::*;

/// Each lost race (task id or destination taken by another writer) costs one attempt; with many
/// writers on one database the unluckiest needs about as many attempts as there are writers.
const MAX_PREPARE_ATTEMPTS: usize = 200;

#[path = "queue.rs"]
mod queue;

pub struct Core<S: Store> {
    pub store: S,
    pub vault: Box<dyn SecretVault>,
    /// Every engine submission, appended before the call so it survives a later store error.
    pub dispatch_log: Vec<DispatchEvent>,
    /// Where downloads go; without a policy no destination is reserved (simulations).
    destination: Option<DestinationPolicy>,
    /// What the extension may read; nothing in a message can change it.
    settings: Settings,
    settings_problem: Option<String>,
    /// Queue limits; unlimited unless the application sets them from its settings.
    max_active: u32,
    per_origin: u32,
    /// Seconds between questions to the engine about running tasks (0 = every pump).
    poll_interval: u64,
    last_poll: u64,
    /// task id to site, kept in memory only: the host never goes into the database.
    origin_cache: std::collections::HashMap<u64, String>,
}

fn reply(env: &Envelope, body: Message) -> Envelope {
    Envelope {
        version: PROTOCOL_VERSION,
        message_id: format!("r-{}", env.message_id),
        session_id: env.session_id.clone(),
        request_id: env.request_id.clone(),
        generation: env.generation,
        body,
    }
}

fn error(env: &Envelope, kind: ErrorKind, detail: &str) -> Envelope {
    reply(env, Message::Error(ProtoError::new(kind, detail)))
}

fn receipt(r: &Record) -> Receipt {
    Receipt {
        task_id: r.task_id,
        fingerprint: r.fingerprint.clone(),
        state: r.state,
    }
}

fn set(r: &mut Record, state: TaskState) {
    r.state = state;
    r.history.push(state);
}

fn commit_record(r: &mut Record) {
    set(r, TaskState::Committed);
    r.dispatch_attempt = Some(format!("t{}-g{}", r.task_id, r.generation));
}

fn abort_record(r: &mut Record, now: u64) {
    set(r, TaskState::Aborted);
    r.aborted_at = Some(now);
    r.request = None;
    r.context_ref = None;
    // the name goes back to the pool; the file system is never touched
    if let Some(d) = r.destination.as_mut() {
        d.released = true;
    }
}

fn was_armed(r: &Record) -> bool {
    r.history.contains(&TaskState::Armed)
}

impl<S: Store> Core<S> {
    pub fn new(store: S) -> Self {
        Self::with_vault(store, Box::new(MemVault::default()))
    }

    pub fn with_vault(store: S, vault: Box<dyn SecretVault>) -> Self {
        Self {
            store,
            vault,
            dispatch_log: Vec::new(),
            destination: None,
            settings: Settings::default(),
            settings_problem: None,
            max_active: u32::MAX,
            per_origin: u32::MAX,
            poll_interval: 0,
            last_poll: 0,
            origin_cache: std::collections::HashMap::new(),
        }
    }

    /// At most `max_active` tasks run at once and at most `per_origin` of them per site.
    pub fn with_limits(mut self, max_active: u32, per_origin: u32) -> Self {
        self.max_active = max_active.max(1);
        self.per_origin = per_origin.max(1);
        self
    }

    pub fn with_poll_interval(mut self, seconds: u64) -> Self {
        self.poll_interval = seconds;
        self
    }

    pub fn with_settings(mut self, loaded: Loaded) -> Self {
        self.settings = loaded.settings;
        self.settings_problem = loaded.problem.map(str::to_string);
        self
    }

    pub fn with_destination(mut self, policy: DestinationPolicy) -> Self {
        self.destination = Some(policy);
        self
    }

    pub fn handle(&mut self, env: &Envelope, now: u64) -> Envelope {
        if let Err(e) = env.validate() {
            return reply(env, Message::Error(e));
        }
        match &env.body {
            Message::Prepare(p) => self.prepare(env, p),
            Message::BeginHandoff(r) => self.apply(env, now, Some(r), Message::Armed, |rec, _| {
                match rec.state {
                    TaskState::Prepared => {
                        set(rec, TaskState::Armed);
                        Ok(true)
                    }
                    TaskState::Armed => Ok(false),
                    TaskState::Aborted => Err(ErrorKind::Aborted),
                    _ => Err(ErrorKind::WrongState),
                }
            }),
            Message::Commit(c) => self.apply(
                env,
                now,
                Some(&c.receipt),
                Message::Committed,
                |rec, _| match rec.state {
                    TaskState::Armed => {
                        commit_record(rec);
                        Ok(true)
                    }
                    TaskState::Committed
                    | TaskState::Transferring
                    | TaskState::Done
                    | TaskState::Failed => Ok(false),
                    TaskState::Prepared => Err(ErrorKind::NotArmed),
                    TaskState::Aborted => Err(ErrorKind::Aborted),
                    TaskState::OwnershipUnknown => Err(ErrorKind::WrongState),
                },
            ),
            Message::Abort(a) => self.abort(env, now, a.receipt.as_ref()),
            Message::Reconcile(b) => self.reconcile(env, now, b),
            Message::Status(_) => {
                self.apply(env, now, None, Message::StatusReply, |_, _| Ok(false))
            }
            Message::SettingsGet(_) => reply(
                env,
                Message::SettingsReply(self.settings.snapshot(self.settings_problem.as_deref())),
            ),
            _ => error(env, ErrorKind::WrongState, "not a request"),
        }
    }

    /// Every vault entry a request owns: its context and its URL.
    fn stored_context(&self, request_id: &str) -> Vec<String> {
        let Some(rec) = self.store.get_by_request(request_id).ok().flatten() else {
            return Vec::new();
        };
        let url_ref = rec.request.map(|r| r.url_ref).filter(|r| !r.is_empty());
        rec.context_ref.into_iter().chain(url_ref).collect()
    }

    fn release_context(&mut self, refs: Vec<String>) {
        for r in refs {
            self.vault.remove(&r);
        }
    }

    fn reconcile(&mut self, env: &Envelope, now: u64, b: &ReconcileBody) -> Envelope {
        let owner = b.owner;
        let cref = self.stored_context(&env.request_id);
        let out = self.apply(
            env,
            now,
            Some(&b.receipt),
            Message::Reconciled,
            move |r, now| {
                use OwnerEvidence::*;
                use TaskState::*;
                match (owner, r.state) {
                    // arming (durable cancellation intent) must have happened on every route to a decision
                    (_, Prepared) => Err(ErrorKind::NotArmed),
                    (BrowserOwns, Armed | OwnershipUnknown) => {
                        abort_record(r, now);
                        Ok(true)
                    }
                    (BrowserOwns, Aborted) => Ok(false),
                    (AppOwns, Armed) => {
                        commit_record(r);
                        Ok(true)
                    }
                    (AppOwns, OwnershipUnknown) if was_armed(r) => {
                        commit_record(r);
                        Ok(true)
                    }
                    (AppOwns, OwnershipUnknown) => Err(ErrorKind::NotArmed),
                    (AppOwns, Committed | Transferring | Done | Failed) => Ok(false),
                    (Unknown, Armed) => {
                        set(r, OwnershipUnknown);
                        Ok(true)
                    }
                    (
                        Unknown,
                        OwnershipUnknown | Aborted | Committed | Transferring | Done | Failed,
                    ) => Ok(false),
                    _ => Err(ErrorKind::WrongState),
                }
            },
        );
        if matches!(&out.body, Message::Reconciled(r) if r.state == TaskState::Aborted) {
            self.release_context(cref);
        }
        out
    }

    fn prepare(&mut self, env: &Envelope, p: &PrepareBody) -> Envelope {
        let fp = fingerprint(p);
        for _ in 0..MAX_PREPARE_ATTEMPTS {
            match self.store.get_by_request(&env.request_id) {
                Err(e) => return error(env, ErrorKind::Storage, &e.to_string()),
                Ok(Some(rec)) => {
                    return if rec.state == TaskState::Aborted {
                        // tombstone: report the fenced state so the sender aborts too
                        reply(env, Message::Prepared(receipt(&rec)))
                    } else if rec.fingerprint != fp {
                        error(
                            env,
                            ErrorKind::PayloadMismatch,
                            "payload changed for this request",
                        )
                    } else if rec.generation != env.generation {
                        error(env, ErrorKind::StaleGeneration, "generation mismatch")
                    } else {
                        reply(env, Message::Prepared(receipt(&rec)))
                    };
                }
                Ok(None) => {}
            }
            let task_id = match self.store.next_task_id() {
                Ok(id) => id,
                Err(e) => return error(env, ErrorKind::Storage, &e.to_string()),
            };
            // chosen before any secret is stored, so a refusal leaves nothing behind
            let destination = match &self.destination {
                None => None,
                Some(policy) => {
                    let taken = |key: &str| self.store.is_reserved(key).unwrap_or(true);
                    match policy.choose(&p.filename, &taken) {
                        Some(r) => Some(r),
                        None => {
                            return error(
                                env,
                                ErrorKind::NoDestination,
                                "no valid destination for this download",
                            )
                        }
                    }
                }
            };
            let Ok(cref) = self.vault.put(task_id, &p.context) else {
                return error(env, ErrorKind::Storage, "secret vault unavailable");
            };
            let Ok(uref) = self.vault.put(task_id, &Secret(p.url.clone())) else {
                self.vault.remove(&cref);
                return error(env, ErrorKind::Storage, "secret vault unavailable");
            };
            let mut rec = Record::new(
                task_id,
                &env.request_id,
                env.generation,
                &fp,
                TaskState::Prepared,
            );
            rec.request = Some(StoredRequest {
                download_key: p.download_key.clone(),
                filename: p.filename.clone(),
                url_ref: uref.clone(),
            });
            rec.context_ref = Some(cref.clone());
            rec.destination = destination;
            match self.store.insert(&rec) {
                Ok(()) => return reply(env, Message::Prepared(receipt(&rec))),
                Err(StoreError::Conflict) => {
                    self.vault.remove(&cref);
                    self.vault.remove(&uref);
                }
                Err(e) => {
                    self.vault.remove(&cref);
                    self.vault.remove(&uref);
                    return error(env, ErrorKind::Storage, &e.to_string());
                }
            }
        }
        error(env, ErrorKind::Storage, "could not allocate a task id")
    }

    fn abort(&mut self, env: &Envelope, now: u64, expect: Option<&RequestRef>) -> Envelope {
        let cref = self.stored_context(&env.request_id);
        let existing = match self.store.get_by_request(&env.request_id) {
            Err(e) => return error(env, ErrorKind::Storage, &e.to_string()),
            Ok(r) => r,
        };
        let Some(rec) = existing else {
            return self.tombstone_unknown(env, now);
        };
        // a tombstone created from an unknown request has no fingerprint to check
        let expect = if rec.fingerprint.is_empty() {
            None
        } else {
            expect
        };
        let out = self.apply(env, now, expect, Message::Aborted, |r, now| match r.state {
            // an abort carries evidence that the browser still owns the download,
            // so it also resolves an unknown ownership
            TaskState::Prepared | TaskState::Armed | TaskState::OwnershipUnknown => {
                abort_record(r, now);
                Ok(true)
            }
            TaskState::Aborted => Ok(false),
            _ => Err(ErrorKind::WrongState),
        });
        if matches!(&out.body, Message::Aborted(_)) {
            self.release_context(cref);
        }
        out
    }

    /// Aborting a request the core never saw leaves a fence so a delayed prepare cannot revive it.
    fn tombstone_unknown(&mut self, env: &Envelope, now: u64) -> Envelope {
        for _ in 0..5 {
            let task_id = match self.store.next_task_id() {
                Ok(id) => id,
                Err(e) => return error(env, ErrorKind::Storage, &e.to_string()),
            };
            let mut rec = Record::new(
                task_id,
                &env.request_id,
                env.generation,
                "",
                TaskState::Aborted,
            );
            rec.aborted_at = Some(now);
            match self.store.insert(&rec) {
                Ok(()) => return reply(env, Message::Aborted(receipt(&rec))),
                Err(StoreError::Conflict) => {
                    if let Ok(Some(existing)) = self.store.get_by_request(&env.request_id) {
                        return reply(env, Message::Aborted(receipt(&existing)));
                    }
                }
                Err(e) => return error(env, ErrorKind::Storage, &e.to_string()),
            }
        }
        error(env, ErrorKind::Storage, "could not allocate a task id")
    }

    fn apply(
        &mut self,
        env: &Envelope,
        now: u64,
        expect: Option<&RequestRef>,
        make: fn(Receipt) -> Message,
        f: impl FnOnce(&mut Record, u64) -> Result<bool, ErrorKind>,
    ) -> Envelope {
        let mut rec = match self.store.get_by_request(&env.request_id) {
            Ok(Some(r)) => r,
            Ok(None) => return error(env, ErrorKind::NotFound, "unknown request"),
            Err(e) => return error(env, ErrorKind::Storage, &e.to_string()),
        };
        if rec.generation != env.generation {
            return error(env, ErrorKind::StaleGeneration, "generation mismatch");
        }
        if let Some(r) = expect {
            // a tombstone made from an unknown request has no receipt: it simply answers "aborted"
            if !rec.fingerprint.is_empty()
                && (r.task_id != rec.task_id || r.fingerprint != rec.fingerprint)
            {
                return error(
                    env,
                    ErrorKind::IdentityMismatch,
                    "receipt does not match this request",
                );
            }
        }
        match f(&mut rec, now) {
            Err(kind) => error(env, kind, "rejected in current state"),
            Ok(false) => reply(env, make(receipt(&rec))),
            Ok(true) => match self.store.put(&rec) {
                Ok(()) => reply(env, make(receipt(&rec))),
                Err(e) => error(env, ErrorKind::Storage, &e.to_string()),
            },
        }
    }

    /// Compacts aborted records whose tombstone is older than `retention`: the payload is dropped
    /// but the request id and generation keep fencing stale messages. Returns how many were compacted.
    pub fn purge_tombstones(&mut self, now: u64, retention: u64) -> Result<usize, StoreError> {
        let mut compacted = 0;
        for mut rec in self.store.all()? {
            if rec.state != TaskState::Aborted || rec.compacted {
                continue;
            }
            let expired = rec
                .aborted_at
                .and_then(|at| at.checked_add(retention))
                .is_some_and(|t| t <= now);
            if expired {
                rec.compacted = true;
                rec.history = vec![TaskState::Aborted];
                rec.request = None;
                rec.context_ref = None;
                rec.dispatch_attempt = None;
                self.store.put(&rec)?;
                compacted += 1;
            }
        }
        Ok(compacted)
    }
}

/// Transfer engine failure modes. A lost reply is ambiguous (the engine may have accepted the
/// task) and is retried with the same attempt id; a rejection is terminal and is surfaced.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum EngineError {
    #[error("engine reply lost")]
    ReplyLost,
    #[error("engine rejected the task")]
    Rejected,
    /// The engine has no such control.
    #[error("the engine does not support this")]
    Unsupported,
}

/// What an engine says about a task it was given. `Unknown` means "I have never heard of it".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineStatus {
    Unknown,
    Active {
        done: u64,
        total: u64,
    },
    Paused,
    Done,
    /// Stopped by something that may pass (timeout, dropped connection, a server that was busy):
    /// worth another attempt. Everything else that stops a task is `Failed`.
    Interrupted,
    /// The engine's own text: it can contain a URL, so the core never stores it.
    Failed(String),
}

/// The one-call answer the core needs about a task that is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poll {
    /// Still going (including paused or waiting inside the engine).
    Running,
    Done,
    Failed,
    /// Stopped by something worth retrying; see `EngineStatus::Interrupted`.
    Interrupted,
    /// The engine says it has never heard of the task (for example after a restart).
    Forgotten,
    /// The engine could not be asked; nothing is known.
    Unreachable,
}

/// Questions about one engine task that may go unanswered before the core holds the task.
const MAX_STATUS_QUERIES: u32 = 5;
/// Times a task the engine forgot is submitted again before it fails.
const MAX_REDISPATCHES: u32 = 3;

/// Everything an engine needs, rebuilt from the durable record (so it survives a restart).
#[derive(Clone, PartialEq, Eq)]
pub struct EngineRequest {
    pub attempt: String,
    pub url: String,
    pub filename: String,
    pub context_ref: Option<String>,
    /// The file the core reserved for this task; the engine writes exactly there.
    pub destination: Option<String>,
    /// The protected browser context, resolved from the vault at dispatch (opaque to the core).
    pub context: Option<String>,
}

impl std::fmt::Debug for EngineRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EngineRequest {{ attempt: {}, <redacted> }}",
            self.attempt
        )
    }
}

/// Transfer engine boundary. `submit` must be idempotent by `attempt` id.
pub trait Engine {
    fn submit(&mut self, request: &EngineRequest) -> Result<(), EngineError>;
    /// `Some(true)` finished OK, `Some(false)` failed, `None` still running or unknown.
    fn finished(&mut self, attempt: &str) -> Option<bool>;

    /// The task's state inside the engine, found by its attempt id (its identity there). `Err` means
    /// the engine could not be asked or did not answer; `Ok(Unknown)` means it answered "no such task".
    fn status(&mut self, attempt: &str) -> Result<EngineStatus, EngineError> {
        Ok(match self.finished(attempt) {
            Some(true) => EngineStatus::Done,
            Some(false) => EngineStatus::Failed("transfer failed".into()),
            None => EngineStatus::Unknown,
        })
    }
    /// What happened to a running task, in one question. The default is built from the older calls
    /// so every existing engine keeps working; a real engine overrides it to ask only once.
    fn poll(&mut self, attempt: &str) -> Poll {
        match self.finished(attempt) {
            Some(true) => Poll::Done,
            Some(false) => Poll::Failed,
            None if self.has_forgotten(attempt) => Poll::Forgotten,
            None => match self.status(attempt) {
                Ok(EngineStatus::Interrupted) => Poll::Interrupted,
                Err(_) => Poll::Unreachable,
                Ok(_) => Poll::Running,
            },
        }
    }

    /// True when the engine positively says it no longer holds a task it was given (for example
    /// after its process restarted). Unlike `status`, a failure to ask is NOT "forgotten".
    fn has_forgotten(&mut self, _attempt: &str) -> bool {
        false
    }
    fn pause(&mut self, _attempt: &str) -> Result<(), EngineError> {
        Err(EngineError::Unsupported)
    }
    fn resume(&mut self, _attempt: &str) -> Result<(), EngineError> {
        Err(EngineError::Unsupported)
    }
    fn cancel(&mut self, _attempt: &str) -> Result<(), EngineError> {
        Err(EngineError::Unsupported)
    }
}

impl<E: Engine + ?Sized> Engine for Box<E> {
    fn submit(&mut self, request: &EngineRequest) -> Result<(), EngineError> {
        (**self).submit(request)
    }
    fn finished(&mut self, attempt: &str) -> Option<bool> {
        (**self).finished(attempt)
    }
    fn status(&mut self, attempt: &str) -> Result<EngineStatus, EngineError> {
        (**self).status(attempt)
    }
    fn has_forgotten(&mut self, attempt: &str) -> bool {
        (**self).has_forgotten(attempt)
    }
    fn poll(&mut self, attempt: &str) -> Poll {
        (**self).poll(attempt)
    }
    fn pause(&mut self, attempt: &str) -> Result<(), EngineError> {
        (**self).pause(attempt)
    }
    fn resume(&mut self, attempt: &str) -> Result<(), EngineError> {
        (**self).resume(attempt)
    }
    fn cancel(&mut self, attempt: &str) -> Result<(), EngineError> {
        (**self).cancel(attempt)
    }
}

/// What `pump` did, so a checker can verify ordering (for example that nothing was
/// submitted before the record was committed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchEvent {
    pub task_id: u64,
    pub state_before: TaskState,
}

impl<S: Store> Core<S> {
    /// Everything the engine needs for one task, rebuilt from the record and the vault. A missing
    /// piece is a visible failure, never a partial request.
    fn engine_request(&self, rec: &Record, attempt: String) -> Result<EngineRequest, &'static str> {
        let req = rec.request.as_ref().ok_or("request metadata missing")?;
        let context = match &rec.context_ref {
            Some(c) => Some(self.vault.get(c).ok_or("protected context unavailable")?.0),
            None => None,
        };
        let url = self
            .vault
            .get(&req.url_ref)
            .ok_or("request url unavailable")?;
        Ok(EngineRequest {
            attempt,
            url: url.0,
            filename: req.filename.clone(),
            context_ref: rec.context_ref.clone(),
            destination: rec
                .destination
                .as_ref()
                .filter(|d| !d.released)
                .map(|d| d.path.clone()),
            context,
        })
    }

    /// Drives committed tasks into the engine. Prepared and armed tasks are never submitted.
    /// Drives committed tasks into the engine with no clock (retries never become due). Kept for
    /// callers that do not schedule; the application uses `pump_at`.
    pub fn pump(&mut self, engine: &mut dyn Engine) -> Result<Vec<DispatchEvent>, StoreError> {
        self.pump_at(engine, 0)
    }
}
