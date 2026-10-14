// SPDX-License-Identifier: GPL-3.0-only
//! The ownership state machine (spec section 4), app side.

use crate::store::{Record, Store, StoreError, StoredRequest};
use crate::vault::{MemVault, SecretVault};
use velqra_protocol::*;

pub struct Core<S: Store> {
    pub store: S,
    pub vault: Box<dyn SecretVault>,
    /// Every engine submission, appended before the call so it survives a later store error.
    pub dispatch_log: Vec<DispatchEvent>,
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
        }
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
            _ => error(env, ErrorKind::WrongState, "not a request"),
        }
    }

    fn stored_context(&self, request_id: &str) -> Option<String> {
        self.store
            .get_by_request(request_id)
            .ok()
            .flatten()
            .and_then(|r| r.context_ref)
    }

    fn release_context(&mut self, cref: Option<String>) {
        if let Some(c) = cref {
            self.vault.remove(&c);
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
        for _ in 0..5 {
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
            let Ok(cref) = self.vault.put(task_id, &p.context) else {
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
                url: p.url.clone(),
                filename: p.filename.clone(),
            });
            rec.context_ref = Some(cref.clone());
            match self.store.insert(&rec) {
                Ok(()) => return reply(env, Message::Prepared(receipt(&rec))),
                Err(StoreError::Conflict) => self.vault.remove(&cref),
                Err(e) => {
                    self.vault.remove(&cref);
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
}

/// Everything an engine needs, rebuilt from the durable record (so it survives a restart).
#[derive(Clone, PartialEq, Eq)]
pub struct EngineRequest {
    pub attempt: String,
    pub url: String,
    pub filename: String,
    pub context_ref: Option<String>,
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
}

/// What `pump` did, so a checker can verify ordering (for example that nothing was
/// submitted before the record was committed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchEvent {
    pub task_id: u64,
    pub state_before: TaskState,
}

impl<S: Store> Core<S> {
    /// Drives committed tasks into the engine. Prepared and armed tasks are never submitted.
    pub fn pump(&mut self, engine: &mut dyn Engine) -> Result<Vec<DispatchEvent>, StoreError> {
        let mut events = Vec::new();
        for mut rec in self.store.all()? {
            let Some(attempt) = rec.dispatch_attempt.clone() else {
                continue;
            };
            match rec.state {
                TaskState::Committed => {
                    let Some(req) = rec.request.clone() else {
                        rec.fail_reason = Some("request metadata missing".into());
                        set(&mut rec, TaskState::Failed);
                        self.store.put(&rec)?;
                        continue;
                    };
                    if let Some(c) = &rec.context_ref {
                        if self.vault.get(c).is_none() {
                            // never dispatch without the protected context: surface the loss instead
                            rec.fail_reason = Some("protected context unavailable".into());
                            set(&mut rec, TaskState::Failed);
                            self.store.put(&rec)?;
                            continue;
                        }
                    }
                    let request = EngineRequest {
                        attempt,
                        url: req.url,
                        filename: req.filename,
                        context_ref: rec.context_ref.clone(),
                    };
                    let event = DispatchEvent {
                        task_id: rec.task_id,
                        state_before: rec.state,
                    };
                    self.dispatch_log.push(event.clone());
                    events.push(event);
                    match engine.submit(&request) {
                        Ok(()) => {
                            set(&mut rec, TaskState::Transferring);
                            self.store.put(&rec)?;
                        }
                        Err(EngineError::Rejected) => {
                            rec.fail_reason = Some("engine rejected the task".into());
                            set(&mut rec, TaskState::Failed);
                            self.store.put(&rec)?;
                        }
                        Err(EngineError::ReplyLost) => {}
                    }
                }
                TaskState::Transferring => {
                    if let Some(ok) = engine.finished(&attempt) {
                        if !ok {
                            rec.fail_reason = Some("transfer failed".into());
                        }
                        set(
                            &mut rec,
                            if ok {
                                TaskState::Done
                            } else {
                                TaskState::Failed
                            },
                        );
                        self.store.put(&rec)?;
                    }
                }
                _ => {}
            }
        }
        Ok(events)
    }
}
