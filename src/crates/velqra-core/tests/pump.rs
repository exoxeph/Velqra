// SPDX-License-Identifier: GPL-3.0-only
use std::collections::HashSet;
use velqra_core::store::{MemStore, Store};
use velqra_core::{Core, Engine, EngineError, EngineRequest};
use velqra_protocol::*;

#[derive(Default)]
struct TestEngine {
    submitted: HashSet<String>,
    requests: Vec<EngineRequest>,
    lose_next_reply: bool,
    reject: bool,
    fail_transfer: bool,
    calls: usize,
}

impl Engine for TestEngine {
    fn submit(&mut self, request: &EngineRequest) -> Result<(), EngineError> {
        self.calls += 1;
        if self.reject {
            return Err(EngineError::Rejected);
        }
        self.submitted.insert(request.attempt.clone());
        self.requests.push(request.clone());
        if self.lose_next_reply {
            self.lose_next_reply = false;
            return Err(EngineError::ReplyLost);
        }
        Ok(())
    }
    fn finished(&mut self, attempt: &str) -> Option<bool> {
        self.submitted
            .contains(attempt)
            .then_some(!self.fail_transfer)
    }
}

fn body() -> PrepareBody {
    PrepareBody {
        download_key: "d".into(),
        url: "https://x.test/a.zip".into(),
        filename: "a.zip".into(),
        context: Secret("x".into()),
    }
}

fn rref() -> RequestRef {
    RequestRef {
        task_id: 1,
        fingerprint: fingerprint(&body()),
    }
}

fn send(c: &mut Core<MemStore>, rid: &str, m: Message, now: u64) {
    let env = Envelope {
        version: PROTOCOL_VERSION,
        message_id: format!("{rid}-{now}"),
        session_id: "s".into(),
        request_id: rid.into(),
        generation: 1,
        body: m,
    };
    c.handle(&env, now);
}

fn prepare(c: &mut Core<MemStore>, upto_commit: bool) {
    send(c, "r1", Message::Prepare(body()), 1);
    if upto_commit {
        send(c, "r1", Message::BeginHandoff(rref()), 2);
        send(
            c,
            "r1",
            Message::Commit(CommitBody {
                cancel: CancelEvidence::Confirmed,
                receipt: rref(),
            }),
            3,
        );
    }
}

fn state(c: &Core<MemStore>) -> TaskState {
    c.store.get_by_request("r1").unwrap().unwrap().state
}

#[test]
fn pump_never_submits_prepared_or_armed_tasks() {
    let mut c = Core::new(MemStore::default());
    let mut e = TestEngine::default();
    prepare(&mut c, false);
    send(&mut c, "r1", Message::BeginHandoff(rref()), 2);
    assert!(c.pump(&mut e).unwrap().is_empty());
    assert_eq!(e.calls, 0);
}

#[test]
fn pump_submits_committed_task_once_with_its_stored_request_and_finishes_it() {
    let mut c = Core::new(MemStore::default());
    let mut e = TestEngine::default();
    prepare(&mut c, true);
    let events = c.pump(&mut e).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].state_before, TaskState::Committed);
    assert_eq!(state(&c), TaskState::Transferring);
    assert_eq!(
        (e.requests[0].url.as_str(), e.requests[0].filename.as_str()),
        ("https://x.test/a.zip", "a.zip")
    );
    assert!(e.requests[0].context_ref.is_some());
    c.pump(&mut e).unwrap();
    assert_eq!(state(&c), TaskState::Done);
    assert_eq!(e.submitted.len(), 1);
}

#[test]
fn lost_engine_reply_is_retried_with_the_same_attempt_id() {
    let mut c = Core::new(MemStore::default());
    let mut e = TestEngine {
        lose_next_reply: true,
        ..Default::default()
    };
    prepare(&mut c, true);
    c.pump(&mut e).unwrap();
    assert_eq!(state(&c), TaskState::Committed);
    c.pump(&mut e).unwrap();
    assert_eq!(e.submitted.len(), 1);
    assert_eq!(state(&c), TaskState::Transferring);
}

#[test]
fn engine_rejection_is_terminal_and_visible() {
    // review I3: a refusal must not retry invisibly forever
    let mut c = Core::new(MemStore::default());
    let mut e = TestEngine {
        reject: true,
        ..Default::default()
    };
    prepare(&mut c, true);
    c.pump(&mut e).unwrap();
    let rec = c.store.get_by_request("r1").unwrap().unwrap();
    assert_eq!(rec.state, TaskState::Failed);
    assert_eq!(rec.fail_reason.as_deref(), Some("engine rejected the task"));
    c.pump(&mut e).unwrap();
    assert_eq!(e.calls, 1, "a rejected task is not submitted again");
}

#[test]
fn a_failed_transfer_is_recorded_with_a_reason() {
    let mut c = Core::new(MemStore::default());
    let mut e = TestEngine {
        fail_transfer: true,
        ..Default::default()
    };
    prepare(&mut c, true);
    c.pump(&mut e).unwrap();
    c.pump(&mut e).unwrap();
    let rec = c.store.get_by_request("r1").unwrap().unwrap();
    assert_eq!(
        (rec.state, rec.fail_reason.as_deref()),
        (TaskState::Failed, Some("transfer failed"))
    );
}

/// A store that can be told to refuse writes, to model a disk error after the engine accepted a task.
struct FlakyStore {
    inner: MemStore,
    fail_put: bool,
}

impl Store for FlakyStore {
    fn get_by_request(
        &self,
        r: &str,
    ) -> Result<Option<velqra_core::store::Record>, velqra_core::store::StoreError> {
        self.inner.get_by_request(r)
    }
    fn get_by_task(
        &self,
        t: u64,
    ) -> Result<Option<velqra_core::store::Record>, velqra_core::store::StoreError> {
        self.inner.get_by_task(t)
    }
    fn put(
        &mut self,
        r: &velqra_core::store::Record,
    ) -> Result<(), velqra_core::store::StoreError> {
        if self.fail_put {
            return Err(velqra_core::store::StoreError::Io("disk".into()));
        }
        self.inner.put(r)
    }
    fn insert(
        &mut self,
        r: &velqra_core::store::Record,
    ) -> Result<(), velqra_core::store::StoreError> {
        self.inner.insert(r)
    }
    fn next_task_id(&self) -> Result<u64, velqra_core::store::StoreError> {
        self.inner.next_task_id()
    }
    fn all(&self) -> Result<Vec<velqra_core::store::Record>, velqra_core::store::StoreError> {
        self.inner.all()
    }
    fn remove(&mut self, t: u64) -> Result<(), velqra_core::store::StoreError> {
        self.inner.remove(t)
    }
}

#[test]
fn dispatch_log_keeps_a_submit_even_when_the_store_fails_afterwards() {
    let mut c = Core::new(FlakyStore {
        inner: MemStore::default(),
        fail_put: false,
    });
    let env = |m: Message, n: u64| Envelope {
        version: PROTOCOL_VERSION,
        message_id: format!("m{n}"),
        session_id: "s".into(),
        request_id: "r1".into(),
        generation: 1,
        body: m,
    };
    c.handle(&env(Message::Prepare(body()), 1), 1);
    c.handle(&env(Message::BeginHandoff(rref()), 2), 2);
    c.handle(
        &env(
            Message::Commit(CommitBody {
                cancel: CancelEvidence::Confirmed,
                receipt: rref(),
            }),
            3,
        ),
        3,
    );
    c.store.fail_put = true;
    let mut e = TestEngine::default();
    assert!(c.pump(&mut e).is_err());
    assert_eq!(e.calls, 1, "the engine was called");
    assert_eq!(c.dispatch_log.len(), 1, "and the submit is on the record");
    assert_eq!(c.dispatch_log[0].state_before, TaskState::Committed);
}
