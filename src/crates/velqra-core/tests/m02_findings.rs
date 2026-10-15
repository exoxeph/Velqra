// SPDX-License-Identifier: GPL-3.0-only
//! Regression tests for the second Codex review (24c): R-I1, R-I2 and the surviving mutation N8.
use std::cell::Cell;
use velqra_core::store::{MemStore, Record, Store, StoreError};
use velqra_core::vault::{MemVault, SecretVault};
use velqra_core::{Core, Engine, EngineError, EngineRequest};
use velqra_protocol::*;

fn body(key: &str) -> PrepareBody {
    PrepareBody {
        download_key: key.into(),
        url: format!("https://x.test/{key}.zip"),
        filename: format!("{key}.zip"),
        context: Secret(format!("secret-{key}")),
    }
}

fn env(rid: &str, n: u64, m: Message) -> Envelope {
    Envelope {
        version: PROTOCOL_VERSION,
        message_id: format!("m{n}"),
        session_id: "s".into(),
        request_id: rid.into(),
        generation: 1,
        body: m,
    }
}

fn reply_receipt(e: &Envelope) -> Receipt {
    match &e.body {
        Message::Prepared(r)
        | Message::Armed(r)
        | Message::Committed(r)
        | Message::Reconciled(r) => r.clone(),
        other => panic!("not a receipt: {other:?}"),
    }
}

#[derive(Default)]
struct CountingEngine {
    calls: usize,
}

impl Engine for CountingEngine {
    fn submit(&mut self, _r: &EngineRequest) -> Result<(), EngineError> {
        self.calls += 1;
        Ok(())
    }
    fn finished(&mut self, _a: &str) -> Option<bool> {
        None
    }
}

/// A store whose next id can be made stale once, as when two writers race for the same id.
struct StaleIdStore {
    inner: MemStore,
    stale: Cell<Option<u64>>,
}

impl Store for StaleIdStore {
    fn get_by_request(&self, r: &str) -> Result<Option<Record>, StoreError> {
        self.inner.get_by_request(r)
    }
    fn get_by_task(&self, t: u64) -> Result<Option<Record>, StoreError> {
        self.inner.get_by_task(t)
    }
    fn put(&mut self, r: &Record) -> Result<(), StoreError> {
        self.inner.put(r)
    }
    fn insert(&mut self, r: &Record) -> Result<(), StoreError> {
        self.inner.insert(r)
    }
    fn next_task_id(&self) -> Result<u64, StoreError> {
        match self.stale.take() {
            Some(id) => Ok(id),
            None => self.inner.next_task_id(),
        }
    }
    fn all(&self) -> Result<Vec<Record>, StoreError> {
        self.inner.all()
    }
    fn remove(&mut self, t: u64) -> Result<(), StoreError> {
        self.inner.remove(t)
    }
    fn is_reserved(&self, key: &str) -> Result<bool, StoreError> {
        self.inner.is_reserved(key)
    }
}

#[test]
fn a_lost_id_race_never_erases_another_tasks_context() {
    let vault = MemVault::default();
    let store = StaleIdStore {
        inner: MemStore::default(),
        stale: Cell::new(None),
    };
    let mut c = Core::with_vault(store, Box::new(vault.clone()));
    let a = reply_receipt(&c.handle(&env("ra", 1, Message::Prepare(body("a"))), 1));
    let cref_a = c
        .store
        .get_by_task(a.task_id)
        .unwrap()
        .unwrap()
        .context_ref
        .unwrap();
    // writer B reads a stale next id (the one A already took), collides, and retries
    c.store.stale.set(Some(a.task_id));
    let b = reply_receipt(&c.handle(&env("rb", 2, Message::Prepare(body("b"))), 2));
    assert_ne!(a.task_id, b.task_id);
    assert_eq!(
        vault.get(&cref_a).map(|s| s.0),
        Some("secret-a".to_string()),
        "A's context was destroyed"
    );
    let cref_b = c
        .store
        .get_by_task(b.task_id)
        .unwrap()
        .unwrap()
        .context_ref
        .unwrap();
    assert_ne!(cref_a, cref_b);
    assert_eq!(
        vault.get(&cref_b).map(|s| s.0),
        Some("secret-b".to_string())
    );
}

#[test]
fn a_failed_allocation_leaves_no_orphaned_context() {
    let vault = MemVault::default();
    let store = StaleIdStore {
        inner: MemStore::default(),
        stale: Cell::new(None),
    };
    let mut c = Core::with_vault(store, Box::new(vault.clone()));
    c.handle(&env("ra", 1, Message::Prepare(body("a"))), 1);
    c.store.stale.set(Some(1));
    c.handle(&env("rb", 2, Message::Prepare(body("b"))), 2);
    assert_eq!(
        vault.len(),
        4,
        "context and url per accepted task, none leaked by the collision"
    );
}

#[test]
fn a_committed_task_whose_context_is_gone_fails_visibly_instead_of_dispatching() {
    let mut c = Core::new(MemStore::default());
    let r = reply_receipt(&c.handle(&env("r1", 1, Message::Prepare(body("a"))), 1));
    let rr = r.as_ref();
    c.handle(&env("r1", 2, Message::BeginHandoff(rr.clone())), 2);
    c.handle(
        &env(
            "r1",
            3,
            Message::Commit(CommitBody {
                cancel: CancelEvidence::Confirmed,
                receipt: rr,
            }),
        ),
        3,
    );
    // the core restarts and the protected store has lost the context
    c.vault = Box::new(MemVault::default());
    let mut e = CountingEngine::default();
    c.pump(&mut e).unwrap();
    assert_eq!(e.calls, 0, "dispatched without its protected context");
    let rec = c.store.get_by_request("r1").unwrap().unwrap();
    assert_eq!(rec.state, TaskState::Failed);
    assert!(rec.fail_reason.unwrap().contains("context"));
}

// ---- N8: a recovered record that is Unknown without ever having been Armed ----

#[test]
fn a_recovered_unknown_record_without_armed_history_cannot_become_owned() {
    let mut c = Core::new(MemStore::default());
    let fp = fingerprint(&body("a"));
    let mut rec = Record::new(1, "r1", 1, &fp, TaskState::Prepared);
    rec.state = TaskState::OwnershipUnknown;
    rec.history = vec![TaskState::Prepared, TaskState::OwnershipUnknown];
    c.store.insert(&rec).unwrap();
    let receipt = RequestRef {
        task_id: 1,
        fingerprint: fp,
    };
    let out = c.handle(
        &env(
            "r1",
            1,
            Message::Reconcile(ReconcileBody {
                owner: OwnerEvidence::AppOwns,
                receipt,
            }),
        ),
        5,
    );
    assert!(
        matches!(&out.body, Message::Error(e) if e.kind == ErrorKind::NotArmed),
        "{:?}",
        out.body
    );
    let mut e = CountingEngine::default();
    c.pump(&mut e).unwrap();
    assert_eq!(e.calls, 0);
    assert_eq!(
        c.store.get_by_request("r1").unwrap().unwrap().state,
        TaskState::OwnershipUnknown
    );
}
