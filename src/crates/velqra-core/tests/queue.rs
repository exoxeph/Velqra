// SPDX-License-Identifier: GPL-3.0-only
//! B4: the queue. At most `max_active` tasks run at once and at most `per_origin` per site; waiting
//! tasks start in priority order then arrival order; a transient engine failure is retried with an
//! exponential backoff on an injected clock and a fresh attempt id, up to a cap; a permanent
//! failure is never retried; pause reasons and priorities survive a restart.
use proptest::prelude::*;
use std::collections::HashMap;
use velqra_core::store::{MemStore, SqliteStore, Store};
use velqra_core::vault::MemVault;
use velqra_core::{Core, Engine, EngineError, EngineRequest, EngineStatus};
use velqra_protocol::*;

#[derive(Default)]
struct Fake {
    submitted: Vec<String>,
    state: HashMap<String, EngineStatus>,
    paused: Vec<String>,
    resumed: Vec<String>,
    /// The next submit takes effect but its reply is lost.
    lose_next: bool,
    /// The engine cannot be asked anything.
    down: bool,
    finished_calls: usize,
}

impl Fake {
    fn finish(&mut self, attempt: &str) {
        self.state.insert(attempt.into(), EngineStatus::Done);
    }
    fn interrupt(&mut self, attempt: &str) {
        self.state.insert(attempt.into(), EngineStatus::Interrupted);
    }
    fn fail(&mut self, attempt: &str) {
        self.state.insert(
            attempt.into(),
            EngineStatus::Failed("transfer failed".into()),
        );
    }
}

impl Engine for Fake {
    fn submit(&mut self, r: &EngineRequest) -> Result<(), EngineError> {
        self.submitted.push(r.attempt.clone());
        self.state.insert(
            r.attempt.clone(),
            EngineStatus::Active { done: 0, total: 0 },
        );
        if std::mem::take(&mut self.lose_next) {
            return Err(EngineError::ReplyLost);
        }
        Ok(())
    }
    fn finished(&mut self, a: &str) -> Option<bool> {
        self.finished_calls += 1;
        if self.down {
            return None;
        }
        match self.state.get(a) {
            Some(EngineStatus::Done) => Some(true),
            Some(EngineStatus::Failed(_)) => Some(false),
            _ => None,
        }
    }
    fn status(&mut self, a: &str) -> Result<EngineStatus, EngineError> {
        if self.down {
            return Err(EngineError::ReplyLost);
        }
        Ok(self.state.get(a).cloned().unwrap_or(EngineStatus::Unknown))
    }
    fn pause(&mut self, a: &str) -> Result<(), EngineError> {
        self.paused.push(a.into());
        Ok(())
    }
    fn resume(&mut self, a: &str) -> Result<(), EngineError> {
        self.resumed.push(a.into());
        Ok(())
    }
}

fn env(rid: &str, body: Message) -> Envelope {
    Envelope {
        version: PROTOCOL_VERSION,
        message_id: format!("m-{rid}-{}", body.kind()),
        session_id: "s".into(),
        request_id: rid.into(),
        generation: 1,
        body,
    }
}

/// Prepares, arms and commits one task for `host`; returns its task id.
fn commit<S: Store>(core: &mut Core<S>, n: u32, host: &str) -> u64 {
    let rid = format!("r{n}");
    let body = PrepareBody {
        download_key: format!("k{n}"),
        url: format!("https://{host}/f{n}.zip"),
        filename: format!("f{n}.zip"),
        context: Secret("c".into()),
    };
    let out = core.handle(&env(&rid, Message::Prepare(body)), 1);
    let Message::Prepared(r) = out.body else {
        panic!("prepare failed: {:?}", out.body)
    };
    let rr = RequestRef {
        task_id: r.task_id,
        fingerprint: r.fingerprint,
    };
    core.handle(&env(&rid, Message::BeginHandoff(rr.clone())), 2);
    core.handle(
        &env(
            &rid,
            Message::Commit(CommitBody {
                cancel: CancelEvidence::Confirmed,
                receipt: rr,
            }),
        ),
        3,
    );
    r.task_id
}

fn state<S: Store>(c: &Core<S>, id: u64) -> TaskState {
    c.store.get_by_task(id).unwrap().unwrap().state
}

fn rec<S: Store>(c: &Core<S>, id: u64) -> velqra_core::store::Record {
    c.store.get_by_task(id).unwrap().unwrap()
}

fn attempt(id: u64) -> String {
    format!("t{id}-g1")
}

fn new_core(max_active: u32, per_origin: u32) -> Core<MemStore> {
    Core::new(MemStore::default()).with_limits(max_active, per_origin)
}

#[test]
fn at_most_max_active_tasks_run_and_the_rest_wait_visibly() {
    let mut c = new_core(2, 99);
    let mut e = Fake::default();
    let ids: Vec<u64> = (1..=5).map(|n| commit(&mut c, n, "a.test")).collect();
    c.pump_at(&mut e, 10).unwrap();
    assert_eq!(e.submitted, [attempt(ids[0]), attempt(ids[1])]);
    for id in &ids[2..] {
        let r = rec(&c, *id);
        assert_eq!(r.state, TaskState::Committed);
        assert_eq!(r.queued_reason.as_deref(), Some("waiting for a free slot"));
    }
    assert_eq!(
        rec(&c, ids[0]).queued_reason,
        None,
        "a started task shows no wait"
    );
    // a finishing task frees exactly one slot
    e.finish(&attempt(ids[0]));
    c.pump_at(&mut e, 11).unwrap();
    assert_eq!(e.submitted.len(), 3);
    assert_eq!(e.submitted[2], attempt(ids[2]));
    assert_eq!(rec(&c, ids[2]).queued_reason, None);
}

#[test]
fn waiting_tasks_start_by_priority_then_arrival() {
    let mut c = new_core(1, 99);
    let mut e = Fake::default();
    let ids: Vec<u64> = (1..=4).map(|n| commit(&mut c, n, "a.test")).collect();
    c.set_priority(ids[3], 10).unwrap();
    c.set_priority(ids[2], 5).unwrap();
    for (round, want) in [ids[3], ids[2], ids[0], ids[1]].into_iter().enumerate() {
        c.pump_at(&mut e, 10 + round as u64).unwrap();
        assert_eq!(e.submitted.last(), Some(&attempt(want)), "round {round}");
        e.finish(&attempt(want));
        c.pump_at(&mut e, 10 + round as u64).unwrap(); // records the finish
    }
    assert_eq!(
        rec(&c, ids[3]).priority,
        10,
        "priority is persisted on the record"
    );
}

#[test]
fn at_most_per_origin_tasks_run_per_site_and_a_busy_site_does_not_block_others() {
    let mut c = new_core(10, 1);
    let mut e = Fake::default();
    let a1 = commit(&mut c, 1, "a.test");
    let a2 = commit(&mut c, 2, "a.test");
    let b1 = commit(&mut c, 3, "b.test");
    c.pump_at(&mut e, 10).unwrap();
    assert_eq!(e.submitted, [attempt(a1), attempt(b1)]);
    assert_eq!(
        rec(&c, a2).queued_reason.as_deref(),
        Some("waiting for a free connection to this site")
    );
    e.finish(&attempt(a1));
    c.pump_at(&mut e, 11).unwrap();
    assert!(e.submitted.contains(&attempt(a2)));
    // spelling does not buy a second slot
    let mut c = new_core(10, 1);
    let mut e = Fake::default();
    commit(&mut c, 1, "A.Test");
    commit(&mut c, 2, "a.test");
    c.pump_at(&mut e, 10).unwrap();
    assert_eq!(e.submitted.len(), 1, "host case must not matter");
}

#[test]
fn the_queue_survives_a_restart_and_the_limits_still_hold() {
    let d = tempfile::tempdir().unwrap();
    let db = d.path().join("c.db");
    let vault = MemVault::default();
    let ids: Vec<u64>;
    {
        let mut c = Core::with_vault(SqliteStore::open(&db).unwrap(), Box::new(vault.clone()))
            .with_limits(2, 99);
        let mut e = Fake::default();
        ids = (1..=4).map(|n| commit(&mut c, n, "a.test")).collect();
        c.pump_at(&mut e, 10).unwrap();
        assert_eq!(e.submitted.len(), 2);
    }
    let mut c = Core::with_vault(SqliteStore::open(&db).unwrap(), Box::new(vault.clone()))
        .with_limits(2, 99);
    let mut e = Fake::default(); // a new engine that, like a fresh process, knows nothing
    c.pump_at(&mut e, 20).unwrap();
    assert!(
        e.submitted.is_empty(),
        "the two running tasks still hold both slots: {:?}",
        e.submitted
    );
    for id in &ids[2..] {
        assert_eq!(rec(&c, *id).state, TaskState::Committed);
    }
    e.state.insert(attempt(ids[0]), EngineStatus::Done);
    e.state.insert(attempt(ids[1]), EngineStatus::Done);
    c.pump_at(&mut e, 21).unwrap();
    c.pump_at(&mut e, 22).unwrap();
    assert_eq!(e.submitted, [attempt(ids[2]), attempt(ids[3])]);
}

fn delays_until_failed(max_active: u32) -> (Vec<u64>, TaskState, Option<String>, Vec<String>) {
    let mut c = new_core(max_active, 99);
    let mut e = Fake::default();
    let id = commit(&mut c, 1, "a.test");
    let mut now = 1000u64;
    let mut delays = Vec::new();
    c.pump_at(&mut e, now).unwrap();
    for _ in 0..8 {
        let a = e.submitted.last().unwrap().clone();
        e.interrupt(&a);
        c.pump_at(&mut e, now).unwrap();
        let r = rec(&c, id);
        if r.state == TaskState::Failed {
            break;
        }
        assert_eq!(r.state, TaskState::Committed);
        assert_eq!(r.queued_reason.as_deref(), Some("waiting to retry"));
        delays.push(r.retry_at - now);
        // not before it is due
        c.pump_at(&mut e, r.retry_at - 1).unwrap();
        let before = e.submitted.len();
        now = r.retry_at;
        c.pump_at(&mut e, now).unwrap();
        assert_eq!(e.submitted.len(), before + 1, "retried exactly when due");
    }
    let r = rec(&c, id);
    (delays, r.state, r.fail_reason, e.submitted)
}

#[test]
fn a_transient_failure_is_retried_with_doubling_delays_a_fresh_attempt_and_a_cap() {
    let (delays, end_state, reason, submitted) = delays_until_failed(3);
    assert_eq!(delays, [5, 10, 20, 40, 80]);
    assert_eq!(end_state, TaskState::Failed);
    assert_eq!(reason.as_deref(), Some("transfer failed after retries"));
    assert_eq!(
        submitted,
        ["t1-g1", "t1-g1-r1", "t1-g1-r2", "t1-g1-r3", "t1-g1-r4", "t1-g1-r5"]
    );
}

#[test]
fn a_permanent_failure_is_never_retried() {
    let mut c = new_core(3, 99);
    let mut e = Fake::default();
    let id = commit(&mut c, 1, "a.test");
    c.pump_at(&mut e, 10).unwrap();
    e.fail(&attempt(id));
    for t in 11..30 {
        c.pump_at(&mut e, t).unwrap();
    }
    assert_eq!(state(&c, id), TaskState::Failed);
    assert_eq!(e.submitted.len(), 1);
    assert_eq!(rec(&c, id).fail_reason.as_deref(), Some("transfer failed"));
}

#[test]
fn a_retrying_task_does_not_hold_a_running_slot_while_it_waits() {
    let mut c = new_core(1, 99);
    let mut e = Fake::default();
    let first = commit(&mut c, 1, "a.test");
    let second = commit(&mut c, 2, "a.test");
    c.pump_at(&mut e, 100).unwrap();
    e.interrupt(&attempt(first));
    c.pump_at(&mut e, 100).unwrap();
    // while the first waits out its backoff the single slot goes to the next task
    assert_eq!(e.submitted.last(), Some(&attempt(second)));
    assert_eq!(state(&c, first), TaskState::Committed);
}

#[test]
fn pause_reasons_survive_and_a_paused_task_is_not_started() {
    let d = tempfile::tempdir().unwrap();
    let db = d.path().join("c.db");
    let vault = MemVault::default();
    let (a, b);
    {
        let mut c = Core::with_vault(SqliteStore::open(&db).unwrap(), Box::new(vault.clone()))
            .with_limits(5, 99);
        let mut e = Fake::default();
        a = commit(&mut c, 1, "a.test");
        b = commit(&mut c, 2, "a.test");
        c.pause_task(&mut e, b, "paused by the user").unwrap();
        c.pump_at(&mut e, 10).unwrap();
        assert_eq!(e.submitted, [attempt(a)], "the paused task stays put");
    }
    let mut c = Core::with_vault(SqliteStore::open(&db).unwrap(), Box::new(vault.clone()))
        .with_limits(5, 99);
    let mut e = Fake::default();
    let r = rec(&c, b);
    assert!(r.paused);
    assert_eq!(r.pause_reason.as_deref(), Some("paused by the user"));
    c.pump_at(&mut e, 20).unwrap();
    assert!(!e.submitted.contains(&attempt(b)));
    c.resume_task(&mut e, b).unwrap();
    c.pump_at(&mut e, 21).unwrap();
    assert!(e.submitted.contains(&attempt(b)));
    assert!(!rec(&c, b).paused && rec(&c, b).pause_reason.is_none());
}

#[test]
fn pausing_a_running_task_pauses_it_in_the_engine_and_keeps_its_slot() {
    let mut c = new_core(1, 99);
    let mut e = Fake::default();
    let first = commit(&mut c, 1, "a.test");
    let second = commit(&mut c, 2, "a.test");
    c.pump_at(&mut e, 10).unwrap();
    c.pause_task(&mut e, first, "paused by the user").unwrap();
    assert_eq!(e.paused, [attempt(first)]);
    c.pump_at(&mut e, 11).unwrap();
    assert!(
        !e.submitted.contains(&attempt(second)),
        "the paused task still holds the slot"
    );
    c.resume_task(&mut e, first).unwrap();
    assert_eq!(e.resumed, [attempt(first)]);
}

#[test]
fn a_task_whose_submit_reply_was_lost_keeps_its_slot_until_its_fate_is_known() {
    let mut c = new_core(1, 99);
    let mut e = Fake::default();
    let first = commit(&mut c, 1, "a.test");
    let second = commit(&mut c, 2, "a.test");
    e.lose_next = true;
    c.pump_at(&mut e, 10).unwrap();
    assert_eq!(e.submitted, [attempt(first)]);
    assert!(rec(&c, first).engine_ambiguous);
    // the second must not start while the first might be running
    e.down = true;
    for t in 11..14 {
        c.pump_at(&mut e, t).unwrap();
    }
    assert!(!e.submitted.contains(&attempt(second)));
    e.down = false;
    c.pump_at(&mut e, 20).unwrap();
    assert_eq!(state(&c, first), TaskState::Transferring);
    assert!(
        !e.submitted.contains(&attempt(second)),
        "now it is plainly running and still holds the slot"
    );
}

#[test]
fn an_engine_that_cannot_be_asked_does_not_fail_or_retry_running_tasks() {
    let mut c = new_core(2, 99);
    let mut e = Fake::default();
    let id = commit(&mut c, 1, "a.test");
    c.pump_at(&mut e, 10).unwrap();
    e.down = true;
    for t in 11..40 {
        c.pump_at(&mut e, t).unwrap();
    }
    assert_eq!(state(&c, id), TaskState::Transferring);
    assert_eq!(e.submitted.len(), 1);
    assert_eq!(rec(&c, id).retries, 0);
}

#[test]
fn the_engine_is_asked_at_most_once_per_poll_interval() {
    let mut c = new_core(2, 99).with_poll_interval(3);
    let mut e = Fake::default();
    commit(&mut c, 1, "a.test");
    c.pump_at(&mut e, 10).unwrap(); // starts it and polls
    let base = e.finished_calls;
    for t in [11, 12] {
        c.pump_at(&mut e, t).unwrap();
        assert_eq!(e.finished_calls, base, "t={t}: too early to ask again");
    }
    c.pump_at(&mut e, 13).unwrap();
    assert_eq!(
        e.finished_calls,
        base + 1,
        "exactly the interval later it asks"
    );
    c.pump_at(&mut e, 14).unwrap();
    assert_eq!(e.finished_calls, base + 1);
}

#[test]
fn unknown_tasks_are_refused_not_invented() {
    let mut c = new_core(1, 1);
    let mut e = Fake::default();
    assert!(c.set_priority(99, 1).is_err());
    assert!(c.pause_task(&mut e, 99, "x").is_err());
    assert!(c.resume_task(&mut e, 99).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]
    /// Under any interleaving of arrivals, completions and clock ticks the limits are never
    /// exceeded, and once nothing new arrives every task eventually completes.
    #[test]
    fn the_limits_hold_under_random_schedules_and_nothing_starves(
        max_active in 1u32..4,
        per_origin in 1u32..3,
        ops in proptest::collection::vec((0u8..4, 0usize..3), 5..60),
    ) {
        let mut c = new_core(max_active, per_origin);
        let mut e = Fake::default();
        let hosts = ["a.test", "b.test", "c.test"];
        let mut ids: Vec<(u64, usize)> = Vec::new();
        let mut now = 1000u64;
        let mut n = 0u32;
        let check = |c: &Core<MemStore>, ids: &[(u64, usize)]| -> Result<(), TestCaseError> {
            let running: Vec<usize> = ids
                .iter()
                .filter(|(id, _)| rec(c, *id).state == TaskState::Transferring)
                .map(|(_, h)| *h)
                .collect();
            prop_assert!(running.len() as u32 <= max_active, "{} > {}", running.len(), max_active);
            for h in 0..3 {
                let k = running.iter().filter(|x| **x == h).count() as u32;
                prop_assert!(k <= per_origin, "host {}: {} > {}", h, k, per_origin);
            }
            Ok(())
        };
        for (op, host) in ops {
            now += 1;
            match op {
                0 | 1 => {
                    n += 1;
                    ids.push((commit(&mut c, n, hosts[host]), host));
                }
                2 => {
                    let running: Vec<u64> = ids.iter().map(|(i, _)| *i)
                        .filter(|i| rec(&c, *i).state == TaskState::Transferring).collect();
                    if !running.is_empty() {
                        let id = running[host % running.len()];
                        e.finish(&rec(&c, id).dispatch_attempt.unwrap());
                    }
                }
                _ => {}
            }
            c.pump_at(&mut e, now).unwrap();
            check(&c, &ids)?;
        }
        // drain: complete everything that runs until nothing is left
        for _ in 0..(ids.len() * 3 + 5) {
            now += 1;
            let running: Vec<u64> = ids.iter().map(|(i, _)| *i)
                .filter(|i| rec(&c, *i).state == TaskState::Transferring).collect();
            for id in running {
                e.finish(&rec(&c, id).dispatch_attempt.unwrap());
            }
            c.pump_at(&mut e, now).unwrap();
            check(&c, &ids)?;
        }
        for (id, _) in &ids {
            prop_assert_eq!(rec(&c, *id).state, TaskState::Done, "task {} starved", id);
        }
    }
}
