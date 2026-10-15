// SPDX-License-Identifier: GPL-3.0-only
//! B1: what the core does when an engine's reply to a submit is lost. The attempt id is the task's
//! identity inside the engine; the core must establish it with `status` before it ever submits
//! again, resubmit at most once when the engine says it has never heard of it, and hold the task
//! visibly when identity cannot be proven. A rejection is terminal.
use std::collections::VecDeque;
use velqra_core::store::{MemStore, Store};
use velqra_core::{Core, Engine, EngineError, EngineRequest, EngineStatus};
use velqra_protocol::*;

/// An engine whose replies are scripted.
#[derive(Default)]
struct Scripted {
    /// What each submit call answers; `applied` says whether the engine really took the task.
    submits: VecDeque<(Result<(), EngineError>, bool)>,
    statuses: VecDeque<Result<EngineStatus, EngineError>>,
    known: Vec<String>,
    /// How many times in a row the engine claims to have forgotten the task.
    forgets: usize,
    submit_calls: usize,
    status_calls: usize,
}

impl Engine for Scripted {
    fn submit(&mut self, r: &EngineRequest) -> Result<(), EngineError> {
        self.submit_calls += 1;
        let (reply, applied) = self.submits.pop_front().unwrap_or((Ok(()), true));
        if applied && !self.known.contains(&r.attempt) {
            self.known.push(r.attempt.clone());
        }
        reply
    }
    fn finished(&mut self, _attempt: &str) -> Option<bool> {
        None
    }
    fn has_forgotten(&mut self, _attempt: &str) -> bool {
        if self.forgets > 0 {
            self.forgets -= 1;
            true
        } else {
            false
        }
    }
    fn status(&mut self, _attempt: &str) -> Result<EngineStatus, EngineError> {
        self.status_calls += 1;
        self.statuses
            .pop_front()
            .unwrap_or(Ok(EngineStatus::Unknown))
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

fn committed_core() -> Core<MemStore> {
    let mut c = Core::new(MemStore::default());
    let rr = RequestRef {
        task_id: 1,
        fingerprint: fingerprint(&body()),
    };
    let env = |n: &str, m: Message| Envelope {
        version: PROTOCOL_VERSION,
        message_id: n.into(),
        session_id: "s".into(),
        request_id: "r1".into(),
        generation: 1,
        body: m,
    };
    c.handle(&env("m1", Message::Prepare(body())), 1);
    c.handle(&env("m2", Message::BeginHandoff(rr.clone())), 2);
    c.handle(
        &env(
            "m3",
            Message::Commit(CommitBody {
                cancel: CancelEvidence::Confirmed,
                receipt: rr,
            }),
        ),
        3,
    );
    c
}

fn state(c: &Core<MemStore>) -> TaskState {
    c.store.get_by_task(1).unwrap().unwrap().state
}

fn reason(c: &Core<MemStore>) -> Option<String> {
    c.store.get_by_task(1).unwrap().unwrap().fail_reason
}

fn lost(applied: bool) -> (Result<(), EngineError>, bool) {
    (Err(EngineError::ReplyLost), applied)
}

#[test]
fn a_lost_reply_whose_task_is_found_active_is_adopted_without_a_second_submit() {
    let mut c = committed_core();
    let mut e = Scripted::default();
    e.submits.push_back(lost(true));
    e.statuses
        .push_back(Ok(EngineStatus::Active { done: 0, total: 10 }));
    c.pump(&mut e).unwrap();
    assert_eq!(state(&c), TaskState::Committed, "identity not yet proven");
    c.pump(&mut e).unwrap();
    assert_eq!(state(&c), TaskState::Transferring);
    assert_eq!((e.submit_calls, e.known.len()), (1, 1));
}

#[test]
fn a_lost_reply_whose_task_already_finished_ends_without_resubmitting() {
    let mut c = committed_core();
    let mut e = Scripted::default();
    e.submits.push_back(lost(true));
    e.statuses.push_back(Ok(EngineStatus::Done));
    c.pump(&mut e).unwrap();
    c.pump(&mut e).unwrap();
    assert_eq!(state(&c), TaskState::Done);
    assert_eq!(e.submit_calls, 1);
}

#[test]
fn a_lost_reply_whose_task_is_absent_is_resubmitted_exactly_once() {
    let mut c = committed_core();
    let mut e = Scripted::default();
    e.submits.push_back(lost(false)); // never applied
    e.statuses.push_back(Ok(EngineStatus::Unknown));
    c.pump(&mut e).unwrap();
    c.pump(&mut e).unwrap();
    assert_eq!(e.submit_calls, 2, "one original and one resubmission");
    assert_eq!(e.known.len(), 1, "a single engine task");
    assert_eq!(state(&c), TaskState::Transferring);
}

#[test]
fn a_second_lost_reply_after_the_resubmission_holds_the_task_after_the_query_budget() {
    let mut c = committed_core();
    let mut e = Scripted::default();
    e.submits.push_back(lost(false));
    e.submits.push_back(lost(false));
    for _ in 0..20 {
        e.statuses.push_back(Ok(EngineStatus::Unknown));
    }
    for _ in 0..30 {
        c.pump(&mut e).unwrap();
    }
    assert_eq!(e.submit_calls, 2, "never a third submit");
    assert_eq!(state(&c), TaskState::Committed);
    assert_eq!(reason(&c).as_deref(), Some("engine identity unprovable"));
    let calls = e.status_calls;
    c.pump(&mut e).unwrap();
    assert_eq!(e.status_calls, calls, "a held task is not polled again");
}

#[test]
fn an_engine_that_cannot_answer_status_never_causes_a_blind_resubmit() {
    let mut c = committed_core();
    let mut e = Scripted::default();
    e.submits.push_back(lost(true));
    for _ in 0..20 {
        e.statuses.push_back(Err(EngineError::ReplyLost));
    }
    for _ in 0..25 {
        c.pump(&mut e).unwrap();
    }
    assert_eq!(e.submit_calls, 1);
    assert_eq!(state(&c), TaskState::Committed);
    assert_eq!(reason(&c).as_deref(), Some("engine identity unprovable"));
}

#[test]
fn the_query_budget_is_five_so_four_failed_queries_still_recover() {
    let mut c = committed_core();
    let mut e = Scripted::default();
    e.submits.push_back(lost(true));
    for _ in 0..4 {
        e.statuses.push_back(Err(EngineError::ReplyLost));
    }
    e.statuses.push_back(Ok(EngineStatus::Paused));
    for _ in 0..6 {
        c.pump(&mut e).unwrap();
    }
    assert_eq!(state(&c), TaskState::Transferring);
    assert_eq!(reason(&c), None);
}

#[test]
fn a_rejection_is_terminal_and_asks_nothing() {
    let mut c = committed_core();
    let mut e = Scripted::default();
    e.submits.push_back((Err(EngineError::Rejected), false));
    c.pump(&mut e).unwrap();
    assert_eq!(state(&c), TaskState::Failed);
    assert_eq!(reason(&c).as_deref(), Some("engine rejected the task"));
    for _ in 0..3 {
        c.pump(&mut e).unwrap();
    }
    assert_eq!((e.submit_calls, e.status_calls), (1, 0));
}

#[test]
fn engine_failure_text_never_reaches_the_record() {
    let mut c = committed_core();
    let mut e = Scripted::default();
    e.submits.push_back(lost(true));
    e.statuses.push_back(Ok(EngineStatus::Failed(
        "GET https://secret.example/t=1 refused".into(),
    )));
    c.pump(&mut e).unwrap();
    c.pump(&mut e).unwrap();
    assert_eq!(state(&c), TaskState::Failed);
    assert_eq!(reason(&c).as_deref(), Some("transfer failed"));
}

#[test]
fn the_default_controls_are_unsupported_and_status_maps_the_old_finished_call() {
    struct Old;
    impl Engine for Old {
        fn submit(&mut self, _: &EngineRequest) -> Result<(), EngineError> {
            Ok(())
        }
        fn finished(&mut self, a: &str) -> Option<bool> {
            match a {
                "ok" => Some(true),
                "bad" => Some(false),
                _ => None,
            }
        }
    }
    let mut e = Old;
    assert_eq!(e.status("ok"), Ok(EngineStatus::Done));
    assert_eq!(
        e.status("bad"),
        Ok(EngineStatus::Failed("transfer failed".into()))
    );
    assert_eq!(e.status("other"), Ok(EngineStatus::Unknown));
    for r in [e.pause("ok"), e.resume("ok"), e.cancel("ok")] {
        assert_eq!(r, Err(EngineError::Unsupported));
    }
}

#[test]
fn the_hold_comes_exactly_at_the_fifth_unanswered_question() {
    let mut c = committed_core();
    let mut e = Scripted::default();
    e.submits.push_back(lost(true));
    for _ in 0..5 {
        e.statuses.push_back(Err(EngineError::ReplyLost));
    }
    e.statuses.push_back(Ok(EngineStatus::Paused)); // would be adopted if the task were not held
    for _ in 0..8 {
        c.pump(&mut e).unwrap();
    }
    assert_eq!(e.status_calls, 5);
    assert_eq!(state(&c), TaskState::Committed);
    assert_eq!(reason(&c).as_deref(), Some("engine identity unprovable"));
}

fn transferring_core(e: &mut Scripted) -> Core<MemStore> {
    let mut c = committed_core();
    c.pump(e).unwrap(); // submit succeeds, the task is now Transferring
    assert_eq!(state(&c), TaskState::Transferring);
    c
}

#[test]
fn a_task_the_engine_has_forgotten_is_submitted_again_with_the_same_attempt() {
    let mut e = Scripted::default();
    let mut c = transferring_core(&mut e);
    e.forgets = 1;
    c.pump(&mut e).unwrap();
    assert_eq!(e.submit_calls, 2, "re-dispatched once");
    assert_eq!(e.known.len(), 1, "same attempt id, one engine task");
    assert_eq!(state(&c), TaskState::Transferring);
    c.pump(&mut e).unwrap();
    assert_eq!(
        e.submit_calls, 2,
        "nothing more while the engine remembers it"
    );
}

#[test]
fn a_task_that_keeps_vanishing_fails_visibly_after_three_re_dispatches() {
    let mut e = Scripted::default();
    let mut c = transferring_core(&mut e);
    e.forgets = 100;
    for _ in 0..10 {
        c.pump(&mut e).unwrap();
    }
    assert_eq!(e.submit_calls, 1 + 3);
    assert_eq!(state(&c), TaskState::Failed);
    assert_eq!(reason(&c).as_deref(), Some("engine lost the task"));
}

#[test]
fn a_rejected_re_dispatch_is_terminal() {
    let mut e = Scripted::default();
    let mut c = transferring_core(&mut e);
    e.forgets = 1;
    e.submits.push_back((Err(EngineError::Rejected), false));
    c.pump(&mut e).unwrap();
    assert_eq!(state(&c), TaskState::Failed);
    assert_eq!(reason(&c).as_deref(), Some("engine rejected the task"));
}

#[test]
fn an_unanswered_question_is_not_forgetting() {
    // has_forgotten stays false when the engine cannot be asked, so nothing is submitted again
    let mut e = Scripted::default();
    let mut c = transferring_core(&mut e);
    for _ in 0..5 {
        c.pump(&mut e).unwrap();
    }
    assert_eq!((e.submit_calls, state(&c)), (1, TaskState::Transferring));
}

#[test]
fn a_finished_task_is_never_re_dispatched_even_if_the_engine_also_claims_to_have_forgotten() {
    struct Done;
    impl Engine for Done {
        fn submit(&mut self, _: &EngineRequest) -> Result<(), EngineError> {
            Ok(())
        }
        fn finished(&mut self, _: &str) -> Option<bool> {
            Some(true)
        }
        fn has_forgotten(&mut self, _: &str) -> bool {
            true
        }
    }
    let mut c = committed_core();
    let mut e = Done;
    c.pump(&mut e).unwrap();
    c.pump(&mut e).unwrap();
    assert_eq!(state(&c), TaskState::Done);
}
