// SPDX-License-Identifier: GPL-3.0-only
//! Regression tests for the second Codex review (24c): R-C1, R-I3, R-I4, R-I5.
use std::{cell::RefCell, rc::Rc};
use velqra_core::{Engine, EngineRequest};
use velqra_protocol::*;
use velqra_sim::fault::{FaultCtl, FaultKind};
use velqra_sim::invariants::{check, classify, Outcome};
use velqra_sim::scenarios::run_with;
use velqra_sim::world::{JState, World, SENTINEL};

fn world_with(ctl: FaultCtl) -> World {
    World::new(Rc::new(RefCell::new(ctl)))
}

fn step_until(w: &mut World, ok: impl Fn(&World) -> bool, what: &str) {
    for _ in 0..80 {
        if ok(w) {
            return;
        }
        w.step();
    }
    panic!("never reached: {what}");
}

fn matching(state: TaskState, w: &World) -> Receipt {
    let r = w.journal_receipt().expect("journal holds the receipt");
    Receipt {
        task_id: r.task_id,
        fingerprint: r.fingerprint,
        state,
    }
}

// ---- R-C1: an engine call the core never logged cannot hide behind a later valid one ----

#[test]
fn an_early_engine_call_hidden_by_a_later_valid_dispatch_is_caught() {
    let mut w = world_with(FaultCtl::default());
    step_until(
        &mut w,
        |w| w.journal_state() == Some(JState::ReceiptStored),
        "receipt stored",
    );
    // a buggy core touches the engine before any commit, and does not log it
    let early = EngineRequest {
        attempt: "t1-g1".into(),
        url: "https://x.test/a.zip".into(),
        filename: "a.zip".into(),
        context_ref: None,
    };
    let _ = w.engine.submit(&early);
    let r = w.run();
    assert!(r.quiesced);
    let v = check(&r);
    assert!(
        v.iter().any(|m| m.starts_with("I2")),
        "early engine call went unnoticed: {v:?}"
    );
}

#[test]
fn every_engine_call_in_a_normal_run_is_ledgered() {
    let (r, _) = run_with(vec![], vec![], false, 0);
    assert_eq!(r.engine_calls, r.dispatches.len());
    assert!(r.engine_calls >= 1);
}

// ---- R-I3: a reconcile acknowledgement must carry a state that answers the question ----

#[test]
fn a_held_extension_ignores_a_reconciled_reply_in_an_unrelated_state() {
    let dead = [
        ("ext.journal.cancel_confirmed", FaultKind::StorageError),
        ("ext.journal.reconcile_required", FaultKind::StorageError),
        ("ext.journal.commit_sent", FaultKind::StorageError),
        ("ext.journal.handed_off", FaultKind::StorageError),
    ];
    let mut ctl = FaultCtl::default();
    for (n, k) in dead {
        ctl = ctl.persistent(n, k);
    }
    let mut w = world_with(ctl);
    step_until(
        &mut w,
        |w| w.is_held() && w.pending_kind() == Some("reconcile"),
        "post-cancel hold",
    );
    for bad in [TaskState::Armed, TaskState::Prepared, TaskState::Aborted] {
        let env = w.make_env(Message::Reconciled(matching(bad, &w)));
        w.feed_ext(env);
        assert_eq!(
            w.pending_kind(),
            Some("reconcile"),
            "{bad:?} acknowledged the reconcile"
        );
    }
    let env = w.make_env(Message::Reconciled(matching(
        TaskState::OwnershipUnknown,
        &w,
    )));
    w.feed_ext(env);
    assert_eq!(
        w.pending_kind(),
        None,
        "a state that answers the question must be accepted"
    );
}

#[test]
fn reconcile_required_ignores_a_reconciled_reply_in_an_unrelated_state() {
    let mut ctl = FaultCtl::default();
    ctl.plan_name.push((
        "browser.cancel".into(),
        1,
        FaultKind::BrowserUnknownNotApplied,
    ));
    let mut w = world_with(ctl);
    step_until(
        &mut w,
        |w| w.journal_state() == Some(JState::ReconcileRequired),
        "reconcile required",
    );
    for bad in [TaskState::Armed, TaskState::Prepared, TaskState::Aborted] {
        let env = w.make_env(Message::Reconciled(matching(bad, &w)));
        w.feed_ext(env);
        assert_eq!(
            w.pending_kind(),
            Some("reconcile"),
            "{bad:?} acknowledged the reconcile"
        );
        assert_eq!(w.journal_state(), Some(JState::ReconcileRequired));
    }
}

// ---- R-I4: a vanished browser item is injected at every recovery state ----

#[test]
fn an_erased_item_before_the_cancel_gate_is_returned_cleanly_and_was_injected() {
    for state in ["receipt_stored", "prepare_sent", "paused"] {
        let plan = vec![
            (format!("ext.journal.{state}"), 1, FaultKind::CrashAfter),
            ("ext.recover.browser".to_string(), 1, FaultKind::ItemErased),
        ];
        let r = run_with(vec![], plan, false, 0).0;
        assert!(
            r.injected.iter().any(|(_, k)| *k == FaultKind::ItemErased),
            "{state}: erase not injected"
        );
        assert_eq!(classify(&r), Outcome::Returned, "{state}");
        assert!(
            r.browser_cancelled_by.is_none(),
            "{state}: the journal proves no cancel was issued"
        );
        assert!(check(&r).is_empty(), "{state}: {:?}", check(&r));
    }
}

// ---- R-I5: rejected messages never put untrusted detail into the trace ----

#[test]
fn error_detail_from_a_rejected_envelope_is_not_logged() {
    let mut w = world_with(FaultCtl::default());
    step_until(
        &mut w,
        |w| w.journal_state() == Some(JState::PrepareSent),
        "prepare sent",
    );
    let mut env = w.make_env(Message::Error(ProtoError::new(
        ErrorKind::Malformed,
        SENTINEL,
    )));
    env.session_id = "other".into();
    w.feed_ext(env);
    let r = w.record(false);
    assert!(!r.trace_leaks_secret, "error detail reached the trace");
}
