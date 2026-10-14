// SPDX-License-Identifier: GPL-3.0-only
//! Regression tests for the Codex review of M0 (findings C3, I3, I6, I7 and the temporal checks).
use std::{cell::RefCell, rc::Rc};
use velqra_protocol::*;
use velqra_sim::browser::{Actor, BState};
use velqra_sim::fault::{FaultCtl, FaultKind};
use velqra_sim::invariants::{check, classify, Outcome};
use velqra_sim::scenarios::{run_persistent, run_with};
use velqra_sim::world::{prepare_body, JState, World};

fn world() -> World {
    World::new(Rc::new(RefCell::new(FaultCtl::default())))
}

fn step_until(w: &mut World, want: JState) {
    for _ in 0..60 {
        if w.journal_state() == Some(want) {
            return;
        }
        w.step();
    }
    panic!("never reached {want:?}, at {:?}", w.journal_state());
}

fn good_receipt(state: TaskState) -> Receipt {
    Receipt {
        task_id: 1,
        fingerprint: fingerprint(&prepare_body()),
        state,
    }
}

// ---- C3: replies are believed only when they carry this run's identity ----

#[test]
fn a_reply_with_the_wrong_session_request_generation_or_version_changes_nothing() {
    for tweak in 0..4 {
        let mut w = world();
        step_until(&mut w, JState::PrepareSent);
        let mut env = w.make_env(Message::Prepared(good_receipt(TaskState::Prepared)));
        match tweak {
            0 => env.session_id = "other".into(),
            1 => env.request_id = "req-2".into(),
            2 => env.generation = 9,
            _ => env.version = PROTOCOL_VERSION + 1,
        }
        w.feed_ext(env);
        assert_eq!(
            w.journal_state(),
            Some(JState::PrepareSent),
            "tweak {tweak} was believed"
        );
    }
}

#[test]
fn a_prepared_reply_for_a_different_payload_is_not_believed() {
    let mut w = world();
    step_until(&mut w, JState::PrepareSent);
    let mut bad = good_receipt(TaskState::Prepared);
    bad.fingerprint = "0".repeat(64);
    let env = w.make_env(Message::Prepared(bad));
    w.feed_ext(env);
    assert_eq!(w.journal_state(), Some(JState::PrepareSent));
}

#[test]
fn the_receipt_is_journaled_and_later_replies_must_match_it() {
    let mut w = world();
    step_until(&mut w, JState::ReceiptStored);
    let held = w
        .journal_receipt()
        .expect("the journal carries the receipt");
    assert_eq!(held.fingerprint, fingerprint(&prepare_body()));
    // an Armed reply for another task id must not unlock the cancel
    let mut other = good_receipt(TaskState::Armed);
    other.task_id = held.task_id + 7;
    let env = w.make_env(Message::Armed(other));
    w.feed_ext(env);
    assert_eq!(w.journal_state(), Some(JState::ReceiptStored));
    // nor must a receipt claiming a state other than Armed
    let env = w.make_env(Message::Armed(Receipt {
        state: TaskState::Prepared,
        ..good_receipt(TaskState::Armed)
    }));
    w.feed_ext(env);
    assert_eq!(w.journal_state(), Some(JState::ReceiptStored));
    assert!(w.browser.cancelled_by.is_none());
}

#[test]
fn an_abort_ack_must_be_aborted_and_match_the_receipt() {
    let mut w = world();
    step_until(&mut w, JState::ReceiptStored);
    let held = w.journal_receipt().unwrap();
    // force the abort path with a pre-cancel failure reply
    let env = w.make_env(Message::Error(ProtoError::new(ErrorKind::WrongState, "no")));
    w.feed_ext(env);
    assert_eq!(w.journal_state(), Some(JState::Returning));
    // NotFound is not an ack any more, and neither is an Aborted receipt for another task
    let env = w.make_env(Message::Error(ProtoError::new(
        ErrorKind::NotFound,
        "unknown",
    )));
    w.feed_ext(env);
    assert_eq!(w.journal_state(), Some(JState::Returning));
    let wrong = Receipt {
        task_id: held.task_id + 1,
        fingerprint: held.fingerprint.clone(),
        state: TaskState::Aborted,
    };
    let env = w.make_env(Message::Aborted(wrong));
    w.feed_ext(env);
    assert_eq!(w.journal_state(), Some(JState::Returning));
    let right = Receipt {
        task_id: held.task_id,
        fingerprint: held.fingerprint,
        state: TaskState::Aborted,
    };
    let env = w.make_env(Message::Aborted(right));
    w.feed_ext(env);
    assert_eq!(w.journal_state(), Some(JState::Returned));
}

// ---- I3: an engine rejection is visible ----

#[test]
fn an_engine_rejection_is_a_visible_failure_and_a_clean_hand_off() {
    let r = run_with(
        vec![],
        vec![("engine.submit".into(), 1, FaultKind::EngineReject)],
        false,
        0,
    )
    .0;
    assert_eq!(r.core_final, Some(TaskState::Failed));
    assert_eq!(classify(&r), Outcome::HandedOff);
    assert!(check(&r).is_empty(), "{:?}", check(&r));
    assert_eq!(
        r.dispatches.len(),
        1,
        "the core stopped retrying after the rejection"
    );
}

// ---- I6: a browser item that vanished is not a resolved ownership ----

#[test]
fn an_erased_browser_item_after_our_cancel_goes_to_reconcile_not_abort() {
    let plan = vec![
        ("browser.cancel".to_string(), 1, FaultKind::CrashAfter),
        ("ext.recover.browser".to_string(), 1, FaultKind::ItemErased),
    ];
    let r = run_with(vec![], plan, false, 0).0;
    assert!(
        r.injected.iter().any(|(_, k)| *k == FaultKind::ItemErased),
        "erase fault was not injected"
    );
    assert_eq!(r.browser_final, BState::Erased);
    assert_eq!(r.browser_cancelled_by, Some(Actor::Ext));
    assert_eq!(classify(&r), Outcome::NeedsUser);
    assert!(check(&r).is_empty(), "{:?}", check(&r));
}

// ---- I7: a broken journal produces a visible hold, never an endless retry ----

#[test]
fn a_journal_that_never_works_holds_before_the_cancel_gate_and_leaves_the_download_alone() {
    let r = run_persistent(&[("ext.journal.*", FaultKind::StorageError)], vec![]);
    assert!(r.held, "no visible hold");
    assert_eq!(classify(&r), Outcome::Held);
    assert_eq!(r.browser_final, BState::InProgress);
    assert!(r.browser_cancelled_by.is_none());
    assert!(r.cancels.is_empty());
    assert!(check(&r).is_empty(), "{:?}", check(&r));
}

#[test]
fn a_journal_that_dies_after_the_cancel_holds_and_asks_the_core_to_surface_the_question() {
    let dead = [
        ("ext.journal.cancel_confirmed", FaultKind::StorageError),
        ("ext.journal.reconcile_required", FaultKind::StorageError),
        ("ext.journal.commit_sent", FaultKind::StorageError),
        ("ext.journal.handed_off", FaultKind::StorageError),
    ];
    let r = run_persistent(&dead, vec![]);
    assert!(r.held, "no visible hold");
    assert_eq!(r.browser_cancelled_by, Some(Actor::Ext));
    assert_eq!(r.core_final, Some(TaskState::OwnershipUnknown));
    assert!(check(&r).is_empty(), "{:?}", check(&r));
}

// ---- temporal ledger: the happy path records what it should ----

#[test]
fn the_happy_path_ledgers_one_armed_cancel_and_one_committed_dispatch() {
    let (r, _) = run_with(vec![], vec![], false, 0);
    assert_eq!(r.cancels.len(), 1);
    assert_eq!(r.cancels[0].journal, Some(JState::CancelRequested));
    assert_eq!(r.cancels[0].core, Some(TaskState::Armed));
    assert_eq!(r.dispatches.len(), 1);
    assert_eq!(r.dispatches[0].state_before, TaskState::Committed);
}
