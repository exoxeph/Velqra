// SPDX-License-Identifier: GPL-3.0-only
use velqra_sim::fault::FaultKind::*;
use velqra_sim::invariants::{check, classify, Outcome};
use velqra_sim::scenarios::{by_name, run_with};
use velqra_sim::world::RunRecord;

fn assert_row(r: &RunRecord, allowed: &[Outcome]) {
    let v = check(r);
    assert!(v.is_empty(), "violations: {v:?}\nfaults: {:?}", r.injected);
    assert!(
        allowed.contains(&classify(r)),
        "outcome {:?} not in {allowed:?}",
        classify(r)
    );
}

#[test]
fn row_app_absent_before_prepare() {
    let (r, _) = run_with(vec![], vec![], false, 10);
    assert_row(&r, &[Outcome::Returned]);
}
#[test]
fn row_prepare_ack_lost() {
    assert_row(
        &by_name("core.reply.prepared", 1, Loss),
        &[Outcome::HandedOff],
    );
}
#[test]
fn row_storage_error_on_prepare_returns_to_browser() {
    assert_row(
        &by_name("core.store.put", 1, StorageError),
        &[Outcome::Returned],
    );
}
#[test]
fn row_extension_journal_write_fails_before_cancel() {
    assert_row(
        &by_name("ext.journal.cancel_intent_stored", 1, StorageError),
        &[Outcome::Returned],
    );
}
#[test]
fn row_app_dies_after_durable_receipt() {
    assert_row(
        &by_name("core.reply.prepared", 1, CrashAfter),
        &[Outcome::HandedOff, Outcome::Returned],
    );
}
#[test]
fn row_browser_finishes_during_cancel() {
    let r = by_name("browser.cancel", 1, RaceComplete);
    assert_row(&r, &[Outcome::Returned]);
    assert!(r.engine_attempts.is_empty());
}
#[test]
fn row_worker_dies_before_cancel() {
    assert_row(
        &by_name("ext.journal.cancel_requested", 1, CrashBefore),
        &[Outcome::Returned],
    );
}
#[test]
fn row_worker_dies_after_cancel_before_confirmed_is_saved() {
    assert_row(
        &by_name("ext.journal.cancel_confirmed", 1, CrashBefore),
        &[Outcome::NeedsUser],
    );
}
#[test]
fn row_worker_dies_after_confirmed_before_commit() {
    assert_row(
        &by_name("ext.journal.cancel_confirmed", 1, CrashAfter),
        &[Outcome::HandedOff],
    );
}
#[test]
fn row_commit_ack_lost_never_recreates_a_browser_task() {
    let r = by_name("core.reply.committed", 1, Loss);
    assert_row(&r, &[Outcome::HandedOff]);
    assert_eq!(r.engine_attempts.len(), 1);
}
#[test]
fn row_user_cancel_is_honoured() {
    let r = by_name("browser.cancel", 1, UserCancelFirst);
    assert_row(&r, &[Outcome::Returned]);
    assert!(r.engine_attempts.is_empty());
}
#[test]
fn row_cancel_outcome_unknown_needs_the_user() {
    assert_row(
        &by_name("browser.cancel", 1, BrowserUnknownApplied),
        &[Outcome::NeedsUser],
    );
    assert_row(
        &by_name("browser.cancel", 1, BrowserUnknownNotApplied),
        &[Outcome::NeedsUser],
    );
}
#[test]
fn row_engine_reply_lost_does_not_double_submit() {
    let r = by_name("engine.submit", 1, LostReply);
    assert_row(&r, &[Outcome::HandedOff]);
    assert_eq!(r.engine_attempts.len(), 1);
}
#[test]
fn row_duplicate_messages_are_idempotent() {
    for name in [
        "net.ext_to_core.prepare",
        "net.ext_to_core.commit",
        "core.reply.committed",
    ] {
        assert_row(
            &by_name(name, 1, Duplicate),
            &[Outcome::HandedOff, Outcome::Returned],
        );
    }
}

#[test]
fn row_journal_write_of_final_handed_off_state_fails_and_is_retried() {
    let r = by_name("ext.journal.handed_off", 1, StorageError);
    assert_row(&r, &[Outcome::HandedOff]);
}

#[test]
fn row_journal_write_of_final_returned_state_fails_and_is_retried() {
    let plan = vec![
        (
            "ext.journal.cancel_intent_stored".to_string(),
            1,
            StorageError,
        ),
        ("ext.journal.returned".to_string(), 1, StorageError),
    ];
    let (r, _) = run_with(vec![], plan, false, 0);
    assert_row(&r, &[Outcome::Returned]);
}

#[test]
fn row_abort_decision_survives_a_failed_returning_journal_write() {
    let plan = vec![
        (
            "ext.journal.cancel_intent_stored".to_string(),
            1,
            CrashAfter,
        ),
        ("ext.journal.returning".to_string(), 1, StorageError),
    ];
    let (r, _) = run_with(vec![], plan, false, 0);
    assert_row(&r, &[Outcome::Returned]);
}

#[test]
fn row_reconcile_journal_write_failure_is_retried() {
    let plan = vec![
        ("browser.cancel".to_string(), 1, BrowserUnknownApplied),
        (
            "ext.journal.reconcile_required".to_string(),
            1,
            StorageError,
        ),
    ];
    let (r, _) = run_with(vec![], plan, false, 0);
    assert_row(&r, &[Outcome::NeedsUser]);
}
