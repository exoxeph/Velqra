// SPDX-License-Identifier: GPL-3.0-only
//! Invariants I1-I10 of the ownership protocol, checked on every finished run.

use crate::browser::{Actor, BState};
use crate::world::{JState, RunRecord};
use velqra_protocol::TaskState;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Outcome {
    HandedOff,
    Returned,
    NeedsUser,
    /// The extension gave up journaling and showed a hold; the browser keeps (or the app has) the file.
    Held,
    Unclassified,
}

pub fn classify(r: &RunRecord) -> Outcome {
    use TaskState::*;
    if r.held {
        return Outcome::Held;
    }
    match (r.ext_final, r.core_final) {
        (Some(JState::HandedOff), Some(Transferring | Done)) if r.engine_attempts.len() == 1 => {
            Outcome::HandedOff
        }
        // the engine refused the task: still handed off, and the failure is visible in the core
        (Some(JState::HandedOff), Some(Failed)) if r.engine_attempts.len() <= 1 => {
            Outcome::HandedOff
        }
        (Some(JState::Returned), None | Some(Aborted)) if r.engine_attempts.is_empty() => {
            Outcome::Returned
        }
        (Some(JState::ReconcileRequired), Some(OwnershipUnknown)) => Outcome::NeedsUser,
        _ => Outcome::Unclassified,
    }
}

pub fn check(r: &RunRecord) -> Vec<String> {
    use TaskState::*;
    let mut v = Vec::new();
    if !r.quiesced {
        v.push(format!("LIVENESS: no quiescence within {} ticks", r.ticks));
    }
    let outcome = classify(r);
    if outcome == Outcome::Unclassified {
        v.push(format!(
            "I1: unclassified final state ext={:?} core={:?} engine={}",
            r.ext_final,
            r.core_final,
            r.engine_attempts.len()
        ));
    }
    // I1: every acknowledged intent ends resolved or surfaced
    if !r.acked_prepares.is_empty() {
        match r.core_final {
            Some(Transferring | Done | Failed | Aborted | OwnershipUnknown) => {}
            other => v.push(format!("I1: acknowledged intent ended as {other:?}")),
        }
    }
    // I1: the browser download is never lost
    let held_but_owned = outcome == Outcome::Held
        && matches!(
            r.core_final,
            Some(Transferring | Done | Failed | OwnershipUnknown)
        );
    if r.browser_cancelled_by == Some(Actor::Ext)
        && !matches!(outcome, Outcome::HandedOff | Outcome::NeedsUser)
        && !held_but_owned
    {
        v.push("I1: browser download cancelled by the extension but not handed off".into());
    }
    if matches!(outcome, Outcome::Returned | Outcome::Held) && r.browser_final == BState::Paused {
        v.push("I1: returned or held download left paused".into());
    }
    // I2: engine work only after commit
    if !r.engine_attempts.is_empty() && !r.core_history.contains(&Committed) {
        v.push("I2: engine work without a committed record".into());
    }
    // I2, in order: every submission happened while the record was Committed, and none is unlogged
    for d in &r.dispatches {
        if d.state_before != Committed {
            v.push(format!(
                "I2: engine submit while the record was {:?}",
                d.state_before
            ));
        }
    }
    if !r.engine_attempts.is_empty() && r.dispatches.is_empty() {
        v.push("I2: engine work with no dispatch record".into());
    }
    // the engine counts its own calls: a call the core did not log cannot hide behind a later valid one
    if r.engine_calls != r.dispatches.len() {
        v.push(format!(
            "I2: engine received {} calls but the core logged {}",
            r.engine_calls,
            r.dispatches.len()
        ));
    }
    // I3: one owner, no duplicate copies
    if r.engine_attempts.len() > 1 {
        v.push("I3: more than one engine attempt".into());
    }
    if r.browser_final == BState::Completed && !r.engine_attempts.is_empty() {
        v.push("I3: browser and app both copied the file".into());
    }
    // I4: no commit after abort
    if let (Some(a), Some(c)) = (
        r.core_history.iter().position(|s| *s == Aborted),
        r.core_history.iter().position(|s| *s == Committed),
    ) {
        if c > a {
            v.push("I4: committed after abort".into());
        }
    }
    // I5: every cancel happened after a durable receipt and an armed record, and is on the ledger
    for c in &r.cancels {
        if c.journal != Some(JState::CancelRequested) || c.core != Some(Armed) {
            v.push(format!(
                "I5: cancelled with journal={:?} core={:?}",
                c.journal, c.core
            ));
        }
    }
    if r.browser_cancelled_by == Some(Actor::Ext) && r.cancels.is_empty() {
        v.push("I5: browser cancelled by the extension with no cancel ledger entry".into());
    }
    // I6: user cancel honoured
    if r.browser_cancelled_by == Some(Actor::User) && !r.engine_attempts.is_empty() {
        v.push("I6: user cancellation converted into an app transfer".into());
    }
    // I7: browser completed first
    if r.browser_final == BState::Completed
        && !(r.engine_attempts.is_empty() && matches!(r.core_final, None | Some(Aborted)))
    {
        v.push("I7: browser completed first but app state/work exists".into());
    }
    // I9: ambiguity surfaced, never silently resolved
    if outcome != Outcome::Held
        && (r.ext_final == Some(JState::ReconcileRequired))
            != (r.core_final == Some(OwnershipUnknown))
    {
        v.push("I9: ownership ambiguity not surfaced on both sides".into());
    }
    if r.core_final == Some(OwnershipUnknown) && !r.engine_attempts.is_empty() {
        v.push("I9: transfer started while ownership unknown".into());
    }
    // I10: no secrets in traces
    if r.trace_leaks_secret {
        v.push("I10: secret value found in trace output".into());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::{Actor, BState};
    use crate::world::{CancelEvent, JState, RunRecord};
    use velqra_core::DispatchEvent;
    use velqra_protocol::TaskState as T;

    fn handed_off() -> RunRecord {
        RunRecord {
            quiesced: true,
            ticks: 20,
            ext_final: Some(JState::HandedOff),
            core_final: Some(T::Done),
            core_history: vec![
                T::Prepared,
                T::Armed,
                T::Committed,
                T::Transferring,
                T::Done,
            ],
            engine_attempts: vec!["t1-g1".into()],
            browser_final: BState::Cancelled,
            browser_cancelled_by: Some(Actor::Ext),
            cancels: vec![CancelEvent {
                journal: Some(JState::CancelRequested),
                core: Some(T::Armed),
            }],
            dispatches: vec![DispatchEvent {
                task_id: 1,
                state_before: T::Committed,
            }],
            engine_calls: 1,
            held: false,
            acked_prepares: vec!["req-1".into()],
            trace_leaks_secret: false,
            injected: vec![],
        }
    }

    fn returned() -> RunRecord {
        RunRecord {
            ext_final: Some(JState::Returned),
            core_final: Some(T::Aborted),
            core_history: vec![T::Prepared, T::Aborted],
            engine_attempts: vec![],
            browser_final: BState::InProgress,
            browser_cancelled_by: None,
            cancels: vec![],
            dispatches: vec![],
            engine_calls: 0,
            ..handed_off()
        }
    }

    fn violated(r: &RunRecord, tag: &str) -> bool {
        check(r).iter().any(|v| v.starts_with(tag))
    }

    #[test]
    fn correct_runs_are_clean_and_classified() {
        assert!(check(&handed_off()).is_empty());
        assert_eq!(classify(&handed_off()), Outcome::HandedOff);
        assert!(check(&returned()).is_empty());
        assert_eq!(classify(&returned()), Outcome::Returned);
    }

    #[test]
    fn i1_lost_download_is_caught() {
        let mut r = returned();
        r.browser_final = BState::Cancelled;
        r.browser_cancelled_by = Some(Actor::Ext);
        assert!(violated(&r, "I1"));
    }

    #[test]
    fn i1_stuck_acknowledged_intent_is_caught() {
        let mut r = returned();
        r.core_final = Some(T::Armed);
        assert!(violated(&r, "I1"));
    }

    #[test]
    fn i2_engine_work_without_commit_is_caught() {
        let mut r = returned();
        r.engine_attempts = vec!["t1-g1".into()];
        assert!(violated(&r, "I2"));
    }

    #[test]
    fn i3_duplicate_transfers_are_caught() {
        let mut r = handed_off();
        r.engine_attempts.push("t1-g2".into());
        assert!(violated(&r, "I3"));
    }

    #[test]
    fn i4_commit_after_abort_is_caught() {
        let mut r = handed_off();
        r.core_history = vec![T::Prepared, T::Aborted, T::Committed];
        assert!(violated(&r, "I4"));
    }

    #[test]
    fn i5_cancel_without_arming_is_caught() {
        let mut r = handed_off();
        r.cancels = vec![CancelEvent {
            journal: Some(JState::ReceiptStored),
            core: Some(T::Prepared),
        }];
        assert!(violated(&r, "I5"));
    }

    #[test]
    fn i6_user_cancel_converted_to_transfer_is_caught() {
        let mut r = handed_off();
        r.browser_cancelled_by = Some(Actor::User);
        assert!(violated(&r, "I6"));
    }

    #[test]
    fn i7_browser_completed_and_app_copied_is_caught() {
        let mut r = handed_off();
        r.browser_final = BState::Completed;
        assert!(violated(&r, "I7"));
    }

    #[test]
    fn i9_unresolved_ownership_must_be_surfaced() {
        let mut r = returned();
        r.core_final = Some(T::OwnershipUnknown);
        assert!(violated(&r, "I9"));
    }

    #[test]
    fn i10_secret_leak_is_caught_and_no_quiescence_is_caught() {
        let mut r = handed_off();
        r.trace_leaks_secret = true;
        assert!(violated(&r, "I10"));
        let mut r = handed_off();
        r.quiesced = false;
        assert!(violated(&r, "LIVENESS"));
    }

    #[test]
    fn temporal_engine_submit_from_armed_is_caught() {
        let mut r = handed_off();
        r.dispatches = vec![DispatchEvent {
            task_id: 1,
            state_before: T::Armed,
        }];
        assert!(violated(&r, "I2"));
    }

    #[test]
    fn temporal_engine_work_without_a_dispatch_record_is_caught() {
        let mut r = handed_off();
        r.dispatches = vec![];
        assert!(violated(&r, "I2"));
    }

    #[test]
    fn temporal_extension_cancel_with_no_ledger_entry_is_caught() {
        let mut r = handed_off();
        r.cancels = vec![];
        assert!(violated(&r, "I5"));
    }

    #[test]
    fn a_rejected_transfer_after_commit_is_a_clean_hand_off() {
        let mut r = handed_off();
        r.core_final = Some(T::Failed);
        r.core_history = vec![T::Prepared, T::Armed, T::Committed, T::Failed];
        r.engine_attempts = vec![];
        assert_eq!(classify(&r), Outcome::HandedOff);
        assert!(check(&r).is_empty(), "{:?}", check(&r));
    }

    #[test]
    fn a_visible_hold_before_the_cancel_gate_is_clean() {
        let mut r = returned();
        r.held = true;
        r.ext_final = Some(JState::Seen);
        r.core_final = Some(T::Aborted);
        assert_eq!(classify(&r), Outcome::Held);
        assert!(check(&r).is_empty(), "{:?}", check(&r));
    }

    #[test]
    fn a_hold_that_leaves_the_download_paused_or_the_task_armed_is_caught() {
        let mut r = returned();
        r.held = true;
        r.browser_final = BState::Paused;
        assert!(violated(&r, "I1"));
        let mut r = returned();
        r.held = true;
        r.core_final = Some(T::Armed);
        assert!(violated(&r, "I1"));
    }

    #[test]
    fn temporal_engine_calls_must_match_the_core_ledger() {
        let mut r = handed_off();
        r.engine_calls = 2;
        assert!(violated(&r, "I2"));
    }
}
