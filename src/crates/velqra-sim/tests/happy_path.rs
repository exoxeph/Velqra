// SPDX-License-Identifier: GPL-3.0-only
use std::{cell::RefCell, rc::Rc};
use velqra_protocol::TaskState;
use velqra_sim::browser::{Actor, BState};
use velqra_sim::fault::FaultCtl;
use velqra_sim::world::{JState, World};

#[test]
fn happy_path_hands_the_download_to_the_app_exactly_once() {
    let fc = Rc::new(RefCell::new(FaultCtl::default()));
    let mut w = World::new(fc);
    let r = w.run();
    assert!(r.quiesced, "did not quiesce in {} ticks", r.ticks);
    assert_eq!(r.ext_final, Some(JState::HandedOff));
    assert_eq!(r.browser_final, BState::Cancelled);
    assert_eq!(r.browser_cancelled_by, Some(Actor::Ext));
    assert!(matches!(
        r.core_final,
        Some(TaskState::Transferring) | Some(TaskState::Done)
    ));
    assert_eq!(r.engine_attempts.len(), 1);
    assert!(!r.trace_leaks_secret);
    assert!(!w.trace.is_empty());
}
