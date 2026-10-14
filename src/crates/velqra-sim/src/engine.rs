// SPDX-License-Identifier: GPL-3.0-only
//! Fake transfer engine: durable, idempotent by attempt id, can lose replies or refuse tasks.

use crate::fault::{FaultKind, Fc};
use velqra_core::{Engine, EngineError, EngineRequest};

pub struct FakeEngine {
    /// Distinct attempt ids the engine has accepted (it remembers them across lost replies).
    pub submitted: Vec<String>,
    /// The accepted requests, as the engine received them.
    pub requests: Vec<EngineRequest>,
    pub calls: usize,
    fc: Fc,
}

impl FakeEngine {
    pub fn new(fc: Fc) -> Self {
        Self {
            submitted: Vec::new(),
            requests: Vec::new(),
            calls: 0,
            fc,
        }
    }
}

impl Engine for FakeEngine {
    fn submit(&mut self, request: &EngineRequest) -> Result<(), EngineError> {
        self.calls += 1;
        let k = self.fc.borrow_mut().check(
            "engine.submit",
            &[FaultKind::LostReply, FaultKind::EngineReject],
        );
        if k == Some(FaultKind::EngineReject) {
            return Err(EngineError::Rejected);
        }
        if !self.submitted.contains(&request.attempt) {
            self.submitted.push(request.attempt.clone());
            self.requests.push(request.clone());
        }
        if k == Some(FaultKind::LostReply) {
            Err(EngineError::ReplyLost)
        } else {
            Ok(())
        }
    }
    fn finished(&mut self, attempt: &str) -> Option<bool> {
        self.submitted.iter().any(|a| a == attempt).then_some(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::{FaultCtl, FaultKind};
    use std::{cell::RefCell, rc::Rc};

    fn req(attempt: &str) -> EngineRequest {
        EngineRequest {
            attempt: attempt.into(),
            url: "https://x.test/a".into(),
            filename: "a.zip".into(),
            context_ref: None,
        }
    }

    #[test]
    fn submit_is_idempotent_by_attempt_and_can_lose_the_reply() {
        let fc = Rc::new(RefCell::new(FaultCtl::default()));
        fc.borrow_mut()
            .plan_name
            .push(("engine.submit".into(), 1, FaultKind::LostReply));
        let mut e = FakeEngine::new(fc);
        assert!(e.submit(&req("t1-g1")).is_err()); // applied but reply lost
        assert!(e.submit(&req("t1-g1")).is_ok());
        assert_eq!(e.submitted.len(), 1);
        assert_eq!(e.requests.len(), 1);
        assert_eq!(e.calls, 2);
        assert_eq!(e.finished("t1-g1"), Some(true));
    }

    #[test]
    fn rejection_records_nothing() {
        let fc = Rc::new(RefCell::new(FaultCtl::default()));
        fc.borrow_mut()
            .plan_name
            .push(("engine.submit".into(), 1, FaultKind::EngineReject));
        let mut e = FakeEngine::new(fc);
        assert_eq!(e.submit(&req("t1-g1")), Err(EngineError::Rejected));
        assert!(e.submitted.is_empty());
    }
}
