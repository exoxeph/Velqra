// SPDX-License-Identifier: GPL-3.0-only
//! The boundary between the bridge and the ownership core.
//!
//! `Spy` sits on that boundary and keeps its own log of every envelope that crosses it. Security
//! tests assert on the spy, never on counters kept by the code under test.

use std::cell::RefCell;
use std::rc::Rc;
use velqra_core::store::Store;
use velqra_core::{Core, Engine};
use velqra_protocol::Envelope;

pub trait Backend {
    /// Handles one validated, authenticated envelope and returns the reply.
    fn handle(&mut self, env: &Envelope, now: u64) -> Envelope;
    /// Lets queued work (engine dispatch) run.
    fn pump(&mut self);
    /// Short engine description for health replies.
    fn engine_name(&self) -> String;
    fn transfer_capable(&mut self) -> bool {
        true
    }
    fn problem(&mut self) -> Option<String> {
        None
    }
}

/// The real ownership core with an engine.
pub struct CoreBackend<S: Store, E: Engine> {
    pub core: Core<S>,
    pub engine: E,
    name: String,
}

impl<S: Store, E: Engine> CoreBackend<S, E> {
    pub fn new(core: Core<S>, engine: E, name: &str) -> Self {
        Self {
            core,
            engine,
            name: name.to_string(),
        }
    }
    fn refresh_capability(&mut self) {
        if let Some(capable) = self.engine.readiness() {
            self.core.transfer_capable = capable;
            self.core.engine_problem = (!capable).then(|| {
                "Pinned transfer engine unavailable; downloads stay in the browser.".into()
            });
        }
    }
}

impl<S: Store, E: Engine> Backend for CoreBackend<S, E> {
    fn handle(&mut self, env: &Envelope, now: u64) -> Envelope {
        self.refresh_capability();
        self.core.handle(env, now)
    }

    fn pump(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = self.core.pump_at(&mut self.engine, now);
        // the observation buffer is bounded here: durable ownership never depends on it
        self.core.dispatch_log.clear();
    }

    fn engine_name(&self) -> String {
        self.name.clone()
    }
    fn transfer_capable(&mut self) -> bool {
        self.refresh_capability();
        self.core.transfer_capable
    }
    fn problem(&mut self) -> Option<String> {
        self.refresh_capability();
        self.core.engine_problem.clone()
    }
}

pub type SpyLog = Rc<RefCell<Vec<Envelope>>>;

/// Wraps a backend and records every envelope handed to it.
pub struct Spy<B: Backend> {
    inner: B,
    log: SpyLog,
}

impl<B: Backend> Spy<B> {
    pub fn new(inner: B) -> (Self, SpyLog) {
        let log: SpyLog = Rc::new(RefCell::new(Vec::new()));
        (
            Self {
                inner,
                log: log.clone(),
            },
            log,
        )
    }
}

impl<B: Backend> Backend for Spy<B> {
    fn handle(&mut self, env: &Envelope, now: u64) -> Envelope {
        self.log.borrow_mut().push(env.clone());
        self.inner.handle(env, now)
    }

    fn pump(&mut self) {
        self.inner.pump();
    }

    fn engine_name(&self) -> String {
        self.inner.engine_name()
    }
    fn transfer_capable(&mut self) -> bool {
        self.inner.transfer_capable()
    }
    fn problem(&mut self) -> Option<String> {
        self.inner.problem()
    }
}
