// SPDX-License-Identifier: GPL-3.0-only
//! Keeps one aria2 process running and presents it as the core's `Engine`. aria2 is started on first
//! use and started again if it dies; while it is down every call answers "could not ask", which the
//! core treats as ambiguity, never as "the task is gone". A fresh aria2 has no tasks, so the core's
//! `has_forgotten` question then re-dispatches whatever was running, by the same gid.

use super::adapter::{Aria2Config, Aria2Engine};
use super::process::{Aria2Process, Launch};
use super::rpc::RpcClient;
use std::time::{Duration, Instant};
use velqra_core::{Engine, EngineError, EngineRequest, EngineStatus, Poll};

/// After a failed start, wait this long before trying again.
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(2);

pub struct Aria2Supervisor {
    launch: Launch,
    cfg: Aria2Config,
    timeout: Duration,
    live: Option<Aria2Process>,
    retry_after: Option<Instant>,
    /// How many processes have been started (tests and diagnostics).
    pub starts: u32,
}

impl Aria2Supervisor {
    pub fn new(launch: Launch, cfg: Aria2Config) -> Self {
        Self {
            launch,
            cfg,
            timeout: Duration::from_secs(3),
            live: None,
            retry_after: None,
            starts: 0,
        }
    }

    /// The engine over the current process, starting or restarting aria2 first when needed.
    fn engine(&mut self) -> Option<Aria2Engine<RpcClient>> {
        if self.live.as_mut().is_some_and(|p| !p.is_alive()) {
            self.live = None;
        }
        if self.live.is_none() {
            if self.retry_after.is_some_and(|t| Instant::now() < t) {
                return None;
            }
            match Aria2Process::spawn(&self.launch) {
                Ok(p) => {
                    self.live = Some(p);
                    self.retry_after = None;
                    self.starts += 1;
                }
                Err(_) => {
                    self.retry_after = Some(Instant::now() + RETRY_AFTER_FAILURE);
                    return None;
                }
            }
        }
        let client = self.live.as_ref()?.client(self.timeout);
        Some(Aria2Engine::new(client, self.cfg))
    }

    pub fn ready(&mut self) -> bool {
        if self.engine().is_none() {
            return false;
        }
        let responsive = self.live.as_ref().is_some_and(|p| {
            p.client(self.timeout)
                .call("aria2.getVersion", vec![])
                .is_ok_and(|v| v["version"] == super::process::PINNED_ARIA2_VERSION)
        });
        if !responsive {
            self.stop();
            self.retry_after = Some(Instant::now() + RETRY_AFTER_FAILURE);
        }
        responsive
    }

    /// The running process id, if any (diagnostics and tests).
    pub fn pid(&mut self) -> Option<u32> {
        let p = self.live.as_mut()?;
        p.is_alive().then(|| p.pid())
    }

    pub fn stop(&mut self) {
        if let Some(mut p) = self.live.take() {
            p.stop();
        }
    }
}

impl Engine for Aria2Supervisor {
    fn readiness(&mut self) -> Option<bool> {
        Some(self.ready())
    }
    fn submit(&mut self, request: &EngineRequest) -> Result<(), EngineError> {
        match self.engine() {
            Some(mut e) => e.submit(request),
            None => Err(EngineError::ReplyLost),
        }
    }

    fn finished(&mut self, attempt: &str) -> Option<bool> {
        self.engine()?.finished(attempt)
    }

    fn status(&mut self, attempt: &str) -> Result<EngineStatus, EngineError> {
        match self.engine() {
            Some(mut e) => e.status(attempt),
            None => Err(EngineError::ReplyLost),
        }
    }

    fn has_forgotten(&mut self, attempt: &str) -> bool {
        self.engine().is_some_and(|mut e| e.has_forgotten(attempt))
    }

    fn poll(&mut self, attempt: &str) -> Poll {
        match self.engine() {
            Some(mut e) => e.poll(attempt),
            None => Poll::Unreachable,
        }
    }

    fn pause(&mut self, attempt: &str) -> Result<(), EngineError> {
        match self.engine() {
            Some(mut e) => e.pause(attempt),
            None => Err(EngineError::ReplyLost),
        }
    }

    fn resume(&mut self, attempt: &str) -> Result<(), EngineError> {
        match self.engine() {
            Some(mut e) => e.resume(attempt),
            None => Err(EngineError::ReplyLost),
        }
    }

    fn cancel(&mut self, attempt: &str) -> Result<(), EngineError> {
        match self.engine() {
            Some(mut e) => e.cancel(attempt),
            None => Err(EngineError::ReplyLost),
        }
    }
}

impl Drop for Aria2Supervisor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_tracks_restart_failure_and_recovery_at_admission() {
        use velqra_bridge::backend::{Backend, CoreBackend};
        use velqra_core::{store::MemStore, Core};
        use velqra_protocol::*;
        let d = tempfile::tempdir().unwrap();
        let exe = d.path().join("aria2c.exe");
        let vendor = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../vendor/aria2/1.37.0/aria2c.exe");
        std::fs::copy(&vendor, &exe).unwrap();
        let launch = Launch {
            exe: exe.clone(),
            expected_sha256: super::super::process::PINNED_ARIA2_SHA256.into(),
            run_dir: d.path().join("run"),
            max_concurrent: 1,
            parent_pid: std::process::id(),
            ready_timeout: Duration::from_secs(5),
        };
        let mut s = Aria2Supervisor::new(launch, Aria2Config::default());
        assert!(s.ready());
        let mut b = CoreBackend::new(Core::new(MemStore::default()), s, "aria2");
        assert!(b.transfer_capable());
        let envelope = |rid: &str, body| Envelope {
            version: PROTOCOL_VERSION,
            message_id: format!("m-{rid}"),
            session_id: "s".into(),
            request_id: rid.into(),
            generation: 1,
            body,
        };
        let prep = || {
            Message::Prepare(PrepareBody {
                download_key: "k".into(),
                url: "https://x.test/a".into(),
                filename: "a.bin".into(),
                context: Secret("c".into()),
            })
        };
        let prepared = b.handle(&envelope("old", prep()), 1);
        let Message::Prepared(receipt) = prepared.body else {
            panic!("prepare failed")
        };
        assert!(matches!(
            b.handle(&envelope("old", Message::BeginHandoff(receipt.as_ref())), 1)
                .body,
            Message::Armed(_)
        ));
        let Message::Prepared(owned) = b.handle(&envelope("owned", prep()), 1).body else {
            panic!("prepare owned failed")
        };
        b.handle(&envelope("owned", Message::BeginHandoff(owned.as_ref())), 1);
        assert!(matches!(
            b.handle(
                &envelope(
                    "owned",
                    Message::Commit(CommitBody {
                        receipt: owned.as_ref(),
                        cancel: CancelEvidence::Confirmed
                    })
                ),
                1
            )
            .body,
            Message::Committed(_)
        ));
        b.engine.stop();
        std::fs::write(&exe, b"invalid executable").unwrap();
        assert!(
            !b.transfer_capable(),
            "health must lose capability after persistent restart failure"
        );
        assert!(b.problem().is_some());
        assert!(
            matches!(b.handle(&envelope("owned", Message::Status(Empty {})), 2).body,
            Message::StatusReply(ref r) if r.state == TaskState::Committed),
            "lost readiness must preserve committed ownership"
        );
        assert!(matches!(
            b.handle(&envelope("new", prep()), 2).body,
            Message::Error(_)
        ));
        assert!(matches!(
            b.handle(&envelope("old", Message::BeginHandoff(receipt.as_ref())), 3)
                .body,
            Message::Error(_)
        ));
        assert!(
            matches!(
                b.handle(&envelope("old", Message::Status(Empty {})), 3)
                    .body,
                Message::Error(_)
            ),
            "Armed status must refuse final handoff admission when engine is lost"
        );
        let settings = b.handle(&envelope("settings", Message::SettingsGet(Empty {})), 4);
        assert!(
            matches!(settings.body, Message::SettingsReply(ref s) if !s.transfer_capable && s.problem.is_some())
        );
        // Backoff does not erase failure; a later retry with restored bytes recovers readiness.
        assert!(!b.transfer_capable());
        std::fs::copy(vendor, &exe).unwrap();
        b.engine.retry_after = None;
        assert!(b.transfer_capable());
        assert!(b.problem().is_none());
        assert!(matches!(
            b.handle(&envelope("new", prep()), 5).body,
            Message::Prepared(_)
        ));
    }

    #[test]
    fn a_launch_that_cannot_start_answers_could_not_ask_and_backs_off() {
        let d = tempfile::tempdir().unwrap();
        let missing = Launch {
            exe: d.path().join("nope.exe"),
            expected_sha256: super::super::process::PINNED_ARIA2_SHA256.into(),
            run_dir: d.path().join("run"),
            max_concurrent: 1,
            parent_pid: std::process::id(),
            ready_timeout: Duration::from_secs(1),
        };
        let mut s = Aria2Supervisor::new(missing, Aria2Config::default());
        let req = EngineRequest {
            attempt: "a".into(),
            url: "https://x.test/a".into(),
            filename: "a".into(),
            context_ref: None,
            destination: Some(r"C:\dl\a".into()),
            context: None,
        };
        assert_eq!(s.submit(&req), Err(EngineError::ReplyLost));
        assert_eq!(s.status("a"), Err(EngineError::ReplyLost));
        assert!(
            !s.has_forgotten("a"),
            "not being able to ask is not forgetting"
        );
        assert_eq!(s.finished("a"), None);
        assert_eq!(
            s.poll("a"),
            Poll::Unreachable,
            "down is not forgotten and not failed"
        );
        assert_eq!(s.pid(), None);
        assert_eq!(s.starts, 0);
        assert!(
            s.retry_after.is_some(),
            "a failed start is not retried in a tight loop"
        );
    }
}
