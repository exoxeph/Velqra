// SPDX-License-Identifier: GPL-3.0-only
//! Review C1: an accepted task must be reconstructible after both sides restart.
use velqra_core::store::{SqliteStore, Store};
use velqra_core::vault::{MemVault, SecretVault};
use velqra_core::{Core, Engine, EngineError, EngineRequest};
use velqra_protocol::*;

#[derive(Default)]
struct Capture {
    requests: Vec<EngineRequest>,
}

impl Engine for Capture {
    fn submit(&mut self, request: &EngineRequest) -> Result<(), EngineError> {
        self.requests.push(request.clone());
        Ok(())
    }
    fn finished(&mut self, _attempt: &str) -> Option<bool> {
        Some(true)
    }
}

fn env(body: Message) -> Envelope {
    Envelope {
        version: PROTOCOL_VERSION,
        message_id: format!("m-{}", body.kind()),
        session_id: "s".into(),
        request_id: "r1".into(),
        generation: 1,
        body,
    }
}

#[test]
fn committed_task_runs_after_core_and_store_are_reopened() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("core.db");
    let vault = MemVault::default(); // outlives the core, like a protected store would
    let body = PrepareBody {
        download_key: "d1".into(),
        url: "https://x.test/files/a.zip?sig=ABC".into(),
        filename: "a.zip".into(),
        context: Secret("S3CR3T-SENTINEL".into()),
    };
    let rr = RequestRef {
        task_id: 1,
        fingerprint: fingerprint(&body),
    };
    {
        let mut core = Core::with_vault(SqliteStore::open(&path).unwrap(), Box::new(vault.clone()));
        core.handle(&env(Message::Prepare(body.clone())), 1);
        core.handle(&env(Message::BeginHandoff(rr.clone())), 2);
        core.handle(
            &env(Message::Commit(CommitBody {
                cancel: CancelEvidence::Confirmed,
                receipt: rr,
            })),
            3,
        );
    } // core and database connection dropped: simulated restart before any engine work
    let mut core = Core::with_vault(SqliteStore::open(&path).unwrap(), Box::new(vault.clone()));
    let mut engine = Capture::default();
    core.pump(&mut engine).unwrap();
    let req = engine
        .requests
        .first()
        .expect("the restarted core still knows what to download");
    assert_eq!(req.url, "https://x.test/files/a.zip?sig=ABC");
    assert_eq!(req.filename, "a.zip");
    let secret = vault.get(req.context_ref.as_deref().unwrap()).unwrap();
    assert_eq!(secret.0, "S3CR3T-SENTINEL");
    let stored = core.store.get_by_request("r1").unwrap().unwrap();
    assert!(!serde_json::to_string(&stored)
        .unwrap()
        .contains("S3CR3T-SENTINEL"));
}
