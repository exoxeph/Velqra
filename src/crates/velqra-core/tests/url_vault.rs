// SPDX-License-Identifier: GPL-3.0-only
//! A4: the download URL (which can carry signed tokens) and the browser context live only in the
//! protected vault. The database holds references, never the URL.
use std::path::Path;
use velqra_core::file_vault::{FileVault, Protector};
use velqra_core::store::{SqliteStore, Store};
use velqra_core::{Core, Engine, EngineError, EngineRequest};
use velqra_protocol::*;

const URL: &str = "https://files.secret-host.example/dl/a.zip?sig=TOKEN-SENTINEL-abc123";
const CONTEXT: &str = "CONTEXT-SENTINEL-cookie=xyz";

struct Scramble;
impl Protector for Scramble {
    fn protect(&self, plain: &[u8], _: &[u8]) -> Result<Vec<u8>, String> {
        Ok(plain.iter().map(|b| b ^ 0xa7).collect())
    }
    fn unprotect(&self, blob: &[u8], _: &[u8]) -> Result<Vec<u8>, String> {
        Ok(blob.iter().map(|b| b ^ 0xa7).collect())
    }
}

#[derive(Default)]
struct Capture {
    requests: Vec<EngineRequest>,
}
impl Engine for Capture {
    fn submit(&mut self, request: &EngineRequest) -> Result<(), EngineError> {
        self.requests.push(request.clone());
        Ok(())
    }
    fn finished(&mut self, _: &str) -> Option<bool> {
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

fn body() -> PrepareBody {
    PrepareBody {
        download_key: "d1".into(),
        url: URL.into(),
        filename: "a.zip".into(),
        context: Secret(CONTEXT.into()),
    }
}

fn open(db: &Path, vault_dir: &Path) -> Core<SqliteStore> {
    Core::with_vault(
        SqliteStore::open(db).unwrap(),
        Box::new(FileVault::open(vault_dir, Scramble).unwrap()),
    )
}

fn request_ref() -> RequestRef {
    RequestRef {
        task_id: 1,
        fingerprint: fingerprint(&body()),
    }
}

fn commit_path(core: &mut Core<SqliteStore>) {
    core.handle(&env(Message::Prepare(body())), 1);
    core.handle(&env(Message::BeginHandoff(request_ref())), 2);
    core.handle(
        &env(Message::Commit(CommitBody {
            cancel: CancelEvidence::Confirmed,
            receipt: request_ref(),
        })),
        3,
    );
}

/// Every needle that must never appear in a database file.
fn needles() -> Vec<&'static str> {
    vec![
        URL,
        "secret-host.example",
        "TOKEN-SENTINEL-abc123",
        "sig=",
        CONTEXT,
    ]
}

fn leaks(dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let bytes = std::fs::read(&path).unwrap();
        for n in needles() {
            if bytes.windows(n.len()).any(|w| w == n.as_bytes()) {
                found.push(format!("{} in {}", n, path.display()));
            }
        }
    }
    found
}

fn vault_files(vault_dir: &Path) -> usize {
    std::fs::read_dir(vault_dir).unwrap().count()
}

#[test]
fn the_scan_helper_sees_a_planted_sentinel() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("x.db"), format!("junk{URL}junk")).unwrap();
    assert!(!leaks(d.path()).is_empty(), "the control must be detected");
}

#[test]
fn database_files_hold_no_url_host_token_or_context_through_a_whole_task() {
    let d = tempfile::tempdir().unwrap();
    let (db_dir, vault_dir) = (d.path().join("db"), d.path().join("vault"));
    std::fs::create_dir(&db_dir).unwrap();
    let mut core = open(&db_dir.join("core.db"), &vault_dir);
    commit_path(&mut core);
    assert!(
        leaks(&db_dir).is_empty(),
        "after commit: {:?}",
        leaks(&db_dir)
    );
    let mut engine = Capture::default();
    core.pump(&mut engine).unwrap();
    assert_eq!(engine.requests[0].url, URL, "the engine still gets the URL");
    core.pump(&mut engine).unwrap(); // transferring -> done
    let names: Vec<_> = std::fs::read_dir(&db_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(names.iter().any(|n| n == "core.db"), "{names:?}");
    assert!(
        leaks(&db_dir).is_empty(),
        "while open: {:?}",
        leaks(&db_dir)
    );
    drop(core);
    assert!(
        leaks(&db_dir).is_empty(),
        "after close: {:?}",
        leaks(&db_dir)
    );
}

#[test]
fn a_restarted_core_with_a_new_vault_over_the_same_directory_dispatches_the_original_url() {
    let d = tempfile::tempdir().unwrap();
    let (db, vault_dir) = (d.path().join("core.db"), d.path().join("vault"));
    {
        let mut core = open(&db, &vault_dir);
        commit_path(&mut core);
    }
    let mut core = open(&db, &vault_dir);
    let mut engine = Capture::default();
    core.pump(&mut engine).unwrap();
    assert_eq!(engine.requests.len(), 1);
    assert_eq!(engine.requests[0].url, URL);
    assert_eq!(engine.requests[0].filename, "a.zip");
}

/// Deletes every vault file whose plaintext does not satisfy `keep`.
fn lose_entries(vault_dir: &Path, keep: fn(&str) -> bool) {
    for e in std::fs::read_dir(vault_dir).unwrap() {
        let p = e.unwrap().path();
        let plain: Vec<u8> = std::fs::read(&p)
            .unwrap()
            .iter()
            .map(|b| b ^ 0xa7)
            .collect();
        if !keep(&String::from_utf8_lossy(&plain)) {
            std::fs::remove_file(p).unwrap();
        }
    }
}

#[test]
fn losing_the_url_entry_fails_the_task_visibly_and_never_calls_the_engine() {
    let d = tempfile::tempdir().unwrap();
    let (db, vault_dir) = (d.path().join("core.db"), d.path().join("vault"));
    {
        let mut core = open(&db, &vault_dir);
        commit_path(&mut core);
    }
    lose_entries(&vault_dir, |plain| plain == CONTEXT); // only the context survives
    let mut core = open(&db, &vault_dir);
    let mut engine = Capture::default();
    core.pump(&mut engine).unwrap();
    assert!(engine.requests.is_empty(), "no engine call without the URL");
    let rec = core.store.get_by_task(1).unwrap().unwrap();
    assert_eq!(rec.state, TaskState::Failed);
    assert_eq!(rec.fail_reason.as_deref(), Some("request url unavailable"));
}

#[test]
fn losing_the_context_entry_still_fails_visibly() {
    let d = tempfile::tempdir().unwrap();
    let (db, vault_dir) = (d.path().join("core.db"), d.path().join("vault"));
    {
        let mut core = open(&db, &vault_dir);
        commit_path(&mut core);
    }
    lose_entries(&vault_dir, |plain| plain == URL); // only the URL survives
    let mut core = open(&db, &vault_dir);
    let mut engine = Capture::default();
    core.pump(&mut engine).unwrap();
    assert!(engine.requests.is_empty());
    let rec = core.store.get_by_task(1).unwrap().unwrap();
    assert_eq!(rec.state, TaskState::Failed);
    assert_eq!(
        rec.fail_reason.as_deref(),
        Some("protected context unavailable")
    );
}

#[test]
fn the_record_debug_and_json_carry_no_url_and_aborting_releases_both_entries() {
    let d = tempfile::tempdir().unwrap();
    let (db, vault_dir) = (d.path().join("core.db"), d.path().join("vault"));
    let mut core = open(&db, &vault_dir);
    core.handle(&env(Message::Prepare(body())), 1);
    let rec = core.store.get_by_task(1).unwrap().unwrap();
    let text = format!("{:?} {}", rec, serde_json::to_string(&rec).unwrap());
    for n in needles() {
        assert!(!text.contains(n), "{n} leaked into the record");
    }
    assert_eq!(vault_files(&vault_dir), 2, "url + context");
    core.handle(
        &env(Message::Abort(AbortBody {
            receipt: Some(request_ref()),
        })),
        5,
    );
    assert_eq!(vault_files(&vault_dir), 0, "abort releases both entries");
}

/// A vault whose second put fails, as a full disk or a locked key store would.
struct FailSecondPut {
    inner: velqra_core::vault::MemVault,
    puts: std::cell::Cell<u32>,
}
impl velqra_core::vault::SecretVault for FailSecondPut {
    fn put(&self, task_id: u64, secret: &Secret) -> Result<String, String> {
        self.puts.set(self.puts.get() + 1);
        if self.puts.get() == 2 {
            return Err("injected".into());
        }
        self.inner.put(task_id, secret)
    }
    fn get(&self, reference: &str) -> Option<Secret> {
        self.inner.get(reference)
    }
    fn remove(&self, reference: &str) {
        self.inner.remove(reference)
    }
}

#[test]
fn a_failed_url_store_rolls_back_the_context_and_creates_no_record() {
    let inner = velqra_core::vault::MemVault::default();
    let vault = FailSecondPut {
        inner: inner.clone(),
        puts: std::cell::Cell::new(0),
    };
    let mut core = Core::with_vault(velqra_core::store::MemStore::default(), Box::new(vault));
    let out = core.handle(&env(Message::Prepare(body())), 1);
    assert!(matches!(out.body, Message::Error(_)), "{:?}", out.body);
    assert!(inner.is_empty(), "the context stored first was removed");
    assert!(core.store.get_by_request("r1").unwrap().is_none());
}
