// SPDX-License-Identifier: GPL-3.0-only
//! The core runtime over real named pipes, in-process. Process-level tests (real binaries and the
//! native host) are in `e2e.rs`.
#![cfg(windows)]

mod common;

use common::*;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use velqra_app::paths::{db_path, ensure_secret, load_secret};
use velqra_app::runtime::{Runtime, RuntimeConfig};
use velqra_bridge::secret::InstallSecret;
use velqra_bridge::server::MAX_CONNS;
use velqra_bridge::testkit::{attach, auth, envelope, envelope_frame, hello, jframe, ORIGIN};
use velqra_core::store::{Record, SqliteStore, Store};
use velqra_protocol::*;

static N: AtomicU32 = AtomicU32::new(0);

fn unique_pipe() -> String {
    velqra_ipc::pipe_name(&format!(
        "rt-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ))
    .unwrap()
}

fn cfg(home: &Path, pipe: &str) -> RuntimeConfig {
    RuntimeConfig {
        home: home.to_path_buf(),
        pipe: pipe.to_string(),
        allowed: vec![ORIGIN.to_string()],
        tick_ms: 5,
    }
}

fn secret_of(home: &Path) -> InstallSecret {
    load_secret(home)
        .unwrap()
        .expect("the runtime creates the install secret on start")
}

fn records(home: &Path) -> Vec<Record> {
    SqliteStore::open(&db_path(home)).unwrap().all().unwrap()
}

fn connect(pipe: &str) -> Client<PipeTransport> {
    Client::new(PipeTransport::connect(pipe).unwrap())
}

fn session(pipe: &str, secret: &InstallSecret, cn: u8) -> Client<PipeTransport> {
    let mut c = connect(pipe);
    c.handshake(secret, ORIGIN, [cn; 16], true)
        .expect("honest handshake");
    c
}

fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn a_full_hand_off_runs_through_the_real_pipe_core_store_and_engine() {
    let dir = tempfile::tempdir().unwrap();
    let pipe = unique_pipe();
    let rt = Runtime::start(cfg(dir.path(), &pipe)).unwrap();
    let secret = secret_of(dir.path());
    let mut c = session(&pipe, &secret, 1);

    let health = c.request("h1", "req-1", Message::Health(Empty {})).unwrap();
    assert!(
        matches!(health.body, Message::HealthReply(ref h) if h.engine == "loopback" && h.versions == vec![1])
    );

    let prepared = receipt_of(
        &c.request("m1", "req-1", Message::Prepare(prepare_body()))
            .unwrap(),
    );
    assert_eq!(prepared.state, TaskState::Prepared);
    let armed = c
        .request("m2", "req-1", Message::BeginHandoff(prepared.as_ref()))
        .unwrap();
    assert_eq!(receipt_of(&armed).state, TaskState::Armed);
    let commit = CommitBody {
        cancel: CancelEvidence::Confirmed,
        receipt: prepared.as_ref(),
    };
    let committed = c.request("m3", "req-1", Message::Commit(commit)).unwrap();
    assert!(matches!(
        receipt_of(&committed).state,
        TaskState::Committed | TaskState::Transferring | TaskState::Done
    ));

    wait_for("the loopback engine to finish the task", || {
        records(dir.path())
            .iter()
            .any(|r| r.task_id == prepared.task_id && r.state == TaskState::Done)
    });
    rt.stop();
}

#[test]
fn a_second_core_instance_is_refused_and_the_first_keeps_serving() {
    let dir = tempfile::tempdir().unwrap();
    let pipe = unique_pipe();
    let rt = Runtime::start(cfg(dir.path(), &pipe)).unwrap();
    let other = tempfile::tempdir().unwrap();
    let err = Runtime::start(cfg(other.path(), &pipe))
        .err()
        .expect("a second core must not start");
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    let secret = secret_of(dir.path());
    let mut c = session(&pipe, &secret, 1);
    assert!(c.request("h1", "r", Message::Health(Empty {})).is_ok());
    rt.stop();
}

#[test]
fn stopping_closes_connections_and_removes_the_pipe() {
    let dir = tempfile::tempdir().unwrap();
    let pipe = unique_pipe();
    let rt = Runtime::start(cfg(dir.path(), &pipe)).unwrap();
    let secret = secret_of(dir.path());
    let mut c = session(&pipe, &secret, 1);
    let started = Instant::now();
    rt.stop();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "stop took {:?}",
        started.elapsed()
    );
    wait_for("the connected client to be closed", || {
        c.t.recv(Duration::from_millis(50));
        c.t.is_closed()
    });
    let e = velqra_ipc::connect(&pipe, Duration::from_millis(300))
        .err()
        .expect("the pipe is gone");
    assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn an_unauthenticated_client_never_creates_a_record_or_gets_a_reply_to_an_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let pipe = unique_pipe();
    let rt = Runtime::start(cfg(dir.path(), &pipe)).unwrap();
    let mut t = PipeTransport::connect(&pipe).unwrap();
    t.send(b"\x07\x00\x00\x00garbage");
    let forged = "00000000000000000000000000000000";
    t.send(&envelope_frame(&envelope(
        forged,
        "m1",
        "req-1",
        Message::Prepare(prepare_body()),
    )));
    t.send(&envelope_frame(&envelope(
        forged,
        "m2",
        "req-2",
        Message::Abort(AbortBody { receipt: None }),
    )));
    let mut frames = 0;
    while let Some(p) = t.recv(Duration::from_millis(500)) {
        let v: serde_json::Value = serde_json::from_slice(&p).unwrap();
        assert_eq!(
            v["t"], "reject",
            "an unauthenticated peer received something other than a reject: {v}"
        );
        frames += 1;
    }
    assert!(frames <= 1);
    assert!(t.is_closed());
    assert!(
        records(dir.path()).is_empty(),
        "an unauthenticated client created a record (an abort would leave a tombstone)"
    );
    rt.stop();
}

#[test]
fn the_wrong_origin_the_wrong_secret_and_a_replayed_hello_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let pipe = unique_pipe();
    let rt = Runtime::start(cfg(dir.path(), &pipe)).unwrap();
    let secret = secret_of(dir.path());

    let mut t = PipeTransport::connect(&pipe).unwrap();
    t.send(&attach(
        "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/",
    ));
    let v: serde_json::Value =
        serde_json::from_slice(&t.recv(Duration::from_secs(2)).expect("a reject")).unwrap();
    assert_eq!(v["code"], "bad_origin");

    let mut wrong = [0u8; 32];
    wrong[0] = 99;
    let mut c = connect(&pipe);
    let err = c
        .handshake(&InstallSecret::from_bytes(wrong), ORIGIN, [2; 16], true)
        .unwrap_err();
    assert!(err.contains("could not prove"), "{err}");

    // an attacker that ignores the server's proof and sends a made-up auth still gets nowhere
    let mut raw = PipeTransport::connect(&pipe).unwrap();
    raw.send(&attach(ORIGIN));
    raw.send(&hello(&[3; 16]));
    assert!(raw.recv(Duration::from_secs(2)).is_some(), "challenge");
    raw.send(&auth(&[9; 32]));
    let v: serde_json::Value =
        serde_json::from_slice(&raw.recv(Duration::from_secs(2)).unwrap()).unwrap();
    assert_eq!(v["code"], "bad_auth");

    // replaying a hello nonce that a real session already used
    let _good = session(&pipe, &secret, 4);
    let mut replay = PipeTransport::connect(&pipe).unwrap();
    replay.send(&attach(ORIGIN));
    replay.send(&hello(&[4; 16]));
    let v: serde_json::Value =
        serde_json::from_slice(&replay.recv(Duration::from_secs(2)).unwrap()).unwrap();
    assert_eq!(v["code"], "replay");
    assert!(records(dir.path()).is_empty());
    rt.stop();
}

#[test]
fn a_restart_keeps_the_receipt_and_a_new_session_can_ask_about_it() {
    let dir = tempfile::tempdir().unwrap();
    let pipe = unique_pipe();
    let rt = Runtime::start(cfg(dir.path(), &pipe)).unwrap();
    let secret = secret_of(dir.path());
    let before = receipt_of(
        &session(&pipe, &secret, 1)
            .request("m1", "req-1", Message::Prepare(prepare_body()))
            .unwrap(),
    );
    rt.stop();

    let rt = Runtime::start(cfg(dir.path(), &pipe)).unwrap();
    let mut c = session(&pipe, &secret_of(dir.path()), 2);
    let after = receipt_of(&c.request("s1", "req-1", Message::Status(Empty {})).unwrap());
    assert_eq!(after.task_id, before.task_id);
    assert_eq!(after.fingerprint, before.fingerprint);
    assert_eq!(after.state, TaskState::Prepared);
    assert_eq!(
        secret_of(dir.path()).expose(),
        secret.expose(),
        "the install secret changed across a restart"
    );
    rt.stop();
}

#[test]
fn only_a_bounded_number_of_connections_is_served_and_slots_come_back() {
    let dir = tempfile::tempdir().unwrap();
    let pipe = unique_pipe();
    let rt = Runtime::start(cfg(dir.path(), &pipe)).unwrap();
    let mut held: Vec<PipeTransport> = (0..MAX_CONNS)
        .map(|_| PipeTransport::connect(&pipe).unwrap())
        .collect();
    for h in &mut held {
        h.send(&attach(ORIGIN));
    }
    std::thread::sleep(Duration::from_millis(200));
    let mut extra = PipeTransport::connect(&pipe).unwrap();
    extra.send(&attach(ORIGIN));
    let v: serde_json::Value =
        serde_json::from_slice(&extra.recv(Duration::from_secs(2)).expect("a busy reject"))
            .unwrap();
    assert_eq!(v["code"], "busy");
    drop(held.pop());
    wait_for("a freed slot to be reusable", || {
        let mut t = PipeTransport::connect(&pipe).unwrap();
        t.send(&jframe(
            &serde_json::json!({"t": "attach", "origin": ORIGIN}),
        ));
        t.send(&hello(&[7; 16]));
        t.recv(Duration::from_millis(500)).is_some_and(|p| {
            serde_json::from_slice::<serde_json::Value>(&p).unwrap()["t"] == "challenge"
        })
    });
    rt.stop();
}

#[test]
fn a_connection_that_never_speaks_is_dropped_by_the_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let pipe = unique_pipe();
    let rt = Runtime::start(cfg(dir.path(), &pipe)).unwrap();
    let mut silent = PipeTransport::connect(&pipe).unwrap();
    let started = Instant::now();
    let reject = silent
        .recv(Duration::from_secs(5))
        .expect("a timeout reject");
    let v: serde_json::Value = serde_json::from_slice(&reject).unwrap();
    assert_eq!(v["code"], "timeout");
    assert!(started.elapsed() < Duration::from_secs(4));
    rt.stop();
}

#[test]
fn the_runtime_creates_the_secret_once_and_never_changes_it() {
    let dir = tempfile::tempdir().unwrap();
    let a = ensure_secret(dir.path()).unwrap();
    let rt = Runtime::start(cfg(dir.path(), &unique_pipe())).unwrap();
    assert_eq!(secret_of(dir.path()).expose(), a.expose());
    rt.stop();
}

#[test]
fn a_closed_authenticated_session_frees_its_slot_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let pipe = unique_pipe();
    let rt = Runtime::start(cfg(dir.path(), &pipe)).unwrap();
    let secret = secret_of(dir.path());
    // authenticated sessions are only reaped after a long idle time, so a freed slot can only come
    // from the disconnect being reported to the server
    let mut sessions: Vec<_> = (0..MAX_CONNS as u8)
        .map(|i| session(&pipe, &secret, 10 + i))
        .collect();
    drop(sessions.pop());
    wait_for("the closed session's slot to be reusable", || {
        let mut c = connect(&pipe);
        c.handshake(&secret, ORIGIN, [99; 16], true).is_ok()
    });
    rt.stop();
}
