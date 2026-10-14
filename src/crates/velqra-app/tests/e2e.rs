// SPDX-License-Identifier: GPL-3.0-only
//! Process-level tests: the real `velqra-app` and `velqra-host` executables, with a Rust test driver
//! playing the Chrome extension over the host's stdio exactly as native messaging does.
#![cfg(windows)]

mod common;

use common::*;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};
use velqra_app::paths::{db_path, DEV_EXTENSION_ORIGIN};
use velqra_bridge::frame::{FrameDecoder, MAX_TO_BROWSER};
use velqra_bridge::handshake::{b64_decode, b64_encode};
use velqra_bridge::host::native_manifest;
use velqra_bridge::secret::InstallSecret;
use velqra_bridge::testkit::{frame, SENTINEL};
use velqra_core::store::{Record, SqliteStore, Store};
use velqra_protocol::*;

const APP: &str = env!("CARGO_BIN_EXE_velqra-app");
const HOST: &str = env!("CARGO_BIN_EXE_velqra-host");
static N: AtomicU32 = AtomicU32::new(0);

struct Env {
    home: tempfile::TempDir,
    suffix: String,
    pipe: String,
    kids: Vec<Child>,
}

impl Env {
    fn new() -> Self {
        let suffix = format!(
            "e2e-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        );
        let pipe = velqra_ipc::pipe_name(&suffix).unwrap();
        Self {
            home: tempfile::tempdir().unwrap(),
            suffix,
            pipe,
            kids: Vec::new(),
        }
    }

    fn home(&self) -> &Path {
        self.home.path()
    }

    fn cmd(&self, exe: &str) -> Command {
        let mut c = Command::new(exe);
        c.env("VELQRA_HOME", self.home())
            .env("VELQRA_PIPE", &self.suffix)
            .env("VELQRA_APP", APP);
        c.env_remove("VELQRA_ALLOWED_ORIGINS");
        c
    }

    fn log(&self, name: &str) -> PathBuf {
        self.home().join(name)
    }

    fn pipe_up(&self) -> bool {
        velqra_ipc::connect(&self.pipe, Duration::from_millis(200)).is_ok()
    }

    fn start_app(&mut self, log: &str) -> u32 {
        let err = fs::File::create(self.log(log)).unwrap();
        let child = self
            .cmd(APP)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(err)
            .spawn()
            .unwrap();
        let pid = child.id();
        self.kids.push(child);
        wait_until("the core's pipe", || self.pipe_up());
        pid
    }

    fn app_pid(&self) -> Option<u32> {
        fs::read_to_string(self.log("velqra-app.pid"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    fn kill_core_quiet(&self) {
        if let Some(pid) = self.app_pid() {
            let _ = Command::new("taskkill")
                .args(["/F", "/PID", &pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.pipe_up() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = fs::remove_file(self.log("velqra-app.pid"));
    }

    fn kill_core(&self) {
        self.kill_core_quiet();
        assert!(
            !self.pipe_up(),
            "the core is still running after it was killed"
        );
    }

    fn spawn_host(&mut self, origin: Option<&str>, log: &str) -> Host {
        let err = fs::File::create(self.log(log)).unwrap();
        let mut c = self.cmd(HOST);
        if let Some(o) = origin {
            c.arg(o).arg("--parent-window=0");
        }
        let mut child = c
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(err)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let (tx, rx) = channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut dec = FrameDecoder::new(MAX_TO_BROWSER);
            let mut buf = vec![0u8; 16384];
            while let Ok(n) = std::io::Read::read(&mut stdout, &mut buf) {
                if n == 0 {
                    break;
                }
                match dec.feed(&buf[..n]) {
                    Ok(frames) => frames.into_iter().for_each(|f| drop(tx.send(f))),
                    Err(_) => break,
                }
            }
        });
        Host {
            child,
            stdin: Some(stdin),
            rx,
            closed: false,
        }
    }

    fn records(&self) -> Vec<Record> {
        SqliteStore::open(&db_path(self.home()))
            .unwrap()
            .all()
            .unwrap()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        // cleanup must never panic: a panic while a test is already unwinding aborts the whole run
        self.kill_core_quiet();
        for k in &mut self.kids {
            let _ = k.kill();
            let _ = k.wait();
        }
    }
}

fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out waiting for {what}");
}

struct Host {
    child: Child,
    stdin: Option<ChildStdin>,
    rx: Receiver<Vec<u8>>,
    closed: bool,
}

impl Host {
    fn exit_code(&mut self, within: Duration) -> Option<i32> {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if let Ok(Some(s)) = self.child.try_wait() {
                return s.code();
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }

    fn close_stdin(&mut self) {
        self.stdin = None;
    }
}

impl Transport for Host {
    fn send(&mut self, bytes: &[u8]) {
        if let Some(s) = &mut self.stdin {
            let _ = s.write_all(bytes).and_then(|_| s.flush());
        }
    }

    fn recv(&mut self, timeout: Duration) -> Option<Vec<u8>> {
        match self.rx.recv_timeout(timeout) {
            Ok(f) => Some(f),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => {
                self.closed = true;
                None
            }
        }
    }

    fn is_closed(&self) -> bool {
        self.closed
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// What the extension does on first run: ask the host for the install secret.
fn pair(host: &mut Host) -> InstallSecret {
    host.send(&frame(br#"{"t":"pair"}"#));
    let reply = host.recv(Duration::from_secs(10)).expect("a pairing reply");
    let v: serde_json::Value = serde_json::from_slice(&reply).unwrap();
    assert_eq!(v["t"], "paired", "{v}");
    let bytes = b64_decode(v["secret"].as_str().unwrap()).unwrap();
    InstallSecret::from_bytes(bytes.try_into().unwrap())
}

fn ready_client(env: &mut Env, cn: u8, log: &str) -> Client<Host> {
    let mut host = env.spawn_host(Some(DEV_EXTENSION_ORIGIN), log);
    let secret = pair(&mut host);
    let mut c = Client::new(host);
    c.handshake(&secret, DEV_EXTENSION_ORIGIN, [cn; 16], false)
        .expect("handshake through the host");
    c
}

#[test]
fn pairing_then_a_full_hand_off_works_through_the_real_host_and_core() {
    let mut env = Env::new();
    env.start_app("app.err");
    let mut c = ready_client(&mut env, 1, "host.err");
    let health = c.request("h1", "req-1", Message::Health(Empty {})).unwrap();
    assert!(matches!(health.body, Message::HealthReply(ref h) if h.engine == "loopback"));
    let prepared = receipt_of(
        &c.request("m1", "req-1", Message::Prepare(prepare_body()))
            .unwrap(),
    );
    let armed = c
        .request("m2", "req-1", Message::BeginHandoff(prepared.as_ref()))
        .unwrap();
    assert_eq!(receipt_of(&armed).state, TaskState::Armed);
    let commit = CommitBody {
        cancel: CancelEvidence::Confirmed,
        receipt: prepared.as_ref(),
    };
    c.request("m3", "req-1", Message::Commit(commit)).unwrap();
    wait_until("the task to finish in the engine", || {
        env.records()
            .iter()
            .any(|r| r.task_id == prepared.task_id && r.state == TaskState::Done)
    });
    c.t.close_stdin();
    assert_eq!(
        c.t.exit_code(Duration::from_secs(5)),
        Some(0),
        "the host did not end when the browser closed its input"
    );
}

#[test]
fn a_wrong_origin_never_touches_the_pipe_and_never_starts_a_core() {
    let mut env = Env::new();
    let other = format!("chrome-extension://{}/", "b".repeat(32));
    let mut host = env.spawn_host(Some(&other), "host.err");
    assert_eq!(host.exit_code(Duration::from_secs(5)), Some(2));
    assert!(
        !env.pipe_up(),
        "a core was started for an origin that is not allowed"
    );
    assert!(env.app_pid().is_none());

    let mut none = env.spawn_host(None, "host2.err");
    assert_eq!(
        none.exit_code(Duration::from_secs(5)),
        Some(2),
        "no origin argument at all"
    );
    assert!(!env.pipe_up());
}

#[test]
fn a_second_core_exits_with_a_distinct_code_and_the_first_keeps_serving() {
    let mut env = Env::new();
    env.start_app("app.err");
    let mut second = env
        .cmd(APP)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let status = loop {
        if let Some(s) = second.try_wait().unwrap() {
            break s;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(3));
    let mut c = ready_client(&mut env, 1, "host.err");
    assert!(c.request("h1", "r", Message::Health(Empty {})).is_ok());
}

#[test]
fn killing_the_core_ends_the_host_and_closes_its_output() {
    let mut env = Env::new();
    env.start_app("app.err");
    let mut c = ready_client(&mut env, 1, "host.err");
    env.kill_core();
    assert_eq!(
        c.t.exit_code(Duration::from_secs(10)),
        Some(0),
        "the host stayed alive after the core died"
    );
    assert!(c.t.recv(Duration::from_millis(500)).is_none());
}

#[test]
fn the_host_starts_the_core_on_demand_and_pairing_works_on_the_very_first_run() {
    let mut env = Env::new();
    assert!(!env.pipe_up());
    assert!(
        !env.home().join("install-secret").exists(),
        "precondition: a first run has no secret yet"
    );
    let mut c = ready_client(&mut env, 1, "host.err");
    assert!(env.pipe_up());
    assert!(c.request("h1", "r", Message::Health(Empty {})).is_ok());
}

#[test]
fn a_core_restart_keeps_the_receipt_and_the_stale_pipe_is_reusable() {
    let mut env = Env::new();
    env.start_app("app1.err");
    let before = {
        let mut c = ready_client(&mut env, 1, "host1.err");
        receipt_of(
            &c.request("m1", "req-1", Message::Prepare(prepare_body()))
                .unwrap(),
        )
    };
    env.kill_core();
    env.start_app("app2.err");
    let mut c = ready_client(&mut env, 2, "host2.err");
    let after = receipt_of(&c.request("s1", "req-1", Message::Status(Empty {})).unwrap());
    assert_eq!(
        (after.task_id, after.fingerprint, after.state),
        (before.task_id, before.fingerprint, TaskState::Prepared)
    );
}

#[test]
fn a_raw_pipe_client_without_the_secret_cannot_change_the_store() {
    let mut env = Env::new();
    env.start_app("app.err");
    let mut t = PipeTransport::connect(&env.pipe).unwrap();
    t.send(b"\x04\x00\x00\x00junk");
    t.send(&frame(
        br#"{"t":"hello","v":[1],"cn":"AAAAAAAAAAAAAAAAAAAAAA=="}"#,
    ));
    while t.recv(Duration::from_millis(300)).is_some() {}
    assert!(env.records().is_empty());
}

#[test]
fn no_secret_and_no_request_data_reaches_any_log_the_manifest_or_the_database() {
    let mut env = Env::new();
    env.start_app("app.err");
    let secret_text = {
        let mut c = ready_client(&mut env, 1, "host.err");
        let prepared = receipt_of(
            &c.request("m1", "req-1", Message::Prepare(prepare_body()))
                .unwrap(),
        );
        c.request("m2", "req-1", Message::BeginHandoff(prepared.as_ref()))
            .unwrap();
        fs::read_to_string(env.home().join("install-secret"))
            .unwrap()
            .trim()
            .to_string()
    };
    let raw_secret = b64_decode(&secret_text).unwrap();
    assert_eq!(b64_encode(&raw_secret), secret_text);
    for entry in fs::read_dir(env.home()).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "install-secret" || name.ends_with("-wal") || name.ends_with("-shm") {
            continue;
        }
        let bytes = fs::read(entry.path()).unwrap_or_default();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains(&secret_text),
            "{name} contains the install secret"
        );
        assert!(
            !bytes.windows(32).any(|w| w == raw_secret.as_slice()),
            "{name} contains the raw secret bytes"
        );
        assert!(
            !text.contains(SENTINEL),
            "{name} contains the protected request context"
        );
        if name != "core.db" {
            assert!(!text.contains("x.test"), "{name} contains the request URL");
        }
    }
}

#[test]
fn registration_dry_runs_print_the_exact_manifest_and_change_nothing() {
    let env = Env::new();
    let out = env
        .cmd(HOST)
        .args(["--register", "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    let (manifest, reg) = text
        .split_once("\nreg add")
        .expect("a manifest then a reg command");
    let want = native_manifest(HOST, &[DEV_EXTENSION_ORIGIN.to_string()]).unwrap();
    assert_eq!(manifest.trim(), want.trim());
    assert!(
        reg.contains(r"HKCU\Software\Google\Chrome\NativeMessagingHosts\com.velqra.host"),
        "{reg}"
    );
    assert!(
        !env.home().join("com.velqra.host.json").exists(),
        "a dry run wrote the manifest"
    );

    let out = env
        .cmd(HOST)
        .args(["--unregister", "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8(out.stdout)
        .unwrap()
        .contains("reg delete"));
    let bad = env
        .cmd(HOST)
        .args(["--register", "--frobnicate"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(3));
}

#[test]
fn a_core_started_by_the_host_does_not_keep_the_browsers_pipes_open() {
    // Chrome learns that a native host is gone when the write end of its stdout pipe closes. If the
    // core the host launched inherited that pipe, Chrome would never see the port disconnect for as
    // long as the core runs.
    let mut env = Env::new();
    let mut host = env.spawn_host(Some(DEV_EXTENSION_ORIGIN), "host.err");
    wait_until("the host to start the core", || env.pipe_up());
    host.close_stdin();
    assert_eq!(host.exit_code(Duration::from_secs(10)), Some(0));
    assert!(
        env.pipe_up(),
        "precondition: the core must still be running"
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_eof = false;
    while Instant::now() < deadline {
        if let Err(RecvTimeoutError::Disconnected) =
            host.rx.recv_timeout(Duration::from_millis(100))
        {
            saw_eof = true;
            break;
        }
    }
    assert!(
        saw_eof,
        "the host's stdout stayed open after it exited: the core inherited it"
    );
}
