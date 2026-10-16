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
            .env("VELQRA_APP", APP)
            .env("VELQRA_ALLOW_LOOPBACK", "1")
            .env_remove("VELQRA_ARIA2");
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
        self.start_app_with(log, &[])
    }

    fn start_app_with(&mut self, log: &str, envs: &[(&str, &std::ffi::OsStr)]) -> u32 {
        let err = fs::File::create(self.log(log)).unwrap();
        let mut cmd = self.cmd(APP);
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let child = cmd
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
            let _ = Command::new("powershell.exe")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &format!("Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue"),
                ])
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
        for k in &mut self.kids {
            let _ = k.kill();
            let _ = k.wait();
        }
        self.kill_core_quiet();
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
        let key = velqra_app::paths::load_secret(env.home())
            .unwrap()
            .expect("pairing created the secret");
        b64_encode(key.expose())
    };
    let raw_secret = b64_decode(&secret_text).unwrap();
    assert_eq!(b64_encode(&raw_secret), secret_text);
    let on_disk = fs::read(env.home().join("install-secret")).unwrap();
    assert!(
        !String::from_utf8_lossy(&on_disk).contains(&secret_text)
            && !on_disk.windows(32).any(|w| w == raw_secret.as_slice()),
        "the install secret file holds the key in the clear"
    );
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
        assert!(!text.contains("x.test"), "{name} contains the request URL");
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

fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[test]
fn the_url_and_context_reach_no_file_in_the_home_directory_in_the_clear() {
    const URL: &str = "https://tokens.leak-check.example/dl/a.zip?sig=E2E-URL-SENTINEL-77";
    let mut env = Env::new();
    env.start_app("app.err");
    let mut c = ready_client(&mut env, 1, "host.err");
    let mut body = prepare_body();
    body.url = URL.into();
    let prepared = receipt_of(&c.request("m1", "req-1", Message::Prepare(body)).unwrap());
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
    let mut files = Vec::new();
    walk(env.home(), &mut files);
    let vault = velqra_app::paths::vault_dir(env.home());
    assert_eq!(
        files.iter().filter(|f| f.starts_with(&vault)).count(),
        2,
        "the url and the context are in the vault: {files:?}"
    );
    let needles = [
        URL,
        "leak-check.example",
        "E2E-URL-SENTINEL",
        velqra_bridge::testkit::SENTINEL,
    ];
    for f in files
        .iter()
        .filter(|f| !f.ends_with("install-secret") && !f.to_string_lossy().ends_with(".err"))
    {
        let bytes = std::fs::read(f).unwrap();
        for n in needles {
            assert!(
                !bytes.windows(n.len()).any(|w| w == n.as_bytes()),
                "{n} found in {}",
                f.display()
            );
        }
    }
}

#[test]
fn the_snapshot_comes_from_settings_json_and_a_download_gets_a_reserved_destination() {
    let mut env = Env::new();
    fs::write(
        env.home().join("settings.json"),
        r#"{"mode":"per_site","allowed_sites":["*.example.test"],"extensions":["zip","iso"]}"#,
    )
    .unwrap();
    env.start_app("app.err");
    let mut c = ready_client(&mut env, 1, "host.err");
    let reply = c
        .request("g1", "req-1", Message::SettingsGet(Empty {}))
        .unwrap();
    let Message::SettingsReply(snap) = &reply.body else {
        panic!("{:?}", reply.body)
    };
    assert_eq!(snap.mode, CaptureMode::PerSite);
    assert_eq!(snap.allowed_sites, ["*.example.test"]);
    assert_eq!(snap.extensions, ["zip", "iso"]);
    assert_eq!(snap.problem, None);
    let wire = serde_json::to_string(&reply).unwrap();
    assert!(
        !wire.contains("downloads") && !wire.contains("Compressed"),
        "{wire}"
    );

    let prepared = receipt_of(
        &c.request("m1", "req-1", Message::Prepare(prepare_body()))
            .unwrap(),
    );
    let rec = env
        .records()
        .into_iter()
        .find(|r| r.task_id == prepared.task_id)
        .unwrap();
    let dest = std::path::PathBuf::from(rec.destination.expect("a reserved destination").path);
    assert!(
        dest.starts_with(env.home().join("downloads").join("Compressed")),
        "{}",
        dest.display()
    );
    assert!(dest.ends_with("a.zip"));
    assert!(
        !dest.exists(),
        "Prepare reserves a name; it creates no file"
    );
}

#[test]
fn a_damaged_settings_file_keeps_the_defaults_and_is_reported() {
    let mut env = Env::new();
    fs::write(env.home().join("settings.json"), r#"{"mode":"always"}"#).unwrap();
    env.start_app("app.err");
    let mut c = ready_client(&mut env, 1, "host.err");
    let reply = c
        .request("g1", "req-1", Message::SettingsGet(Empty {}))
        .unwrap();
    let Message::SettingsReply(snap) = &reply.body else {
        panic!("{:?}", reply.body)
    };
    assert_eq!(snap.mode, CaptureMode::On);
    assert!(snap.problem.is_some());
    assert!(!snap.problem.as_deref().unwrap().contains("always"));
}

#[test]
fn a_client_cannot_write_settings_by_sending_a_reply_type() {
    let mut env = Env::new();
    env.start_app("app.err");
    let mut c = ready_client(&mut env, 1, "host.err");
    let forged = SettingsSnapshot {
        transfer_capable: true,
        mode: CaptureMode::Off,
        extensions: vec!["pdf".into()],
        excluded_sites: vec![],
        allowed_sites: vec![],
        problem: None,
    };
    let reply = c
        .request("f1", "req-1", Message::SettingsReply(forged))
        .unwrap();
    assert!(matches!(reply.body, Message::Error(_)), "{:?}", reply.body);
    let after = c
        .request("g1", "req-1", Message::SettingsGet(Empty {}))
        .unwrap();
    let Message::SettingsReply(snap) = &after.body else {
        panic!("{:?}", after.body)
    };
    assert_eq!(snap.mode, CaptureMode::On);
    assert_ne!(snap.extensions, ["pdf"]);
}

fn aria2_exe() -> Option<PathBuf> {
    let p = std::env::var_os("VELQRA_ARIA2")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../vendor/aria2/1.37.0/aria2c.exe")
        });
    if !p.exists() {
        eprintln!("SKIPPED: aria2c.exe not found");
        return None;
    }
    Some(p.canonicalize().unwrap())
}

fn aria2_process_count() -> usize {
    let out = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "@(Get-Process aria2c -ErrorAction SilentlyContinue).Count",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "process count unavailable");
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
}

#[test]
fn real_host_core_and_aria2_download_a_file_and_aria2_dies_with_the_core() {
    let Some(exe) = aria2_exe() else { return };
    use std::io::{Read, Write};
    let body: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let served = body.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut s) = conn else { continue };
            let served = served.clone();
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut b = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&b[..n]),
                    }
                }
                let h = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    served.len()
                );
                let _ = s.write_all(h.as_bytes());
                let _ = s.write_all(&served);
            });
        }
    });

    assert_eq!(
        aria2_process_count(),
        0,
        "another aria2 is running; the test needs a clean machine"
    );
    let mut env = Env::new();
    env.start_app_with("app.err", &[("VELQRA_ARIA2", exe.as_os_str())]);
    let mut c = ready_client(&mut env, 1, "host.err");
    let health = c.request("h1", "req-1", Message::Health(Empty {})).unwrap();
    assert!(
        matches!(health.body, Message::HealthReply(ref h) if h.engine == "aria2"),
        "{:?}",
        health.body
    );

    let mut prepare = prepare_body();
    prepare.url = format!("http://127.0.0.1:{port}/file.bin");
    prepare.filename = "file.bin".into();
    let prepared = receipt_of(&c.request("m1", "req-1", Message::Prepare(prepare)).unwrap());
    let armed = c
        .request("m2", "req-1", Message::BeginHandoff(prepared.as_ref()))
        .unwrap();
    assert_eq!(receipt_of(&armed).state, TaskState::Armed);
    let commit = CommitBody {
        cancel: CancelEvidence::Confirmed,
        receipt: prepared.as_ref(),
    };
    c.request("m3", "req-1", Message::Commit(commit)).unwrap();
    wait_until("the real download to finish", || {
        env.records()
            .iter()
            .any(|r| r.task_id == prepared.task_id && r.state == TaskState::Done)
    });
    let dest = env.home().join("downloads").join("Other").join("file.bin");
    assert_eq!(fs::read(&dest).unwrap(), body);
    assert_eq!(
        fs::read_dir(env.home().join("aria2-run"))
            .map(|d| d.count())
            .unwrap_or(0),
        0,
        "the secret config file lingered"
    );
    assert!(
        aria2_process_count() >= 1,
        "aria2 should be running while the core is"
    );

    // killing the core must take aria2 with it
    env.kill_core_quiet();
    wait_until("aria2 to exit with the core", || aria2_process_count() == 0);
}

#[test]
fn settings_limits_gate_real_downloads_the_second_waits_for_the_first() {
    let Some(exe) = aria2_exe() else { return };
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    let finished = Arc::new(AtomicUsize::new(0));
    // for each request: how many responses were already complete when it arrived
    let seen: Arc<Mutex<Vec<(usize, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (fin, log) = (finished.clone(), seen.clone());
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut s) = conn else { continue };
            let (fin, log) = (fin.clone(), log.clone());
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut b = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&b[..n]),
                    }
                }
                let first_line = String::from_utf8_lossy(&head)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                log.lock()
                    .unwrap()
                    .push((fin.load(Ordering::SeqCst), first_line));
                let body = vec![7u8; 400_000];
                let h = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(h.as_bytes());
                let pieces: Vec<&[u8]> = body.chunks(40_000).collect();
                for (i, piece) in pieces.iter().enumerate() {
                    if s.write_all(piece).is_err() {
                        return;
                    }
                    if i + 1 < pieces.len() {
                        std::thread::sleep(Duration::from_millis(150));
                    }
                }
                // counted the moment the last byte is out, not after a pause the client never sees
                fin.fetch_add(1, Ordering::SeqCst);
            });
        }
    });

    let mut env = Env::new();
    fs::write(
        env.home().join("settings.json"),
        r#"{"limits":{"max_active":2,"per_origin":1}}"#,
    )
    .unwrap();
    env.start_app_with("app.err", &[("VELQRA_ARIA2", exe.as_os_str())]);
    let mut c = ready_client(&mut env, 1, "host.err");
    let mut ids = Vec::new();
    for n in 1..=2u32 {
        let rid = format!("req-{n}");
        let mut prepare = prepare_body();
        prepare.download_key = format!("k{n}");
        prepare.url = format!("http://127.0.0.1:{port}/f{n}.bin");
        prepare.filename = format!("f{n}.bin");
        let prepared = receipt_of(
            &c.request(&format!("m1-{n}"), &rid, Message::Prepare(prepare))
                .unwrap(),
        );
        c.request(
            &format!("m2-{n}"),
            &rid,
            Message::BeginHandoff(prepared.as_ref()),
        )
        .unwrap();
        let commit = CommitBody {
            cancel: CancelEvidence::Confirmed,
            receipt: prepared.as_ref(),
        };
        c.request(&format!("m3-{n}"), &rid, Message::Commit(commit))
            .unwrap();
        ids.push(prepared.task_id);
    }
    wait_until("both downloads to finish", || {
        env.records()
            .iter()
            .filter(|r| ids.contains(&r.task_id) && r.state == TaskState::Done)
            .count()
            == 2
    });
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(seen[0].0, 0);
    let summary: Vec<String> = env
        .records()
        .iter()
        .map(|r| {
            format!(
                "task {} state {:?} history {:?} retries {} attempt {:?} reason {:?} queued {:?}",
                r.task_id,
                r.state,
                r.history,
                r.retries,
                r.dispatch_attempt,
                r.fail_reason,
                r.queued_reason
            )
        })
        .collect();
    assert_eq!(
        seen[1].0,
        1,
        "the second download started before the first had finished: {seen:?}
{}",
        summary.join(
            "
"
        )
    );
    env.kill_core_quiet();
}

#[test]
fn by_the_time_the_core_answers_on_its_pipe_the_install_secret_already_exists() {
    // The host reads the secret as soon as the pipe answers, so the secret must come first.
    let mut hits = 0;
    for _ in 0..12 {
        let mut env = Env::new();
        let child = env
            .cmd(APP)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        env.kids.push(child);
        let secret = env.home().join("install-secret");
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if env.pipe_up() {
                assert!(
                    secret.exists(),
                    "the pipe answered before the install secret existed"
                );
                hits += 1;
                break;
            }
            assert!(Instant::now() < end, "the core never answered");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(hits, 12);
}
