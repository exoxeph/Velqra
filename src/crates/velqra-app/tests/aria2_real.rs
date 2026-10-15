// SPDX-License-Identifier: GPL-3.0-only
//! The real aria2 1.37.0 (the pinned build in vendor/) driven through our process manager and
//! adapter, against a local HTTP server. Skipped, loudly, when the binary is not there.
#![cfg(windows)]

use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use velqra_app::aria2::adapter::{Aria2Config, Aria2Engine};
use velqra_app::aria2::process::{Aria2Process, Launch, PINNED_ARIA2_SHA256};
use velqra_core::{Engine, EngineRequest, EngineStatus};

fn aria2_path() -> Option<PathBuf> {
    let from_env = std::env::var_os("VELQRA_ARIA2").map(PathBuf::from);
    let vendored =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../vendor/aria2/1.37.0/aria2c.exe");
    let found = from_env.or(Some(vendored)).filter(|p| p.exists());
    if found.is_none() {
        eprintln!("SKIPPED: aria2c.exe not found (set VELQRA_ARIA2 or run handoff 26a)");
    }
    found
}

fn launch(exe: PathBuf, run_dir: PathBuf) -> Launch {
    Launch {
        exe,
        expected_sha256: PINNED_ARIA2_SHA256.into(),
        run_dir,
        max_concurrent: 3,
        parent_pid: std::process::id(),
        ready_timeout: Duration::from_secs(15),
    }
}

/// Pseudo-random but reproducible content.
fn payload(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

struct Server {
    port: u16,
    ranges: Arc<Mutex<Vec<String>>>,
    sent: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

/// Serves `body` at /file.bin with Range support; `bytes_per_second` slows it down (0 = full speed).
fn serve(body: Vec<u8>, bytes_per_second: usize) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let ranges = Arc::new(Mutex::new(Vec::new()));
    let sent = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (r, s, st) = (ranges.clone(), sent.clone(), stop.clone());
    let body = Arc::new(body);
    thread::spawn(move || {
        for conn in listener.incoming() {
            if st.load(Ordering::Relaxed) {
                return;
            }
            let Ok(mut stream) = conn else { continue };
            let (body, r, s, st) = (body.clone(), r.clone(), s.clone(), st.clone());
            thread::spawn(move || {
                let mut head = Vec::new();
                let mut b = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut b) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&b[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&head).to_string();
                let range_start = text
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("range: bytes=")
                            .map(str::to_string)
                    })
                    .and_then(|v| {
                        v.split('-')
                            .next()
                            .and_then(|n| n.trim().parse::<usize>().ok())
                    });
                if let Some(start) = range_start {
                    r.lock().unwrap().push(format!("bytes={start}-"));
                }
                let start = range_start.unwrap_or(0).min(body.len());
                let status = if range_start.is_some() {
                    "206 Partial Content"
                } else {
                    "200 OK"
                };
                let mut header = format!(
                    "HTTP/1.1 {status}\r\nAccept-Ranges: bytes\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len() - start
                );
                if range_start.is_some() {
                    header += &format!(
                        "Content-Range: bytes {start}-{}/{}\r\n",
                        body.len() - 1,
                        body.len()
                    );
                }
                header += "\r\n";
                if stream.write_all(header.as_bytes()).is_err() {
                    return;
                }
                if text.starts_with("HEAD ") {
                    return;
                }
                let chunk = if bytes_per_second == 0 {
                    64 * 1024
                } else {
                    (bytes_per_second / 10).max(1)
                };
                for piece in body[start..].chunks(chunk) {
                    if st.load(Ordering::Relaxed) || stream.write_all(piece).is_err() {
                        return;
                    }
                    s.fetch_add(piece.len() as u64, Ordering::Relaxed);
                    if bytes_per_second != 0 {
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            });
        }
    });
    Server {
        port,
        ranges,
        sent,
        stop,
    }
}

fn request(attempt: &str, port: u16, dest: &Path) -> EngineRequest {
    EngineRequest {
        attempt: attempt.into(),
        url: format!("http://127.0.0.1:{port}/file.bin"),
        filename: "file.bin".into(),
        context_ref: None,
        destination: Some(dest.to_string_lossy().into_owned()),
        context: None,
    }
}

fn until<T>(what: &str, secs: u64, mut f: impl FnMut() -> Option<T>) -> T {
    let end = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < end, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(100));
    }
}

fn command_line_of(pid: u32) -> String {
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("(Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\").CommandLine"),
        ])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn start_answers_with_the_pinned_version_keeps_the_secret_off_the_command_line_and_stops() {
    let Some(exe) = aria2_path() else { return };
    let d = tempfile::tempdir().unwrap();
    let run = d.path().join("run");
    let mut p = Aria2Process::spawn(&launch(exe, run.clone())).expect("aria2 starts");
    let client = p.client(Duration::from_secs(3));
    let v = client.call("aria2.getVersion", vec![]).unwrap();
    assert_eq!(v["version"], "1.37.0");
    // the config file that carried the secret is gone
    assert_eq!(
        std::fs::read_dir(&run).unwrap().count(),
        0,
        "the secret file lingered"
    );
    // the folder that held the secret file has no inherited access list
    let acl = std::process::Command::new("icacls")
        .arg(&run)
        .output()
        .unwrap();
    let acl = String::from_utf8_lossy(&acl.stdout).to_string();
    assert!(
        !acl.contains("(I)"),
        "the run folder inherits access: {acl}"
    );
    assert!(!acl.contains("Administrators"), "{acl}");
    let cmd = command_line_of(p.pid());
    assert!(cmd.contains("--stop-with-process="), "{cmd}");
    assert!(cmd.contains("--check-certificate=true"), "{cmd}");
    assert!(!cmd.to_ascii_lowercase().contains("rpc-secret"), "{cmd}");
    let pid = p.pid();
    assert!(p.is_alive());
    p.stop();
    assert!(!p.is_alive());
    assert!(
        !command_line_of(pid).contains("aria2"),
        "the process is gone"
    );
}

#[test]
fn a_download_completes_with_the_right_bytes_and_the_same_attempt_is_the_same_task() {
    let Some(exe) = aria2_path() else { return };
    let d = tempfile::tempdir().unwrap();
    let data = payload(1_500_000);
    let server = serve(data.clone(), 0);
    let p = Aria2Process::spawn(&launch(exe, d.path().join("run"))).unwrap();
    let mut engine = Aria2Engine::new(p.client(Duration::from_secs(3)), Aria2Config::default());
    let dest_dir = d.path().join("dl");
    std::fs::create_dir_all(&dest_dir).unwrap();
    let dest = dest_dir.join("file.bin");
    let req = request("t1-g1", server.port, &dest);
    engine.submit(&req).expect("accepted");
    engine
        .submit(&req)
        .expect("the same attempt again is the same task, not an error");
    let done = until("completion", 30, || match engine.status("t1-g1") {
        Ok(EngineStatus::Done) => Some(true),
        Ok(EngineStatus::Failed(_)) => Some(false),
        _ => None,
    });
    assert!(done, "the download failed");
    assert_eq!(sha(&std::fs::read(&dest).unwrap()), sha(&data));
    assert_eq!(engine.finished("t1-g1"), Some(true));
    assert_eq!(
        std::fs::read_dir(&dest_dir).unwrap().count(),
        1,
        "no stray control files"
    );
}

#[test]
fn an_existing_file_is_never_overwritten_or_renamed() {
    let Some(exe) = aria2_path() else { return };
    let d = tempfile::tempdir().unwrap();
    let server = serve(payload(200_000), 0);
    let p = Aria2Process::spawn(&launch(exe, d.path().join("run"))).unwrap();
    let mut engine = Aria2Engine::new(p.client(Duration::from_secs(3)), Aria2Config::default());
    let dest = d.path().join("file.bin");
    std::fs::write(&dest, b"mine, do not touch").unwrap();
    engine
        .submit(&request("t2-g1", server.port, &dest))
        .unwrap();
    let failed = until("a verdict", 20, || match engine.status("t2-g1") {
        Ok(EngineStatus::Failed(_)) => Some(true),
        Ok(EngineStatus::Done) => Some(false),
        _ => None,
    });
    assert!(
        failed,
        "aria2 must refuse to download over an existing file"
    );
    assert_eq!(std::fs::read(&dest).unwrap(), b"mine, do not touch");
    let names: Vec<_> = std::fs::read_dir(d.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("file"))
        .collect();
    assert_eq!(names, ["file.bin"], "no renamed copy: {names:?}");
}

#[test]
fn killing_aria2_mid_transfer_then_restarting_resumes_the_same_task_by_gid() {
    let Some(exe) = aria2_path() else { return };
    let d = tempfile::tempdir().unwrap();
    let data = payload(2_000_000);
    let server = serve(data.clone(), 400_000); // about 5 seconds for the whole file
    let dest_dir = d.path().join("dl");
    std::fs::create_dir_all(&dest_dir).unwrap();
    let dest = dest_dir.join("file.bin");
    let req = request("t3-g1", server.port, &dest);
    let one = Aria2Config {
        split: 1,
        per_origin: 1,
    };

    let mut first = Aria2Process::spawn(&launch(exe.clone(), d.path().join("run"))).unwrap();
    {
        let mut engine = Aria2Engine::new(first.client(Duration::from_secs(3)), one);
        engine.submit(&req).unwrap();
        until("some progress", 20, || match engine.status("t3-g1") {
            Ok(EngineStatus::Active { done, .. }) if done > 300_000 => Some(()),
            _ => None,
        });
        thread::sleep(Duration::from_millis(1800)); // let aria2 write its control file
        first.stop();
        // while it is dead the engine cannot tell anything: that is NOT "forgotten"
        assert!(engine.status("t3-g1").is_err());
        assert!(!engine.has_forgotten("t3-g1"));
    }

    let second = Aria2Process::spawn(&launch(exe, d.path().join("run"))).unwrap();
    let mut engine = Aria2Engine::new(second.client(Duration::from_secs(3)), one);
    assert!(
        engine.has_forgotten("t3-g1"),
        "a fresh aria2 has never heard of the gid"
    );
    assert_eq!(engine.status("t3-g1"), Ok(EngineStatus::Unknown));
    engine
        .submit(&req)
        .expect("the same gid is submitted again");
    let ok = until("completion after restart", 40, || {
        match engine.status("t3-g1") {
            Ok(EngineStatus::Done) => Some(true),
            Ok(EngineStatus::Failed(_)) => Some(false),
            _ => None,
        }
    });
    assert!(ok, "the resumed download failed");
    assert_eq!(sha(&std::fs::read(&dest).unwrap()), sha(&data));
    let ranges = server.ranges.lock().unwrap().clone();
    assert!(
        ranges.iter().any(|r| r != "bytes=0-"),
        "the second run must have resumed with a Range request, saw {ranges:?}"
    );
    assert!(
        server.sent.load(Ordering::Relaxed) < 2 * data.len() as u64 - 200_000,
        "the whole file was fetched twice"
    );
}

mod end_to_end {
    use super::*;
    use velqra_app::aria2::supervisor::Aria2Supervisor;
    use velqra_core::destination::DestinationPolicy;
    use velqra_core::store::{MemStore, Store};
    use velqra_core::Core;
    use velqra_protocol::*;

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
    fn the_core_finishes_a_download_even_when_aria2_is_killed_in_the_middle() {
        let Some(exe) = aria2_path() else { return };
        let d = tempfile::tempdir().unwrap();
        let data = payload(2_000_000);
        let server = serve(data.clone(), 400_000);
        let root = d.path().join("downloads");
        std::fs::create_dir_all(&root).unwrap();
        let mut core =
            Core::new(MemStore::default()).with_destination(DestinationPolicy::new(root.clone()));
        let body = PrepareBody {
            download_key: "k".into(),
            url: format!("http://127.0.0.1:{}/file.bin", server.port),
            filename: "file.bin".into(),
            context: Secret("{}".into()),
        };
        let rr = RequestRef {
            task_id: 1,
            fingerprint: fingerprint(&body),
        };
        core.handle(&env(Message::Prepare(body)), 1);
        core.handle(&env(Message::BeginHandoff(rr.clone())), 2);
        core.handle(
            &env(Message::Commit(CommitBody {
                cancel: CancelEvidence::Confirmed,
                receipt: rr,
            })),
            3,
        );
        let dest = PathBuf::from(
            core.store
                .get_by_task(1)
                .unwrap()
                .unwrap()
                .destination
                .unwrap()
                .path,
        );
        assert!(dest.starts_with(root.join("Other")), "{}", dest.display());
        // the folder the core chose is made by the engine side before the first write
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();

        let mut engine = Aria2Supervisor::new(
            launch(exe, d.path().join("run")),
            Aria2Config {
                split: 1,
                per_origin: 1,
            },
        );
        let mut killed = false;
        let state = until("the task to end", 60, || {
            core.pump(&mut engine).unwrap();
            let rec = core.store.get_by_task(1).unwrap().unwrap();
            if !killed && server.sent.load(Ordering::Relaxed) > 700_000 {
                thread::sleep(Duration::from_millis(1800));
                let pid = engine.pid().expect("aria2 is running");
                let out = std::process::Command::new("taskkill")
                    .args(["/F", "/PID", &pid.to_string()])
                    .output()
                    .unwrap();
                assert!(out.status.success(), "could not kill aria2");
                killed = true;
            }
            matches!(rec.state, TaskState::Done | TaskState::Failed).then_some(rec.state)
        });
        assert!(killed, "the kill never happened; the test proved nothing");
        assert_eq!(state, TaskState::Done);
        assert_eq!(engine.starts, 2, "aria2 was restarted exactly once");
        assert_eq!(sha(&std::fs::read(&dest).unwrap()), sha(&data));
        assert!(
            server
                .ranges
                .lock()
                .unwrap()
                .iter()
                .any(|r| r != "bytes=0-"),
            "the restarted download must resume with a Range request"
        );
        let rec = core.store.get_by_task(1).unwrap().unwrap();
        assert_eq!(rec.engine_redispatches, 1);
    }

    #[test]
    fn a_dropped_connection_is_retried_by_the_core_with_a_fresh_attempt_and_the_file_is_exact() {
        use velqra_app::guard::Guarded;
        let Some(exe) = aria2_path() else { return };
        let d = tempfile::tempdir().unwrap();
        let data = payload(1_500_000);
        let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (body, count) = (data.clone(), served.clone());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut s) = conn else { continue };
                let (body, count) = (body.clone(), count.clone());
                thread::spawn(move || {
                    let mut head = Vec::new();
                    let mut b = [0u8; 1024];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut b) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&b[..n]),
                        }
                    }
                    let first = count.fetch_add(1, Ordering::SeqCst) == 0;
                    let h = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = s.write_all(h.as_bytes());
                    let send = if first { 500_000 } else { body.len() };
                    let _ = s.write_all(&body[..send]); // the first connection hangs up early
                });
            }
        });
        let root = d.path().join("downloads");
        std::fs::create_dir_all(&root).unwrap();
        let mut core = Core::new(MemStore::default())
            .with_destination(DestinationPolicy::new(root.clone()))
            .with_limits(3, 4);
        let body = PrepareBody {
            download_key: "k".into(),
            url: format!("http://127.0.0.1:{port}/file.bin"),
            filename: "file.bin".into(),
            context: Secret("{}".into()),
        };
        let rr = RequestRef {
            task_id: 1,
            fingerprint: fingerprint(&body),
        };
        core.handle(&env(Message::Prepare(body)), 1);
        core.handle(&env(Message::BeginHandoff(rr.clone())), 2);
        core.handle(
            &env(Message::Commit(CommitBody {
                cancel: CancelEvidence::Confirmed,
                receipt: rr,
            })),
            3,
        );
        let mut engine = Guarded::new(
            Aria2Supervisor::new(launch(exe, d.path().join("run")), Aria2Config::default()),
            root.clone(),
        );
        let clock = Instant::now();
        let end = until("the task to end", 60, || {
            core.pump_at(&mut engine, clock.elapsed().as_secs())
                .unwrap();
            let rec = core.store.get_by_task(1).unwrap().unwrap();
            matches!(rec.state, TaskState::Done | TaskState::Failed).then_some(rec)
        });
        assert_eq!(end.state, TaskState::Done, "reason: {:?}", end.fail_reason);
        assert_eq!(end.retries, 1, "exactly one retry was needed");
        assert_eq!(end.dispatch_attempt.as_deref(), Some("t1-g1-r1"));
        let dest = PathBuf::from(end.destination.unwrap().path);
        assert_eq!(sha(&std::fs::read(&dest).unwrap()), sha(&data));
        let stale = std::fs::read_dir(dest.parent().unwrap())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".stale-")
            })
            .count();
        assert!(
            stale >= 1,
            "the interrupted partial was set aside, not resumed"
        );
    }
}
