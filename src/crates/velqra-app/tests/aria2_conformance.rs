// SPDX-License-Identifier: GPL-3.0-only
//! Spec 10.2 "Representation identity and resume", one test per row, run against the real aria2
//! through the product stack (guard + supervisor + adapter). The shared invariant: a task reported
//! Done has exactly the origin's bytes under the final name; anything else is Failed and leaves
//! nothing under the final name. Skipped, loudly, when aria2 is not present.
#![cfg(windows)]

#[path = "support/httpd.rs"]
mod httpd;

use httpd::{payload, ranged, serve, Httpd, Plan};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use velqra_app::aria2::adapter::Aria2Config;
use velqra_app::aria2::process::{Launch, PINNED_ARIA2_SHA256};
use velqra_app::aria2::supervisor::Aria2Supervisor;
use velqra_app::guard::Guarded;
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

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

struct Rig {
    engine: Guarded<Aria2Supervisor>,
    root: PathBuf,
    _dir: tempfile::TempDir,
}

fn rig(exe: PathBuf, split: u32) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("dl");
    std::fs::create_dir_all(&root).unwrap();
    let launch = Launch {
        exe,
        expected_sha256: PINNED_ARIA2_SHA256.into(),
        run_dir: dir.path().join("run"),
        max_concurrent: 3,
        parent_pid: std::process::id(),
        ready_timeout: Duration::from_secs(15),
    };
    let sup = Aria2Supervisor::new(
        launch,
        Aria2Config {
            split,
            per_origin: split,
        },
    );
    Rig {
        engine: Guarded::new(sup, root.clone()),
        root,
        _dir: dir,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum End {
    Done,
    Failed,
    /// The engine stopped for a reason that may pass; the core would retry it.
    Interrupted,
    Stuck,
}

impl Rig {
    fn dest(&self, name: &str) -> PathBuf {
        self.root.join("Other").join(name)
    }

    fn request(&self, attempt: &str, url: &str, name: &str) -> EngineRequest {
        EngineRequest {
            attempt: attempt.into(),
            url: url.into(),
            filename: name.into(),
            context_ref: None,
            destination: Some(self.dest(name).to_string_lossy().into_owned()),
            context: None,
        }
    }

    /// Submits and polls until the task ends or `secs` pass.
    fn run(&mut self, attempt: &str, url: &str, name: &str, secs: u64) -> End {
        let req = self.request(attempt, url, name);
        if self.engine.submit(&req).is_err() {
            return End::Failed;
        }
        self.wait(attempt, secs)
    }

    fn wait(&mut self, attempt: &str, secs: u64) -> End {
        let end = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < end {
            match self.engine.status(attempt) {
                Ok(EngineStatus::Done) => return End::Done,
                Ok(EngineStatus::Failed(_)) => return End::Failed,
                Ok(EngineStatus::Interrupted) => return End::Interrupted,
                _ => std::thread::sleep(Duration::from_millis(100)),
            }
        }
        End::Stuck
    }

    /// The invariant every row shares.
    fn assert_integrity(&self, end: &End, name: &str, acceptable: &[&[u8]]) {
        let dest = self.dest(name);
        match end {
            End::Done => {
                let got = std::fs::read(&dest).expect("Done but nothing under the final name");
                assert!(
                    acceptable.iter().any(|a| sha(a) == sha(&got)),
                    "Done with bytes that are not the origin's (len {})",
                    got.len()
                );
            }
            End::Failed | End::Interrupted | End::Stuck => {
                assert!(
                    !dest.exists(),
                    "{end:?} but something sits under the final name ({} bytes)",
                    std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0)
                );
            }
        }
    }
}

const SIZE: usize = 12_000_000;

#[test]
fn row_valid_206_is_used_for_segments_and_the_bytes_are_exact() {
    let Some(exe) = aria2_path() else { return };
    let data = Arc::new(payload(SIZE, 1));
    let d = data.clone();
    let server = serve(move |r| ranged(&d, r, Some("\"strong-1\"")));
    let mut rig = rig(exe, 4); // segmented mode is opt-in; a correct server must give exact bytes
    let end = rig.run("c1-g1", &server.url("/f.bin"), "f.bin", 40);
    assert_eq!(end, End::Done);
    rig.assert_integrity(&end, "f.bin", &[&data]);
    let ranged_requests = server
        .requests()
        .iter()
        .filter(|r| r.range_start.is_some())
        .count();
    assert!(
        ranged_requests >= 1,
        "no ranged request was made: {ranged_requests}"
    );
}

#[test]
fn row_200_after_a_range_request_is_never_appended() {
    let Some(exe) = aria2_path() else { return };
    let data = Arc::new(payload(SIZE, 2));
    let d = data.clone();
    // a server that ignores Range and always sends the whole body with 200
    let server = serve(move |_| Plan::ok(d.to_vec()));
    let mut rig = rig(exe, 4);
    let end = rig.run("c2-g1", &server.url("/f.bin"), "f.bin", 40);
    println!(
        "row 200-after-range: {end:?}, requests {}",
        server.requests().len()
    );
    rig.assert_integrity(&end, "f.bin", &[&data]);
}

#[test]
fn row_416_never_produces_a_wrong_file() {
    let Some(exe) = aria2_path() else { return };
    let data = Arc::new(payload(SIZE, 3));
    let d = data.clone();
    let server = serve(move |r| {
        if r.range_start.is_some() {
            Plan::status("416 Range Not Satisfiable")
                .header("Content-Range", &format!("bytes */{}", d.len()))
        } else {
            Plan::ok(d.to_vec()).header("Accept-Ranges", "bytes")
        }
    });
    let mut rig = rig(exe, 4);
    let end = rig.run("c3-g1", &server.url("/f.bin"), "f.bin", 40);
    println!("row 416: {end:?}");
    rig.assert_integrity(&end, "f.bin", &[&data]);
}

#[test]
fn row_missing_validators_download_sequentially_and_exactly() {
    let Some(exe) = aria2_path() else { return };
    let data = Arc::new(payload(SIZE, 4));
    let d = data.clone();
    // no ETag, no Last-Modified, no Accept-Ranges
    let server = serve(move |_| Plan::ok(d.to_vec()));
    let mut rig = rig(exe, 4);
    let end = rig.run("c4-g1", &server.url("/f.bin"), "f.bin", 40);
    assert_eq!(end, End::Done);
    rig.assert_integrity(&end, "f.bin", &[&data]);
}

#[test]
fn row_an_html_login_page_is_not_a_finished_download() {
    let Some(exe) = aria2_path() else { return };
    let page = b"<!DOCTYPE html><html><head><title>Sign in</title></head><body>Please log in</body></html>".to_vec();
    let server = serve(move |_| Plan::ok(page.clone()).header("Content-Type", "text/html"));
    let mut rig = rig(exe, 4);
    let end = rig.run("c6-g1", &server.url("/archive.zip"), "archive.zip", 30);
    assert_eq!(
        end,
        End::Failed,
        "an HTML login page was accepted as archive.zip"
    );
    rig.assert_integrity(&end, "archive.zip", &[]);
}

#[test]
fn row_redirect_chains_are_followed_to_the_real_file() {
    let Some(exe) = aria2_path() else { return };
    let data = Arc::new(payload(500_000, 7));
    let d = data.clone();
    let server = serve(move |r| match r.path.as_str() {
        "/a" => Plan::status("302 Found").header("Location", "/b"),
        "/b" => Plan::status("301 Moved Permanently").header("Location", "/c?x=1"),
        _ => ranged(&d, r, Some("\"r\"")),
    });
    let mut rig = rig(exe, 2);
    let end = rig.run("c7-g1", &server.url("/a"), "r.bin", 30);
    assert_eq!(end, End::Done);
    rig.assert_integrity(&end, "r.bin", &[&data]);
}

#[test]
fn row_a_redirect_to_another_scheme_is_not_followed() {
    let Some(exe) = aria2_path() else { return };
    for (i, target) in ["ftp://127.0.0.1:9/x.bin", "file:///C:/Windows/win.ini"]
        .iter()
        .enumerate()
    {
        let t = target.to_string();
        let server = serve(move |_| Plan::status("302 Found").header("Location", &t));
        let mut rig = rig(exe.clone(), 1);
        let end = rig.run(&format!("c8-g{i}"), &server.url("/x"), "x.bin", 30);
        assert_ne!(end, End::Done, "{target}");
        rig.assert_integrity(&end, "x.bin", &[]);
    }
}

#[test]
fn row_after_a_restart_the_partial_is_isolated_and_the_download_starts_over() {
    let Some(exe) = aria2_path() else { return };
    let data = Arc::new(payload(2_000_000, 9));
    let d = data.clone();
    let server = serve(move |r| ranged(&d, r, Some("\"k\"")).slow(400_000));
    let mut rig = rig(exe, 1);
    let req = rig.request("c10-g1", &server.url("/f.bin"), "f.bin");
    rig.engine.submit(&req).unwrap();
    let end = Instant::now() + Duration::from_secs(20);
    while server.sent.load(Ordering::Relaxed) < 600_000 {
        assert!(Instant::now() < end, "no progress");
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(1800)); // let aria2 write its control file
    let before = server.requests().len();
    rig.engine.inner().stop(); // aria2 dies mid-transfer
    assert!(rig.engine.status("c10-g1").is_ok() || rig.engine.status("c10-g1").is_err());
    // the core's behaviour: a fresh aria2 has forgotten the task, so it is submitted again
    let mut tries = 0;
    while !rig.engine.has_forgotten("c10-g1") {
        tries += 1;
        assert!(tries < 100, "aria2 never came back");
        std::thread::sleep(Duration::from_millis(100));
    }
    rig.engine.submit(&req).unwrap();
    let end = rig.wait("c10-g1", 60);
    assert_eq!(end, End::Done);
    rig.assert_integrity(&end, "f.bin", &[&data]);
    let new_requests: Vec<_> = server.requests().into_iter().skip(before).collect();
    assert!(
        new_requests
            .iter()
            .all(|r| r.range_start.is_none() || r.range_start == Some(0)),
        "the restarted run resumed from saved bytes: {new_requests:?}"
    );
    let stale = std::fs::read_dir(rig.dest("f.bin").parent().unwrap())
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".stale-")
        })
        .count();
    assert!(stale >= 1, "the old partial was not kept aside");
}

#[test]
fn row_the_destination_is_never_overwritten() {
    let Some(exe) = aria2_path() else { return };
    let data = Arc::new(payload(200_000, 10));
    let d = data.clone();
    let server: Httpd = serve(move |r| ranged(&d, r, None));
    let mut rig = rig(exe, 2);
    std::fs::create_dir_all(rig.dest("f.bin").parent().unwrap()).unwrap();
    std::fs::write(rig.dest("f.bin"), b"theirs").unwrap();
    let end = rig.run("c11-g1", &server.url("/f.bin"), "f.bin", 10);
    assert_eq!(end, End::Failed);
    assert_eq!(std::fs::read(rig.dest("f.bin")).unwrap(), b"theirs");
    assert!(
        server.requests().is_empty(),
        "the server was contacted for a doomed task"
    );
}

#[test]
fn the_product_default_is_one_connection_and_no_in_session_retry() {
    // These two settings are what keeps aria2 from ever splicing different bytes into one file.
    assert_eq!(Aria2Config::default().split, 1);
    assert_eq!(Aria2Config::default().per_origin, 1);
}

#[test]
fn row_changed_bytes_between_a_dropped_connection_and_its_retry_never_make_a_mixed_file() {
    let Some(exe) = aria2_path() else { return };
    let a = Arc::new(payload(SIZE, 11));
    let b = Arc::new(payload(SIZE, 12)); // same length, different bytes
    let (ca, cb) = (a.clone(), b.clone());
    let n = Arc::new(AtomicUsize::new(0));
    let server = serve(move |r| {
        if n.fetch_add(1, Ordering::Relaxed) == 0 {
            ranged(&ca, r, Some("\"v1\"")).cut(2_000_000)
        } else {
            ranged(&cb, r, Some("\"v2\""))
        }
    });
    let mut rig = rig(exe, 1);
    let end = rig.run("c5-g1", &server.url("/f.bin"), "f.bin", 40);
    assert_eq!(
        end,
        End::Interrupted,
        "a dropped connection must end the attempt (for the core to retry), not resume it"
    );
    rig.assert_integrity(&end, "f.bin", &[&a, &b]);
    assert_eq!(
        server.requests().len(),
        1,
        "aria2 asked again by itself: {:?}",
        server
            .requests()
            .iter()
            .map(|r| r.range_start)
            .collect::<Vec<_>>()
    );
}

#[test]
fn row_a_mid_transfer_disconnect_is_reported_as_interrupted_and_leaves_nothing_under_the_final_name(
) {
    let Some(exe) = aria2_path() else { return };
    let data = Arc::new(payload(SIZE, 8));
    let d = data.clone();
    let server = serve(move |r| ranged(&d, r, Some("\"keep\"")).cut(700_000));
    let mut rig = rig(exe, 1);
    let end = rig.run("c9-g1", &server.url("/f.bin"), "f.bin", 40);
    assert_eq!(end, End::Interrupted);
    rig.assert_integrity(&end, "f.bin", &[&data]);
    let part = rig.dest("f.bin").with_file_name("f.bin.velqra-part");
    assert!(
        part.exists(),
        "the partial bytes stay in the part file for the user to see"
    );
}

/// Known limitation, kept as a manual probe (cargo test -- --ignored): with several segments aria2
/// does not check that every segment request returns the same representation, so a server that
/// changes its bytes between segment requests can produce a mixed file reported as Done. This is
/// why segmented mode is not the default.
#[test]
#[ignore = "documents a confirmed aria2 limitation; prints instead of asserting"]
fn probe_segmented_mode_can_mix_representations() {
    let Some(exe) = aria2_path() else { return };
    let a = Arc::new(payload(SIZE, 5));
    let b = Arc::new(payload(SIZE, 6));
    let (ca, cb) = (a.clone(), b.clone());
    let served = Arc::new(AtomicUsize::new(0));
    let server = serve(move |r| {
        if served.fetch_add(1, Ordering::Relaxed) == 0 {
            ranged(&ca, r, Some("\"v1\""))
        } else {
            ranged(&cb, r, Some("\"v2\""))
        }
    });
    let mut rig = rig(exe, 4);
    let end = rig.run("p-g1", &server.url("/f.bin"), "f.bin", 40);
    let got = std::fs::read(rig.dest("f.bin")).unwrap_or_default();
    println!(
        "segmented, changed bytes: {end:?}; equals A: {}, equals B: {}",
        sha(&got) == sha(&a),
        sha(&got) == sha(&b)
    );
}

#[test]
fn row_a_file_created_under_the_final_name_during_the_download_is_never_replaced() {
    let Some(exe) = aria2_path() else { return };
    let data = Arc::new(payload(2_000_000, 13));
    let d = data.clone();
    let server = serve(move |r| ranged(&d, r, Some("\"z\"")).slow(500_000));
    let mut rig = rig(exe, 1);
    let req = rig.request("c12-g1", &server.url("/f.bin"), "f.bin");
    rig.engine.submit(&req).unwrap();
    std::thread::sleep(Duration::from_millis(800));
    std::fs::write(rig.dest("f.bin"), b"created by someone else meanwhile").unwrap();
    let end = rig.wait("c12-g1", 40);
    assert_eq!(end, End::Failed);
    assert_eq!(
        std::fs::read(rig.dest("f.bin")).unwrap(),
        b"created by someone else meanwhile"
    );
    let part = rig.dest("f.bin").with_file_name("f.bin.velqra-part");
    assert_eq!(
        sha(&std::fs::read(part).unwrap()),
        sha(&data),
        "the finished download is kept in the part file, not deleted"
    );
}

fn openssl_path() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = std::env::var_os("VELQRA_OPENSSL") {
        candidates.push(PathBuf::from(p));
    }
    candidates.push(PathBuf::from(r"C:\Program Files\Git\usr\bin\openssl.exe"));
    candidates.push(PathBuf::from("openssl"));
    let found = candidates.into_iter().find(|c| {
        std::process::Command::new(c)
            .arg("version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    });
    if found.is_none() {
        eprintln!("SKIPPED: no openssl to build a TLS test server (set VELQRA_OPENSSL)");
    }
    found
}

struct Killer(std::process::Child);
impl Drop for Killer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn row_a_certificate_error_stops_the_download_and_there_is_no_way_around_it() {
    let (Some(exe), Some(openssl)) = (aria2_path(), openssl_path()) else {
        return;
    };
    let tls = tempfile::tempdir().unwrap();
    let web = tls.path().join("web");
    std::fs::create_dir_all(&web).unwrap();
    let data = payload(400_000, 14);
    std::fs::write(web.join("file.bin"), &data).unwrap();
    let made = std::process::Command::new(&openssl)
        .current_dir(tls.path())
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "k.pem",
            "-out",
            "c.pem",
            "-subj",
            "/CN=127.0.0.1",
            "-days",
            "1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
        ])
        .output()
        .unwrap();
    assert!(made.status.success(), "could not make a test certificate");
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let _server = Killer(
        std::process::Command::new(&openssl)
            .current_dir(&web)
            .args([
                "s_server",
                "-accept",
                &port.to_string(),
                "-cert",
                "../c.pem",
                "-key",
                "../k.pem",
                "-WWW",
                "-quiet",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let up = Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < up, "the TLS test server did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
    let url = format!("https://127.0.0.1:{port}/file.bin");

    // control: the same server, fetched by an aria2 started by hand with verification switched off
    // globally, delivers the file - so what stops the product's download is the certificate check
    let work = tempfile::tempdir().unwrap();
    let rpc_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let control_aria2 = Killer(
        std::process::Command::new(&exe)
            .args([
                "--enable-rpc=true".to_string(),
                format!("--rpc-listen-port={rpc_port}"),
                "--rpc-secret=control".to_string(),
                "--check-certificate=false".to_string(),
                "--no-conf=true".to_string(),
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let rpc = velqra_app::aria2::rpc::RpcClient::new(
        std::net::SocketAddr::from(([127, 0, 0, 1], rpc_port)),
        "control".into(),
        Duration::from_secs(3),
    );
    let ready = Instant::now() + Duration::from_secs(15);
    while rpc.call("aria2.getVersion", vec![]).is_err() {
        assert!(Instant::now() < ready, "the control aria2 did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
    let control_dir = work.path().join("control");
    rpc.call(
        "aria2.addUri",
        vec![
            serde_json::json!([url]),
            serde_json::json!({"dir": control_dir.to_string_lossy(), "out": "c.bin"}),
        ],
    )
    .expect("control download accepted");
    // s_server answers close-delimited and may keep the connection open, so a finished body is
    // either a completed task or an active one that already holds every byte
    let until = Instant::now() + Duration::from_secs(30);
    let control_ok = loop {
        let stopped = rpc
            .call(
                "aria2.tellStopped",
                vec![serde_json::json!(0), serde_json::json!(10)],
            )
            .unwrap();
        if let Some(t) = stopped.as_array().and_then(|a| a.first()) {
            break t["status"] == "complete";
        }
        let active = rpc.call("aria2.tellActive", vec![]).unwrap();
        if let Some(t) = active.as_array().and_then(|a| a.first()) {
            let got = t["completedLength"]
                .as_str()
                .and_then(|n| n.parse::<usize>().ok());
            if got == Some(data.len()) {
                break true;
            }
        }
        if Instant::now() >= until {
            panic!(
                "control download never delivered the bytes; active {active}; stopped {stopped}"
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    assert!(
        control_ok,
        "the TLS test server cannot be fetched even without verification"
    );
    assert_eq!(
        sha(&std::fs::read(control_dir.join("c.bin")).unwrap()),
        sha(&data)
    );

    // s_server serves one connection at a time and the control's may still be open: end it first
    drop(control_aria2);

    // the product path: certificate verification on, nothing to switch it off
    let mut rig = rig(exe, 1);
    let end = rig.run("c13-g1", &url, "file.bin", 30);
    assert_eq!(end, End::Failed, "an untrusted certificate was accepted");
    rig.assert_integrity(&end, "file.bin", &[]);
}
