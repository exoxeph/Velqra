// SPDX-License-Identifier: GPL-3.0-only
//! Throwaway probe (prints): try to win the window between the guard's checks and aria2's first write
//! by flipping the category folder to a junction that points outside the root.
#![cfg(windows)]
#[path = "support/httpd.rs"]
mod httpd;
use httpd::{payload, ranged, serve};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use velqra_app::aria2::adapter::Aria2Config;
use velqra_app::aria2::process::{Launch, PINNED_ARIA2_SHA256};
use velqra_app::aria2::supervisor::Aria2Supervisor;
use velqra_app::guard::Guarded;
use velqra_core::{Engine, EngineRequest, EngineStatus};

/// Manual probe: cargo test -p velqra-app --test aria2_race_probe -- --ignored --nocapture
#[test]
#[ignore = "manual race probe; prints instead of asserting"]
fn probe_folder_swap_race() {
    let exe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../vendor/aria2/1.37.0/aria2c.exe");
    if !exe.exists() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("dl");
    let outside = d.path().join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let data = Arc::new(payload(300_000, 1));
    let dd = data.clone();
    let server = serve(move |r| ranged(&dd, r, None));
    let sup = Aria2Supervisor::new(
        Launch {
            exe,
            expected_sha256: PINNED_ARIA2_SHA256.into(),
            run_dir: d.path().join("run"),
            max_concurrent: 3,
            parent_pid: std::process::id(),
            ready_timeout: Duration::from_secs(15),
        },
        Aria2Config::default(),
    );
    let mut engine = Guarded::new(sup, root.clone());
    let cat = root.join("Other");
    let stop = Arc::new(AtomicBool::new(false));
    let flips = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (s2, f2, cat2, out2) = (stop.clone(), flips.clone(), cat.clone(), outside.clone());
    let attacker = std::thread::spawn(move || {
        while !s2.load(Ordering::Relaxed) {
            // remove the folder when it is empty, put a junction in its place, then undo it
            if std::fs::remove_dir(&cat2).is_ok() || !cat2.exists() {
                let made = std::process::Command::new("cmd")
                    .args(["/C", "mklink", "/J"])
                    .arg(&cat2)
                    .arg(&out2)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                if made.is_ok() {
                    f2.fetch_add(1, Ordering::Relaxed);
                }
                std::thread::sleep(Duration::from_millis(5));
                let _ = std::fs::remove_dir(&cat2);
            }
        }
    });
    let (mut done, mut failed, mut rejected, mut stuck) = (0, 0, 0, 0);
    for i in 0..40 {
        let name = format!("f{i}.bin");
        let req = EngineRequest {
            attempt: format!("r{i}-g1"),
            url: server.url(&format!("/{name}")),
            filename: name.clone(),
            context_ref: None,
            destination: Some(cat.join(&name).to_string_lossy().into_owned()),
            context: None,
        };
        if engine.submit(&req).is_err() {
            rejected += 1;
            continue;
        }
        let end = Instant::now() + Duration::from_secs(8);
        let mut verdict = "stuck";
        while Instant::now() < end {
            match engine.status(&format!("r{i}-g1")) {
                Ok(EngineStatus::Done) => {
                    verdict = "done";
                    break;
                }
                Ok(EngineStatus::Failed(_)) | Ok(EngineStatus::Interrupted) => {
                    verdict = "failed";
                    break;
                }
                _ => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        match verdict {
            "done" => done += 1,
            "failed" => failed += 1,
            _ => stuck += 1,
        }
        // a Done must be a real file under the root with the right bytes
        if verdict == "done" {
            let p = cat.join(&name);
            let got = std::fs::read(&p).unwrap_or_default();
            assert_eq!(
                got,
                *data,
                "Done but the file under the root is wrong: {}",
                p.display()
            );
        }
    }
    stop.store(true, Ordering::Relaxed);
    attacker.join().unwrap();
    let leaked: Vec<_> = std::fs::read_dir(&outside)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    println!(
        "PROBE flips={} done={done} failed={failed} rejected={rejected} stuck={stuck}",
        flips.load(Ordering::Relaxed)
    );
    println!("PROBE files that landed outside the root: {leaked:?}");
}
