// SPDX-License-Identifier: GPL-3.0-only
//! The native-messaging host. Chrome starts it with the caller's origin as an argument and speaks
//! length-prefixed JSON on stdio; the host relays between that and the core's named pipe.
//!
//! Exit codes: 0 normal end (browser closed stdin or the core went away), 2 not started by an
//! allowed extension, 3 bad arguments, 4 the core could not be reached or started, 5 bad data from
//! the browser, 6 write failed, 7 pipe read failed.
//!
//! The origin is checked before the pipe is touched, so a wrong caller never causes a core to start.

use crate::paths::{allowed_origins, home_dir, load_secret, pipe_name};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{sync_channel, TryRecvError};
use std::time::{Duration, Instant};
use velqra_bridge::host::{native_manifest, parse_origin, HostRelay, Out};
use velqra_ipc::{connect, Connection};

const START_BUDGET: Duration = Duration::from_secs(5);
const REGISTRY_KEY: &str = r"HKCU\Software\Google\Chrome\NativeMessagingHosts\com.velqra.host";

fn say(msg: &str) {
    eprintln!("velqra-host: {msg}");
}

pub fn run(args: Vec<String>) -> i32 {
    if let Some(cmd) = args.first().map(String::as_str) {
        if matches!(cmd, "--register" | "--unregister") {
            return manage(cmd, &args[1..]);
        }
    }
    let Some(origin) = parse_origin(&args) else {
        say("not started by an extension");
        return 2;
    };
    let allowed = allowed_origins();
    // the origin is judged before anything else happens: a wrong caller must never start a core
    if !allowed.contains(&origin) {
        say("this extension is not allowed");
        return 2;
    }
    let Some(mut conn) = reach_core() else {
        say("the core is not reachable");
        return 4;
    };
    // the secret is read only now: on the very first run the core creates it when it starts
    let secret = home_dir().ok().and_then(|h| load_secret(&h).ok().flatten());
    let mut relay = match HostRelay::new(&origin, &allowed, secret) {
        Ok(r) => r,
        Err(_) => {
            say("this extension is not allowed");
            return 2;
        }
    };
    if conn.write_all(&relay.attach_frame()).is_err() {
        say("the core is not reachable");
        return 4;
    }
    relay_loop(&mut relay, &mut conn)
}

fn relay_loop(relay: &mut HostRelay, conn: &mut Connection) -> i32 {
    // stdin is read on its own thread so the main loop can also watch the pipe
    let (tx, rx) = sync_channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => {
                    let _ = tx.send(Vec::new()); // end of input
                    return;
                }
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        return;
                    }
                }
            }
        }
    });
    let mut stdout = std::io::stdout().lock();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match rx.try_recv() {
            Ok(chunk) if chunk.is_empty() => return 0,
            Ok(chunk) => {
                let outs = match relay.from_browser(&chunk) {
                    Ok(o) => o,
                    Err(_) => return 5,
                };
                for o in outs {
                    let ok = match o {
                        Out::ToPipe(b) => conn.write_all(&b).is_ok(),
                        Out::ToBrowser(b) => {
                            stdout.write_all(&b).and_then(|_| stdout.flush()).is_ok()
                        }
                    };
                    if !ok {
                        return 6;
                    }
                }
                continue;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => return 0,
        }
        match conn.read_timeout(&mut buf, Duration::from_millis(10)) {
            Ok(0) => return 0, // the core went away: closing stdout tells Chrome the port is gone
            Ok(n) => {
                let outs = match relay.from_pipe(&buf[..n]) {
                    Ok(o) => o,
                    Err(_) => return 5,
                };
                for o in outs {
                    if let Out::ToBrowser(b) = o {
                        if stdout.write_all(&b).and_then(|_| stdout.flush()).is_err() {
                            return 6;
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return 7,
        }
    }
}

/// Connects to the core, starting it when it is not running (within a bounded wait).
fn reach_core() -> Option<Connection> {
    let pipe = pipe_name().ok()?;
    match connect(&pipe, Duration::from_millis(500)) {
        Ok(c) => return Some(c),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return None,
    }
    start_core()?;
    let deadline = Instant::now() + START_BUDGET;
    while Instant::now() < deadline {
        if let Ok(c) = connect(&pipe, Duration::from_millis(200)) {
            return Some(c);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn core_exe() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("VELQRA_APP") {
        return Some(PathBuf::from(p));
    }
    let me = std::env::current_exe().ok()?;
    Some(me.with_file_name("velqra-app.exe"))
}

fn start_core() -> Option<()> {
    let exe = core_exe()?;
    if !exe.is_file() {
        return None;
    }
    // a second core that loses the race exits on its own: the pipe name allows only one owner
    velqra_ipc::spawn_detached(&exe).ok()
}

fn manifest_path(home: &Path) -> PathBuf {
    home.join("com.velqra.host.json")
}

/// `--register` / `--unregister`, each with an optional `--dry-run` that only prints what it would do.
fn manage(cmd: &str, rest: &[String]) -> i32 {
    let dry = rest.iter().any(|a| a == "--dry-run");
    if rest.iter().any(|a| a != "--dry-run") {
        say("unknown argument");
        return 3;
    }
    let Ok(home) = home_dir() else {
        say("no home directory");
        return 3;
    };
    let path = manifest_path(&home);
    if cmd == "--register" {
        let Ok(exe) = std::env::current_exe() else {
            return 3;
        };
        let Ok(manifest) = native_manifest(&exe.to_string_lossy(), &allowed_origins()) else {
            say("cannot build the manifest");
            return 3;
        };
        println!("{manifest}");
        println!(
            "reg add \"{REGISTRY_KEY}\" /ve /t REG_SZ /d \"{}\" /f",
            path.display()
        );
        if dry {
            return 0;
        }
        if std::fs::create_dir_all(&home)
            .and_then(|_| std::fs::write(&path, &manifest))
            .is_err()
        {
            say("cannot write the manifest");
            return 3;
        }
        let ok = Command::new("reg")
            .args(["add", REGISTRY_KEY, "/ve", "/t", "REG_SZ", "/d"])
            .arg(&path)
            .arg("/f")
            .status()
            .is_ok_and(|s| s.success());
        return if ok { 0 } else { 3 };
    }
    println!("reg delete \"{REGISTRY_KEY}\" /f");
    println!("delete {}", path.display());
    if dry {
        return 0;
    }
    let _ = Command::new("reg")
        .args(["delete", REGISTRY_KEY, "/f"])
        .status();
    let _ = std::fs::remove_file(&path);
    0
}
