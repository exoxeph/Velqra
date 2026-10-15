// SPDX-License-Identifier: GPL-3.0-only
//! Starts and supervises the pinned aria2 process. It is a separate program (GPL-2.0-or-later) that
//! we only talk to over loopback JSON-RPC; nothing of it is linked into Velqra.
//!
//! What the process is given, and what it is not:
//! - the RPC secret travels in a one-line config file that exists only until aria2 has answered its
//!   first call, never on the command line (a command line is visible to every tool on the machine);
//! - no session file, no log file, no stdout or stderr (aria2's own text can name URLs);
//! - the pinned executable is checked by SHA-256 before it is started;
//! - `--stop-with-process` ties aria2's life to ours, so a dead core leaves no orphan behind.

use super::rpc::RpcClient;
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// SHA-256 of the aria2 1.37.0 Windows x64 build we ship (see vendor/aria2/INVENTORY.txt).
pub const PINNED_ARIA2_SHA256: &str =
    "be2099c214f63a3cb4954b09a0becd6e2e34660b886d4c898d260febfe9d70c2";
pub const PINNED_ARIA2_VERSION: &str = "1.37.0";

#[derive(Debug, Clone)]
pub struct Launch {
    pub exe: PathBuf,
    /// Expected SHA-256 of `exe` as hex; `PINNED_ARIA2_SHA256` in production.
    pub expected_sha256: String,
    /// A private folder for the short-lived config file.
    pub run_dir: PathBuf,
    pub max_concurrent: u32,
    /// The process aria2 should die with (ours).
    pub parent_pid: u32,
    pub ready_timeout: Duration,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LaunchError {
    BadExecutable(&'static str),
    Io(&'static str),
    NotReady(&'static str),
}

pub struct Aria2Process {
    child: Child,
    addr: SocketAddr,
    secret: String,
}

/// The one-line config that carries the secret.
pub(crate) fn conf_text(secret: &str) -> String {
    format!("rpc-secret={secret}\n")
}

/// Everything that is safe to show on a command line.
pub(crate) fn args_for(conf: &Path, port: u16, l: &Launch) -> Vec<String> {
    let flag = |k: &str, v: &str| format!("--{k}={v}");
    vec![
        flag("conf-path", &conf.to_string_lossy()),
        flag("enable-rpc", "true"),
        flag("rpc-listen-port", &port.to_string()),
        flag("rpc-listen-all", "false"),
        flag("rpc-allow-origin-all", "false"),
        flag("rpc-max-request-size", "2M"),
        flag("check-certificate", "true"),
        flag("max-concurrent-downloads", &l.max_concurrent.to_string()),
        flag("stop-with-process", &l.parent_pid.to_string()),
        flag("allow-overwrite", "false"),
        flag("auto-file-renaming", "false"),
        flag("continue", "false"),
        flag("max-tries", "1"),
        // the control file is what lets a restarted aria2 resume a partial file, so write it often
        flag("auto-save-interval", "1"),
        flag("enable-dht", "false"),
        flag("enable-dht6", "false"),
        flag("bt-enable-lpd", "false"),
        flag("enable-peer-exchange", "false"),
        flag("follow-torrent", "false"),
        flag("follow-metalink", "false"),
        flag("no-netrc", "true"),
        flag("keep-unfinished-download-result", "false"),
        flag("max-download-result", "200"),
        flag("console-log-level", "error"),
        flag("summary-interval", "0"),
    ]
}

/// Hashes the file with a read cap and compares it with the pinned value.
pub fn verify_executable(path: &Path, expected_sha256: &str) -> Result<(), LaunchError> {
    const MAX_EXE: u64 = 64 * 1024 * 1024;
    let file = std::fs::File::open(path).map_err(|_| LaunchError::BadExecutable("cannot open"))?;
    let mut hasher = Sha256::new();
    let mut taken = 0u64;
    let mut reader = file.take(MAX_EXE + 1);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|_| LaunchError::BadExecutable("cannot read"))?;
        if n == 0 {
            break;
        }
        taken += n as u64;
        hasher.update(&buf[..n]);
    }
    if taken > MAX_EXE {
        return Err(LaunchError::BadExecutable("too large"));
    }
    if hex(&hasher.finalize()).eq_ignore_ascii_case(expected_sha256) {
        Ok(())
    } else {
        Err(LaunchError::BadExecutable("not the pinned build"))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Aria2Process {
    pub fn spawn(l: &Launch) -> Result<Aria2Process, LaunchError> {
        verify_executable(&l.exe, &l.expected_sha256)?;
        // the secret file lives here for a moment: no inherited access list, current user only
        velqra_ipc::make_private_dir(&l.run_dir).map_err(|_| LaunchError::Io("run folder"))?;
        let mut last = LaunchError::NotReady("not started");
        // the port is chosen by asking the OS and releasing it, so another program can take it first
        for _ in 0..4 {
            match Self::try_spawn(l) {
                Ok(p) => return Ok(p),
                Err(e @ LaunchError::BadExecutable(_)) => return Err(e),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn try_spawn(l: &Launch) -> Result<Aria2Process, LaunchError> {
        let mut raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let secret = hex(&raw);
        let port = {
            let probe = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
                .map_err(|_| LaunchError::Io("port"))?;
            probe
                .local_addr()
                .map_err(|_| LaunchError::Io("port"))?
                .port()
        };
        let mut tag = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut tag);
        let conf = l.run_dir.join(format!("aria2-{}.conf", hex(&tag)));
        write_new(&conf, conf_text(&secret).as_bytes()).map_err(|_| LaunchError::Io("config"))?;

        let mut cmd = Command::new(&l.exe);
        cmd.args(args_for(&conf, port, l))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(_) => {
                let _ = std::fs::remove_file(&conf);
                return Err(LaunchError::Io("spawn"));
            }
        };
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
        let client = RpcClient::new(addr, secret.clone(), Duration::from_millis(500));
        let deadline = Instant::now() + l.ready_timeout;
        let answer = loop {
            if let Ok(Some(_)) = child.try_wait() {
                break Err(LaunchError::NotReady("aria2 exited"));
            }
            match client.call("aria2.getVersion", vec![]) {
                Ok(v) => break Ok(v),
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Err(_) => break Err(LaunchError::NotReady("no answer in time")),
            }
        };
        // the secret has been read once aria2 answers; the file must not outlive that
        let removed = std::fs::remove_file(&conf);
        let fail = |child: &mut Child, e: LaunchError| {
            let _ = child.kill();
            let _ = child.wait();
            Err(e)
        };
        match answer {
            Err(e) => fail(&mut child, e),
            Ok(v) if v.get("version") != Some(&Value::String(PINNED_ARIA2_VERSION.into())) => {
                fail(&mut child, LaunchError::BadExecutable("unexpected version"))
            }
            Ok(_) if removed.is_err() => {
                fail(&mut child, LaunchError::Io("config could not be removed"))
            }
            Ok(_) => Ok(Aria2Process {
                child,
                addr,
                secret,
            }),
        }
    }

    pub fn client(&self, timeout: Duration) -> RpcClient {
        RpcClient::new(self.addr, self.secret.clone(), timeout)
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// False once the process has exited, for any reason.
    pub fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Aria2Process {
    fn drop(&mut self) {
        self.stop();
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch() -> Launch {
        Launch {
            exe: PathBuf::from(r"C:\x\aria2c.exe"),
            expected_sha256: PINNED_ARIA2_SHA256.into(),
            run_dir: PathBuf::from(r"C:\run"),
            max_concurrent: 3,
            parent_pid: 4242,
            ready_timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn the_secret_is_in_the_config_file_and_nowhere_in_the_arguments() {
        let secret = "S3CR3T-0123456789abcdef-0123456789abcdef";
        let args = args_for(Path::new(r"C:\run\aria2-1.conf"), 6800, &launch());
        let joined = args.join("\n");
        assert!(!joined.contains(secret));
        assert!(!joined.to_ascii_lowercase().contains("secret"), "{joined}");
        assert!(!args.iter().any(|a| a.starts_with("--rpc-secret")));
        assert_eq!(conf_text(secret), format!("rpc-secret={secret}\n"));
    }

    #[test]
    fn the_arguments_pin_the_safe_settings() {
        let args = args_for(Path::new(r"C:\run\aria2-1.conf"), 6800, &launch());
        for want in [
            "--conf-path=C:\\run\\aria2-1.conf",
            "--enable-rpc=true",
            "--rpc-listen-port=6800",
            "--rpc-listen-all=false",
            "--rpc-allow-origin-all=false",
            "--check-certificate=true",
            "--max-concurrent-downloads=3",
            "--stop-with-process=4242",
            "--allow-overwrite=false",
            "--auto-file-renaming=false",
            "--enable-dht=false",
            "--follow-torrent=false",
            "--no-netrc=true",
            "--continue=false",
            "--max-tries=1",
            "--auto-save-interval=1",
        ] {
            assert!(args.iter().any(|a| a == want), "missing {want}: {args:?}");
        }
        for banned in [
            "--save-session",
            "--log=",
            "--input-file",
            "--load-cookies",
            "--daemon",
            "--check-certificate=false",
            "--continue=true",
            "--no-conf",
            "--enable-rpc=false",
            "--rpc-listen-all=true",
        ] {
            assert!(
                !args.iter().any(|a| a.starts_with(banned)),
                "{banned} present"
            );
        }
    }

    #[test]
    fn only_the_pinned_executable_is_accepted() {
        let d = tempfile::tempdir().unwrap();
        let exe = d.path().join("fake.exe");
        std::fs::write(&exe, b"not aria2").unwrap();
        assert_eq!(
            verify_executable(&exe, PINNED_ARIA2_SHA256),
            Err(LaunchError::BadExecutable("not the pinned build"))
        );
        let sum = hex(&Sha256::digest(b"not aria2"));
        assert_eq!(verify_executable(&exe, &sum), Ok(()));
        assert_eq!(verify_executable(&exe, &sum.to_uppercase()), Ok(()));
        assert_eq!(
            verify_executable(&d.path().join("missing.exe"), &sum),
            Err(LaunchError::BadExecutable("cannot open"))
        );
        assert_eq!(PINNED_ARIA2_SHA256.len(), 64);
    }

    #[test]
    fn a_wrong_executable_is_never_started() {
        let d = tempfile::tempdir().unwrap();
        // a script that would leave a marker if it ever ran
        let marker = d.path().join("ran.txt");
        let exe = d.path().join("evil.bat");
        std::fs::write(&exe, format!("@echo ran> \"{}\"\r\n", marker.display())).unwrap();
        let l = Launch {
            exe,
            run_dir: d.path().join("run"),
            ..launch()
        };
        assert!(matches!(
            Aria2Process::spawn(&l),
            Err(LaunchError::BadExecutable(_))
        ));
        std::thread::sleep(Duration::from_millis(300));
        assert!(!marker.exists(), "an unverified executable was run");
        assert!(!l.run_dir.exists() || std::fs::read_dir(&l.run_dir).unwrap().count() == 0);
    }
}
