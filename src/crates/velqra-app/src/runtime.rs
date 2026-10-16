// SPDX-License-Identifier: GPL-3.0-only
//! The core process: one thread owns the bridge server and the SQLite store (the exclusive writer);
//! the accept thread and one thread per connection only move bytes.
//!
//! Queues are bounded everywhere. A connection whose queue fills up is dropped, never buffered
//! without limit. Nothing that came from outside is ever formatted into a log line.

use crate::aria2::adapter::Aria2Config;
use crate::aria2::process::{Launch, PINNED_ARIA2_SHA256};
use crate::aria2::supervisor::Aria2Supervisor;
use crate::guard::Guarded;
use crate::paths::{db_path, ensure_secret, settings_path, vault_dir};
use crate::protector::UserProtector;
use rand::rngs::{OsRng, StdRng};
use rand::SeedableRng;
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use velqra_bridge::backend::CoreBackend;
use velqra_bridge::server::{Action, BridgeServer, ConnId};
use velqra_core::file_vault::FileVault;
use velqra_core::settings::Settings;
use velqra_core::store::SqliteStore;
use velqra_core::{Core, Engine, EngineError, EngineRequest};
use velqra_ipc::{Connection, PipeServer};

const QUEUE: usize = 256;

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub home: PathBuf,
    pub pipe: String,
    pub allowed: Vec<String>,
    /// Used when `settings.json` names no destination folder.
    pub download_root: PathBuf,
    /// The pinned aria2 executable. Missing/unusable engines refuse capture.
    pub aria2: Option<PathBuf>,
    /// Test-only simulation opt-in, read from VELQRA_ALLOW_LOOPBACK=1.
    pub allow_loopback: bool,
    /// Length of one server tick in milliseconds (100 in production; tests shorten it).
    pub tick_ms: u64,
}

impl RuntimeConfig {
    pub fn from_env() -> io::Result<Self> {
        let home = crate::paths::home_dir()?;
        let download_root = crate::paths::default_download_root(
            std::env::var("VELQRA_HOME").ok().as_deref(),
            std::env::var("USERPROFILE").ok().as_deref(),
            &home,
        );
        let allow_loopback = std::env::var("VELQRA_ALLOW_LOOPBACK").as_deref() == Ok("1");
        Ok(Self {
            home,
            pipe: crate::paths::pipe_name()?,
            allowed: crate::paths::allowed_origins(),
            download_root,
            aria2: std::env::var_os("VELQRA_ARIA2")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .or_else(|| (!allow_loopback).then(dev_aria2).flatten()),
            allow_loopback,
            tick_ms: 100,
        })
    }
}

/// Only an exact build-time repository path is searched in debug builds; never PATH or cwd.
fn dev_aria2() -> Option<PathBuf> {
    if !cfg!(debug_assertions) {
        return None;
    }
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../vendor/aria2/1.37.0/aria2c.exe");
    crate::aria2::process::verify_executable(&path, PINNED_ARIA2_SHA256)
        .ok()
        .map(|()| path)
}

struct UnavailableEngine;
impl Engine for UnavailableEngine {
    fn readiness(&mut self) -> Option<bool> {
        Some(false)
    }
    fn submit(&mut self, _: &EngineRequest) -> Result<(), EngineError> {
        Err(EngineError::ReplyLost)
    }
    fn finished(&mut self, _: &str) -> Option<bool> {
        None
    }
}

/// Simulation engine for explicitly opted-in tests. It never transfers bytes.
pub struct LoopbackEngine;

impl Engine for LoopbackEngine {
    fn submit(&mut self, _request: &EngineRequest) -> Result<(), EngineError> {
        Ok(())
    }

    fn finished(&mut self, _attempt: &str) -> Option<bool> {
        Some(true)
    }
}

enum Event {
    Connect(ConnId, SyncSender<Vec<u8>>),
    Bytes(ConnId, Vec<u8>),
    Disconnect(ConnId),
}

pub struct Runtime {
    pipe: String,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
    core: Option<JoinHandle<()>>,
    conns: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Runtime {
    /// Creates the pipe first, so a second instance fails immediately, then starts the threads.
    pub fn start(cfg: RuntimeConfig) -> io::Result<Runtime> {
        // the home holds the database, the vault and the install secret: current user and SYSTEM only
        velqra_ipc::make_private_dir(&cfg.home)?;
        // The secret comes first: the host reads it the moment the pipe answers, so the pipe must not
        // exist before the secret does. Two cores racing here agree (the secret is published atomically).
        let secret = ensure_secret(&cfg.home)?;
        let pipe_server = PipeServer::create_first(&cfg.pipe).map_err(|_| {
            io::Error::new(
                io::ErrorKind::AddrInUse,
                "another Velqra core is running, or the pipe cannot be created",
            )
        })?;
        let store = SqliteStore::open(&db_path(&cfg.home))
            .map_err(|_| io::Error::other("cannot open the task store"))?;

        let vault = FileVault::open(&vault_dir(&cfg.home), UserProtector::default())
            .map_err(|_| io::Error::other("cannot open the protected vault"))?;

        let loaded = Settings::load_file(&settings_path(&cfg.home));
        let policy = loaded
            .settings
            .destination_policy(cfg.download_root.clone());
        // the folder is the user's own setting (or our default), never something a page named
        let _ = std::fs::create_dir_all(&policy.root);
        let limits = loaded.settings.limits.clone();
        let segments = loaded.settings.segments;
        let engine_root = policy.root.clone();
        let aria2_exe = cfg.aria2.clone();
        let allow_loopback = cfg.allow_loopback;
        let run_dir = cfg.home.join("aria2-run");

        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = sync_channel::<Event>(QUEUE);
        let conns: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));

        let core = {
            let (stop, allowed, tick_ms) = (stop.clone(), cfg.allowed.clone(), cfg.tick_ms);
            thread::Builder::new()
                .name("velqra-core".into())
                .spawn(move || {
                    // built here because the core is deliberately not Send: exactly one thread ever touches it
                    let backend = {
                        let (engine, name, capable): (Box<dyn Engine>, &str, bool) = match aria2_exe
                        {
                            Some(exe) => {
                                let launch = Launch {
                                    exe,
                                    expected_sha256: PINNED_ARIA2_SHA256.to_string(),
                                    run_dir,
                                    max_concurrent: limits.max_active,
                                    parent_pid: std::process::id(),
                                    ready_timeout: Duration::from_secs(5),
                                };
                                let cfg = Aria2Config {
                                    split: segments,
                                    per_origin: segments,
                                };
                                let mut supervisor = Aria2Supervisor::new(launch, cfg);
                                let capable = supervisor.ready();
                                (
                                    Box::new(Guarded::new(supervisor, engine_root)),
                                    "aria2",
                                    capable,
                                )
                            }
                            None if allow_loopback => (Box::new(LoopbackEngine), "loopback", true),
                            None => (Box::new(UnavailableEngine), "unavailable", false),
                        };
                        CoreBackend::new(
                            Core::with_vault(store, Box::new(vault))
                                .with_limits(limits.max_active, limits.per_origin)
                                .with_poll_interval(1)
                                .with_settings(loaded)
                                .with_transfer_capability(capable)
                                .with_destination(policy),
                            engine,
                            name,
                        )
                    };
                    let rng = StdRng::from_rng(OsRng).expect("the OS random source is available");
                    let server = BridgeServer::new(backend, secret, allowed, Box::new(rng));
                    core_loop(server, rx, stop, tick_ms);
                })?
        };

        let accept = {
            let (stop, conns) = (stop.clone(), conns.clone());
            thread::Builder::new()
                .name("velqra-accept".into())
                .spawn(move || accept_loop(pipe_server, tx, stop, conns))?
        };

        Ok(Runtime {
            pipe: cfg.pipe,
            stop,
            accept: Some(accept),
            core: Some(core),
            conns,
        })
    }

    pub fn pipe(&self) -> &str {
        &self.pipe
    }

    /// Stops accepting, closes every connection and waits for the threads.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // a throw-away connection wakes the blocked accept call
        let _ = velqra_ipc::connect(&self.pipe, Duration::from_millis(500));
        if let Some(h) = self.accept.take() {
            let _ = h.join();
        }
        let handles: Vec<JoinHandle<()>> =
            std::mem::take(&mut *self.conns.lock().unwrap_or_else(|e| e.into_inner()));
        for h in handles {
            let _ = h.join();
        }
        if let Some(h) = self.core.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn accept_loop(
    mut server: PipeServer,
    tx: SyncSender<Event>,
    stop: Arc<AtomicBool>,
    conns: Arc<Mutex<Vec<JoinHandle<()>>>>,
) {
    let next_id = AtomicU64::new(1);
    while !stop.load(Ordering::SeqCst) {
        let conn = match server.accept() {
            Ok(c) => c,
            Err(_) => {
                thread::sleep(Duration::from_millis(50)); // never end the loop over one failed accept
                continue;
            }
        };
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let id = next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, stop) = (tx.clone(), stop.clone());
        if let Ok(h) = thread::Builder::new()
            .name("velqra-conn".into())
            .spawn(move || connection_loop(id, conn, tx, stop))
        {
            let mut list = conns.lock().unwrap_or_else(|e| e.into_inner());
            list.retain(|h| !h.is_finished());
            list.push(h);
        }
    }
}

fn connection_loop(
    id: ConnId,
    mut conn: Connection,
    core_tx: SyncSender<Event>,
    stop: Arc<AtomicBool>,
) {
    let (out_tx, out_rx) = sync_channel::<Vec<u8>>(QUEUE);
    if core_tx.send(Event::Connect(id, out_tx)).is_err() {
        return;
    }
    let mut buf = vec![0u8; 16 * 1024];
    'run: while !stop.load(Ordering::SeqCst) {
        loop {
            match out_rx.try_recv() {
                Ok(bytes) => {
                    if conn.write_all(&bytes).is_err() {
                        break 'run;
                    }
                }
                // the core dropped its sender: everything queued has been written, now close
                Err(TryRecvError::Disconnected) => break 'run,
                Err(TryRecvError::Empty) => break,
            }
        }
        match conn.read_timeout(&mut buf, Duration::from_millis(10)) {
            Ok(0) => break,
            // a full queue means the core cannot keep up: drop this connection instead of buffering
            Ok(n) => {
                if core_tx
                    .try_send(Event::Bytes(id, buf[..n].to_vec()))
                    .is_err()
                {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
    let _ = core_tx.send(Event::Disconnect(id));
}

fn core_loop(
    mut server: BridgeServer<CoreBackend<SqliteStore, Box<dyn Engine>>>,
    rx: Receiver<Event>,
    stop: Arc<AtomicBool>,
    tick_ms: u64,
) {
    let tick = Duration::from_millis(tick_ms.max(1));
    let started = Instant::now();
    let mut conns: HashMap<ConnId, SyncSender<Vec<u8>>> = HashMap::new();
    let mut last_tick = 0u64;
    while !stop.load(Ordering::SeqCst) {
        let event = rx.recv_timeout(tick);
        let now = (started.elapsed().as_millis() / tick.as_millis()) as u64;
        let mut actions: Vec<Action> = Vec::new();
        match event {
            Ok(Event::Connect(id, out)) => {
                conns.insert(id, out);
                actions.extend(server.on_connect(id, now));
            }
            Ok(Event::Bytes(id, bytes)) => {
                actions.extend(server.on_bytes(id, &bytes, now));
                actions.extend(server.process(now, 64));
            }
            Ok(Event::Disconnect(id)) => {
                server.on_disconnect(id);
                conns.remove(&id);
            }
            Err(RecvTimeoutError::Timeout) => actions.extend(server.process(now, 64)),
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if now != last_tick {
            last_tick = now;
            actions.extend(server.tick(now));
        }
        for action in actions {
            match action {
                Action::Send(id, bytes) => {
                    let delivered = conns.get(&id).is_some_and(|tx| tx.try_send(bytes).is_ok());
                    if !delivered && conns.remove(&id).is_some() {
                        server.on_disconnect(id); // a reader that never keeps up loses its connection
                    }
                }
                // dropping the sender closes the connection after its queued frames are written
                Action::Close(id) => {
                    conns.remove(&id);
                }
            }
        }
    }
}

/// Runs until the process is killed.
pub fn run_forever(cfg: RuntimeConfig) -> io::Result<()> {
    let _rt = Runtime::start(cfg)?;
    loop {
        thread::park();
    }
}

#[cfg(all(test, windows))]
#[path = "../tests/common/mod.rs"]
mod test_common;

#[cfg(all(test, windows))]
mod review_tests {
    use super::test_common::*;
    use super::*;
    use velqra_protocol::*;
    #[test]
    fn actual_runtime_settings_send_one_connection_to_aria2() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(
            settings_path(home.path()),
            br#"{"limits":{"max_active":2,"per_origin":16}}"#,
        )
        .unwrap();
        let pipe = velqra_ipc::pipe_name(&format!("review28-{}", std::process::id())).unwrap();
        let exe = dev_aria2().expect("pinned dev binary required for this regression");
        let rt = Runtime::start(RuntimeConfig {
            home: home.path().into(),
            pipe: pipe.clone(),
            allowed: vec![velqra_bridge::testkit::ORIGIN.into()],
            download_root: home.path().join("downloads"),
            aria2: Some(exe),
            allow_loopback: false,
            tick_ms: 5,
        })
        .unwrap();
        let mut c = Client::new(PipeTransport::connect(&pipe).unwrap());
        c.handshake(
            &crate::paths::load_secret(home.path()).unwrap().unwrap(),
            velqra_bridge::testkit::ORIGIN,
            [28; 16],
            true,
        )
        .unwrap();
        let mut p = prepare_body();
        // Keep a real loopback task active while querying the options aria2 accepted.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        p.url = format!(
            "http://127.0.0.1:{}/review28.bin",
            listener.local_addr().unwrap().port()
        );
        p.filename = "review28.bin".into();
        let receipt = receipt_of(
            &c.request("p", "runtime-options", Message::Prepare(p))
                .unwrap(),
        );
        c.request(
            "a",
            "runtime-options",
            Message::BeginHandoff(receipt.as_ref()),
        )
        .unwrap();
        c.request(
            "c",
            "runtime-options",
            Message::Commit(CommitBody {
                cancel: CancelEvidence::Confirmed,
                receipt: receipt.as_ref(),
            }),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let options = loop {
            let options = crate::aria2::adapter::SENT_OPTIONS
                .lock()
                .unwrap()
                .iter()
                .find(|v| v["out"] == "review28.bin.velqra-part")
                .cloned();
            if let Some(options) = options {
                break options;
            }
            assert!(Instant::now() < deadline, "no addUri observed");
            thread::sleep(Duration::from_millis(10));
        };
        rt.stop();
        assert_eq!(options["split"], "1");
        assert_eq!(options["max-connection-per-server"], "1");
    }
}
