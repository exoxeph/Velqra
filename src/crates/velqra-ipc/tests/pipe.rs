// SPDX-License-Identifier: GPL-3.0-only
//! Real named-pipe tests (Windows only). Behaviour under a second Windows user and from a remote
//! machine cannot be exercised here and is recorded as UNKNOWN in the milestone report.
#![cfg(windows)]

use std::io::ErrorKind;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use velqra_ipc::{connect, current_user_sid, pipe_name, PipeServer};

static COUNTER: AtomicU32 = AtomicU32::new(0);
/// Every test in this file takes this lock: the handle-leak test counts handles for the whole process, so
/// no other test may create or close handles while it measures.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn unique_name() -> String {
    pipe_name(&format!(
        "test-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ))
    .unwrap()
}

const T: Duration = Duration::from_secs(5);

fn read_exact(c: &mut velqra_ipc::Connection, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 65536];
    let deadline = Instant::now() + Duration::from_secs(20);
    while out.len() < n {
        assert!(
            Instant::now() < deadline,
            "timed out after {} of {n} bytes",
            out.len()
        );
        match c.read_timeout(&mut buf, Duration::from_millis(200)) {
            Ok(0) => panic!("peer closed after {} of {n} bytes", out.len()),
            Ok(k) => out.extend_from_slice(&buf[..k]),
            Err(e) if e.kind() == ErrorKind::TimedOut => {}
            Err(e) => panic!("{e}"),
        }
    }
    out
}

#[test]
fn a_client_and_server_exchange_bytes_both_ways() {
    let _serial = serial();
    let name = unique_name();
    let mut server = PipeServer::create_first(&name).unwrap();
    let t = thread::spawn(move || {
        let mut c = server.accept().unwrap();
        let got = read_exact(&mut c, 4);
        c.write_all(&got).unwrap();
        got
    });
    let mut client = connect(&name, T).unwrap();
    client.write_all(b"ping").unwrap();
    assert_eq!(read_exact(&mut client, 4), b"ping");
    assert_eq!(t.join().unwrap(), b"ping");
}

#[test]
fn only_one_core_can_own_the_pipe_name() {
    let _serial = serial();
    let name = unique_name();
    let _first = PipeServer::create_first(&name).unwrap();
    assert!(
        PipeServer::create_first(&name).is_err(),
        "a second core took over the same pipe name"
    );
}

#[test]
fn the_pipe_is_open_to_the_current_user_and_system_only() {
    let _serial = serial();
    let server = PipeServer::create_first(&unique_name()).unwrap();
    let sddl = server.dacl_sddl().unwrap();
    let sid = current_user_sid().unwrap();
    assert!(
        sddl.starts_with("D:P"),
        "the DACL inherits from a parent or is not protected: {sddl}"
    );
    assert!(sddl.contains(&sid), "the current user has no entry: {sddl}");
    assert!(sddl.contains(";;;SY)"), "SYSTEM has no entry: {sddl}");
    assert_eq!(
        sddl.matches("(A;").count(),
        2,
        "exactly two allow entries expected: {sddl}"
    );
    for broad in [";WD)", ";AU)", ";BU)", ";AN)", ";BA)", ";IU)", ";NU)"] {
        assert!(
            !sddl.contains(broad),
            "a broad principal {broad} is allowed: {sddl}"
        );
    }
    assert!(!sddl.contains("(D;"), "unexpected deny entry: {sddl}");
}

#[test]
fn a_timed_out_read_can_be_repeated_and_later_data_still_arrives() {
    let _serial = serial();
    let name = unique_name();
    let mut server = PipeServer::create_first(&name).unwrap();
    let t = thread::spawn(move || {
        let mut c = server.accept().unwrap();
        let mut buf = [0u8; 16];
        let first = c.read_timeout(&mut buf, Duration::from_millis(50));
        let second = read_exact(&mut c, 3);
        (first.map_err(|e| e.kind()), second)
    });
    let mut client = connect(&name, T).unwrap();
    thread::sleep(Duration::from_millis(300));
    client.write_all(b"abc").unwrap();
    let (first, second) = t.join().unwrap();
    assert_eq!(first, Err(ErrorKind::TimedOut));
    assert_eq!(second, b"abc");
}

#[test]
fn a_closed_peer_reads_as_zero_not_as_a_hang() {
    let _serial = serial();
    let name = unique_name();
    let mut server = PipeServer::create_first(&name).unwrap();
    let t = thread::spawn(move || {
        let mut c = server.accept().unwrap();
        let mut buf = [0u8; 16];
        let started = Instant::now();
        let r = c.read_timeout(&mut buf, Duration::from_secs(10));
        (r.map_err(|e| e.kind()), started.elapsed())
    });
    drop(connect(&name, T).unwrap());
    let (r, took) = t.join().unwrap();
    assert_eq!(r, Ok(0));
    assert!(took < Duration::from_secs(5), "took {took:?}");
}

#[test]
fn connecting_to_an_absent_pipe_fails_fast_with_not_found() {
    let _serial = serial();
    let started = Instant::now();
    let e = connect(&unique_name(), T)
        .err()
        .expect("no server is listening");
    assert_eq!(e.kind(), ErrorKind::NotFound);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn a_256_kib_message_survives_the_pipe_buffer() {
    let _serial = serial();
    let name = unique_name();
    let mut server = PipeServer::create_first(&name).unwrap();
    let t = thread::spawn(move || {
        let mut c = server.accept().unwrap();
        read_exact(&mut c, 256 * 1024)
    });
    let mut client = connect(&name, T).unwrap();
    let data: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    client.write_all(&data).unwrap();
    assert_eq!(t.join().unwrap(), data);
}

fn handle_count() -> u32 {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};
    let mut n = 0u32;
    // SAFETY: GetCurrentProcess returns a pseudo handle that is always valid; `n` is a valid out pointer.
    unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut n) };
    n
}

#[test]
fn many_connect_and_close_cycles_do_not_leak_handles() {
    let _serial = serial();
    let name = unique_name();
    let mut server = PipeServer::create_first(&name).unwrap();
    let cycles = 300;
    let t = thread::spawn(move || {
        for _ in 0..cycles {
            let mut c = server.accept().unwrap();
            let mut buf = [0u8; 8];
            let _ = c.read_timeout(&mut buf, Duration::from_millis(200));
        }
    });
    let before = handle_count();
    for _ in 0..cycles {
        let mut c = connect(&name, T).unwrap();
        c.write_all(b"x").unwrap();
    }
    t.join().unwrap();
    let after = handle_count();
    assert!(
        after <= before + 15,
        "handle count grew from {before} to {after}"
    );
}

#[test]
fn successive_clients_are_each_served() {
    let _serial = serial();
    let name = unique_name();
    let mut server = PipeServer::create_first(&name).unwrap();
    let t = thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..3 {
            let mut c = server.accept().unwrap();
            seen.push(read_exact(&mut c, 1)[0]);
        }
        seen
    });
    for b in [1u8, 2, 3] {
        let mut c = connect(&name, T).unwrap();
        c.write_all(&[b]).unwrap();
        thread::sleep(Duration::from_millis(30));
    }
    assert_eq!(t.join().unwrap(), vec![1, 2, 3]);
}

/// Not a behavioural proof: a remote client cannot be created from one machine, so this only stops the
/// flag from being deleted by accident. The milestone report lists remote rejection as UNKNOWN.
#[test]
fn source_guard_the_pipe_is_created_rejecting_remote_clients() {
    let _serial = serial();
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/win.rs")).unwrap();
    let create = src
        .split("CreateNamedPipeW(")
        .nth(1)
        .expect("the create call");
    let call = create.split(");").next().unwrap();
    assert!(
        call.contains("PIPE_REJECT_REMOTE_CLIENTS"),
        "CreateNamedPipeW no longer rejects remote clients"
    );
}

#[test]
fn many_clients_connecting_at_once_never_see_a_missing_pipe() {
    let _serial = serial();
    let name = unique_name();
    let mut server = PipeServer::create_first(&name).unwrap();
    let clients = 12; // fewer than the 16 instances the pipe allows: excess connections are refused by design
    let t = thread::spawn(move || {
        let mut held = Vec::new();
        for _ in 0..clients {
            held.push(server.accept().unwrap());
        }
        held.len()
    });
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(clients));
    let handles: Vec<_> = (0..clients)
        .map(|_| {
            let (name, barrier) = (name.clone(), barrier.clone());
            thread::spawn(move || {
                barrier.wait();
                connect(&name, T).map(|c| {
                    thread::sleep(Duration::from_millis(300));
                    drop(c);
                })
            })
        })
        .collect();
    for h in handles {
        h.join()
            .unwrap()
            .expect("a client saw the pipe as missing or busy while the server was accepting");
    }
    assert_eq!(t.join().unwrap(), clients);
}

#[test]
fn spawning_a_program_that_does_not_exist_is_an_error_not_a_panic() {
    let _serial = serial();
    let missing = std::env::temp_dir().join("velqra-no-such-program.exe");
    assert!(velqra_ipc::spawn_detached(&missing).is_err());
}
