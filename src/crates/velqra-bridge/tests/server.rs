// SPDX-License-Identifier: GPL-3.0-only
//! Security tests for the bridge server. Every "never reaches the core" claim is proven with the
//! spy that sits on the backend boundary and keeps its own log.
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::json;
use velqra_bridge::backend::{CoreBackend, Spy, SpyLog};
use velqra_bridge::handshake::*;
use velqra_bridge::secret::InstallSecret;
use velqra_bridge::server::*;
use velqra_bridge::testkit::*;
use velqra_core::store::MemStore;
use velqra_core::Core;
use velqra_protocol::*;

type Srv = BridgeServer<Spy<CoreBackend<MemStore, NullEngine>>>;

fn server() -> (Srv, SpyLog) {
    let core = Core::new(MemStore::default());
    let (spy, log) = Spy::new(CoreBackend::new(core, NullEngine, "fake"));
    let srv = BridgeServer::new(
        spy,
        secret(),
        vec![ORIGIN.to_string()],
        Box::new(StdRng::seed_from_u64(7)),
    );
    (srv, log)
}

fn cn(n: u8) -> [u8; 16] {
    [n; 16]
}

fn established(srv: &mut Srv, conn: ConnId, n: u8) -> String {
    handshake(srv, conn, 0, &secret(), ORIGIN, cn(n))
        .expect("honest handshake")
        .sid
}

/// Bytes in, then let the backend run: what the runtime does for every read.
fn drive(srv: &mut Srv, conn: ConnId, bytes: &[u8], now: u64) -> Vec<Action> {
    let mut a = srv.on_bytes(conn, bytes, now);
    a.extend(srv.process(now, 1000));
    a
}

fn status(sid: &str, id: &str) -> Vec<u8> {
    envelope_frame(&envelope(sid, id, "req-1", Message::Status(Empty {})))
}

/// The independent cross-check: the server's own counter must equal what the spy saw.
fn consistent(srv: &Srv, log: &SpyLog) {
    assert_eq!(
        srv.stats.reached_backend as usize,
        log.borrow().len(),
        "server counter and spy disagree"
    );
}

fn expect_reject_on(conn: ConnId, code: &str, srv: &Srv, log: &SpyLog, a: Vec<Action>) {
    assert_eq!(reject_code(&a, conn).as_deref(), Some(code));
    assert!(closed(&a, conn));
    assert!(log.borrow().is_empty());
    consistent(srv, log);
}

fn after_attach(srv: &mut Srv) {
    srv.on_connect(1, 0);
    assert!(reject_code(&srv.on_bytes(1, &attach(ORIGIN), 0), 1).is_none());
}

fn expect_reject(label: &str, code: &str, srv: &Srv, log: &SpyLog, a: Vec<Action>) {
    assert_eq!(reject_code(&a, 1).as_deref(), Some(code), "{label}");
    assert!(closed(&a, 1), "{label}: not closed");
    assert!(log.borrow().is_empty(), "{label}: reached the backend");
    assert!(
        !sent(&a, 1)
            .iter()
            .any(|p| String::from_utf8_lossy(p).contains("detail")),
        "{label}: detail text"
    );
    consistent(srv, log);
}

// ---- (a) honest flow ----

#[test]
fn an_honest_session_reaches_the_backend_once_and_gets_a_receipt() {
    let (mut srv, log) = server();
    let sid = established(&mut srv, 1, 1);
    let prep = envelope(&sid, "m1", "req-1", Message::Prepare(prepare_body()));
    let a = drive(&mut srv, 1, &envelope_frame(&prep), 1);
    assert_eq!(log.borrow().len(), 1);
    let reply = Envelope::decode(&sent(&a, 1)[0]).unwrap();
    assert!(
        matches!(reply.body, Message::Prepared(ref r) if r.state == TaskState::Prepared),
        "{reply:?}"
    );
    assert_eq!(reply.session_id, sid);
    consistent(&srv, &log);
}

#[test]
fn health_is_answered_locally_without_touching_the_backend() {
    let (mut srv, log) = server();
    let sid = established(&mut srv, 1, 1);
    let a = drive(
        &mut srv,
        1,
        &envelope_frame(&envelope(&sid, "h1", "r", Message::Health(Empty {}))),
        1,
    );
    let reply = Envelope::decode(&sent(&a, 1)[0]).unwrap();
    assert!(
        matches!(reply.body, Message::HealthReply(ref h) if h.versions == vec![1] && h.engine == "fake")
    );
    assert!(log.borrow().is_empty());
    assert_eq!(srv.stats.answered_locally, 1);
    consistent(&srv, &log);
}

// ---- (b) nothing before ready ----

#[test]
fn no_frame_before_ready_ever_reaches_the_backend() {
    let forged = envelope_frame(&envelope(
        "0123456789abcdef0123456789abcdef",
        "m1",
        "req-1",
        Message::Abort(AbortBody { receipt: None }),
    ));
    for stage in 0..3 {
        let (mut srv, log) = server();
        srv.on_connect(1, 0);
        if stage >= 1 {
            srv.on_bytes(1, &attach(ORIGIN), 0);
        }
        if stage >= 2 {
            srv.on_bytes(1, &hello(&cn(1)), 0);
        }
        let a = drive(&mut srv, 1, &forged, 0);
        assert!(closed(&a, 1), "stage {stage}: connection stayed open");
        assert_eq!(
            reject_code(&a, 1).as_deref(),
            Some("bad_frame"),
            "stage {stage}"
        );
        assert!(
            log.borrow().is_empty(),
            "stage {stage}: a frame reached the backend"
        );
        consistent(&srv, &log);
    }
}

#[test]
fn an_unauthenticated_abort_without_receipt_never_reaches_the_backend() {
    let (mut srv, log) = server();
    srv.on_connect(1, 0);
    let abort = envelope(
        "deadbeef",
        "m1",
        "req-1",
        Message::Abort(AbortBody { receipt: None }),
    );
    let a = drive(&mut srv, 1, &envelope_frame(&abort), 0);
    assert!(closed(&a, 1));
    assert!(log.borrow().is_empty());
}

// ---- (c) malformed and hostile handshakes ----

#[test]
fn hostile_attach_frames_are_rejected() {
    let dup = format!("{{\"t\":\"attach\",\"t\":\"attach\",\"origin\":\"{ORIGIN}\"}}");
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        (
            "wrong origin",
            attach("chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/"),
            "bad_origin",
        ),
        (
            "wildcard origin",
            attach("chrome-extension://*/"),
            "bad_origin",
        ),
        ("empty origin", attach(""), "bad_origin"),
        (
            "origin with path",
            attach(&format!("{ORIGIN}extra")),
            "bad_origin",
        ),
        ("not json", frame(b"attach"), "bad_frame"),
        ("array", frame(b"[1]"), "bad_frame"),
        ("hello first", hello(&cn(1)), "bad_frame"),
        ("auth first", auth(&[0; 32]), "bad_frame"),
        (
            "extra key",
            jframe(&json!({"t":"attach","origin":ORIGIN,"x":1})),
            "bad_frame",
        ),
        ("duplicate key", frame(dup.as_bytes()), "bad_frame"),
        (
            "origin not a string",
            jframe(&json!({"t":"attach","origin":5})),
            "bad_frame",
        ),
        ("envelope instead", status("deadbeef", "m1"), "bad_frame"),
    ];
    for (label, bytes, code) in cases {
        let (mut srv, log) = server();
        srv.on_connect(1, 0);
        let a = srv.on_bytes(1, &bytes, 0);
        expect_reject(label, code, &srv, &log, a);
    }
}

#[test]
fn hostile_hello_frames_are_rejected() {
    let b = |v: serde_json::Value| jframe(&v);
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        (
            "version 2 only",
            b(json!({"t":"hello","v":[2],"cn":b64_encode(&cn(1))})),
            "bad_version",
        ),
        (
            "no versions",
            b(json!({"t":"hello","v":[],"cn":b64_encode(&cn(1))})),
            "bad_version",
        ),
        (
            "version not a list",
            b(json!({"t":"hello","v":1,"cn":b64_encode(&cn(1))})),
            "bad_frame",
        ),
        (
            "short cn",
            b(json!({"t":"hello","v":[1],"cn":b64_encode(&[1; 15])})),
            "bad_frame",
        ),
        (
            "long cn",
            b(json!({"t":"hello","v":[1],"cn":b64_encode(&[1; 17])})),
            "bad_frame",
        ),
        (
            "cn not base64",
            b(json!({"t":"hello","v":[1],"cn":"!!!!"})),
            "bad_frame",
        ),
        ("missing cn", b(json!({"t":"hello","v":[1]})), "bad_frame"),
        (
            "extra key",
            b(json!({"t":"hello","v":[1],"cn":b64_encode(&cn(1)),"x":0})),
            "bad_frame",
        ),
        ("second attach", attach(ORIGIN), "bad_frame"),
        ("auth before hello", auth(&[0; 32]), "bad_frame"),
        ("unknown type", b(json!({"t":"bye"})), "bad_frame"),
        (
            "over 1 KiB before ready",
            frame(&vec![b' '; 2000]),
            "bad_frame",
        ),
    ];
    for (label, bytes, code) in cases {
        let (mut srv, log) = server();
        after_attach(&mut srv);
        let a = srv.on_bytes(1, &bytes, 0);
        expect_reject(label, code, &srv, &log, a);
    }
}

#[test]
fn hostile_auth_frames_are_rejected() {
    let b = |v: serde_json::Value| jframe(&v);
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("wrong mac", auth(&[7; 32]), "bad_auth"),
        ("short mac", auth(&[7; 31]), "bad_auth"),
        ("empty mac", auth(&[]), "bad_auth"),
        (
            "mac not base64",
            b(json!({"t":"auth","cm":"@@@@"})),
            "bad_frame",
        ),
        ("missing cm", b(json!({"t":"auth"})), "bad_frame"),
        ("second hello", hello(&cn(2)), "bad_frame"),
        ("envelope instead", status("deadbeef", "m1"), "bad_frame"),
    ];
    for (label, bytes, code) in cases {
        let (mut srv, log) = server();
        after_attach(&mut srv);
        srv.on_bytes(1, &hello(&cn(1)), 0);
        let a = srv.on_bytes(1, &bytes, 0);
        expect_reject(label, code, &srv, &log, a);
    }
}

// ---- (d) every single-bit corruption of the client MAC ----

fn challenge(srv: &mut Srv, n: u8) -> (Vec<u8>, Vec<u8>) {
    let a = srv.on_bytes(1, &hello(&cn(n)), 0);
    let ch = &sent_json(&a, 1)[0];
    (
        b64_decode(ch["sn"].as_str().unwrap()).unwrap(),
        b64_decode(ch["core"].as_str().unwrap()).unwrap(),
    )
}

#[test]
fn flipping_any_bit_of_the_client_mac_is_rejected() {
    for bit in 0..256 {
        let (mut srv, log) = server();
        after_attach(&mut srv);
        let (sn, core) = challenge(&mut srv, 1);
        let f = Fields {
            cn: &cn(1),
            sn: &sn,
            origin: ORIGIN.as_bytes(),
            core: &core,
        };
        let mut cm = mac(&secret(), LABEL_CLIENT, &f);
        cm[bit / 8] ^= 1 << (bit % 8);
        let a = srv.on_bytes(1, &auth(&cm), 0);
        expect_reject(&format!("bit {bit}"), "bad_auth", &srv, &log, a);
    }
}

#[test]
fn a_mac_made_with_a_different_secret_or_the_server_label_is_rejected() {
    let mut other = [0u8; 32];
    other[5] = 1;
    for (label, key, lab) in [
        ("other secret", other, LABEL_CLIENT),
        ("server label", *secret().expose(), LABEL_SERVER),
    ] {
        let (mut srv, log) = server();
        after_attach(&mut srv);
        let (sn, core) = challenge(&mut srv, 1);
        let f = Fields {
            cn: &cn(1),
            sn: &sn,
            origin: ORIGIN.as_bytes(),
            core: &core,
        };
        let cm = mac(&InstallSecret::from_bytes(key), lab, &f);
        let a = srv.on_bytes(1, &auth(&cm), 0);
        expect_reject(label, "bad_auth", &srv, &log, a);
    }
}

// ---- (e) replays ----

#[test]
fn a_replayed_hello_is_rejected_on_a_new_connection() {
    let (mut srv, log) = server();
    established(&mut srv, 1, 9);
    srv.on_connect(2, 0);
    srv.on_bytes(2, &attach(ORIGIN), 0);
    let a = srv.on_bytes(2, &hello(&cn(9)), 0);
    expect_reject_on(2, "replay", &srv, &log, a);
}

#[test]
fn a_recorded_auth_frame_does_not_work_on_a_new_connection() {
    let (mut srv, log) = server();
    srv.on_connect(1, 0);
    srv.on_bytes(1, &attach(ORIGIN), 0);
    let (sn, core) = challenge(&mut srv, 1);
    let f = Fields {
        cn: &cn(1),
        sn: &sn,
        origin: ORIGIN.as_bytes(),
        core: &core,
    };
    let recorded_auth = auth(&mac(&secret(), LABEL_CLIENT, &f));
    assert!(reject_code(&srv.on_bytes(1, &recorded_auth, 0), 1).is_none());
    // an attacker opens a new connection and replays the recorded auth after a fresh hello
    srv.on_connect(2, 0);
    srv.on_bytes(2, &attach(ORIGIN), 0);
    srv.on_bytes(2, &hello(&cn(2)), 0);
    let a = srv.on_bytes(2, &recorded_auth, 0);
    expect_reject_on(2, "bad_auth", &srv, &log, a);
}

// ---- (f)(g) session identity on every envelope ----

#[test]
fn an_envelope_with_the_wrong_session_id_is_rejected_and_never_forwarded() {
    for forged in ["00000000000000000000000000000000", "OTHER", "", "x"] {
        let (mut srv, log) = server();
        let _own = established(&mut srv, 1, 1);
        let other = established(&mut srv, 2, 2);
        let sid = if forged == "OTHER" {
            other.as_str()
        } else {
            forged
        };
        let a = drive(&mut srv, 1, &status(sid, "m1"), 1);
        assert!(
            closed(&a, 1),
            "forged session {forged:?} kept the connection"
        );
        assert!(matches!(
            reject_code(&a, 1).as_deref(),
            Some("bad_session") | Some("bad_frame")
        ));
        assert!(log.borrow().is_empty());
        consistent(&srv, &log);
        // the honest second connection is unaffected by the first one being rejected
        let a = drive(&mut srv, 2, &status(&other, "m1"), 1);
        assert_eq!(log.borrow().len(), 1);
        assert!(!closed(&a, 2));
    }
}

#[test]
fn an_envelope_with_another_protocol_version_is_rejected() {
    let (mut srv, log) = server();
    let sid = established(&mut srv, 1, 1);
    let good = envelope(&sid, "m1", "req-1", Message::Status(Empty {}))
        .encode()
        .unwrap();
    let bad = String::from_utf8(good)
        .unwrap()
        .replace("\"version\":1", "\"version\":2");
    let a = drive(&mut srv, 1, &frame(bad.as_bytes()), 1);
    assert_eq!(reject_code(&a, 1).as_deref(), Some("bad_version"));
    assert!(closed(&a, 1));
    assert!(log.borrow().is_empty());
}

#[test]
fn malformed_envelopes_after_ready_close_the_connection_without_forwarding() {
    let (mut probe, _) = server();
    let sid = established(&mut probe, 1, 1);
    let valid = String::from_utf8(
        envelope(&sid, "m1", "req-1", Message::Status(Empty {}))
            .encode()
            .unwrap(),
    )
    .unwrap();
    let deep = format!("{}1{}", "{\"a\":".repeat(20), "}".repeat(20));
    let cases = vec![
        "not json".to_string(),
        "[]".to_string(),
        valid.replacen('{', "{\"generation\":9,", 1),
        valid.replace("\"request_id\":\"req-1\"", "\"request_id\":\"\""),
        valid.replace("\"payload\":{}", &format!("\"payload\":{deep}")),
    ];
    for (i, text) in cases.into_iter().enumerate() {
        let (mut srv, log) = server();
        let _ = established(&mut srv, 1, 1);
        let a = drive(&mut srv, 1, &frame(text.as_bytes()), 1);
        assert!(closed(&a, 1), "case {i}");
        assert!(log.borrow().is_empty(), "case {i}");
        consistent(&srv, &log);
    }
}

// ---- (h) time ----

#[test]
fn handshake_deadlines_close_silent_connections() {
    let (mut srv, log) = server();
    srv.on_connect(1, 0);
    assert!(
        srv.tick(HELLO_TICKS).is_empty(),
        "closed before the deadline"
    );
    let a = srv.tick(HELLO_TICKS + 1);
    expect_reject_on(1, "timeout", &srv, &log, a);

    let (mut srv, log) = server();
    after_attach(&mut srv);
    srv.on_bytes(1, &hello(&cn(1)), 0);
    assert!(srv.tick(AUTH_TICKS).is_empty());
    let a = srv.tick(AUTH_TICKS + 1);
    expect_reject_on(1, "timeout", &srv, &log, a);
}

#[test]
fn an_idle_session_is_closed_but_activity_keeps_it_open() {
    let (mut srv, log) = server();
    let sid = established(&mut srv, 1, 1);
    drive(&mut srv, 1, &status(&sid, "m1"), 2000);
    assert!(
        srv.tick(2000 + IDLE_TICKS).is_empty(),
        "activity did not extend the session"
    );
    let a = srv.tick(2000 + IDLE_TICKS + 1);
    assert!(closed(&a, 1));
    assert_eq!(log.borrow().len(), 1);
}

// ---- in-flight bound, fairness, duplicate ids ----

#[test]
fn the_101st_in_flight_request_is_refused_before_the_backend() {
    let (mut srv, log) = server();
    let sid = established(&mut srv, 1, 1);
    let mut overloaded = 0;
    for i in 0..101 {
        let a = srv.on_bytes(1, &status(&sid, &format!("m{i}")), 1);
        for p in sent(&a, 1) {
            if matches!(Envelope::decode(&p).unwrap().body, Message::Error(ref e) if e.kind == ErrorKind::Overloaded)
            {
                overloaded += 1;
                assert_eq!(i, 100, "refused too early");
            }
        }
    }
    assert_eq!(overloaded, 1);
    assert!(
        log.borrow().is_empty(),
        "nothing is processed until the backend runs"
    );
    let a = srv.process(2, 1000);
    assert_eq!(log.borrow().len(), 100);
    assert_eq!(sent(&a, 1).len(), 100);
    consistent(&srv, &log);
}

#[test]
fn processing_is_bounded_by_the_budget_and_fair_across_connections() {
    let (mut srv, log) = server();
    let s1 = established(&mut srv, 1, 1);
    let s2 = established(&mut srv, 2, 2);
    for i in 0..4 {
        srv.on_bytes(1, &status(&s1, &format!("a{i}")), 1);
        srv.on_bytes(2, &status(&s2, &format!("b{i}")), 1);
    }
    let a = srv.process(2, 4);
    assert_eq!(log.borrow().len(), 4);
    assert_eq!(sent(&a, 1).len(), 2, "unfair share");
    assert_eq!(sent(&a, 2).len(), 2, "unfair share");
}

#[test]
fn a_duplicate_message_id_with_the_same_payload_is_forwarded_with_another_payload_it_is_refused() {
    let (mut srv, log) = server();
    let sid = established(&mut srv, 1, 1);
    drive(&mut srv, 1, &status(&sid, "m1"), 1);
    drive(&mut srv, 1, &status(&sid, "m1"), 1);
    assert_eq!(
        log.borrow().len(),
        2,
        "an identical retransmission is forwarded (the protocol is idempotent)"
    );
    let other = envelope_frame(&envelope(
        &sid,
        "m1",
        "req-1",
        Message::Prepare(prepare_body()),
    ));
    let a = drive(&mut srv, 1, &other, 1);
    assert_eq!(
        log.borrow().len(),
        2,
        "a conflicting duplicate reached the backend"
    );
    let reply = Envelope::decode(&sent(&a, 1)[0]).unwrap();
    assert!(
        matches!(reply.body, Message::Error(ref e) if e.kind == ErrorKind::PayloadMismatch),
        "{reply:?}"
    );
    assert!(!closed(&a, 1));
}

#[test]
fn reply_type_messages_from_a_client_are_refused_with_a_typed_error() {
    let (mut srv, log) = server();
    let sid = established(&mut srv, 1, 1);
    let receipt = Receipt {
        task_id: 1,
        fingerprint: "ab".into(),
        state: TaskState::Prepared,
    };
    let a = drive(
        &mut srv,
        1,
        &envelope_frame(&envelope(&sid, "m1", "r", Message::Prepared(receipt))),
        1,
    );
    let reply = Envelope::decode(&sent(&a, 1)[0]).unwrap();
    assert!(matches!(reply.body, Message::Error(ref e) if e.kind == ErrorKind::UnknownType));
    assert!(log.borrow().is_empty());
}

// ---- (i)(j) isolation ----

#[test]
fn closing_one_connection_never_affects_another_and_replies_stay_on_their_connection() {
    let (mut srv, log) = server();
    let s1 = established(&mut srv, 1, 1);
    let s2 = established(&mut srv, 2, 2);
    srv.on_disconnect(1);
    let a = drive(&mut srv, 2, &status(&s2, "m1"), 1);
    assert_eq!(sent(&a, 2).len(), 1);
    assert!(sent(&a, 1).is_empty());
    let a = drive(&mut srv, 1, &status(&s1, "m2"), 1);
    assert!(a.is_empty(), "a closed connection produced output");
    assert_eq!(log.borrow().len(), 1);
    assert_eq!(srv.stats.post_close_bytes, 1);
}

#[test]
fn bytes_after_a_rejection_are_ignored() {
    let (mut srv, log) = server();
    srv.on_connect(1, 0);
    let a = srv.on_bytes(
        1,
        &attach("chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/"),
        0,
    );
    assert!(closed(&a, 1));
    for _ in 0..3 {
        assert!(srv.on_bytes(1, &attach(ORIGIN), 0).is_empty());
    }
    assert!(log.borrow().is_empty());
    assert_eq!(srv.stats.post_close_bytes, 3);
}

#[test]
fn only_a_bounded_number_of_connections_is_accepted() {
    let (mut srv, _log) = server();
    for c in 1..=MAX_CONNS as u64 {
        assert!(srv.on_connect(c, 0).is_empty());
    }
    let a = srv.on_connect(99, 0);
    assert_eq!(reject_code(&a, 99).as_deref(), Some("busy"));
    assert!(closed(&a, 99));
    srv.on_disconnect(1);
    assert!(
        srv.on_connect(100, 0).is_empty(),
        "a freed slot was not reused"
    );
}

// ---- framing at the server edge ----

#[test]
fn oversize_zero_and_split_frames_are_handled_at_the_edge() {
    let (mut srv, log) = server();
    established(&mut srv, 1, 1);
    let a = srv.on_bytes(1, &(300_000u32).to_ne_bytes(), 1);
    assert_eq!(reject_code(&a, 1).as_deref(), Some("bad_frame"));
    assert!(log.borrow().is_empty());

    let (mut srv, _log) = server();
    established(&mut srv, 1, 1);
    let a = srv.on_bytes(1, &0u32.to_ne_bytes(), 1);
    assert_eq!(reject_code(&a, 1).as_deref(), Some("bad_frame"));

    // the same honest handshake delivered one byte at a time still works
    let (mut srv, log) = server();
    srv.on_connect(1, 0);
    let mut stream = attach(ORIGIN);
    stream.extend(hello(&cn(1)));
    let mut got = Vec::new();
    for b in &stream {
        got.extend(srv.on_bytes(1, &[*b], 0));
    }
    assert!(reject_code(&got, 1).is_none());
    assert_eq!(sent(&got, 1).len(), 1, "exactly one challenge");
    assert!(log.borrow().is_empty());
}

// ---- (k) nothing secret leaves the server ----

#[test]
fn the_install_secret_never_appears_in_sent_frames_stats_or_reject_shapes() {
    let (mut srv, log) = server();
    let mut all: Vec<Action> = Vec::new();
    all.extend(srv.on_connect(1, 0));
    all.extend(srv.on_bytes(1, &attach(ORIGIN), 0));
    let a = srv.on_bytes(1, &hello(&cn(1)), 0);
    let ch = sent_json(&a, 1)[0].clone();
    all.extend(a);
    all.extend(srv.on_bytes(1, &auth(&[9; 32]), 0));
    let dump = format!("{all:?}{:?}", srv.stats);
    assert!(
        !dump.contains(&b64_encode(secret().expose())),
        "install secret leaked"
    );
    assert!(!dump.contains(SENTINEL));
    // the debug dump prints bytes as numbers, so also scan the raw bytes of every sent frame
    let key = *secret().expose();
    for a in &all {
        if let Action::Send(_, bytes) = a {
            assert!(
                !bytes.windows(32).any(|w| w == key),
                "raw secret bytes were sent"
            );
            assert!(
                !String::from_utf8_lossy(bytes).contains(&b64_encode(&key)),
                "base64 secret was sent"
            );
        }
    }
    for v in sent_json(&all, 1) {
        if v["t"] == "reject" {
            assert_eq!(
                v.as_object().unwrap().len(),
                2,
                "reject frame carries extra data: {v}"
            );
        }
    }
    assert!(ch["sm"].is_string());
    assert!(log.borrow().is_empty());
}

#[test]
fn before_ready_a_large_frame_is_refused_from_its_header_alone() {
    // 200,000 bytes would be a legal envelope, but not a handshake frame: it must be refused as soon
    // as the header is read, without waiting for (or buffering) the payload
    for stage in 0..3 {
        let (mut srv, log) = server();
        srv.on_connect(1, 0);
        if stage >= 1 {
            srv.on_bytes(1, &attach(ORIGIN), 0);
        }
        if stage >= 2 {
            srv.on_bytes(1, &hello(&cn(1)), 0);
        }
        let a = srv.on_bytes(1, &200_000u32.to_ne_bytes(), 0);
        assert_eq!(
            reject_code(&a, 1).as_deref(),
            Some("bad_frame"),
            "stage {stage}"
        );
        assert!(closed(&a, 1));
        assert!(log.borrow().is_empty());
    }
}

#[test]
fn after_ready_an_envelope_larger_than_the_handshake_limit_is_accepted() {
    let (mut srv, log) = server();
    let sid = established(&mut srv, 1, 1);
    let mut body = prepare_body();
    body.url = format!("https://x.test/{}", "a".repeat(5000));
    let a = drive(
        &mut srv,
        1,
        &envelope_frame(&envelope(&sid, "m1", "req-1", Message::Prepare(body))),
        1,
    );
    assert!(!closed(&a, 1), "a legal 5 KB envelope was refused");
    assert_eq!(log.borrow().len(), 1);
}

#[test]
fn debug_output_of_actions_never_contains_handshake_bytes() {
    // Debug on a byte vector prints decimal numbers, which a base64 or raw scan cannot see
    let (mut srv, _log) = server();
    srv.on_connect(1, 0);
    srv.on_bytes(1, &attach(ORIGIN), 0);
    let actions = srv.on_bytes(1, &hello(&cn(1)), 0);
    let challenge = sent_json(&actions, 1)[0].clone();
    let sm = b64_decode(challenge["sm"].as_str().unwrap()).unwrap();
    let sn = b64_decode(challenge["sn"].as_str().unwrap()).unwrap();
    let shown = format!("{actions:?}");
    for (what, bytes) in [("server MAC", sm), ("server nonce", sn)] {
        let decimal = format!("{:?}", &bytes[..8]);
        assert!(
            !shown.contains(decimal.trim_start_matches('[').trim_end_matches(']')),
            "{what} printed as decimal bytes: {shown}"
        );
    }
    assert!(shown.contains("Send") && shown.contains("bytes"));
    assert!(format!("{:?}", Action::Close(3)).contains("Close"));
}
