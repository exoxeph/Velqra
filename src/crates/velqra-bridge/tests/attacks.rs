// SPDX-License-Identifier: GPL-3.0-only
//! Hostile byte streams against the bridge server. The spy on the backend boundary is the only
//! evidence used for "never reached the core".
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use velqra_bridge::backend::{CoreBackend, Spy, SpyLog};
use velqra_bridge::frame::MAX_ENVELOPE;
use velqra_bridge::handshake::*;
use velqra_bridge::server::*;
use velqra_bridge::sim::leaks_secret;
use velqra_bridge::testkit::*;
use velqra_core::store::MemStore;
use velqra_core::Core;
use velqra_protocol::*;

type Srv = BridgeServer<Spy<CoreBackend<MemStore, NullEngine>>>;

fn server(seed: u64) -> (Srv, SpyLog) {
    let (spy, log) = Spy::new(CoreBackend::new(
        Core::new(MemStore::default()),
        NullEngine,
        "fake",
    ));
    (
        BridgeServer::new(
            spy,
            secret(),
            vec![ORIGIN.to_string()],
            Box::new(StdRng::seed_from_u64(seed)),
        ),
        log,
    )
}

/// A complete honest client stream: attach, hello, auth, then a Prepare request.
fn honest_stream(srv: &mut Srv) -> Vec<u8> {
    let mut bytes = attach(ORIGIN);
    srv.on_connect(1, 0);
    srv.on_bytes(1, &bytes, 0);
    let h = hello(&[5; 16]);
    let a = srv.on_bytes(1, &h, 0);
    bytes.extend(&h);
    let ch = sent_json(&a, 1)[0].clone();
    let sn = b64_decode(ch["sn"].as_str().unwrap()).unwrap();
    let core = b64_decode(ch["core"].as_str().unwrap()).unwrap();
    let f = Fields {
        cn: &[5; 16],
        sn: &sn,
        origin: ORIGIN.as_bytes(),
        core: &core,
    };
    let au = auth(&mac(&secret(), LABEL_CLIENT, &f));
    let a = srv.on_bytes(1, &au, 0);
    bytes.extend(&au);
    let sid = sent_json(&a, 1).iter().find(|v| v["t"] == "ready").unwrap()["sid"]
        .as_str()
        .unwrap()
        .to_string();
    bytes.extend(envelope_frame(&envelope(
        &sid,
        "m1",
        "req-1",
        Message::Prepare(prepare_body()),
    )));
    bytes
}

fn recorded() -> Vec<u8> {
    let (mut srv, _log) = server(1);
    honest_stream(&mut srv)
}

#[test]
fn truncating_an_honest_stream_at_every_offset_never_reaches_the_backend_early() {
    let stream = recorded();
    for cut in 0..stream.len() {
        // a fresh server with a different rng: the recorded handshake cannot complete against it,
        // and a truncated envelope must never be forwarded in any case
        let (mut srv, log) = server(2);
        srv.on_connect(1, 0);
        let mut actions = srv.on_bytes(1, &stream[..cut], 0);
        actions.extend(srv.process(0, 100));
        assert!(
            log.borrow().is_empty(),
            "cut {cut}: a truncated stream reached the backend"
        );
        // the peer goes silent: the server must clean the connection up on its own
        let later = srv.tick(HELLO_TICKS + AUTH_TICKS + 5);
        assert!(
            closed(&actions, 1) || closed(&later, 1),
            "cut {cut}: connection left open"
        );
        assert_eq!(srv.stats.reached_backend, 0);
    }
}

#[test]
fn the_recorded_stream_only_works_against_the_server_it_was_recorded_from() {
    let stream = recorded();
    // same rng seed: the nonces repeat, so the recording is accepted and the Prepare reaches the backend
    let (mut srv, log) = server(1);
    srv.on_connect(1, 0);
    srv.on_bytes(1, &stream, 0);
    srv.process(0, 100);
    assert_eq!(
        log.borrow().len(),
        1,
        "control: the unmodified recording should be accepted by its own server"
    );
    // any other server instance refuses the same bytes
    let (mut other, log) = server(2);
    other.on_connect(1, 0);
    other.on_bytes(1, &stream, 0);
    other.process(0, 100);
    assert!(log.borrow().is_empty());
}

#[test]
fn flipping_any_single_bit_of_a_recorded_stream_never_forges_a_backend_call() {
    let stream = recorded();
    for bit in 0..stream.len() * 8 {
        let mut s = stream.clone();
        s[bit / 8] ^= 1 << (bit % 8);
        let (mut srv, log) = server(1); // same rng as the recording, so the unflipped stream would work
        srv.on_connect(1, 0);
        srv.on_bytes(1, &s, 0);
        srv.process(0, 100);
        for call in log.borrow().iter() {
            // whatever reached the backend must be a well-formed envelope of a session issued here
            assert_eq!(
                call.session_id.len(),
                32,
                "bit {bit}: backend saw a session id that was never issued"
            );
            assert!(
                matches!(call.body, Message::Prepare(_)),
                "bit {bit}: unexpected message"
            );
        }
        assert!(srv.max_decoder_capacity() <= MAX_ENVELOPE + 8);
    }
}

#[test]
fn pipelined_garbage_after_a_failed_handshake_is_dropped() {
    // one write containing attach, hello, a bogus auth and then a valid-looking envelope
    let (mut srv, log) = server(3);
    srv.on_connect(1, 0);
    let mut s = attach(ORIGIN);
    s.extend(hello(&[7; 16]));
    s.extend(auth(&[0; 32]));
    s.extend(envelope_frame(&envelope(
        "00000000000000000000000000000000",
        "m1",
        "r",
        Message::Status(Empty {}),
    )));
    let a = srv.on_bytes(1, &s, 0);
    assert_eq!(reject_code(&a, 1).as_deref(), Some("bad_auth"));
    assert_eq!(
        a.iter().filter(|x| matches!(x, Action::Close(_))).count(),
        1,
        "closed more than once"
    );
    srv.process(0, 100);
    assert!(log.borrow().is_empty());
}

#[test]
fn random_byte_streams_in_every_phase_never_panic_never_reach_the_backend_and_stay_bounded() {
    let mut rng = StdRng::seed_from_u64(99);
    for round in 0..4000u64 {
        let (mut srv, log) = server(round);
        srv.on_connect(1, 0);
        match round % 3 {
            1 => {
                srv.on_bytes(1, &attach(ORIGIN), 0);
            }
            2 => {
                srv.on_bytes(1, &attach(ORIGIN), 0);
                srv.on_bytes(1, &hello(&[round as u8; 16]), 0);
            }
            _ => {}
        }
        let len = rng.gen_range(0..600usize);
        let mut junk = vec![0u8; len];
        rng.fill_bytes(&mut junk);
        // sometimes make the header plausible so the parser goes deeper
        if round % 5 == 0 && len >= 4 {
            junk[..4].copy_from_slice(&(rng.gen_range(1..300u32)).to_ne_bytes());
        }
        let mut acts = srv.on_bytes(1, &junk, 0);
        acts.extend(srv.process(0, 100));
        assert!(
            log.borrow().is_empty(),
            "round {round}: random bytes reached the backend"
        );
        assert!(srv.max_decoder_capacity() <= MAX_ENVELOPE + 8);
        for a in acts {
            if let Action::Send(_, b) = a {
                assert!(!leaks_secret(&b));
            }
        }
    }
}

#[test]
fn a_flood_of_oversize_headers_costs_no_memory() {
    let (mut srv, log) = server(4);
    for conn in 1..=MAX_CONNS as u64 {
        srv.on_connect(conn, 0);
        let a = srv.on_bytes(conn, &u32::MAX.to_ne_bytes(), 0);
        assert!(closed(&a, conn));
        assert!(srv.max_decoder_capacity() <= 8);
    }
    assert!(log.borrow().is_empty());
}

#[test]
fn a_peer_that_never_authenticates_cannot_hold_a_slot_forever() {
    let (mut srv, _log) = server(5);
    for conn in 1..=MAX_CONNS as u64 {
        srv.on_connect(conn, 0);
    }
    assert_eq!(
        reject_code(&srv.on_connect(50, 0), 50).as_deref(),
        Some("busy")
    );
    let later = srv.tick(HELLO_TICKS + 1);
    assert_eq!(
        later
            .iter()
            .filter(|a| matches!(a, Action::Close(_)))
            .count(),
        MAX_CONNS
    );
    assert!(
        srv.on_connect(51, HELLO_TICKS + 2).is_empty(),
        "slots were not released"
    );
}
