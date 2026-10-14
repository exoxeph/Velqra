// SPDX-License-Identifier: GPL-3.0-only
//! Deterministic fault harness for the bridge: an honest client model, a lossy link with named
//! fault points, and a checker that validates every backend call as it happens (prefix
//! invariants) against evidence collected independently of the server's own counters.
//!
//! Invariants checked on every run:
//! * B1 every backend call carries a session id the server really issued;
//! * B2 every backend call is byte-for-byte an envelope the honest client really sent;
//! * B3 the honest client completes or gives up, it never hangs (single and pair faults must complete);
//! * B4 the spy log and the server's own counter agree;
//! * B5 replaying every recorded client byte stream on fresh connections never reaches the backend;
//! * B6 the decoder never reserves more than the frame limit;
//! * B7 neither the secret nor the secret's base64 appears on the wire in either direction.

use crate::backend::{CoreBackend, Spy, SpyLog};
use crate::frame::{FrameDecoder, MAX_ENVELOPE, MAX_TO_BROWSER};
use crate::handshake::*;
use crate::server::*;
use crate::testkit::*;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::{HashMap, HashSet};
use velqra_core::store::MemStore;
use velqra_core::Core;
use velqra_protocol::*;

pub const MAX_TICKS: u64 = 600;
const RESEND_EVERY: u64 = 6;
const MAX_ATTEMPTS: u32 = 10;
const DELAY_TICKS: u64 = 8;
const REQUEST_ID: &str = "req-1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FaultKind {
    Loss,
    Duplicate,
    Delay,
    /// Deliver the first half of the chunk, then drop the connection.
    CutMid,
}

pub const KINDS: [FaultKind; 4] = [
    FaultKind::Loss,
    FaultKind::Duplicate,
    FaultKind::Delay,
    FaultKind::CutMid,
];

#[derive(Clone, Copy, Debug)]
pub enum Pick {
    Kind(FaultKind),
    Any(u32),
}

#[derive(Default)]
pub struct Faults {
    plan: Vec<(usize, Pick)>,
    counter: usize,
    record: bool,
    pub points: Vec<String>,
    pub injected: Vec<(String, FaultKind)>,
}

impl Faults {
    pub fn new(plan: Vec<(usize, Pick)>, record: bool) -> Self {
        Self {
            plan,
            record,
            ..Default::default()
        }
    }

    fn check(&mut self, name: &str) -> Option<FaultKind> {
        let idx = self.counter;
        self.counter += 1;
        if self.record {
            self.points.push(name.to_string());
        }
        let kind = self
            .plan
            .iter()
            .find(|(i, _)| *i == idx)
            .map(|(_, p)| match p {
                Pick::Kind(k) => *k,
                Pick::Any(n) => KINDS[*n as usize % KINDS.len()],
            })?;
        self.injected.push((name.to_string(), kind));
        Some(kind)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Server,
    Client,
}

struct Chunk {
    at: u64,
    seq: u64,
    to: Side,
    conn: ConnId,
    bytes: Vec<u8>,
    close_after: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    AwaitChallenge,
    AwaitReady,
    Ready,
}

struct Client {
    conn: Option<ConnId>,
    dec: FrameDecoder,
    stage: Stage,
    cn: [u8; 16],
    next_cn: u8,
    sid: String,
    step: usize,
    receipt: Option<RequestRef>,
    last_sent: u64,
    attempts: u32,
    cooldown_until: u64,
    done: bool,
    gave_up: bool,
}

#[derive(Debug, Clone)]
pub struct RunReport {
    pub completed: bool,
    pub gave_up: bool,
    pub ticks: u64,
    pub backend_calls: usize,
    pub violations: Vec<String>,
    pub injected: Vec<(String, FaultKind)>,
    pub points: Vec<String>,
}

/// Pure check of one backend call against the independent evidence. Unit-tested on wrong inputs.
pub fn check_call(call: &Envelope, issued: &HashSet<String>, sent: &[Envelope]) -> Vec<String> {
    let mut v = Vec::new();
    if !issued.contains(&call.session_id) {
        v.push("B1: backend call with a session id the server never issued".to_string());
    }
    let genuine = sent.iter().any(|e| {
        e.message_id == call.message_id && e.session_id == call.session_id && e.body == call.body
    });
    if !genuine {
        v.push("B2: backend call is not an envelope the honest client sent".to_string());
    }
    v
}

pub fn leaks_secret(bytes: &[u8]) -> bool {
    let key = *secret().expose();
    bytes.windows(32).any(|w| w == key)
        || String::from_utf8_lossy(bytes).contains(&b64_encode(&key))
}

type Srv = BridgeServer<Spy<CoreBackend<MemStore, NullEngine>>>;

pub struct World {
    pub tick: u64,
    seq: u64,
    srv: Srv,
    spy: SpyLog,
    spy_seen: usize,
    faults: Faults,
    net: Vec<Chunk>,
    conn_next: ConnId,
    client: Client,
    issued: HashSet<String>,
    sent: Vec<Envelope>,
    c2s: HashMap<ConnId, Vec<u8>>,
    s2c_wire: Vec<u8>,
    violations: Vec<String>,
}

impl World {
    pub fn new(faults: Faults, seed: u64) -> Self {
        let core = Core::new(MemStore::default());
        let (spy_backend, spy) = Spy::new(CoreBackend::new(core, NullEngine, "fake"));
        let srv = BridgeServer::new(
            spy_backend,
            secret(),
            vec![ORIGIN.to_string()],
            Box::new(StdRng::seed_from_u64(seed)),
        );
        Self {
            tick: 0,
            seq: 0,
            srv,
            spy,
            spy_seen: 0,
            faults,
            net: Vec::new(),
            conn_next: 1,
            client: Client {
                conn: None,
                dec: FrameDecoder::new(MAX_TO_BROWSER),
                stage: Stage::AwaitChallenge,
                cn: [0; 16],
                next_cn: 1,
                sid: String::new(),
                step: 0,
                receipt: None,
                last_sent: 0,
                attempts: 0,
                cooldown_until: 0,
                done: false,
                gave_up: false,
            },
            issued: HashSet::new(),
            sent: Vec::new(),
            c2s: HashMap::new(),
            s2c_wire: Vec::new(),
            violations: Vec::new(),
        }
    }

    fn push(&mut self, to: Side, conn: ConnId, bytes: Vec<u8>, at: u64, close_after: bool) {
        self.seq += 1;
        self.net.push(Chunk {
            at,
            seq: self.seq,
            to,
            conn,
            bytes,
            close_after,
        });
    }

    fn send_chunk(&mut self, to: Side, conn: ConnId, bytes: Vec<u8>, name: &str) {
        if to == Side::Server {
            self.c2s.entry(conn).or_default().extend_from_slice(&bytes);
        }
        let at = self.tick + 1;
        match self.faults.check(name) {
            Some(FaultKind::Loss) => {}
            Some(FaultKind::Duplicate) => {
                self.push(to, conn, bytes.clone(), at, false);
                self.push(to, conn, bytes, at, false);
            }
            Some(FaultKind::Delay) => self.push(to, conn, bytes, self.tick + DELAY_TICKS, false),
            Some(FaultKind::CutMid) => {
                let half = bytes[..bytes.len() / 2].to_vec();
                self.push(to, conn, half, at, true);
            }
            None => self.push(to, conn, bytes, at, false),
        }
    }

    fn handle_actions(&mut self, actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Send(conn, bytes) => {
                    self.s2c_wire.extend_from_slice(&bytes);
                    // evidence about what the server really issued, read before any fault touches it
                    let mut d = FrameDecoder::new(MAX_TO_BROWSER);
                    for p in d.feed(&bytes).unwrap_or_default() {
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&p) {
                            if v["t"] == "ready" {
                                if let Some(s) = v["sid"].as_str() {
                                    self.issued.insert(s.to_string());
                                }
                            }
                        }
                    }
                    self.send_chunk(Side::Client, conn, bytes, "s2c");
                }
                Action::Close(conn) => {
                    self.push(Side::Client, conn, Vec::new(), self.tick + 1, true)
                }
            }
        }
    }

    fn abandon(&mut self) {
        if let Some(c) = self.client.conn.take() {
            self.srv.on_disconnect(c);
        }
        self.client.cooldown_until = self.tick + 2;
    }

    fn request_bytes(&mut self) -> Vec<u8> {
        let (id, body) = match self.client.step {
            0 => ("m-prepare", Message::Prepare(prepare_body())),
            1 => (
                "m-begin",
                Message::BeginHandoff(self.client.receipt.clone().expect("receipt")),
            ),
            _ => (
                "m-commit",
                Message::Commit(CommitBody {
                    cancel: CancelEvidence::Confirmed,
                    receipt: self.client.receipt.clone().expect("receipt"),
                }),
            ),
        };
        let env = envelope(&self.client.sid, id, REQUEST_ID, body);
        self.sent.push(env.clone());
        envelope_frame(&env)
    }

    fn send_request(&mut self, conn: ConnId) {
        let bytes = self.request_bytes();
        self.send_chunk(Side::Server, conn, bytes, "c2s.req");
        self.client.last_sent = self.tick;
    }

    fn client_step(&mut self) {
        if self.client.done || self.client.gave_up {
            return;
        }
        let Some(conn) = self.client.conn else {
            if self.tick < self.client.cooldown_until {
                return;
            }
            if self.client.attempts >= MAX_ATTEMPTS {
                self.client.gave_up = true;
                return;
            }
            self.client.attempts += 1;
            let conn = self.conn_next;
            self.conn_next += 1;
            let a = self.srv.on_connect(conn, self.tick);
            self.handle_actions(a);
            self.client.conn = Some(conn);
            self.client.dec = FrameDecoder::new(MAX_TO_BROWSER);
            self.client.stage = Stage::AwaitChallenge;
            self.client.cn = [self.client.next_cn; 16];
            self.client.next_cn = self.client.next_cn.wrapping_add(1);
            self.send_chunk(Side::Server, conn, attach(ORIGIN), "c2s.attach");
            self.send_chunk(Side::Server, conn, hello(&self.client.cn), "c2s.hello");
            self.client.last_sent = self.tick;
            return;
        };
        if self.tick.saturating_sub(self.client.last_sent) >= RESEND_EVERY {
            if self.client.stage == Stage::Ready {
                self.send_request(conn); // same message id: a retransmission
            } else {
                self.abandon();
            }
        }
    }

    fn client_on_bytes(&mut self, conn: ConnId, bytes: &[u8]) {
        if self.client.conn != Some(conn) {
            return; // a connection the client already left
        }
        let frames = match self.client.dec.feed(bytes) {
            Ok(f) => f,
            Err(_) => return self.abandon(),
        };
        for p in frames {
            if self.client.conn != Some(conn) {
                return;
            }
            match self.client.stage {
                Stage::AwaitChallenge | Stage::AwaitReady => self.client_handshake_frame(conn, &p),
                Stage::Ready => self.client_envelope(conn, &p),
            }
        }
    }

    fn client_handshake_frame(&mut self, conn: ConnId, p: &[u8]) {
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(p) else {
            return self.abandon();
        };
        match (self.client.stage, v["t"].as_str()) {
            (Stage::AwaitChallenge, Some("challenge")) => {
                let dec = |k: &str| v[k].as_str().and_then(b64_decode);
                let (Some(sn), Some(core), Some(sm)) = (dec("sn"), dec("core"), dec("sm")) else {
                    return self.abandon();
                };
                let cn = self.client.cn;
                let f = Fields {
                    cn: &cn,
                    sn: &sn,
                    origin: ORIGIN.as_bytes(),
                    core: &core,
                };
                if !verify(&secret(), LABEL_SERVER, &f, &sm) {
                    return self.abandon(); // a core that cannot prove the secret is not talked to
                }
                let cm = mac(&secret(), LABEL_CLIENT, &f);
                self.client.stage = Stage::AwaitReady;
                self.send_chunk(Side::Server, conn, auth(&cm), "c2s.auth");
                self.client.last_sent = self.tick;
            }
            (Stage::AwaitReady, Some("ready")) => {
                let Some(sid) = v["sid"].as_str() else {
                    return self.abandon();
                };
                self.client.sid = sid.to_string();
                self.client.stage = Stage::Ready;
                self.send_request(conn);
            }
            _ => self.abandon(), // reject or anything unexpected
        }
    }

    fn client_envelope(&mut self, conn: ConnId, p: &[u8]) {
        let Ok(env) = Envelope::decode(p) else {
            return self.abandon();
        };
        let expected_id = ["m-prepare", "m-begin", "m-commit"][self.client.step.min(2)];
        if env.session_id != self.client.sid
            || env.request_id != REQUEST_ID
            || env.message_id != format!("r-{expected_id}")
        {
            return; // identity mismatch: believed by nobody
        }
        match (self.client.step, &env.body) {
            (0, Message::Prepared(r))
                if r.state == TaskState::Prepared
                    && r.fingerprint == fingerprint(&prepare_body()) =>
            {
                self.client.receipt = Some(r.as_ref());
                self.client.step = 1;
                self.send_request(conn);
            }
            (1, Message::Armed(r))
                if r.state == TaskState::Armed && Some(r.as_ref()) == self.client.receipt =>
            {
                self.client.step = 2;
                self.send_request(conn);
            }
            (2, Message::Committed(r))
                if Some(r.as_ref()) == self.client.receipt
                    && matches!(
                        r.state,
                        TaskState::Committed | TaskState::Transferring | TaskState::Done
                    ) =>
            {
                self.client.done = true;
            }
            _ => {}
        }
    }

    fn deliver_due(&mut self) {
        let (mut due, rest): (Vec<Chunk>, Vec<Chunk>) = std::mem::take(&mut self.net)
            .into_iter()
            .partition(|c| c.at <= self.tick);
        self.net = rest;
        due.sort_by_key(|c| (c.at, c.seq));
        for c in due {
            match c.to {
                Side::Server => {
                    let a = self.srv.on_bytes(c.conn, &c.bytes, self.tick);
                    self.handle_actions(a);
                    if c.close_after {
                        self.srv.on_disconnect(c.conn);
                        if self.client.conn == Some(c.conn) {
                            self.abandon();
                        }
                    }
                }
                Side::Client => {
                    self.client_on_bytes(c.conn, &c.bytes);
                    if c.close_after && self.client.conn == Some(c.conn) {
                        self.abandon();
                    }
                }
            }
        }
    }

    fn check_new_calls(&mut self) {
        let log = self.spy.borrow();
        for call in &log[self.spy_seen..] {
            self.violations
                .extend(check_call(call, &self.issued, &self.sent));
        }
        self.spy_seen = log.len();
        drop(log);
        if self.srv.max_decoder_capacity() > MAX_ENVELOPE + 8 {
            self.violations
                .push("B6: decoder reserved more than the frame limit".to_string());
        }
    }

    pub fn run(mut self) -> RunReport {
        while self.tick < MAX_TICKS && !(self.client.done || self.client.gave_up) {
            self.tick += 1;
            self.deliver_due();
            let a = self.srv.process(self.tick, 64);
            self.handle_actions(a);
            let a = self.srv.tick(self.tick);
            self.handle_actions(a);
            self.client_step();
            self.check_new_calls();
        }
        self.finish()
    }

    fn finish(mut self) -> RunReport {
        let completed = self.client.done;
        if !completed && !self.client.gave_up {
            self.violations
                .push("B3: the honest client hung".to_string());
        }
        // B5: replay every recorded client byte stream on fresh connections
        let before = self.spy.borrow().len();
        let streams: Vec<Vec<u8>> = self.c2s.values().cloned().collect();
        for s in streams {
            let conn = self.conn_next;
            self.conn_next += 1;
            self.srv.on_connect(conn, self.tick);
            self.srv.on_bytes(conn, &s, self.tick);
            self.srv.process(self.tick, 1000);
            self.srv.on_disconnect(conn);
        }
        if self.spy.borrow().len() != before {
            self.violations
                .push("B5: a replayed byte stream reached the backend".to_string());
        }
        // B4: independent log versus the server's own counter
        if self.srv.stats.reached_backend as usize != self.spy.borrow().len() {
            self.violations
                .push("B4: spy log and server counter disagree".to_string());
        }
        // B7: the secret is never on the wire
        let c2s_all: Vec<u8> = self.c2s.values().flatten().copied().collect();
        if leaks_secret(&self.s2c_wire) || leaks_secret(&c2s_all) {
            self.violations
                .push("B7: the install secret appeared on the wire".to_string());
        }
        RunReport {
            completed,
            gave_up: self.client.gave_up,
            ticks: self.tick,
            backend_calls: self.spy.borrow().len(),
            violations: self.violations,
            injected: self.faults.injected,
            points: self.faults.points,
        }
    }
}

pub fn run_plan(plan: Vec<(usize, Pick)>, record: bool) -> RunReport {
    World::new(Faults::new(plan, record), 7).run()
}

pub struct Summary {
    pub runs: usize,
    pub points: usize,
    pub violations: Vec<String>,
    pub not_completed: usize,
}

fn absorb(s: &mut Summary, label: &str, r: &RunReport, must_complete: bool) {
    s.runs += 1;
    for v in &r.violations {
        s.violations.push(format!("{label}: {v}"));
    }
    if !r.completed {
        s.not_completed += 1;
        if must_complete {
            s.violations.push(format!(
                "{label}: LIVENESS the honest client did not complete"
            ));
        }
    }
}

/// Every fault kind at every fault point reached by the honest run, one fault per run.
pub fn exhaustive() -> Summary {
    let base = run_plan(vec![], true);
    let mut s = Summary {
        runs: 0,
        points: base.points.len(),
        violations: Vec::new(),
        not_completed: 0,
    };
    absorb(&mut s, "baseline", &base, true);
    for (i, name) in base.points.iter().enumerate() {
        for k in KINDS {
            let r = run_plan(vec![(i, Pick::Kind(k))], false);
            absorb(&mut s, &format!("#{i} {name} + {k:?}"), &r, true);
        }
    }
    s
}

/// Two faults: the second at any point reached after the first (taken from the faulted run itself).
pub fn exhaustive_pairs() -> Summary {
    let base = run_plan(vec![], true);
    let mut s = Summary {
        runs: 0,
        points: base.points.len(),
        violations: Vec::new(),
        not_completed: 0,
    };
    for (i1, n1) in base.points.iter().enumerate() {
        for k1 in KINDS {
            let first = run_plan(vec![(i1, Pick::Kind(k1))], true);
            for (i2, n2) in first.points.iter().enumerate().skip(i1 + 1) {
                for k2 in KINDS {
                    let r = run_plan(vec![(i1, Pick::Kind(k1)), (i2, Pick::Kind(k2))], false);
                    absorb(
                        &mut s,
                        &format!("#{i1} {n1} + {k1:?} then #{i2} {n2} + {k2:?}"),
                        &r,
                        true,
                    );
                }
            }
        }
    }
    s
}

/// `nfaults` random faults over the first `horizon` fault points, reproducible from `seed`.
/// Liveness is only "never hangs": the client may legitimately give up after many faults.
pub fn seeded(seed: u64, nfaults: usize, horizon: usize) -> RunReport {
    let mut rng = StdRng::seed_from_u64(seed);
    let plan = (0..nfaults)
        .map(|_| (rng.gen_range(0..horizon), Pick::Any(rng.gen())))
        .collect();
    World::new(Faults::new(plan, false), seed).run()
}
