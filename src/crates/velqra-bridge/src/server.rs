// SPDX-License-Identifier: GPL-3.0-only
//! The deterministic bridge server: connections in, authenticated envelopes out to the backend.
//! No I/O and no clock: callers pass bytes and a tick count, and perform the returned actions.
//!
//! Nothing reaches the backend until a connection has completed the mutual handshake, and every
//! envelope after that must carry the session id issued to that very connection.

use crate::backend::Backend;
use crate::frame::{encode_frame, FrameDecoder, MAX_ENVELOPE, MAX_HANDSHAKE, MAX_TO_BROWSER};
use crate::handshake::{b64_decode, b64_encode, mac, verify, Fields, LABEL_CLIENT, LABEL_SERVER};
use crate::secret::InstallSecret;
use rand::RngCore;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use velqra_protocol::*;

pub type ConnId = u64;

/// Hello must follow attach, and auth must follow challenge, within this many ticks (100 ms each).
pub const HELLO_TICKS: u64 = 100;
pub const AUTH_TICKS: u64 = 100;
pub const IDLE_TICKS: u64 = 3000;
pub const MAX_INFLIGHT: usize = 100;
pub const DUP_WINDOW: usize = 256;
pub const SEEN_CN: usize = 4096;
pub const MAX_CONNS: usize = 8;

/// What the I/O layer must do. `Send` carries bytes that are already framed.
#[derive(Clone, PartialEq, Eq)]
pub enum Action {
    Send(ConnId, Vec<u8>),
    Close(ConnId),
}

/// Sent bytes carry challenges, MACs, nonces and request data, so they are never printed.
impl std::fmt::Debug for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Send(conn, b) => write!(f, "Send({conn}, <{} bytes>)", b.len()),
            Action::Close(conn) => write!(f, "Close({conn})"),
        }
    }
}

/// Informational counters only. Security tests do not trust these; they use the backend spy.
#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub connections: u64,
    pub rejected: u64,
    pub reached_backend: u64,
    pub answered_locally: u64,
    pub post_close_bytes: u64,
}

enum Phase {
    Attach {
        deadline: u64,
    },
    Hello {
        origin: String,
        deadline: u64,
    },
    Auth {
        origin: String,
        cn: [u8; 16],
        sn: [u8; 16],
        deadline: u64,
    },
    Ready {
        sid: String,
        last: u64,
    },
}

struct Conn {
    phase: Phase,
    dec: FrameDecoder,
    queue: VecDeque<Envelope>,
    recent: VecDeque<(String, [u8; 32])>,
}

pub struct BridgeServer<B: Backend> {
    pub backend: B,
    pub stats: Stats,
    secret: InstallSecret,
    allowed: Vec<String>,
    rng: Box<dyn RngCore>,
    core_id: [u8; 16],
    conns: HashMap<ConnId, Conn>,
    seen_cn: VecDeque<[u8; 16]>,
}

fn send_json(conn: ConnId, v: &Value) -> Action {
    Action::Send(
        conn,
        encode_frame(v.to_string().as_bytes(), MAX_TO_BROWSER).expect("small frame"),
    )
}

fn reply_to(env: &Envelope, body: Message) -> Envelope {
    Envelope {
        version: PROTOCOL_VERSION,
        message_id: format!("r-{}", env.message_id),
        session_id: env.session_id.clone(),
        request_id: env.request_id.clone(),
        generation: env.generation,
        body,
    }
}

fn send_env(conn: ConnId, env: &Envelope) -> Action {
    let bytes = env
        .encode()
        .ok()
        .and_then(|b| encode_frame(&b, MAX_TO_BROWSER).ok());
    match bytes {
        Some(b) => Action::Send(conn, b),
        None => {
            let e = reply_to(
                env,
                Message::Error(ProtoError::new(ErrorKind::TooLarge, "reply too large")),
            );
            Action::Send(
                conn,
                encode_frame(&e.encode().expect("small"), MAX_TO_BROWSER).expect("small"),
            )
        }
    }
}

fn error_env(env: &Envelope, kind: ErrorKind, text: &str) -> Envelope {
    let mut e = reply_to(env, Message::Error(ProtoError::new(kind, text)));
    e.message_id = format!("e-{}", env.message_id);
    e
}

/// A handshake frame must be a JSON object with exactly these keys (no extras, no duplicates).
fn handshake_object(payload: &[u8], keys: &[&str]) -> Option<Map<String, Value>> {
    let Value::Object(m) = parse_strict_json(payload).ok()? else {
        return None;
    };
    (m.len() == keys.len() && keys.iter().all(|k| m.contains_key(*k))).then_some(m)
}

fn array16(v: &[u8]) -> Option<[u8; 16]> {
    v.try_into().ok()
}

impl<B: Backend> BridgeServer<B> {
    pub fn new(
        backend: B,
        secret: InstallSecret,
        allowed_origins: Vec<String>,
        mut rng: Box<dyn RngCore>,
    ) -> Self {
        let mut core_id = [0u8; 16];
        rng.fill_bytes(&mut core_id);
        Self {
            backend,
            stats: Stats::default(),
            secret,
            allowed: allowed_origins,
            rng,
            core_id,
            conns: HashMap::new(),
            seen_cn: VecDeque::new(),
        }
    }

    fn reject(&mut self, conn: ConnId, code: &str) -> Vec<Action> {
        self.conns.remove(&conn);
        self.stats.rejected += 1;
        vec![
            send_json(conn, &json!({"t": "reject", "code": code})),
            Action::Close(conn),
        ]
    }

    pub fn on_connect(&mut self, conn: ConnId, now: u64) -> Vec<Action> {
        if self.conns.len() >= MAX_CONNS && !self.conns.contains_key(&conn) {
            self.stats.rejected += 1;
            return vec![
                send_json(conn, &json!({"t": "reject", "code": "busy"})),
                Action::Close(conn),
            ];
        }
        self.stats.connections += 1;
        self.conns.insert(
            conn,
            Conn {
                phase: Phase::Attach {
                    deadline: now + HELLO_TICKS,
                },
                dec: FrameDecoder::new(MAX_HANDSHAKE),
                queue: VecDeque::new(),
                recent: VecDeque::new(),
            },
        );
        Vec::new()
    }

    /// Largest payload buffer currently reserved by any connection's decoder (bounded-memory checks).
    pub fn max_decoder_capacity(&self) -> usize {
        self.conns
            .values()
            .map(|c| c.dec.buffered_capacity())
            .max()
            .unwrap_or(0)
    }

    pub fn on_disconnect(&mut self, conn: ConnId) {
        self.conns.remove(&conn);
    }

    pub fn on_bytes(&mut self, conn: ConnId, bytes: &[u8], now: u64) -> Vec<Action> {
        let Some(c) = self.conns.get_mut(&conn) else {
            self.stats.post_close_bytes += 1;
            return Vec::new();
        };
        let frames = match c.dec.feed(bytes) {
            Ok(f) => f,
            Err(_) => return self.reject(conn, "bad_frame"),
        };
        let mut out = Vec::new();
        for payload in frames {
            if !self.conns.contains_key(&conn) {
                break; // an earlier frame in this read closed the connection
            }
            out.extend(self.on_frame(conn, &payload, now));
        }
        out
    }

    fn on_frame(&mut self, conn: ConnId, payload: &[u8], now: u64) -> Vec<Action> {
        let stage = match &self.conns[&conn].phase {
            Phase::Attach { .. } => 0,
            Phase::Hello { .. } => 1,
            Phase::Auth { .. } => 2,
            Phase::Ready { .. } => 3,
        };
        match stage {
            0 => self.on_attach(conn, payload, now),
            1 => self.on_hello(conn, payload, now),
            2 => self.on_auth(conn, payload, now),
            _ => self.on_envelope(conn, payload, now),
        }
    }

    fn on_attach(&mut self, conn: ConnId, payload: &[u8], now: u64) -> Vec<Action> {
        let Some(m) = handshake_object(payload, &["t", "origin"]) else {
            return self.reject(conn, "bad_frame");
        };
        let (Some("attach"), Some(origin)) = (m["t"].as_str(), m["origin"].as_str()) else {
            return self.reject(conn, "bad_frame");
        };
        if !self.allowed.iter().any(|a| a == origin) {
            return self.reject(conn, "bad_origin");
        }
        let origin = origin.to_string();
        self.conns.get_mut(&conn).expect("present").phase = Phase::Hello {
            origin,
            deadline: now + HELLO_TICKS,
        };
        Vec::new()
    }

    fn on_hello(&mut self, conn: ConnId, payload: &[u8], now: u64) -> Vec<Action> {
        let Some(m) = handshake_object(payload, &["t", "v", "cn"]) else {
            return self.reject(conn, "bad_frame");
        };
        let (Some("hello"), Some(versions), Some(cn_text)) =
            (m["t"].as_str(), m["v"].as_array(), m["cn"].as_str())
        else {
            return self.reject(conn, "bad_frame");
        };
        let Some(versions) = versions
            .iter()
            .map(|v| v.as_u64())
            .collect::<Option<Vec<u64>>>()
        else {
            return self.reject(conn, "bad_frame");
        };
        if !versions.contains(&1) {
            return self.reject(conn, "bad_version");
        }
        let Some(cn) = b64_decode(cn_text).as_deref().and_then(array16) else {
            return self.reject(conn, "bad_frame");
        };
        if self.seen_cn.contains(&cn) {
            return self.reject(conn, "replay");
        }
        self.seen_cn.push_back(cn);
        if self.seen_cn.len() > SEEN_CN {
            self.seen_cn.pop_front();
        }
        let mut sn = [0u8; 16];
        self.rng.fill_bytes(&mut sn);
        let c = self.conns.get_mut(&conn).expect("present");
        let Phase::Hello { origin, .. } =
            std::mem::replace(&mut c.phase, Phase::Attach { deadline: 0 })
        else {
            unreachable!("stage was checked")
        };
        let f = Fields {
            cn: &cn,
            sn: &sn,
            origin: origin.as_bytes(),
            core: &self.core_id,
        };
        let sm = mac(&self.secret, LABEL_SERVER, &f);
        c.phase = Phase::Auth {
            origin,
            cn,
            sn,
            deadline: now + AUTH_TICKS,
        };
        vec![send_json(
            conn,
            &json!({"t": "challenge", "v": 1, "sn": b64_encode(&sn), "core": b64_encode(&self.core_id), "sm": b64_encode(&sm)}),
        )]
    }

    fn on_auth(&mut self, conn: ConnId, payload: &[u8], now: u64) -> Vec<Action> {
        let Some(m) = handshake_object(payload, &["t", "cm"]) else {
            return self.reject(conn, "bad_frame");
        };
        let (Some("auth"), Some(cm_text)) = (m["t"].as_str(), m["cm"].as_str()) else {
            return self.reject(conn, "bad_frame");
        };
        let Some(cm) = b64_decode(cm_text) else {
            return self.reject(conn, "bad_frame");
        };
        let c = self.conns.get_mut(&conn).expect("present");
        let Phase::Auth { origin, cn, sn, .. } = &c.phase else {
            unreachable!("stage was checked")
        };
        let f = Fields {
            cn,
            sn,
            origin: origin.as_bytes(),
            core: &self.core_id,
        };
        if !verify(&self.secret, LABEL_CLIENT, &f, &cm) {
            return self.reject(conn, "bad_auth");
        }
        let mut raw = [0u8; 16];
        self.rng.fill_bytes(&mut raw);
        let sid: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let c = self.conns.get_mut(&conn).expect("present");
        c.phase = Phase::Ready {
            sid: sid.clone(),
            last: now,
        };
        c.dec.set_max(MAX_ENVELOPE);
        vec![send_json(conn, &json!({"t": "ready", "sid": sid}))]
    }

    fn on_envelope(&mut self, conn: ConnId, payload: &[u8], now: u64) -> Vec<Action> {
        let env = match Envelope::decode(payload) {
            Ok(e) => e,
            Err(e) => {
                let code = if e.kind == ErrorKind::BadVersion {
                    "bad_version"
                } else {
                    "bad_frame"
                };
                return self.reject(conn, code);
            }
        };
        let c = self.conns.get_mut(&conn).expect("present");
        let Phase::Ready { sid, last } = &mut c.phase else {
            unreachable!("stage was checked")
        };
        if env.session_id != *sid {
            return self.reject(conn, "bad_session");
        }
        *last = now;
        match &env.body {
            Message::Health(_) => {
                self.stats.answered_locally += 1;
                let info = HealthInfo {
                    core_instance: b64_encode(&self.core_id),
                    versions: vec![1],
                    engine: self.backend.engine_name(),
                };
                vec![send_env(conn, &reply_to(&env, Message::HealthReply(info)))]
            }
            Message::Prepare(_)
            | Message::BeginHandoff(_)
            | Message::Commit(_)
            | Message::Abort(_)
            | Message::Reconcile(_)
            | Message::Status(_)
            | Message::SettingsGet(_) => {
                if c.queue.len() >= MAX_INFLIGHT {
                    return vec![send_env(
                        conn,
                        &error_env(&env, ErrorKind::Overloaded, "too many requests in flight"),
                    )];
                }
                let hash: [u8; 32] =
                    Sha256::digest(serde_json::to_vec(&env.body).unwrap_or_default()).into();
                if let Some((_, seen)) = c.recent.iter().find(|(id, _)| *id == env.message_id) {
                    if *seen != hash {
                        return vec![send_env(
                            conn,
                            &error_env(&env, ErrorKind::PayloadMismatch, "message id reused"),
                        )];
                    }
                } else {
                    c.recent.push_back((env.message_id.clone(), hash));
                    if c.recent.len() > DUP_WINDOW {
                        c.recent.pop_front();
                    }
                }
                c.queue.push_back(env);
                Vec::new()
            }
            // reply-type messages are only ever produced by the core
            _ => vec![send_env(
                conn,
                &error_env(&env, ErrorKind::UnknownType, "not a request"),
            )],
        }
    }

    /// Runs queued requests through the backend, at most `budget` of them, fairly across connections.
    pub fn process(&mut self, now: u64, budget: usize) -> Vec<Action> {
        let mut out = Vec::new();
        let mut ids: Vec<ConnId> = self.conns.keys().copied().collect();
        ids.sort_unstable();
        let mut left = budget;
        'outer: while left > 0 {
            let mut progressed = false;
            for id in &ids {
                let Some(env) = self.conns.get_mut(id).and_then(|c| c.queue.pop_front()) else {
                    continue;
                };
                let reply = self.backend.handle(&env, now);
                self.stats.reached_backend += 1;
                out.push(send_env(*id, &reply));
                progressed = true;
                left -= 1;
                if left == 0 {
                    break 'outer;
                }
            }
            if !progressed {
                break;
            }
        }
        self.backend.pump();
        out
    }

    pub fn tick(&mut self, now: u64) -> Vec<Action> {
        let mut ids: Vec<ConnId> = self.conns.keys().copied().collect();
        ids.sort_unstable();
        let mut out = Vec::new();
        for id in ids {
            let expired = match &self.conns[&id].phase {
                Phase::Attach { deadline }
                | Phase::Hello { deadline, .. }
                | Phase::Auth { deadline, .. } => now > *deadline,
                Phase::Ready { last, .. } => now > last + IDLE_TICKS,
            };
            if expired {
                out.extend(self.reject(id, "timeout"));
            }
        }
        out
    }
}
