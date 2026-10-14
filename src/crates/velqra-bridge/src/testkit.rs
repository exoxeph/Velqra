// SPDX-License-Identifier: GPL-3.0-only
//! Helpers shared by the bridge tests, the fault harness and the runtime end-to-end tests.

use crate::backend::Backend;
use crate::frame::{encode_frame, FrameDecoder, MAX_TO_BROWSER};
use crate::handshake::*;
use crate::secret::InstallSecret;
use crate::server::{Action, BridgeServer, ConnId};
use serde_json::{json, Value};
use velqra_core::{Engine, EngineError, EngineRequest};
use velqra_protocol::*;

pub const ORIGIN: &str = "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/";
pub const SENTINEL: &str = "S3CR3T-SENTINEL";

pub struct NullEngine;

impl Engine for NullEngine {
    fn submit(&mut self, _r: &EngineRequest) -> Result<(), EngineError> {
        Ok(())
    }
    fn finished(&mut self, _a: &str) -> Option<bool> {
        Some(true)
    }
}

/// The fixed secret used by the golden vectors: bytes 0..31.
pub fn secret() -> InstallSecret {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = i as u8;
    }
    InstallSecret::from_bytes(b)
}

pub fn frame(payload: &[u8]) -> Vec<u8> {
    encode_frame(payload, MAX_TO_BROWSER).expect("test frame fits")
}

pub fn jframe(v: &Value) -> Vec<u8> {
    frame(v.to_string().as_bytes())
}

pub fn attach(origin: &str) -> Vec<u8> {
    jframe(&json!({"t": "attach", "origin": origin}))
}

pub fn hello(cn: &[u8]) -> Vec<u8> {
    jframe(&json!({"t": "hello", "v": [1], "cn": b64_encode(cn)}))
}

pub fn auth(mac: &[u8]) -> Vec<u8> {
    jframe(&json!({"t": "auth", "cm": b64_encode(mac)}))
}

/// The decoded payloads of every `Send` addressed to `conn`.
pub fn sent(actions: &[Action], conn: ConnId) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for a in actions {
        if let Action::Send(c, bytes) = a {
            if *c == conn {
                let mut d = FrameDecoder::new(MAX_TO_BROWSER);
                out.extend(d.feed(bytes).expect("server output is well framed"));
            }
        }
    }
    out
}

pub fn sent_json(actions: &[Action], conn: ConnId) -> Vec<Value> {
    sent(actions, conn)
        .iter()
        .map(|p| serde_json::from_slice(p).expect("server output is json"))
        .collect()
}

pub fn closed(actions: &[Action], conn: ConnId) -> bool {
    actions.contains(&Action::Close(conn))
}

pub fn reject_code(actions: &[Action], conn: ConnId) -> Option<String> {
    sent_json(actions, conn)
        .iter()
        .find(|v| v["t"] == "reject")
        .and_then(|v| v["code"].as_str().map(str::to_string))
}

pub fn envelope(sid: &str, message_id: &str, request_id: &str, body: Message) -> Envelope {
    Envelope {
        version: PROTOCOL_VERSION,
        message_id: message_id.into(),
        session_id: sid.into(),
        request_id: request_id.into(),
        generation: 1,
        body,
    }
}

pub fn envelope_frame(env: &Envelope) -> Vec<u8> {
    frame(&env.encode().expect("test envelope encodes"))
}

pub fn prepare_body() -> PrepareBody {
    PrepareBody {
        download_key: "d1".into(),
        url: "https://x.test/a.zip".into(),
        filename: "a.zip".into(),
        context: Secret(SENTINEL.into()),
    }
}

/// What an honest client learned during the handshake.
#[derive(Debug, Clone)]
pub struct Established {
    pub sid: String,
}

/// Runs the honest client side of the handshake, including the client's check of the server MAC.
/// Returns the session id, or the reject code (or a short reason) on failure.
pub fn handshake<B: Backend>(
    srv: &mut BridgeServer<B>,
    conn: ConnId,
    now: u64,
    secret: &InstallSecret,
    origin: &str,
    cn: [u8; 16],
) -> Result<Established, String> {
    let step = |a: &[Action]| reject_code(a, conn).map(Err).unwrap_or(Ok(()));
    step(&srv.on_connect(conn, now))?;
    step(&srv.on_bytes(conn, &attach(origin), now))?;
    let a = srv.on_bytes(conn, &hello(&cn), now);
    step(&a)?;
    let ch = sent_json(&a, conn)
        .into_iter()
        .next()
        .ok_or("no challenge")?;
    let sn = b64_decode(ch["sn"].as_str().ok_or("no sn")?).ok_or("bad sn")?;
    let core = b64_decode(ch["core"].as_str().ok_or("no core")?).ok_or("bad core")?;
    let sm = b64_decode(ch["sm"].as_str().ok_or("no sm")?).ok_or("bad sm")?;
    let f = Fields {
        cn: &cn,
        sn: &sn,
        origin: origin.as_bytes(),
        core: &core,
    };
    if !verify(secret, LABEL_SERVER, &f, &sm) {
        return Err("bad_server_mac".into());
    }
    let a = srv.on_bytes(conn, &auth(&mac(secret, LABEL_CLIENT, &f)), now);
    step(&a)?;
    let ready = sent_json(&a, conn)
        .into_iter()
        .find(|v| v["t"] == "ready")
        .ok_or("no ready")?;
    Ok(Established {
        sid: ready["sid"].as_str().ok_or("no sid")?.to_string(),
    })
}
