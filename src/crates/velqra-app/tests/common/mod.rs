// SPDX-License-Identifier: GPL-3.0-only
//! Client-side helpers for the runtime tests: a transport abstraction (real named pipe, or a native
//! messaging host's stdio) and a client that performs the mutual handshake the way the extension does.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::time::{Duration, Instant};
use velqra_bridge::frame::{FrameDecoder, MAX_TO_BROWSER};
use velqra_bridge::handshake::*;
use velqra_bridge::secret::InstallSecret;
use velqra_bridge::testkit::{attach, auth, envelope, envelope_frame, hello};
use velqra_protocol::*;

pub trait Transport {
    fn send(&mut self, bytes: &[u8]);
    /// The payload of the next frame, or `None` on timeout or when the peer closed.
    fn recv(&mut self, timeout: Duration) -> Option<Vec<u8>>;
    fn is_closed(&self) -> bool;
}

pub struct PipeTransport {
    conn: velqra_ipc::Connection,
    dec: FrameDecoder,
    queue: VecDeque<Vec<u8>>,
    closed: bool,
}

impl PipeTransport {
    pub fn connect(name: &str) -> std::io::Result<Self> {
        Ok(Self {
            conn: velqra_ipc::connect(name, Duration::from_secs(5))?,
            dec: FrameDecoder::new(MAX_TO_BROWSER),
            queue: VecDeque::new(),
            closed: false,
        })
    }
}

impl Transport for PipeTransport {
    fn send(&mut self, bytes: &[u8]) {
        // a peer that already hung up is a normal outcome in the attack tests
        let _ = self.conn.write_all(bytes);
    }

    fn recv(&mut self, timeout: Duration) -> Option<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        let mut buf = vec![0u8; 65536];
        loop {
            if let Some(f) = self.queue.pop_front() {
                return Some(f);
            }
            if self.closed || Instant::now() >= deadline {
                return None;
            }
            match self.conn.read_timeout(&mut buf, Duration::from_millis(20)) {
                Ok(0) => self.closed = true,
                Ok(n) => match self.dec.feed(&buf[..n]) {
                    Ok(frames) => self.queue.extend(frames),
                    Err(_) => self.closed = true,
                },
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => self.closed = true,
            }
        }
    }

    fn is_closed(&self) -> bool {
        self.closed && self.queue.is_empty()
    }
}

pub struct Client<T: Transport> {
    pub t: T,
    pub sid: String,
}

impl<T: Transport> Client<T> {
    pub fn new(t: T) -> Self {
        Self {
            t,
            sid: String::new(),
        }
    }

    fn recv_json(&mut self, timeout: Duration) -> Result<serde_json::Value, String> {
        let p = self.t.recv(timeout).ok_or("no frame (timeout or closed)")?;
        serde_json::from_slice(&p).map_err(|_| "not json".to_string())
    }

    /// The extension's side of the handshake. `send_attach` is true when talking to the pipe directly;
    /// through the native host the host sends the attach frame itself.
    pub fn handshake(
        &mut self,
        secret: &InstallSecret,
        origin: &str,
        cn: [u8; 16],
        send_attach: bool,
    ) -> Result<(), String> {
        if send_attach {
            self.t.send(&attach(origin));
        }
        self.t.send(&hello(&cn));
        let ch = self.recv_json(Duration::from_secs(5))?;
        if ch["t"] == "reject" {
            return Err(format!("rejected: {}", ch["code"]));
        }
        let field = |k: &str| {
            ch[k]
                .as_str()
                .and_then(b64_decode)
                .ok_or(format!("bad {k}"))
        };
        let (sn, core, sm) = (field("sn")?, field("core")?, field("sm")?);
        let f = Fields {
            cn: &cn,
            sn: &sn,
            origin: origin.as_bytes(),
            core: &core,
        };
        if !verify(secret, LABEL_SERVER, &f, &sm) {
            return Err("the core could not prove it knows the secret".into());
        }
        self.t.send(&auth(&mac(secret, LABEL_CLIENT, &f)));
        let ready = self.recv_json(Duration::from_secs(5))?;
        if ready["t"] == "reject" {
            return Err(format!("rejected: {}", ready["code"]));
        }
        self.sid = ready["sid"].as_str().ok_or("no sid")?.to_string();
        Ok(())
    }

    /// Sends one request and waits for the reply that answers it.
    pub fn request(
        &mut self,
        id: &str,
        request_id: &str,
        body: Message,
    ) -> Result<Envelope, String> {
        self.t
            .send(&envelope_frame(&envelope(&self.sid, id, request_id, body)));
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let Some(p) = self.t.recv(Duration::from_millis(200)) else {
                if self.t.is_closed() {
                    return Err("connection closed".into());
                }
                continue;
            };
            if let Ok(e) = Envelope::decode(&p) {
                if e.message_id == format!("r-{id}") || e.message_id == format!("e-{id}") {
                    return Ok(e);
                }
            }
        }
        Err("timed out waiting for a reply".into())
    }
}

pub fn prepare_body() -> PrepareBody {
    velqra_bridge::testkit::prepare_body()
}

pub fn receipt_of(e: &Envelope) -> Receipt {
    match &e.body {
        Message::Prepared(r)
        | Message::Armed(r)
        | Message::Committed(r)
        | Message::StatusReply(r) => r.clone(),
        other => panic!("not a receipt: {other:?}"),
    }
}
