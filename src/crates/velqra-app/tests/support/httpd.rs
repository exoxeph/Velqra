// SPDX-License-Identifier: GPL-3.0-only
//! A small scriptable HTTP/1.1 server for tests: every response is decided by a closure that sees
//! the parsed request, so a test can lie in exactly the way a row of the conformance table needs
//! (ignore a Range, answer 416, change the bytes, cut the connection, redirect, serve HTML).
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug, Default)]
pub struct Req {
    pub method: String,
    pub path: String,
    pub range_start: Option<usize>,
    pub range_end: Option<usize>,
    pub if_range: Option<String>,
    /// How many requests this path has had before this one.
    pub nth: usize,
}

/// What to send back.
#[derive(Clone, Debug)]
pub struct Plan {
    pub status: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// 0 = full speed.
    pub bytes_per_second: usize,
    /// Close the connection after this many body bytes (a mid-transfer disconnect).
    pub cut_after: Option<usize>,
}

impl Plan {
    pub fn ok(body: Vec<u8>) -> Plan {
        Plan {
            status: "200 OK".into(),
            headers: Vec::new(),
            body,
            bytes_per_second: 0,
            cut_after: None,
        }
    }
    pub fn status(status: &str) -> Plan {
        Plan {
            status: status.into(),
            ..Plan::ok(Vec::new())
        }
    }
    pub fn header(mut self, k: &str, v: &str) -> Plan {
        self.headers.push((k.into(), v.into()));
        self
    }
    pub fn slow(mut self, bytes_per_second: usize) -> Plan {
        self.bytes_per_second = bytes_per_second;
        self
    }
    pub fn cut(mut self, after: usize) -> Plan {
        self.cut_after = Some(after);
        self
    }
}

/// A server that honours `Range: bytes=a-b` correctly (206 with a matching Content-Range).
pub fn ranged(body: &[u8], req: &Req, etag: Option<&str>) -> Plan {
    let len = body.len();
    let mut plan = match req.range_start {
        Some(start) if start < len => {
            let end = req.range_end.unwrap_or(len - 1).min(len - 1);
            let mut p = Plan::ok(body[start..=end].to_vec());
            p.status = "206 Partial Content".into();
            p.header("Content-Range", &format!("bytes {start}-{end}/{len}"))
        }
        Some(_) => Plan::status("416 Range Not Satisfiable")
            .header("Content-Range", &format!("bytes */{len}")),
        None => Plan::ok(body.to_vec()),
    };
    plan = plan.header("Accept-Ranges", "bytes");
    if let Some(e) = etag {
        plan = plan.header("ETag", e);
    }
    plan
}

pub struct Httpd {
    pub port: u16,
    pub log: Arc<Mutex<Vec<Req>>>,
    /// Body bytes actually written to clients.
    pub sent: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl Httpd {
    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }
    pub fn requests(&self) -> Vec<Req> {
        self.log.lock().unwrap().clone()
    }
}

impl Drop for Httpd {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

pub fn serve(handler: impl Fn(&Req) -> Plan + Send + Sync + 'static) -> Httpd {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log: Arc<Mutex<Vec<Req>>> = Arc::new(Mutex::new(Vec::new()));
    let sent = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let handler = Arc::new(handler);
    let (lg, sn, st) = (log.clone(), sent.clone(), stop.clone());
    thread::spawn(move || {
        for conn in listener.incoming() {
            if st.load(Ordering::Relaxed) {
                return;
            }
            let Ok(stream) = conn else { continue };
            let (handler, lg, sn, st) = (handler.clone(), lg.clone(), sn.clone(), st.clone());
            thread::spawn(move || handle(stream, &*handler, &lg, &sn, &st));
        }
    });
    Httpd {
        port,
        log,
        sent,
        stop,
    }
}

fn parse(head: &str) -> Req {
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let mut req = Req {
        method,
        path,
        ..Req::default()
    };
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("range: bytes=") {
            let mut ends = v.trim().splitn(2, '-');
            req.range_start = ends.next().and_then(|n| n.parse().ok());
            req.range_end = ends.next().and_then(|n| n.parse().ok());
        } else if let Some(v) = line.strip_prefix("If-Range: ") {
            req.if_range = Some(v.trim().to_string());
        }
    }
    req
}

fn handle(
    mut stream: TcpStream,
    handler: &(dyn Fn(&Req) -> Plan + Send + Sync),
    log: &Mutex<Vec<Req>>,
    sent: &AtomicU64,
    stop: &AtomicBool,
) {
    let mut head = Vec::new();
    let mut b = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut b) {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(&b[..n]),
        }
    }
    let mut req = parse(&String::from_utf8_lossy(&head));
    {
        let mut l = log.lock().unwrap();
        req.nth = l.iter().filter(|r| r.path == req.path).count();
        l.push(req.clone());
    }
    let plan = handler(&req);
    let mut out = format!("HTTP/1.1 {}\r\n", plan.status);
    for (k, v) in &plan.headers {
        out += &format!("{k}: {v}\r\n");
    }
    out += &format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        plan.body.len()
    );
    if stream.write_all(out.as_bytes()).is_err() || req.method == "HEAD" {
        return;
    }
    let chunk = if plan.bytes_per_second == 0 {
        64 * 1024
    } else {
        (plan.bytes_per_second / 10).max(1)
    };
    let mut written = 0usize;
    for piece in plan.body.chunks(chunk) {
        let piece = match plan.cut_after {
            Some(limit) if written + piece.len() > limit => &piece[..limit - written],
            _ => piece,
        };
        if stop.load(Ordering::Relaxed) || stream.write_all(piece).is_err() {
            return;
        }
        written += piece.len();
        sent.fetch_add(piece.len() as u64, Ordering::Relaxed);
        if plan.cut_after == Some(written) {
            return; // drop the connection with the body unfinished
        }
        if plan.bytes_per_second != 0 {
            thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Pseudo-random but reproducible content; `seed` makes different files.
pub fn payload(len: usize, seed: u64) -> Vec<u8> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15 ^ seed.wrapping_mul(0x2545_f491_4f6c_dd1d);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}
