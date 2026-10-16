// SPDX-License-Identifier: GPL-3.0-only
//! A small, std-only HTTP/1.1 JSON-RPC client for the local aria2 process. Everything that comes
//! back is untrusted: sizes, time and shape are bounded, and an error never echoes remote text
//! (a remote message can contain a URL).

use serde_json::Value;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Replies larger than this are refused (aria2 status replies are a few KiB).
pub const MAX_REPLY_BYTES: usize = 256 * 1024;
const MAX_HEADER_BYTES: usize = 8 * 1024;

/// What kind of refusal aria2 gave, decided from its message, which is then dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteKind {
    /// No such task (`GID ... is not found`).
    NotFound,
    /// The token was not accepted.
    Unauthorized,
    Other,
}

pub(crate) fn classify(code: i64, message: &str, gid: Option<&str>) -> RemoteKind {
    // Measured against pinned 1.37.0; even a grammatically valid error for another GID is not absence.
    if code == 1
        && gid.is_some_and(|g| {
            g.len() == 16
                && g.bytes().all(|b| b.is_ascii_hexdigit())
                && message == format!("GID {g} is not found")
        })
    {
        RemoteKind::NotFound
    } else if message == "Unauthorized" {
        RemoteKind::Unauthorized
    } else {
        RemoteKind::Other
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcError {
    /// Could not connect, send or finish reading in time. The request may or may not have run.
    Transport(&'static str),
    /// A reply arrived but is not a valid, bounded JSON-RPC reply.
    BadReply(&'static str),
    /// aria2 answered with an error object; only its numeric code and a coarse class are kept.
    Remote { code: i64, kind: RemoteKind },
}

pub struct RpcClient {
    addr: SocketAddr,
    secret: String,
    timeout: Duration,
}

impl RpcClient {
    pub fn new(addr: SocketAddr, secret: String, timeout: Duration) -> Self {
        Self {
            addr,
            secret,
            timeout,
        }
    }

    pub fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, RpcError> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let deadline = Instant::now() + self.timeout;
        let id = format!("velqra-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed));
        let mut all = vec![Value::String(format!("token:{}", self.secret))];
        let expected_gid = if matches!(
            method,
            "aria2.tellStatus"
                | "aria2.pause"
                | "aria2.unpause"
                | "aria2.forceRemove"
                | "aria2.removeDownloadResult"
        ) {
            params.first().and_then(Value::as_str).map(str::to_owned)
        } else {
            None
        };
        all.extend(params);
        let body = serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": all})
            .to_string();
        let request = format!(
            "POST /jsonrpc HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.addr,
            body.len()
        );
        let mut stream = TcpStream::connect_timeout(&self.addr, left(deadline)?)
            .map_err(|_| RpcError::Transport("connect failed"))?;
        stream
            .set_write_timeout(Some(left(deadline)?))
            .map_err(|_| RpcError::Transport("socket setup failed"))?;
        stream
            .write_all(request.as_bytes())
            .map_err(|_| RpcError::Transport("send failed"))?;

        // headers: read until the blank line, never past the header cap
        let mut buf: Vec<u8> = Vec::new();
        let head_end = loop {
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break p + 4;
            }
            if buf.len() > MAX_HEADER_BYTES {
                return Err(RpcError::BadReply("headers too large"));
            }
            read_more(&mut stream, &mut buf, deadline)?;
        };
        if head_end > MAX_HEADER_BYTES {
            return Err(RpcError::BadReply("headers too large"));
        }
        let head = std::str::from_utf8(&buf[..head_end])
            .map_err(|_| RpcError::BadReply("bad headers"))?
            .to_string();
        let mut lines = head.split("\r\n");
        let status = lines.next().unwrap_or("");
        let code = status
            .strip_prefix("HTTP/1.1 ")
            .and_then(|r| r.get(..3))
            .ok_or(RpcError::BadReply("bad status line"))?;
        if code != "200" && code != "400" {
            return Err(RpcError::BadReply("unexpected status"));
        }
        let mut length: Option<usize> = None;
        for line in lines.filter(|l| !l.is_empty()) {
            let Some((name, value)) = line.split_once(':') else {
                return Err(RpcError::BadReply("bad header"));
            };
            match name.trim().to_ascii_lowercase().as_str() {
                "transfer-encoding" => return Err(RpcError::BadReply("chunked reply")),
                "content-length" => {
                    let n: usize = value
                        .trim()
                        .parse()
                        .map_err(|_| RpcError::BadReply("bad length"))?;
                    if length.replace(n).is_some() {
                        return Err(RpcError::BadReply("duplicate length"));
                    }
                }
                _ => {}
            }
        }

        // body: exactly Content-Length bytes, or until close when there is none; both capped
        let mut body_bytes = buf.split_off(head_end);
        match length {
            Some(n) if n > MAX_REPLY_BYTES => return Err(RpcError::BadReply("reply too large")),
            Some(n) => {
                while body_bytes.len() < n {
                    read_more(&mut stream, &mut body_bytes, deadline)?;
                }
                body_bytes.truncate(n);
            }
            None => loop {
                if body_bytes.len() > MAX_REPLY_BYTES {
                    return Err(RpcError::BadReply("reply too large"));
                }
                match read_more(&mut stream, &mut body_bytes, deadline) {
                    Ok(()) => {}
                    Err(RpcError::Transport("closed")) => break,
                    Err(e) => return Err(e),
                }
            },
        }
        if body_bytes.len() > MAX_REPLY_BYTES {
            return Err(RpcError::BadReply("reply too large"));
        }

        let reply = velqra_protocol::parse_strict_json(&body_bytes)
            .map_err(|_| RpcError::BadReply("not json"))?;
        if reply.get("jsonrpc") != Some(&Value::String("2.0".into()))
            || reply.get("id") != Some(&Value::String(id))
        {
            return Err(RpcError::BadReply("wrong envelope"));
        }
        match (reply.get("result"), reply.get("error")) {
            (Some(result), None) => {
                let valid = match method {
                    "aria2.pause" | "aria2.unpause" | "aria2.forceRemove" => expected_gid
                        .as_deref()
                        .is_some_and(|g| result.as_str() == Some(g)),
                    "aria2.removeDownloadResult" | "aria2.shutdown" | "aria2.forceShutdown" => {
                        result.as_str() == Some("OK")
                    }
                    "aria2.addUri" => result.as_str().is_some_and(|g| {
                        g.len() == 16
                            && g.bytes().all(|b| b.is_ascii_hexdigit())
                            && g != "0000000000000000"
                    }),
                    _ => true, // Other methods' typed callers validate their payloads.
                };
                if valid {
                    Ok(result.clone())
                } else {
                    Err(RpcError::BadReply("invalid method result"))
                }
            }
            (None, Some(err)) => match err.get("code").and_then(Value::as_i64) {
                Some(code) => {
                    let text = err.get("message").and_then(Value::as_str).unwrap_or("");
                    Err(RpcError::Remote {
                        code,
                        kind: classify(code, text, expected_gid.as_deref()),
                    })
                }
                None => Err(RpcError::BadReply("bad error object")),
            },
            _ => Err(RpcError::BadReply("result or error, not both")),
        }
    }
}

/// Time left before the overall deadline (the whole call is bounded, not each read).
fn left(deadline: Instant) -> Result<Duration, RpcError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(RpcError::Transport("timed out"))
}

/// One bounded read appended to `buf`; `Transport("closed")` on end of stream.
fn read_more(stream: &mut TcpStream, buf: &mut Vec<u8>, deadline: Instant) -> Result<(), RpcError> {
    stream
        .set_read_timeout(Some(left(deadline)?))
        .map_err(|_| RpcError::Transport("socket setup failed"))?;
    let mut chunk = [0u8; 4096];
    match stream.read(&mut chunk) {
        Ok(0) => Err(RpcError::Transport("closed")),
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(())
        }
        Err(_) => Err(RpcError::Transport("timed out")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Instant;

    const SECRET: &str = "S3CR3T-RPC-TOKEN-0123456789abcdef";

    /// What the fake server saw.
    type Seen = Arc<Mutex<Vec<String>>>;
    type Reply = Box<dyn FnOnce(&Value) -> Vec<u8> + Send>;

    /// Serves one connection per element of `replies`: reads the request, records it, then writes
    /// the scripted bytes (the closure gets the parsed request so the reply can echo its id).
    fn serve(replies: Vec<Reply>) -> (SocketAddr, Seen) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        thread::spawn(move || {
            for reply in replies {
                let Ok((mut s, _)) = listener.accept() else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let body_start = loop {
                    let n = s.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break None;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break Some(p + 4);
                    }
                };
                let Some(start) = body_start else { continue };
                let head = String::from_utf8_lossy(&buf[..start]).to_string();
                let len: usize = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse().unwrap_or(0))
                    })
                    .unwrap_or(0);
                while buf.len() < start + len {
                    let n = s.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let body = String::from_utf8_lossy(&buf[start..]).to_string();
                log.lock().unwrap().push(format!("{head}{body}"));
                let req: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                let _ = s.write_all(&reply(&req));
            }
        });
        (addr, seen)
    }

    fn http(status: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn ok_reply(req: &Value, result: Value) -> Vec<u8> {
        http(
            "200 OK",
            &json!({"jsonrpc":"2.0","id":req["id"],"result":result}).to_string(),
        )
    }

    fn client(addr: SocketAddr) -> RpcClient {
        RpcClient::new(addr, SECRET.into(), Duration::from_millis(800))
    }

    fn one(f: impl FnOnce(&Value) -> Vec<u8> + Send + 'static) -> Vec<Reply> {
        vec![Box::new(f)]
    }

    #[test]
    fn control_envelopes_require_exact_gid_or_uppercase_ok() {
        for method in [
            "aria2.pause",
            "aria2.unpause",
            "aria2.forceRemove",
            "aria2.removeDownloadResult",
            "aria2.shutdown",
            "aria2.forceShutdown",
        ] {
            for result in [
                json!(null),
                json!(1),
                json!({}),
                json!("ok"),
                json!("ffffffffffffffff"),
            ] {
                let (addr, _) = serve(one(move |r| ok_reply(r, result)));
                assert!(matches!(
                    client(addr).call(method, vec![json!("0123456789abcdef")]),
                    Err(RpcError::BadReply(_))
                ));
            }
            let want = if method.contains("Shutdown")
                || method.ends_with("shutdown")
                || method.ends_with("DownloadResult")
            {
                "OK"
            } else {
                "0123456789abcdef"
            };
            let (addr, _) = serve(one(move |r| ok_reply(r, json!(want))));
            assert_eq!(
                client(addr)
                    .call(method, vec![json!("0123456789abcdef")])
                    .unwrap(),
                json!(want)
            );
        }
    }

    #[test]
    fn unknown_gid_requires_measured_grammar_code_method_and_requested_identity() {
        let fixture: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/aria2-1.37.0-rpc.json"))
                .unwrap();
        for method in [
            "aria2.tellStatus",
            "aria2.pause",
            "aria2.unpause",
            "aria2.forceRemove",
            "aria2.removeDownloadResult",
        ] {
            let e = &fixture[method]["error"];
            assert_eq!(
                classify(
                    e["code"].as_i64().unwrap(),
                    e["message"].as_str().unwrap(),
                    Some("0123456789abcdef")
                ),
                RemoteKind::NotFound
            );
        }
        for (code, text, gid) in [
            (
                2,
                "GID 0123456789abcdef is not found",
                Some("0123456789abcdef"),
            ),
            (
                1,
                "GID 0123456789abcdef is not found",
                Some("ffffffffffffffff"),
            ),
            (
                1,
                "GID 0123456789abcdef is not found.",
                Some("0123456789abcdef"),
            ),
            (1, "file not found", Some("0123456789abcdef")),
            (1, "GID 0123456789abcdef is not found", None),
        ] {
            assert_eq!(classify(code, text, gid), RemoteKind::Other);
        }
        let (addr, _) = serve(one(|r| {
            http("400 Bad Request", &json!({"jsonrpc":"2.0","id":r["id"],"error":{"code":1,"message":"GID 0123456789abcdef is not found"}}).to_string())
        }));
        assert_eq!(
            client(addr).call("aria2.tellStatus", vec![json!("ffffffffffffffff")]),
            Err(RpcError::Remote {
                code: 1,
                kind: RemoteKind::Other
            })
        );
    }

    #[test]
    fn a_call_posts_json_rpc_with_the_secret_only_as_the_token_parameter() {
        let (addr, seen) = serve(one(|req| ok_reply(req, json!("0123456789abcdef"))));
        let out = client(addr)
            .call(
                "aria2.addUri",
                vec![json!(["https://x.test/a"]), json!({"dir": "d"})],
            )
            .unwrap();
        assert_eq!(out, json!("0123456789abcdef"));
        let raw = seen.lock().unwrap()[0].clone();
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("POST /jsonrpc HTTP/1.1"), "{head}");
        let lower = head.to_ascii_lowercase();
        assert!(lower.contains("content-type: application/json"), "{head}");
        assert!(lower.contains("connection: close"), "{head}");
        assert!(!head.contains(SECRET), "the secret leaked into the headers");
        let v: Value = serde_json::from_str(body).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["method"], "aria2.addUri");
        assert_eq!(v["params"][0], format!("token:{SECRET}"));
        assert_eq!(v["params"][1], json!(["https://x.test/a"]));
        assert_eq!(v["params"][2], json!({"dir": "d"}));
        assert_eq!(body.matches(SECRET).count(), 1);
    }

    #[test]
    fn an_error_object_keeps_only_its_code_and_never_the_remote_text() {
        let (addr, _) = serve(one(|req| {
            http(
                "400 Bad Request",
                &json!({"jsonrpc":"2.0","id":req["id"],"error":{"code":1,"message":"GET https://secret.example/t=1 failed"}}).to_string(),
            )
        }));
        let err = client(addr).call("aria2.tellStatus", vec![]).unwrap_err();
        assert_eq!(
            err,
            RpcError::Remote {
                code: 1,
                kind: RemoteKind::Other
            }
        );
        assert!(!format!("{err:?}").contains("secret.example"));
    }

    fn bad(reply: impl FnOnce(&Value) -> Vec<u8> + Send + 'static) -> RpcError {
        let (addr, _) = serve(one(reply));
        client(addr).call("m", vec![]).unwrap_err()
    }

    #[test]
    fn remote_errors_are_classified_from_the_message_which_is_then_dropped() {
        let kinds = [
            ("GID 1234567890abcdef is not found", RemoteKind::NotFound),
            ("Unauthorized", RemoteKind::Unauthorized),
            ("UNAUTHORIZED access", RemoteKind::Other),
            ("Failed to parse URI", RemoteKind::Other),
            ("", RemoteKind::Other),
        ];
        for (text, want) in kinds {
            let text = text.to_string();
            let (addr, _) = serve(one(move |r| {
                http(
                    "400 Bad Request",
                    &json!({"jsonrpc":"2.0","id":r["id"],"error":{"code":1,"message":text}})
                        .to_string(),
                )
            }));
            let err = client(addr)
                .call("aria2.tellStatus", vec![json!("1234567890abcdef")])
                .unwrap_err();
            assert_eq!(
                err,
                RpcError::Remote {
                    code: 1,
                    kind: want
                }
            );
        }
    }

    #[test]
    fn malformed_or_mismatched_replies_are_refused() {
        let cases: Vec<(&str, Reply)> = vec![
            ("not json", Box::new(|_| http("200 OK", "<html>"))),
            (
                "wrong id",
                Box::new(|_| http("200 OK", r#"{"jsonrpc":"2.0","id":"other","result":1}"#)),
            ),
            (
                "wrong version",
                Box::new(|r| {
                    http(
                        "200 OK",
                        &json!({"jsonrpc":"1.0","id":r["id"],"result":1}).to_string(),
                    )
                }),
            ),
            (
                "both result and error",
                Box::new(|r| {
                    http(
                        "200 OK",
                        &json!({"jsonrpc":"2.0","id":r["id"],"result":1,"error":{"code":1,"message":"m"}})
                            .to_string(),
                    )
                }),
            ),
            (
                "neither",
                Box::new(|r| http("200 OK", &json!({"jsonrpc":"2.0","id":r["id"]}).to_string())),
            ),
            (
                "error without a numeric code",
                Box::new(|r| {
                    http(
                        "400 Bad Request",
                        &json!({"jsonrpc":"2.0","id":r["id"],"error":{"code":"x","message":"m"}})
                            .to_string(),
                    )
                }),
            ),
            (
                "duplicate keys",
                Box::new(|r| {
                    http(
                        "200 OK",
                        &format!(
                            r#"{{"jsonrpc":"2.0","id":{},"result":1,"result":2}}"#,
                            r["id"]
                        ),
                    )
                }),
            ),
            ("redirect", Box::new(|_| http("302 Found", "{}"))),
            (
                "server error",
                Box::new(|_| http("500 Internal Server Error", "{}")),
            ),
            (
                "chunked",
                Box::new(|_| {
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"
                        .to_vec()
                }),
            ),
            (
                "garbage status",
                Box::new(|_| b"SPDY/9 200\r\n\r\n".to_vec()),
            ),
            (
                "no headers end",
                Box::new(|_| b"HTTP/1.1 200 OK\r\n".to_vec()),
            ),
        ];
        for (name, reply) in cases {
            let err = bad(reply);
            assert!(
                matches!(err, RpcError::BadReply(_) | RpcError::Transport(_)),
                "{name}: {err:?}"
            );
        }
    }

    #[test]
    fn oversized_replies_and_header_floods_are_refused_without_buffering_them() {
        // a Content-Length far beyond the cap is refused from the header alone
        let huge = bad(|_| b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n{".to_vec());
        assert_eq!(huge, RpcError::BadReply("reply too large"));
        // a body without a length that never ends stops at the cap
        let (addr, _) = serve(one(|_| {
            let mut v = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
            v.extend(vec![b' '; MAX_REPLY_BYTES + 4096]);
            v
        }));
        assert_eq!(
            client(addr).call("m", vec![]).unwrap_err(),
            RpcError::BadReply("reply too large")
        );
        // header section without an end, longer than the header cap
        let flood = bad(|_| {
            let mut v = b"HTTP/1.1 200 OK\r\n".to_vec();
            v.extend(b"X-Pad: a\r\n".repeat(2000));
            v
        });
        assert_eq!(flood, RpcError::BadReply("headers too large"));
    }

    #[test]
    fn unreachable_silent_and_dribbling_servers_end_at_the_deadline() {
        // nothing listens
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        assert!(matches!(
            client(addr).call("m", vec![]),
            Err(RpcError::Transport(_))
        ));
        // accepts and says nothing
        let silent = TcpListener::bind("127.0.0.1:0").unwrap();
        let saddr = silent.local_addr().unwrap();
        let held = thread::spawn(move || {
            let (s, _) = silent.accept().unwrap();
            thread::sleep(Duration::from_millis(2500));
            drop(s);
        });
        let t = Instant::now();
        assert!(matches!(
            client(saddr).call("m", vec![]),
            Err(RpcError::Transport(_))
        ));
        assert!(
            t.elapsed() < Duration::from_millis(1800),
            "{:?}",
            t.elapsed()
        );
        held.join().unwrap();
        // a byte at a time, forever: the total time is bounded, not each read
        let drip = TcpListener::bind("127.0.0.1:0").unwrap();
        let daddr = drip.local_addr().unwrap();
        let dripper = thread::spawn(move || {
            let (mut s, _) = drip.accept().unwrap();
            let mut sink = [0u8; 4096];
            let _ = s.set_read_timeout(Some(Duration::from_millis(50)));
            let _ = s.read(&mut sink);
            for b in
                b"HTTP/1.1 200 OK\r\nX-Slow: yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"
                    .iter()
            {
                if s.write_all(&[*b]).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
        });
        let t = Instant::now();
        assert!(client(daddr).call("m", vec![]).is_err());
        assert!(
            t.elapsed() < Duration::from_millis(2000),
            "{:?}",
            t.elapsed()
        );
        let _ = dripper.join();
    }

    #[test]
    fn a_connection_closed_in_the_middle_of_the_body_is_a_failure_not_a_partial_result() {
        let err = bad(|_| b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n{\"jsonrpc\":".to_vec());
        assert!(
            matches!(err, RpcError::Transport(_) | RpcError::BadReply(_)),
            "{err:?}"
        );
    }

    /// A body that would be a perfectly good reply, so only the framing can be what is wrong.
    fn good_body(req: &Value) -> String {
        json!({"jsonrpc":"2.0","id":req["id"],"result":"ok"}).to_string()
    }

    #[test]
    fn framing_faults_are_refused_even_when_the_body_looks_valid() {
        // chunked together with a length: ambiguous framing
        let chunked = bad(|r| {
            let b = good_body(r);
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: {}\r\n\r\n{b}",
                b.len()
            )
            .into_bytes()
        });
        assert_eq!(chunked, RpcError::BadReply("chunked reply"));
        // a wrong status with a valid body
        for status in ["500 Internal Server Error", "302 Found", "404 Not Found"] {
            let err = bad(move |r| http(status, &good_body(r)));
            assert_eq!(err, RpcError::BadReply("unexpected status"), "{status}");
        }
        // two lengths
        let two = bad(|r| {
            let b = good_body(r);
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {n}\r\nContent-Length: {n}\r\n\r\n{b}",
                n = b.len()
            )
            .into_bytes()
        });
        assert_eq!(two, RpcError::BadReply("duplicate length"));
        // the connection ends before the declared length, though what arrived is a whole reply
        let short = bad(|r| {
            let b = good_body(r);
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{b}",
                b.len() + 100
            )
            .into_bytes()
        });
        assert!(matches!(short, RpcError::Transport(_)), "{short:?}");
    }

    #[test]
    fn a_reply_without_a_length_that_never_ends_is_cut_off_at_the_cap() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let sent = Arc::new(Mutex::new(0usize));
        let counter = sent.clone();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut sink = [0u8; 4096];
            let _ = s.read(&mut sink);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
            let chunk = vec![b' '; 64 * 1024];
            for _ in 0..128 {
                // 8 MiB on offer
                if s.write_all(&chunk).is_err() {
                    break;
                }
                *counter.lock().unwrap() += chunk.len();
            }
        });
        let err = client(addr).call("m", vec![]).unwrap_err();
        server.join().unwrap();
        assert_eq!(err, RpcError::BadReply("reply too large"));
        let sent = *sent.lock().unwrap();
        assert!(
            sent < 4 * 1024 * 1024,
            "the client kept reading: {sent} bytes were taken"
        );
    }

    #[test]
    fn deep_nesting_huge_numbers_and_odd_content_types_never_panic_or_succeed_wrongly() {
        // nesting far beyond what a real reply has
        let deep = bad(|r| {
            let nest = format!("{}1{}", "[".repeat(500), "]".repeat(500));
            http(
                "200 OK",
                &format!(r#"{{"jsonrpc":"2.0","id":{},"result":{nest}}}"#, r["id"]),
            )
        });
        assert!(matches!(deep, RpcError::BadReply(_)), "{deep:?}");
        // a number with thousands of digits is read without trouble and is just a number
        let (addr, _) = serve(one(|r| {
            let digits = "9".repeat(5000);
            http(
                "200 OK",
                &format!(r#"{{"jsonrpc":"2.0","id":{},"result":{digits}}}"#, r["id"]),
            )
        }));
        let got = client(addr).call("m", vec![]);
        assert!(
            got.is_ok() || matches!(got, Err(RpcError::BadReply(_))),
            "{got:?}"
        );
        // a plain-text or HTML content type with a valid body is judged by the body, as before
        let (addr, _) = serve(one(|r| {
            let body = json!({"jsonrpc":"2.0","id":r["id"],"result":"ok"}).to_string();
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .into_bytes()
        }));
        assert_eq!(client(addr).call("m", vec![]).unwrap(), json!("ok"));
        // a body made of control bytes is refused, not interpreted
        let junk = bad(|_| http("200 OK", &"\u{1}".repeat(300)));
        assert!(matches!(junk, RpcError::BadReply(_)), "{junk:?}");
    }

    #[test]
    fn consecutive_calls_use_different_ids() {
        let ids: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
        let (a, b) = (ids.clone(), ids.clone());
        let (addr, _) = serve(vec![
            Box::new(move |r| {
                a.lock().unwrap().push(r["id"].clone());
                ok_reply(r, json!(1))
            }),
            Box::new(move |r| {
                b.lock().unwrap().push(r["id"].clone());
                ok_reply(r, json!(2))
            }),
        ]);
        let c = client(addr);
        c.call("m", vec![]).unwrap();
        c.call("m", vec![]).unwrap();
        let ids = ids.lock().unwrap();
        assert_ne!(ids[0], ids[1]);
    }
}
