// SPDX-License-Identifier: GPL-3.0-only
//! The core's `Engine` on top of aria2's JSON-RPC. The task's identity inside aria2 is a `gid`
//! derived from the core's attempt id, so a repeated submit finds the same task instead of making a
//! second one, and a restarted core or aria2 can ask about a task knowing only its attempt id.

use super::rpc::{RemoteKind, RpcClient, RpcError};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use velqra_core::{Engine, EngineError, EngineRequest, EngineStatus, Poll};
use velqra_protocol::download_url::parse_download_url;

/// Anything that can make one JSON-RPC call; the real client or a scripted fake.
pub trait Rpc {
    #[cfg(test)]
    fn observe_accepted_options(&self, _gid: &str) {}
    fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, RpcError>;
}

impl Rpc for RpcClient {
    #[cfg(test)]
    fn observe_accepted_options(&self, gid: &str) {
        if let Ok(options) = self.call("aria2.getOption", vec![json!(gid)]) {
            SENT_OPTIONS.lock().unwrap().push(options);
        }
    }
    fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, RpcError> {
        RpcClient::call(self, method, params)
    }
}

/// Limits from the core's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aria2Config {
    /// Segments per download.
    pub split: u32,
    /// Connections to one server per download.
    pub per_origin: u32,
}

impl Default for Aria2Config {
    fn default() -> Self {
        Self {
            split: 1,
            per_origin: 1,
        }
    }
}

/// aria2 wants exactly 16 hex digits. Derived from the attempt id, so it is stable and the same
/// attempt always names the same task.
pub fn gid_for(attempt: &str) -> String {
    let digest = Sha256::digest(format!("velqra-gid-v1:{attempt}").as_bytes());
    let mut gid: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    if gid.bytes().all(|b| b == b'0') {
        gid = "0000000000000001".into(); // aria2 reads all zeros as "no gid"
    }
    gid
}

const MAX_HEADER_VALUE: usize = 2048;

fn header_safe(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_HEADER_VALUE && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// The two request headers a page context may add. Anything odd is dropped, not repaired, and a
/// context that is not our JSON shape simply adds nothing.
fn context_headers(context: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(Value::Object(o)) = context.and_then(|c| serde_json::from_str::<Value>(c).ok()) else {
        return (None, None);
    };
    let referer = o
        .get("referer")
        .and_then(Value::as_str)
        .filter(|r| header_safe(r) && parse_download_url(r).is_ok())
        .map(str::to_string);
    let agent = o
        .get("user_agent")
        .and_then(Value::as_str)
        .filter(|a| header_safe(a))
        .map(str::to_string);
    (referer, agent)
}

/// The `aria2.addUri` parameters, or `None` when the request must not be sent at all.
fn add_uri_params(req: &EngineRequest, cfg: &Aria2Config) -> Option<Vec<Value>> {
    let url = parse_download_url(&req.url).ok()?;
    let dest = Path::new(req.destination.as_deref()?);
    if !dest.is_absolute() {
        return None;
    }
    let dir = dest.parent()?.to_str()?;
    let out = dest.file_name()?.to_str()?;
    let mut o = Map::new();
    o.insert("gid".into(), json!(gid_for(&req.attempt)));
    o.insert("dir".into(), json!(dir));
    o.insert("out".into(), json!(out));
    // `continue=true` would adopt ANY existing file as a partial download and append to it. Our own
    // resumes use aria2's control file instead, which needs no such flag.
    o.insert("continue".into(), json!("false"));
    // aria2 only splits a file into segments above twice this size (its default is 20 MiB)
    o.insert("min-split-size".into(), json!("4M"));
    // aria2 retries by resuming with a Range request and cannot tell that the bytes changed in
    // between, so a dropped connection ends the attempt; the core restarts it from zero instead
    o.insert("max-tries".into(), json!("1"));
    o.insert("split".into(), json!(cfg.split.to_string()));
    o.insert(
        "max-connection-per-server".into(),
        json!(cfg.per_origin.to_string()),
    );
    // never silently pick another name or replace a file, and always verify certificates
    o.insert("allow-overwrite".into(), json!("false"));
    o.insert("auto-file-renaming".into(), json!("false"));
    o.insert("check-certificate".into(), json!("true"));
    let (referer, agent) = context_headers(req.context.as_deref());
    if let Some(r) = referer {
        o.insert("referer".into(), json!(r));
    }
    if let Some(a) = agent {
        o.insert("user-agent".into(), json!(a));
    }
    Some(vec![json!([url.canonical()]), Value::Object(o)])
}

pub struct Aria2Engine<R: Rpc> {
    rpc: R,
    cfg: Aria2Config,
}

impl<R: Rpc> Aria2Engine<R> {
    pub fn new(rpc: R, cfg: Aria2Config) -> Self {
        Self { rpc, cfg }
    }

    fn tell_status(&self, attempt: &str) -> Result<Value, RpcError> {
        let value = self.rpc.call(
            "aria2.tellStatus",
            vec![
                json!(gid_for(attempt)),
                json!([
                    "gid",
                    "status",
                    "completedLength",
                    "totalLength",
                    "errorCode",
                    "errorMessage"
                ]),
            ],
        )?;
        validate_status(&value, &gid_for(attempt))?;
        Ok(value)
    }

    fn control(&self, method: &str, attempt: &str) -> Result<(), EngineError> {
        match self.rpc.call(method, vec![json!(gid_for(attempt))]) {
            Ok(Value::String(got)) if got == gid_for(attempt) => Ok(()),
            Ok(_) => Err(EngineError::ReplyLost),
            // a task that is already gone has nothing left to pause, resume or remove
            Err(RpcError::Remote {
                kind: RemoteKind::NotFound,
                ..
            }) => Ok(()),
            Err(_) => Err(EngineError::ReplyLost),
        }
    }
}

fn number(v: &Value, key: &str) -> Option<u64> {
    let s = v.get(key)?.as_str()?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn validate_status(v: &Value, gid: &str) -> Result<(), RpcError> {
    let bad = RpcError::BadReply("invalid task result");
    if v.get("gid").and_then(Value::as_str) != Some(gid)
        || number(v, "completedLength").is_none()
        || number(v, "totalLength").is_none()
        || !matches!(
            v.get("status").and_then(Value::as_str),
            Some("active" | "waiting" | "paused" | "complete" | "error" | "removed")
        )
        || (v.get("errorCode").is_some() && number(v, "errorCode").is_none())
        || (v.get("errorMessage").is_some() && v["errorMessage"].as_str().is_none())
        || (v["status"] == "error"
            && (number(v, "errorCode").is_none() || v["errorMessage"].as_str().is_none()))
    {
        return Err(bad);
    }
    Ok(())
}

/// True when an errored aria2 task stopped for a reason that may pass. aria2's error codes: 2 time
/// out, 5 too slow, 6 network problem, 19 name resolution failed, 29 server overloaded; code 22 is
/// "unexpected HTTP status": ONLY 408/429/500/502/503/504 are retried. No other 5xx is included.
/// Measured transient codes are 1 (refused/drop), 22 (408/429/500) and 29 (502/503/504).
/// Codes 2/5/6/19 remain policy mappings, not pinned-build measurements. Raw text is dropped.
fn error_is_transient(v: &Value) -> bool {
    let code = v.get("errorCode").and_then(Value::as_str).unwrap_or("");
    match code {
        "2" | "5" | "6" | "19" | "29" => true,
        // code 1 is "unknown error"; the pinned aria2 uses it for a refused connection and for a
        // download whose only source failed after the allowed tries (a dropped connection)
        "1" => {
            let message = v.get("errorMessage").and_then(Value::as_str).unwrap_or("");
            message.starts_with("Network problem") || message.trim_end() == "No URI available."
        }
        "22" => {
            let message = v.get("errorMessage").and_then(Value::as_str).unwrap_or("");
            let status = message
                .rsplit_once("status=")
                .and_then(|(_, tail)| tail.parse::<u16>().ok());
            matches!(status, Some(408 | 429 | 500 | 502 | 503 | 504))
        }
        _ => false,
    }
}

#[cfg(test)]
pub(crate) static SENT_OPTIONS: std::sync::Mutex<Vec<Value>> = std::sync::Mutex::new(Vec::new());

impl<R: Rpc> Engine for Aria2Engine<R> {
    fn submit(&mut self, req: &EngineRequest) -> Result<(), EngineError> {
        let Some(params) = add_uri_params(req, &self.cfg) else {
            return Err(EngineError::Rejected);
        };
        let gid = gid_for(&req.attempt);
        match self.rpc.call("aria2.addUri", params) {
            Ok(Value::String(got)) if got == gid => {
                #[cfg(test)]
                self.rpc.observe_accepted_options(&gid);
                Ok(())
            }
            Ok(_) => Err(EngineError::ReplyLost),
            Err(RpcError::Remote { .. }) => {
                // "already exists" is success: the same attempt id means the same task
                match self.tell_status(&req.attempt) {
                    Ok(_) => Ok(()),
                    Err(RpcError::Remote {
                        kind: RemoteKind::NotFound,
                        ..
                    }) => Err(EngineError::Rejected),
                    Err(_) => Err(EngineError::ReplyLost),
                }
            }
            Err(_) => Err(EngineError::ReplyLost),
        }
    }

    fn finished(&mut self, attempt: &str) -> Option<bool> {
        match self.status(attempt) {
            Ok(EngineStatus::Done) => Some(true),
            Ok(EngineStatus::Failed(_)) => Some(false),
            _ => None,
        }
    }

    fn status(&mut self, attempt: &str) -> Result<EngineStatus, EngineError> {
        match self.tell_status(attempt) {
            Ok(v) => match v.get("status").and_then(Value::as_str) {
                Some("active" | "waiting") => Ok(EngineStatus::Active {
                    done: number(&v, "completedLength").ok_or(EngineError::ReplyLost)?,
                    total: number(&v, "totalLength").ok_or(EngineError::ReplyLost)?,
                }),
                Some("paused") => Ok(EngineStatus::Paused),
                Some("complete") => Ok(EngineStatus::Done),
                Some("error") if error_is_transient(&v) => Ok(EngineStatus::Interrupted),
                // aria2's own error text can name a URL; the core only ever sees a fixed phrase
                Some("error" | "removed") => Ok(EngineStatus::Failed("transfer failed".into())),
                _ => Err(EngineError::ReplyLost),
            },
            Err(RpcError::Remote {
                kind: RemoteKind::NotFound,
                ..
            }) => Ok(EngineStatus::Unknown),
            // transport trouble or a refused token says nothing about whether the task exists
            Err(_) => Err(EngineError::ReplyLost),
        }
    }

    fn has_forgotten(&mut self, attempt: &str) -> bool {
        matches!(self.status(attempt), Ok(EngineStatus::Unknown))
    }

    /// One tellStatus call answers everything the core wants to know about a running task.
    fn poll(&mut self, attempt: &str) -> Poll {
        match self.status(attempt) {
            Ok(EngineStatus::Active { .. } | EngineStatus::Paused) => Poll::Running,
            Ok(EngineStatus::Done) => Poll::Done,
            Ok(EngineStatus::Failed(_)) => Poll::Failed,
            Ok(EngineStatus::Interrupted) => Poll::Interrupted,
            Ok(EngineStatus::Unknown) => Poll::Forgotten,
            Err(_) => Poll::Unreachable,
        }
    }

    fn pause(&mut self, attempt: &str) -> Result<(), EngineError> {
        self.control("aria2.pause", attempt)
    }

    fn resume(&mut self, attempt: &str) -> Result<(), EngineError> {
        self.control("aria2.unpause", attempt)
    }

    fn cancel(&mut self, attempt: &str) -> Result<(), EngineError> {
        self.control("aria2.forceRemove", attempt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::{HashSet, VecDeque};

    type Call = (String, Vec<Value>);

    /// Records every call and answers from a script (an empty script answers with a transport error).
    #[derive(Default)]
    struct Fake {
        calls: RefCell<Vec<Call>>,
        replies: RefCell<VecDeque<Result<Value, RpcError>>>,
    }

    impl Fake {
        fn with(replies: Vec<Result<Value, RpcError>>) -> Self {
            Self {
                calls: RefCell::default(),
                replies: RefCell::new(replies.into()),
            }
        }
        fn methods(&self) -> Vec<String> {
            self.calls.borrow().iter().map(|c| c.0.clone()).collect()
        }
    }

    impl Rpc for &Fake {
        fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, RpcError> {
            self.calls.borrow_mut().push((method.into(), params));
            self.replies
                .borrow_mut()
                .pop_front()
                .unwrap_or(Err(RpcError::Transport("script ended")))
        }
    }

    const NOT_FOUND: RpcError = RpcError::Remote {
        code: 1,
        kind: RemoteKind::NotFound,
    };
    const REFUSED: RpcError = RpcError::Remote {
        code: 1,
        kind: RemoteKind::Unauthorized,
    };
    const OTHER: RpcError = RpcError::Remote {
        code: 1,
        kind: RemoteKind::Other,
    };

    fn request() -> EngineRequest {
        EngineRequest {
            attempt: "t1-g1".into(),
            url: "https://Files.Example.com/a.zip?sig=1#frag".into(),
            filename: "a.zip".into(),
            context_ref: None,
            destination: Some(r"C:\dl\Compressed\a.zip".into()),
            context: Some(
                r#"{"referer":"https://example.com/page","user_agent":"Mozilla/5.0 X"}"#.into(),
            ),
        }
    }

    fn engine(fake: &Fake) -> Aria2Engine<&Fake> {
        Aria2Engine::new(fake, Aria2Config::default())
    }

    #[test]
    fn pinned_build_http_error_fixtures_match_the_exact_retry_policy() {
        let rows: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/aria2-1.37.0-http-errors.json"
        ))
        .unwrap();
        for row in rows.as_array().unwrap() {
            let v = &row["reply"]["result"];
            assert_eq!(
                error_is_transient(v),
                matches!(
                    row["http_status"].as_u64(),
                    Some(408 | 429 | 500 | 502 | 503 | 504)
                )
            );
        }
    }

    #[test]
    fn malformed_numbers_and_duplicate_status_identity_are_never_adopted() {
        for key in ["completedLength", "totalLength", "errorCode"] {
            for bad in [
                json!(null),
                json!([]),
                json!({}),
                json!(true),
                json!(22),
                json!(""),
                json!("-1"),
                json!("+1"),
                json!(" 1"),
                json!("1.0"),
                json!("18446744073709551616"),
            ] {
                let mut v = status_fixture(json!({"status":"error"}));
                v[key] = bad;
                let fake = Fake::with(vec![Ok(v)]);
                assert_eq!(
                    engine(&fake).status("t1-g1"),
                    Err(EngineError::ReplyLost),
                    "{key}"
                );
            }
        }
        let fake = Fake::with(vec![Err(OTHER), Ok(json!({"status":"active"}))]);
        assert_eq!(
            engine(&fake).submit(&request()),
            Err(EngineError::ReplyLost)
        );
    }

    #[test]
    fn hostile_result_shapes_are_ambiguity_never_success_or_zero() {
        for v in [
            json!(null),
            json!(true),
            json!("OK"),
            json!("ffffffffffffffff"),
        ] {
            let fake = Fake::with(vec![Ok(v.clone())]);
            assert_eq!(
                engine(&fake).submit(&request()),
                Err(EngineError::ReplyLost)
            );
            let fake = Fake::with(vec![Ok(v)]);
            assert_eq!(engine(&fake).pause("t1-g1"), Err(EngineError::ReplyLost));
        }
        for v in [
            json!({"status":"active"}),
            json!({"gid":gid_for("t1-g1"),"status":"active","completedLength":"bad","totalLength":"1"}),
            json!({"gid":"ffffffffffffffff","status":"complete","completedLength":"1","totalLength":"1"}),
        ] {
            let fake = Fake::with(vec![Ok(v)]);
            assert_eq!(engine(&fake).status("t1-g1"), Err(EngineError::ReplyLost));
        }
    }

    #[test]
    fn the_gid_is_sixteen_hex_digits_stable_and_collision_free() {
        let g = gid_for("t1-g1");
        assert_eq!(g.len(), 16);
        assert!(g
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_eq!(g, gid_for("t1-g1"));
        assert_ne!(g, gid_for("t1-g2"));
        assert_ne!(g, gid_for("t2-g1"));
        let all: HashSet<String> = (0..100_000u32)
            .map(|i| gid_for(&format!("t{}-g{}", i / 7, i % 7)))
            .collect();
        assert_eq!(all.len(), 100_000);
    }

    #[test]
    fn add_uri_carries_exactly_the_planned_options() {
        let fake = Fake::with(vec![Ok(json!(gid_for("t1-g1")))]);
        engine(&fake).submit(&request()).unwrap();
        let calls = fake.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "aria2.addUri");
        assert_eq!(
            calls[0].1[0],
            json!(["https://files.example.com/a.zip?sig=1"])
        );
        assert_eq!(
            calls[0].1[1],
            json!({
                "gid": gid_for("t1-g1"),
                "dir": r"C:\dl\Compressed",
                "out": "a.zip",
                "continue": "false",
                "min-split-size": "4M",
                "split": "1",
                "max-connection-per-server": "1",
                "max-tries": "1",
                "allow-overwrite": "false",
                "auto-file-renaming": "false",
                "check-certificate": "true",
                "referer": "https://example.com/page",
                "user-agent": "Mozilla/5.0 X"
            })
        );
    }

    #[test]
    fn limits_come_from_the_config() {
        let fake = Fake::with(vec![Ok(json!(gid_for("t1-g1")))]);
        let mut e = Aria2Engine::new(
            &fake,
            Aria2Config {
                split: 8,
                per_origin: 2,
            },
        );
        e.submit(&request()).unwrap();
        let o = fake.calls.borrow()[0].1[1].clone();
        assert_eq!(o["split"], json!("8"));
        assert_eq!(o["max-connection-per-server"], json!("2"));
    }

    #[test]
    fn unsafe_context_headers_are_dropped_and_never_break_the_request() {
        let bad = [
            r#"{"referer":"https://example.com/a\r\nX-Evil: 1","user_agent":"ok"}"#,
            r#"{"referer":"javascript:alert(1)","user_agent":"bad\u0007agent"}"#,
            r#"{"referer":"ftp://example.com/","user_agent":""}"#,
            "not json at all",
            r#"["referer"]"#,
            r#"{"referer":5,"user_agent":null}"#,
        ];
        for ctx in bad {
            let fake = Fake::with(vec![Ok(json!(gid_for("t1-g1")))]);
            let mut r = request();
            r.context = Some(ctx.into());
            engine(&fake).submit(&r).unwrap();
            let o = fake.calls.borrow()[0].1[1].clone();
            assert!(o.get("referer").is_none(), "{ctx}: {o}");
            assert!(
                o.get("user-agent").is_none() || o["user-agent"] == "ok",
                "{ctx}: {o}"
            );
            assert!(!o.to_string().contains("X-Evil"), "{ctx}");
        }
        let fake = Fake::with(vec![Ok(json!(gid_for("t1-g1")))]);
        let mut r = request();
        r.context = Some(format!(
            r#"{{"referer":"https://example.com/{}","user_agent":"{}"}}"#,
            "a".repeat(3000),
            "u".repeat(3000)
        ));
        engine(&fake).submit(&r).unwrap();
        let o = fake.calls.borrow()[0].1[1].clone();
        assert!(o.get("referer").is_none() && o.get("user-agent").is_none());
    }

    #[test]
    fn a_request_that_must_not_be_sent_is_rejected_without_any_call() {
        let mut cases: Vec<EngineRequest> = Vec::new();
        for url in [
            "ftp://example.com/a",
            "file:///c:/x",
            "https://user:pw@example.com/a",
            "https://exa mple.com/a",
            "",
        ] {
            let mut r = request();
            r.url = url.into();
            cases.push(r);
        }
        for dest in [
            None,
            Some(String::new()),
            Some("a.zip".into()),
            Some(r"dl\a.zip".into()),
        ] {
            let mut r = request();
            r.destination = dest;
            cases.push(r);
        }
        for r in cases {
            let fake = Fake::default();
            assert_eq!(
                engine(&fake).submit(&r),
                Err(EngineError::Rejected),
                "{r:?}"
            );
            assert!(fake.methods().is_empty(), "{r:?} reached aria2");
        }
    }

    #[test]
    fn an_unexpected_gid_in_the_reply_is_ambiguous() {
        let fake = Fake::with(vec![Ok(json!("ffffffffffffffff"))]);
        assert_eq!(
            engine(&fake).submit(&request()),
            Err(EngineError::ReplyLost)
        );
        let fake = Fake::with(vec![Ok(json!(42))]);
        assert_eq!(
            engine(&fake).submit(&request()),
            Err(EngineError::ReplyLost)
        );
    }

    fn status_fixture(mut v: Value) -> Value {
        let o = v.as_object_mut().unwrap();
        o.insert("gid".into(), json!(gid_for("t1-g1")));
        o.entry("completedLength").or_insert(json!("0"));
        o.entry("totalLength").or_insert(json!("0"));
        if o.get("status") == Some(&json!("error")) {
            o.entry("errorCode").or_insert(json!("3"));
            o.entry("errorMessage").or_insert(json!("failure"));
        }
        v
    }

    #[test]
    fn an_already_existing_task_counts_as_success_because_the_attempt_id_is_the_identity() {
        let fake = Fake::with(vec![
            Err(OTHER),
            Ok(status_fixture(
                json!({"status":"active","completedLength":"1","totalLength":"2"}),
            )),
        ]);
        assert_eq!(engine(&fake).submit(&request()), Ok(()));
        assert_eq!(fake.methods(), ["aria2.addUri", "aria2.tellStatus"]);
        // a refusal for any other reason is final
        let fake = Fake::with(vec![Err(OTHER), Err(NOT_FOUND)]);
        assert_eq!(engine(&fake).submit(&request()), Err(EngineError::Rejected));
        // and if we cannot even ask, the outcome is ambiguous
        let fake = Fake::with(vec![Err(OTHER), Err(RpcError::Transport("t"))]);
        assert_eq!(
            engine(&fake).submit(&request()),
            Err(EngineError::ReplyLost)
        );
    }

    #[test]
    fn transport_trouble_on_submit_is_ambiguous_not_a_rejection() {
        for e in [RpcError::Transport("t"), RpcError::BadReply("b")] {
            let fake = Fake::with(vec![Err(e)]);
            assert_eq!(
                engine(&fake).submit(&request()),
                Err(EngineError::ReplyLost)
            );
        }
    }

    #[test]
    fn status_maps_every_aria2_state() {
        let failed = EngineStatus::Failed("transfer failed".into());
        let cases = [
            (
                status_fixture(
                    json!({"status":"active","completedLength":"512","totalLength":"1024"}),
                ),
                EngineStatus::Active {
                    done: 512,
                    total: 1024,
                },
            ),
            (
                status_fixture(json!({"status":"waiting","completedLength":"0","totalLength":"0"})),
                EngineStatus::Active { done: 0, total: 0 },
            ),
            (
                status_fixture(json!({"status":"paused"})),
                EngineStatus::Paused,
            ),
            (
                status_fixture(json!({"status":"complete"})),
                EngineStatus::Done,
            ),
            (
                status_fixture(
                    json!({"status":"error","errorMessage":"GET https://secret.example/t=1 failed"}),
                ),
                failed.clone(),
            ),
            (status_fixture(json!({"status":"removed"})), failed),
        ];
        for (reply, want) in cases {
            let fake = Fake::with(vec![Ok(reply.clone())]);
            assert_eq!(engine(&fake).status("t1-g1"), Ok(want), "{reply}");
            let c = fake.calls.borrow();
            assert_eq!(c[0].0, "aria2.tellStatus");
            assert_eq!(c[0].1[0], json!(gid_for("t1-g1")));
        }
    }

    fn errored(code: &str, message: &str) -> Value {
        status_fixture(json!({"status": "error", "errorCode": code, "errorMessage": message}))
    }

    #[test]
    fn failures_are_split_into_worth_retrying_and_final_by_aria2s_own_codes() {
        let transient = [
            errored("2", "timed out"),
            errored("5", "download speed too slow"),
            errored("6", "network problem"),
            errored("19", "name resolution failed"),
            errored("29", "server busy"),
            errored("22", "The response status is not successful. status=408"),
            errored("22", "The response status is not successful. status=429"),
            errored("22", "The response status is not successful. status=500"),
            errored("22", "The response status is not successful. status=502"),
            errored("22", "The response status is not successful. status=503"),
            errored("22", "The response status is not successful. status=504"),
            // measured on the pinned aria2: a refused connection and a mid-body drop both say code 1
            errored(
                "1",
                "Network problem has occurred. cause:No connection could be made",
            ),
            errored("1", "No URI available."),
        ];
        for reply in transient {
            let fake = Fake::with(vec![Ok(reply.clone())]);
            assert_eq!(
                engine(&fake).status("t1-g1"),
                Ok(EngineStatus::Interrupted),
                "{reply}"
            );
            let fake = Fake::with(vec![Ok(reply.clone())]);
            assert_eq!(engine(&fake).poll("t1-g1"), Poll::Interrupted, "{reply}");
        }
        let permanent = [
            errored("22", "The response status is not successful. status=403"),
            errored("22", "The response status is not successful. status=404"),
            errored("22", "The response status is not successful. status=401"),
            errored("22", "The response status is not successful. status=410"),
            errored("22", "The response status is not successful. status=400"),
            errored("22", "unparseable"),
            errored("22", ""),
            errored("3", "not found"),
            errored("9", "disk full"),
            errored("13", "file exists"),
            errored("17", "i/o"),
            errored("23", "too many redirects"),
            errored("24", "auth failed"),
            errored("1", "unknown"),
            errored("1", "Some other code one message"),
            status_fixture(json!({"status": "error"})),
        ];
        for reply in permanent {
            let fake = Fake::with(vec![Ok(reply.clone())]);
            assert_eq!(
                engine(&fake).status("t1-g1"),
                Ok(EngineStatus::Failed("transfer failed".into())),
                "{reply}"
            );
            let fake = Fake::with(vec![Ok(reply.clone())]);
            assert_eq!(engine(&fake).poll("t1-g1"), Poll::Failed, "{reply}");
        }
    }

    #[test]
    fn poll_asks_aria2_once_and_maps_every_answer() {
        let cases = [
            (
                Ok(status_fixture(json!({"status":"active"}))),
                Poll::Running,
            ),
            (
                Ok(status_fixture(json!({"status":"waiting"}))),
                Poll::Running,
            ),
            (
                Ok(status_fixture(json!({"status":"paused"}))),
                Poll::Running,
            ),
            (Ok(status_fixture(json!({"status":"complete"}))), Poll::Done),
            (
                Ok(status_fixture(json!({"status":"removed"}))),
                Poll::Failed,
            ),
            (
                Ok(status_fixture(json!({"status":"mystery"}))),
                Poll::Unreachable,
            ),
            (Ok(json!("text")), Poll::Unreachable),
            (Err(NOT_FOUND), Poll::Forgotten),
            (Err(REFUSED), Poll::Unreachable),
            (Err(OTHER), Poll::Unreachable),
            (Err(RpcError::Transport("t")), Poll::Unreachable),
            (Err(RpcError::BadReply("b")), Poll::Unreachable),
        ];
        for (reply, want) in cases {
            let fake = Fake::with(vec![reply.clone()]);
            assert_eq!(engine(&fake).poll("t1-g1"), want, "{reply:?}");
            assert_eq!(fake.methods(), ["aria2.tellStatus"], "one call, not three");
        }
    }

    #[test]
    fn the_status_question_asks_for_the_error_fields_and_nothing_else_sensitive() {
        let fake = Fake::with(vec![Ok(status_fixture(json!({"status":"active"})))]);
        engine(&fake).poll("t1-g1");
        let keys = fake.calls.borrow()[0].1[1].clone();
        assert_eq!(
            keys,
            json!([
                "gid",
                "status",
                "completedLength",
                "totalLength",
                "errorCode",
                "errorMessage"
            ])
        );
    }

    #[test]
    fn only_a_clean_not_found_means_unknown() {
        let fake = Fake::with(vec![Err(NOT_FOUND)]);
        assert_eq!(engine(&fake).status("t1-g1"), Ok(EngineStatus::Unknown));
        for e in [
            REFUSED,
            OTHER,
            RpcError::Transport("t"),
            RpcError::BadReply("b"),
        ] {
            let fake = Fake::with(vec![Err(e)]);
            assert_eq!(
                engine(&fake).status("t1-g1"),
                Err(EngineError::ReplyLost),
                "{e:?}"
            );
        }
        for odd in [
            status_fixture(json!({"status":"mystery"})),
            json!({}),
            json!("text"),
        ] {
            let fake = Fake::with(vec![Ok(odd)]);
            assert_eq!(engine(&fake).status("t1-g1"), Err(EngineError::ReplyLost));
        }
    }

    #[test]
    fn has_forgotten_is_true_only_when_aria2_says_it_has_never_heard_of_the_task() {
        let fake = Fake::with(vec![Err(NOT_FOUND)]);
        assert!(engine(&fake).has_forgotten("t1-g1"));
        for reply in [
            Err(REFUSED),
            Err(RpcError::Transport("t")),
            Ok(status_fixture(json!({"status":"active"}))),
            Ok(status_fixture(json!({"status":"complete"}))),
        ] {
            let fake = Fake::with(vec![reply]);
            assert!(!engine(&fake).has_forgotten("t1-g1"));
        }
    }

    #[test]
    fn finished_reports_only_terminal_states() {
        for (reply, want) in [
            (Ok(status_fixture(json!({"status":"complete"}))), Some(true)),
            (Ok(status_fixture(json!({"status":"error"}))), Some(false)),
            (Ok(status_fixture(json!({"status":"active"}))), None),
            (Ok(status_fixture(json!({"status":"paused"}))), None),
            (Err(NOT_FOUND), None),
            (Err(RpcError::Transport("t")), None),
        ] {
            let fake = Fake::with(vec![reply]);
            assert_eq!(engine(&fake).finished("t1-g1"), want);
        }
    }

    #[test]
    fn pause_resume_and_cancel_use_the_gid_and_tolerate_a_task_that_is_gone() {
        for (call, method) in [
            (0, "aria2.pause"),
            (1, "aria2.unpause"),
            (2, "aria2.forceRemove"),
        ] {
            let run = |reply: Result<Value, RpcError>| {
                let fake = Fake::with(vec![reply]);
                let mut e = engine(&fake);
                let out = match call {
                    0 => e.pause("t1-g1"),
                    1 => e.resume("t1-g1"),
                    _ => e.cancel("t1-g1"),
                };
                let seen = fake.calls.borrow().clone();
                (out, seen)
            };
            let (out, seen) = run(Ok(json!(gid_for("t1-g1"))));
            assert_eq!(out, Ok(()));
            assert_eq!(seen[0].0, method);
            assert_eq!(seen[0].1, vec![json!(gid_for("t1-g1"))]);
            assert_eq!(run(Err(NOT_FOUND)).0, Ok(()), "{method}: already gone");
            assert_eq!(run(Err(REFUSED)).0, Err(EngineError::ReplyLost), "{method}");
            assert_eq!(
                run(Err(RpcError::Transport("t"))).0,
                Err(EngineError::ReplyLost),
                "{method}"
            );
        }
    }
}
