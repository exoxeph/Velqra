// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]
//! Velqra ownership protocol: envelope, message bodies, limits and fingerprint.

pub mod download_url;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;
pub const MAX_JSON_DEPTH: usize = 16;

/// A secret string. `Debug` never shows the value.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(pub String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepareBody {
    pub download_key: String,
    pub url: String,
    pub filename: String,
    pub context: Secret,
}

/// Whether the extension should hand downloads to Velqra: everywhere, only on allowed sites, or never.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    On,
    PerSite,
    Off,
}

/// A read-only copy of the core's capture settings. The extension reads it and never writes it, and
/// it carries no folders: where files go is the core's own business.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsSnapshot {
    pub transfer_capable: bool,
    pub mode: CaptureMode,
    /// Lower-case suffixes without the dot that are handed over.
    pub extensions: Vec<String>,
    pub excluded_sites: Vec<String>,
    pub allowed_sites: Vec<String>,
    /// A fixed phrase when the settings file was refused and the defaults are in use.
    pub problem: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Prepared,
    Armed,
    Committed,
    Transferring,
    Done,
    Failed,
    Aborted,
    OwnershipUnknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub task_id: u64,
    pub fingerprint: String,
    pub state: TaskState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerEvidence {
    BrowserOwns,
    AppOwns,
    Unknown,
}

/// Only confirmed cancellation is accepted as evidence for a commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelEvidence {
    Confirmed,
}

/// Identity of a receipt: every follow-up message must name the receipt it refers to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestRef {
    pub task_id: u64,
    pub fingerprint: String,
}

impl Receipt {
    pub fn as_ref(&self) -> RequestRef {
        RequestRef {
            task_id: self.task_id,
            fingerprint: self.fingerprint.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitBody {
    pub cancel: CancelEvidence,
    pub receipt: RequestRef,
}

/// Abort names the receipt when the sender has one; an abort for a request the core never saw
/// carries none and creates a tombstone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbortBody {
    pub receipt: Option<RequestRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileBody {
    pub owner: OwnerEvidence,
    pub receipt: RequestRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Empty {}

/// Answer to a health check: which core answered and what it speaks. Nothing secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthInfo {
    pub transfer_capable: bool,
    pub problem: Option<String>,
    pub core_instance: String,
    pub versions: Vec<u16>,
    pub engine: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    TooLarge,
    TooDeep,
    BadVersion,
    UnknownType,
    Malformed,
    ControlChar,
    UrlUserinfo,
    PathTraversal,
    PayloadMismatch,
    StaleGeneration,
    WrongState,
    NotFound,
    NotArmed,
    Aborted,
    Storage,
    /// The core has no valid place to write this download; the browser keeps it.
    NoDestination,
    IdentityMismatch,
    Overloaded,
    Unauthenticated,
}

/// The detail travels on the wire but is untrusted text: it is never printed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[error("{kind:?}")]
pub struct ProtoError {
    pub kind: ErrorKind,
    pub detail: String,
}

impl std::fmt::Debug for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ProtoError {{ kind: {:?}, detail: <redacted> }}",
            self.kind
        )
    }
}

impl ProtoError {
    pub fn new(kind: ErrorKind, detail: &str) -> Self {
        Self {
            kind,
            detail: detail.to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum Message {
    Prepare(PrepareBody),
    Prepared(Receipt),
    BeginHandoff(RequestRef),
    Armed(Receipt),
    Commit(CommitBody),
    Committed(Receipt),
    Abort(AbortBody),
    Aborted(Receipt),
    Reconcile(ReconcileBody),
    Reconciled(Receipt),
    Status(Empty),
    StatusReply(Receipt),
    Health(Empty),
    HealthReply(HealthInfo),
    SettingsGet(Empty),
    SettingsReply(SettingsSnapshot),
    Error(ProtoError),
}

impl Message {
    pub fn kind(&self) -> &'static str {
        match self {
            Message::Prepare(_) => "prepare",
            Message::Prepared(_) => "prepared",
            Message::BeginHandoff(_) => "begin_handoff",
            Message::Armed(_) => "armed",
            Message::Commit(_) => "commit",
            Message::Committed(_) => "committed",
            Message::Abort(_) => "abort",
            Message::Aborted(_) => "aborted",
            Message::Reconcile(_) => "reconcile",
            Message::Reconciled(_) => "reconciled",
            Message::Status(_) => "status",
            Message::StatusReply(_) => "status_reply",
            Message::Health(_) => "health",
            Message::HealthReply(_) => "health_reply",
            Message::SettingsGet(_) => "settings_get",
            Message::SettingsReply(_) => "settings_reply",
            Message::Error(_) => "error",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u16,
    pub message_id: String,
    pub session_id: String,
    pub request_id: String,
    pub generation: u32,
    pub body: Message,
}

/// Stable hash over a canonical form of the state-changing payload.
/// The canonical form is a JSON object with keys in sorted order and
/// no whitespace; the secret context is not part of it.
pub fn fingerprint(p: &PrepareBody) -> String {
    let canonical = serde_json::json!({
        "download_key": p.download_key,
        "filename": p.filename,
        "url": p.url,
    })
    .to_string();
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn depth(v: &serde_json::Value) -> usize {
    match v {
        serde_json::Value::Array(a) => 1 + a.iter().map(depth).max().unwrap_or(0),
        serde_json::Value::Object(o) => 1 + o.values().map(depth).max().unwrap_or(0),
        _ => 0,
    }
}

const MAX_ID_LEN: usize = 128;
const RESERVED_NAMES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

fn has_control(s: &str) -> bool {
    s.chars().any(|c| c.is_control())
}

fn authority_of(url: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    Some((scheme, rest.split(['/', '?', '#']).next().unwrap_or("")))
}

/// Shows only scheme and host: never the path, query, fragment or credentials.
fn redact_url(url: &str) -> String {
    match authority_of(url) {
        Some((scheme, authority)) => format!(
            "{scheme}://{}/...",
            authority.rsplit('@').next().unwrap_or("")
        ),
        None => "<invalid url>".to_string(),
    }
}

impl std::fmt::Debug for PrepareBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PrepareBody {{ download_key: <redacted>, url: {}, filename: <redacted>, context: <redacted> }}",
            redact_url(&self.url)
        )
    }
}

fn url_policy(url: &str) -> Result<(), ProtoError> {
    use download_url::{parse_download_url, UrlError};
    match parse_download_url(url) {
        Ok(_) => Ok(()),
        Err(UrlError::Userinfo) => Err(ProtoError::new(
            ErrorKind::UrlUserinfo,
            "credentials in url",
        )),
        // the reason is a fixed phrase: the URL itself is never echoed
        Err(UrlError::Invalid(why)) => Err(ProtoError::new(ErrorKind::Malformed, why)),
    }
}

fn filename_policy(f: &str) -> Result<(), ProtoError> {
    let unsafe_name = || ProtoError::new(ErrorKind::PathTraversal, "unsafe filename");
    if f.is_empty() || f.len() > 255 {
        return Err(ProtoError::new(ErrorKind::Malformed, "filename length"));
    }
    if f.contains("..") || f.ends_with('.') || f.ends_with(' ') {
        return Err(unsafe_name());
    }
    if f.chars()
        .any(|c| matches!(c, '/' | '\u{5c}' | ':' | '<' | '>' | '"' | '|' | '?' | '*'))
    {
        return Err(unsafe_name());
    }
    let base = f.split('.').next().unwrap_or("").to_ascii_uppercase();
    if RESERVED_NAMES.contains(&base.as_str()) {
        return Err(unsafe_name());
    }
    Ok(())
}

fn check_ref(r: &RequestRef) -> Result<(), ProtoError> {
    if r.fingerprint.is_empty() || r.fingerprint.len() > MAX_ID_LEN || has_control(&r.fingerprint) {
        return Err(ProtoError::new(
            ErrorKind::Malformed,
            "invalid receipt identity",
        ));
    }
    Ok(())
}

/// A JSON value that refuses duplicate object keys at any depth (serde_json::Value keeps the last one,
/// which would let two parsers disagree about what a message says).
struct StrictValue(serde_json::Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{Error, MapAccess, SeqAccess, Visitor};
        use serde_json::{Map, Number, Value};
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Value;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a json value")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
                Ok(Value::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
                Ok(Value::Number(v.into()))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
                Ok(Value::Number(v.into()))
            }
            fn visit_f64<E: Error>(self, v: f64) -> Result<Value, E> {
                Number::from_f64(v)
                    .map(Value::Number)
                    .ok_or_else(|| E::custom("number"))
            }
            fn visit_str<E>(self, v: &str) -> Result<Value, E> {
                Ok(Value::String(v.to_owned()))
            }
            fn visit_string<E>(self, v: String) -> Result<Value, E> {
                Ok(Value::String(v))
            }
            fn visit_unit<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_none<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
                let mut out = Vec::new();
                while let Some(StrictValue(v)) = a.next_element()? {
                    out.push(v);
                }
                Ok(Value::Array(out))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
                let mut out = Map::new();
                while let Some((k, StrictValue(v))) = a.next_entry::<String, StrictValue>()? {
                    if out.insert(k, v).is_some() {
                        // fixed text: the offending key is never echoed
                        return Err(A::Error::custom("duplicate key"));
                    }
                }
                Ok(Value::Object(out))
            }
        }
        d.deserialize_any(V).map(StrictValue)
    }
}

/// Size, syntax, duplicate-key and nesting checks shared by every untrusted JSON input
/// (envelopes and the pre-session handshake frames). Errors are fixed text.
pub fn parse_strict_json(bytes: &[u8]) -> Result<serde_json::Value, ProtoError> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(ProtoError::new(ErrorKind::TooLarge, "envelope too large"));
    }
    let StrictValue(value) = serde_json::from_slice(bytes)
        .map_err(|_| ProtoError::new(ErrorKind::Malformed, "input is not valid json"))?;
    if depth(&value) > MAX_JSON_DEPTH {
        return Err(ProtoError::new(ErrorKind::TooDeep, "json nesting too deep"));
    }
    Ok(value)
}

impl Envelope {
    /// Full validation of a typed envelope. The wire decoder calls this, and the core calls it
    /// again so typed callers cannot bypass it.
    pub fn validate(&self) -> Result<(), ProtoError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtoError::new(
                ErrorKind::BadVersion,
                "unsupported version",
            ));
        }
        for s in [&self.message_id, &self.session_id, &self.request_id] {
            if has_control(s) {
                return Err(ProtoError::new(
                    ErrorKind::ControlChar,
                    "control character in id",
                ));
            }
            if s.is_empty() || s.len() > MAX_ID_LEN {
                return Err(ProtoError::new(ErrorKind::Malformed, "invalid identifier"));
            }
        }
        if self.generation == 0 {
            return Err(ProtoError::new(
                ErrorKind::Malformed,
                "generation must be >= 1",
            ));
        }
        match &self.body {
            Message::Prepare(p) => {
                for s in [&p.download_key, &p.url, &p.filename] {
                    if has_control(s) {
                        return Err(ProtoError::new(ErrorKind::ControlChar, "control character"));
                    }
                }
                if p.download_key.is_empty() || p.download_key.len() > 256 {
                    return Err(ProtoError::new(ErrorKind::Malformed, "download key length"));
                }
                url_policy(&p.url)?;
                filename_policy(&p.filename)?;
            }
            Message::BeginHandoff(r) => check_ref(r)?,
            Message::Commit(c) => check_ref(&c.receipt)?,
            Message::Reconcile(c) => check_ref(&c.receipt)?,
            Message::Abort(a) => {
                if let Some(r) = &a.receipt {
                    check_ref(r)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl Envelope {
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|_| ProtoError::new(ErrorKind::Malformed, "envelope could not be encoded"))?;
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(ProtoError::new(
                ErrorKind::TooLarge,
                "encoded envelope too large",
            ));
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Envelope, ProtoError> {
        let value = parse_strict_json(bytes)?;
        if value.get("version").and_then(|v| v.as_u64()) != Some(PROTOCOL_VERSION as u64) {
            return Err(ProtoError::new(
                ErrorKind::BadVersion,
                "unsupported version",
            ));
        }
        let env: Envelope = serde_json::from_value(value).map_err(|e| {
            // never echo the offending input: only a fixed description leaves this function
            if e.to_string().contains("unknown variant") {
                ProtoError::new(ErrorKind::UnknownType, "unknown message type")
            } else {
                ProtoError::new(ErrorKind::Malformed, "envelope does not match the protocol")
            }
        })?;
        env.validate()?;
        Ok(env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn body() -> PrepareBody {
        PrepareBody {
            download_key: "d1".into(),
            url: "https://x.test/a.zip".into(),
            filename: "a.zip".into(),
            context: Secret("S3CR3T-SENTINEL".into()),
        }
    }

    #[test]
    fn secret_is_redacted_in_debug() {
        let text = format!("{:?}", body());
        assert!(!text.contains("S3CR3T-SENTINEL"));
        assert!(text.contains("<redacted>"));
    }

    #[test]
    fn fingerprint_matches_independent_hash_of_canonical_form() {
        let canonical = r#"{"download_key":"d1","filename":"a.zip","url":"https://x.test/a.zip"}"#;
        let mut h = Sha256::new();
        h.update(canonical.as_bytes());
        let expected: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(fingerprint(&body()), expected);
    }

    #[test]
    fn fingerprint_ignores_secret_context_but_not_url() {
        let a = body();
        let mut b = body();
        b.context = Secret("other".into());
        assert_eq!(fingerprint(&a), fingerprint(&b));
        b.url = "https://x.test/b.zip".into();
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn envelope_roundtrips() {
        let env = Envelope {
            version: PROTOCOL_VERSION,
            message_id: "m1".into(),
            session_id: "s1".into(),
            request_id: "req-1".into(),
            generation: 1,
            body: Message::Prepare(body()),
        };
        let bytes = serde_json::to_vec(&env).unwrap();
        let back: Envelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(env, back);
        assert_eq!(env.body.kind(), "prepare");
    }

    fn good_json() -> serde_json::Value {
        serde_json::json!({
            "version": 1, "message_id": "m1", "session_id": "s1", "request_id": "req-1",
            "generation": 1,
            "body": {"type": "prepare", "payload": {
                "download_key": "d1", "url": "https://x.test/a.zip",
                "filename": "a.zip", "context": "S3CR3T-SENTINEL"}}
        })
    }

    fn decode(v: &serde_json::Value) -> Result<Envelope, ProtoError> {
        Envelope::decode(v.to_string().as_bytes())
    }

    #[test]
    fn decode_accepts_a_good_envelope() {
        assert!(decode(&good_json()).is_ok());
    }

    #[test]
    fn decode_rejects_oversized_input() {
        let big = vec![b' '; MAX_ENVELOPE_BYTES + 1];
        assert_eq!(
            Envelope::decode(&big).unwrap_err().kind,
            ErrorKind::TooLarge
        );
    }

    #[test]
    fn decode_rejects_deep_nesting_before_parsing_types() {
        let mut v = good_json();
        let mut nest = serde_json::json!(1);
        for _ in 0..40 {
            nest = serde_json::json!([nest]);
        }
        v["extra"] = nest;
        assert_eq!(decode(&v).unwrap_err().kind, ErrorKind::TooDeep);
    }

    #[test]
    fn decode_rejects_unknown_type_and_bad_version() {
        let mut v = good_json();
        v["body"]["type"] = serde_json::json!("frobnicate");
        assert_eq!(decode(&v).unwrap_err().kind, ErrorKind::UnknownType);
        let mut v = good_json();
        v["version"] = serde_json::json!(2);
        assert_eq!(decode(&v).unwrap_err().kind, ErrorKind::BadVersion);
    }

    #[test]
    fn decode_rejects_url_userinfo_traversal_and_control_chars() {
        let mut v = good_json();
        v["body"]["payload"]["url"] = serde_json::json!("https://user:pw@x.test/a.zip");
        assert_eq!(decode(&v).unwrap_err().kind, ErrorKind::UrlUserinfo);
        for bad in ["..\\x.zip", "a/b.zip", "C:evil.zip", "a..zip.."] {
            let mut v = good_json();
            v["body"]["payload"]["filename"] = serde_json::json!(bad);
            assert_eq!(
                decode(&v).unwrap_err().kind,
                ErrorKind::PathTraversal,
                "{bad}"
            );
        }
        let mut v = good_json();
        v["request_id"] = serde_json::json!("req\u{0007}1");
        assert_eq!(decode(&v).unwrap_err().kind, ErrorKind::ControlChar);
    }

    #[test]
    fn decode_rejects_malformed_json() {
        assert_eq!(
            Envelope::decode(b"{not json").unwrap_err().kind,
            ErrorKind::Malformed
        );
    }

    proptest::proptest! {
        #[test]
        fn fingerprint_is_stable_and_url_sensitive(url in "https://[a-z]{1,8}\\.test/[a-z]{1,8}", name in "[a-z]{1,8}\\.zip") {
            let a = PrepareBody { download_key: "k".into(), url: url.clone(), filename: name.clone(), context: Secret("x".into()) };
            let b = a.clone();
            proptest::prop_assert_eq!(fingerprint(&a), fingerprint(&b));
            let mut c = a.clone();
            c.url.push('x');
            proptest::prop_assert_ne!(fingerprint(&a), fingerprint(&c));
        }
    }

    // ---- M0.1: identity, validation, redaction ----

    fn good_prepare(url: &str, filename: &str) -> Envelope {
        Envelope {
            version: PROTOCOL_VERSION,
            message_id: "m1".into(),
            session_id: "s1".into(),
            request_id: "req-1".into(),
            generation: 1,
            body: Message::Prepare(PrepareBody {
                download_key: "d1".into(),
                url: url.into(),
                filename: filename.into(),
                context: Secret("x".into()),
            }),
        }
    }

    #[test]
    fn typed_envelopes_can_be_validated_without_the_wire_decoder() {
        let mut e = good_prepare("https://x.test/a.zip", "a.zip");
        assert!(e.validate().is_ok());
        e.version = 99;
        assert_eq!(e.validate().unwrap_err().kind, ErrorKind::BadVersion);
        let mut e = good_prepare("https://x.test/a.zip", "a.zip");
        e.generation = 0;
        assert_eq!(e.validate().unwrap_err().kind, ErrorKind::Malformed);
        let mut e = good_prepare("https://x.test/a.zip", "a.zip");
        e.request_id = String::new();
        assert_eq!(e.validate().unwrap_err().kind, ErrorKind::Malformed);
    }

    #[test]
    fn urls_must_be_http_or_https_with_a_host() {
        for bad in [
            "file:///c:/x.zip",
            "ftp://x.test/a",
            "https://",
            "https:///x",
            "http://:80/x",
            "not a url",
            "",
        ] {
            let e = good_prepare(bad, "a.zip");
            assert!(e.validate().is_err(), "{bad} should be rejected");
        }
        assert!(good_prepare("http://x.test:8080/a?b=c#d", "a.zip")
            .validate()
            .is_ok());
    }

    #[test]
    fn windows_unsafe_filenames_are_rejected() {
        for bad in [
            "CON", "nul.zip", "COM1.txt", "lpt9", "a.", "a ", ".", "a<b", "a>b", "a\"b", "a|b",
            "a?b", "a*b",
        ] {
            let e = good_prepare("https://x.test/a", bad);
            assert!(e.validate().is_err(), "{bad:?} should be rejected");
        }
        assert!(good_prepare("https://x.test/a", "report (1).tar.gz")
            .validate()
            .is_ok());
        assert!(good_prepare("https://x.test/a", "console.zip")
            .validate()
            .is_ok());
    }

    #[test]
    fn debug_output_never_shows_url_query_or_filename() {
        let b = PrepareBody {
            download_key: "KEY123".into(),
            url: "https://host.test/path/TOKENPATH?sig=TOKENQUERY#frag".into(),
            filename: "SECRETNAME.zip".into(),
            context: Secret("S3CR3T".into()),
        };
        let text = format!("{b:?}");
        for leak in [
            "TOKENQUERY",
            "TOKENPATH",
            "SECRETNAME",
            "KEY123",
            "S3CR3T",
            "frag",
        ] {
            assert!(!text.contains(leak), "{leak} leaked in {text}");
        }
        assert!(text.contains("host.test"));
    }

    #[test]
    fn decode_errors_never_echo_the_input() {
        let mut v = good_json();
        v["generation"] = serde_json::json!("TOKEN123");
        let err = decode(&v).unwrap_err();
        assert!(!err.detail.contains("TOKEN123"), "{}", err.detail);
        assert!(!format!("{err}").contains("TOKEN123"));
    }

    #[test]
    fn follow_up_messages_carry_the_receipt_identity() {
        let r = RequestRef {
            task_id: 7,
            fingerprint: "ab".into(),
        };
        let c = CommitBody {
            cancel: CancelEvidence::Confirmed,
            receipt: r.clone(),
        };
        let text = serde_json::to_string(&c).unwrap();
        assert!(text.contains("\"task_id\":7"));
        let back: CommitBody = serde_json::from_str(&text).unwrap();
        assert_eq!(back.receipt, r);
        let rc = Receipt {
            task_id: 7,
            fingerprint: "ab".into(),
            state: TaskState::Armed,
        };
        assert_eq!(rc.as_ref(), r);
    }

    #[test]
    fn error_detail_never_reaches_debug_or_display_output() {
        let e = ProtoError::new(ErrorKind::Malformed, "https://x.test/a?sig=URLSECRET");
        assert!(!format!("{e:?}").contains("URLSECRET"));
        assert!(!format!("{e}").contains("URLSECRET"));
        assert!(format!("{e:?}").contains("Malformed"));
        let env = Envelope {
            version: PROTOCOL_VERSION,
            message_id: "m".into(),
            session_id: "s".into(),
            request_id: "r".into(),
            generation: 1,
            body: Message::Error(e),
        };
        assert!(!format!("{env:?}").contains("URLSECRET"));
    }

    fn status_json() -> String {
        let env = Envelope {
            version: PROTOCOL_VERSION,
            message_id: "m1".into(),
            session_id: "s1".into(),
            request_id: "r1".into(),
            generation: 1,
            body: Message::Status(Empty {}),
        };
        String::from_utf8(env.encode().unwrap()).unwrap()
    }

    #[test]
    fn duplicate_keys_are_rejected_at_every_depth() {
        let ok = status_json();
        assert!(Envelope::decode(ok.as_bytes()).is_ok());
        // top level
        let dup = ok.replacen('{', "{\"generation\":2,", 1);
        let e = Envelope::decode(dup.as_bytes()).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Malformed);
        // inside the payload object
        let dup = ok.replace("\"payload\":{}", "\"payload\":{\"x\":1,\"x\":2}");
        assert_ne!(dup, ok, "fixture did not contain an empty payload");
        assert_eq!(
            Envelope::decode(dup.as_bytes()).unwrap_err().kind,
            ErrorKind::Malformed
        );
        // nested two levels down
        let dup = ok.replace(
            "\"payload\":{}",
            "\"payload\":{\"a\":{\"b\":{\"k\":1,\"k\":1}}}",
        );
        assert_eq!(
            Envelope::decode(dup.as_bytes()).unwrap_err().kind,
            ErrorKind::Malformed
        );
    }

    #[test]
    fn duplicate_key_errors_do_not_echo_the_key() {
        let ok = status_json();
        let dup = ok.replacen('{', "{\"S3CR3T-KEY\":1,\"S3CR3T-KEY\":2,", 1);
        let e = Envelope::decode(dup.as_bytes()).unwrap_err();
        assert!(!format!("{e:?}{e}").contains("S3CR3T-KEY"));
        assert!(!e.detail.contains("S3CR3T-KEY"));
    }

    #[test]
    fn health_messages_round_trip_and_have_kinds() {
        let info = HealthInfo {
            transfer_capable: true,
            problem: None,
            core_instance: "c1".into(),
            versions: vec![1],
            engine: "fake".into(),
        };
        for body in [Message::Health(Empty {}), Message::HealthReply(info)] {
            let env = Envelope {
                version: PROTOCOL_VERSION,
                message_id: "m".into(),
                session_id: "s".into(),
                request_id: "r".into(),
                generation: 1,
                body: body.clone(),
            };
            let back = Envelope::decode(&env.encode().unwrap()).unwrap();
            assert_eq!(back.body, body);
        }
        assert_eq!(Message::Health(Empty {}).kind(), "health");
        assert_eq!(
            Message::HealthReply(HealthInfo {
                transfer_capable: true,
                problem: None,
                core_instance: String::new(),
                versions: vec![],
                engine: String::new()
            })
            .kind(),
            "health_reply"
        );
    }

    #[test]
    fn settings_messages_round_trip_and_have_kinds() {
        let snap = SettingsSnapshot {
            transfer_capable: true,
            mode: CaptureMode::PerSite,
            extensions: vec!["zip".into(), "iso".into()],
            excluded_sites: vec!["a.example".into()],
            allowed_sites: vec!["*.b.example".into()],
            problem: Some("settings file refused".into()),
        };
        for body in [
            Message::SettingsGet(Empty {}),
            Message::SettingsReply(snap.clone()),
        ] {
            let env = Envelope {
                version: PROTOCOL_VERSION,
                message_id: "m".into(),
                session_id: "s".into(),
                request_id: "r".into(),
                generation: 1,
                body: body.clone(),
            };
            let wire = String::from_utf8(env.encode().unwrap()).unwrap();
            assert!(wire.contains("settings_"), "{wire}");
            assert_eq!(Envelope::decode(wire.as_bytes()).unwrap().body, body);
        }
        assert_eq!(Message::SettingsGet(Empty {}).kind(), "settings_get");
        assert_eq!(Message::SettingsReply(snap).kind(), "settings_reply");
        let on = serde_json::to_string(&CaptureMode::PerSite).unwrap();
        assert_eq!(on, "\"per_site\"");
    }

    #[test]
    fn a_snapshot_with_an_unknown_mode_or_extra_field_is_refused() {
        let good = r#"{"version":1,"message_id":"m","session_id":"s","request_id":"r","generation":1,"body":{"type":"settings_reply","payload":{"mode":"on","extensions":[],"excluded_sites":[],"allowed_sites":[],"transfer_capable":true,"problem":null}}}"#;
        assert!(Envelope::decode(good.as_bytes()).is_ok());
        for bad in [
            good.replace("\"on\"", "\"maybe\""),
            good.replace("\"problem\":null", "\"problem\":null,\"root\":\"C:\\x\""),
        ] {
            assert!(Envelope::decode(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn new_error_kinds_use_snake_case_on_the_wire() {
        let e = ProtoError::new(ErrorKind::Overloaded, "x");
        assert!(serde_json::to_string(&e)
            .unwrap()
            .contains("\"overloaded\""));
        let e = ProtoError::new(ErrorKind::Unauthenticated, "x");
        assert!(serde_json::to_string(&e)
            .unwrap()
            .contains("\"unauthenticated\""));
    }

    #[test]
    fn parse_strict_json_rejects_duplicates_depth_and_size() {
        assert!(parse_strict_json(b"{\"a\":1,\"b\":[1,2]}").is_ok());
        assert_eq!(
            parse_strict_json(b"{\"a\":1,\"a\":2}").unwrap_err().kind,
            ErrorKind::Malformed
        );
        let deep = format!("{}1{}", "[".repeat(20), "]".repeat(20));
        assert_eq!(
            parse_strict_json(deep.as_bytes()).unwrap_err().kind,
            ErrorKind::TooDeep
        );
        let big = vec![b' '; MAX_ENVELOPE_BYTES + 1];
        assert_eq!(
            parse_strict_json(&big).unwrap_err().kind,
            ErrorKind::TooLarge
        );
        assert_eq!(
            parse_strict_json(&[0xff, 0xfe]).unwrap_err().kind,
            ErrorKind::Malformed
        );
    }
}
