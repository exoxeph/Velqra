// SPDX-License-Identifier: GPL-3.0-only
//! Pure logic of the native-messaging host: who may start it, how a first-time pairing hands the
//! install secret to the extension, and relaying frames with their size limits. The host never
//! classifies or stores anything; it forwards bytes between Chrome's stdio and the core's pipe.

use crate::frame::{
    encode_frame, FrameDecoder, FrameError, MAX_ENVELOPE, MAX_HANDSHAKE, MAX_TO_BROWSER,
};
use crate::handshake::b64_encode;
use crate::secret::InstallSecret;
use serde_json::json;

pub const HOST_NAME: &str = "com.velqra.host";

/// `chrome-extension://` + 32 characters a-p + `/`, exactly: no wildcard, no path, no uppercase.
pub fn is_extension_origin(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("chrome-extension://") else {
        return false;
    };
    let Some(id) = rest.strip_suffix('/') else {
        return false;
    };
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

/// Chrome passes the caller's origin as an argument (plus, on Windows, `--parent-window=N`).
/// Exactly one origin argument must be present and well formed.
pub fn parse_origin(args: &[String]) -> Option<String> {
    let mut candidates = args.iter().filter(|a| a.starts_with("chrome-extension://"));
    let first = candidates.next()?;
    (candidates.next().is_none() && is_extension_origin(first)).then(|| first.clone())
}

/// The native messaging host manifest Chrome reads. Origins are listed exactly, never as wildcards.
pub fn native_manifest(host_path: &str, origins: &[String]) -> Result<String, &'static str> {
    if host_path.is_empty() {
        return Err("host path is empty");
    }
    if origins.is_empty() {
        return Err("at least one allowed origin is required");
    }
    if !origins.iter().all(|o| is_extension_origin(o)) {
        return Err("origins must be exact extension origins");
    }
    let manifest = json!({
        "name": HOST_NAME,
        "description": "Velqra native messaging host",
        "path": host_path,
        "type": "stdio",
        "allowed_origins": origins,
    });
    Ok(serde_json::to_string_pretty(&manifest).expect("manifest serialises"))
}

/// Exactly `{"t":"pair"}`: any extra field or odd shape is not a pairing request.
fn is_pair_request(payload: &[u8]) -> bool {
    if payload.len() > MAX_HANDSHAKE {
        return false;
    }
    matches!(velqra_protocol::parse_strict_json(payload), Ok(serde_json::Value::Object(m)) if m.len() == 1 && m.get("t").and_then(|t| t.as_str()) == Some("pair"))
}

/// What the host must do with bytes it received.
#[derive(PartialEq, Eq)]
pub enum Out {
    /// Framed bytes for the core's pipe.
    ToPipe(Vec<u8>),
    /// Framed bytes for Chrome (stdout).
    ToBrowser(Vec<u8>),
}

/// Framed bytes can carry the install secret (the pairing reply), so they are never printed.
impl std::fmt::Debug for Out {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Out::ToPipe(b) => write!(f, "ToPipe(<{} bytes>)", b.len()),
            Out::ToBrowser(b) => write!(f, "ToBrowser(<{} bytes>)", b.len()),
        }
    }
}

pub struct HostRelay {
    origin: String,
    secret: Option<InstallSecret>,
    from_browser: FrameDecoder,
    from_pipe: FrameDecoder,
}

impl std::fmt::Debug for HostRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HostRelay {{ origin: {}, secret: <redacted> }}",
            self.origin
        )
    }
}

impl HostRelay {
    /// Refuses to exist for an origin that is not on the allowlist.
    pub fn new(
        origin: &str,
        allowed: &[String],
        secret: Option<InstallSecret>,
    ) -> Result<Self, &'static str> {
        if !is_extension_origin(origin) || !allowed.iter().any(|a| a == origin) {
            return Err("origin is not allowed");
        }
        Ok(Self {
            origin: origin.to_string(),
            secret,
            from_browser: FrameDecoder::new(MAX_ENVELOPE),
            from_pipe: FrameDecoder::new(MAX_TO_BROWSER),
        })
    }

    /// The first frame the host sends on a new pipe connection.
    pub fn attach_frame(&self) -> Vec<u8> {
        let v = json!({"t": "attach", "origin": self.origin});
        encode_frame(v.to_string().as_bytes(), MAX_HANDSHAKE).expect("attach frame is small")
    }

    /// Bytes read from Chrome. A `pair` request is answered here and never reaches the core.
    pub fn from_browser(&mut self, bytes: &[u8]) -> Result<Vec<Out>, FrameError> {
        let mut out = Vec::new();
        for payload in self.from_browser.feed(bytes)? {
            if is_pair_request(&payload) {
                let reply = match &self.secret {
                    Some(s) => json!({"t": "paired", "secret": b64_encode(s.expose())}),
                    None => json!({"t": "reject", "code": "no_secret"}),
                };
                out.push(Out::ToBrowser(encode_frame(
                    reply.to_string().as_bytes(),
                    MAX_TO_BROWSER,
                )?));
            } else {
                out.push(Out::ToPipe(encode_frame(&payload, MAX_ENVELOPE)?));
            }
        }
        Ok(out)
    }

    /// Bytes read from the core's pipe, checked against Chrome's host-to-browser limit.
    pub fn from_pipe(&mut self, bytes: &[u8]) -> Result<Vec<Out>, FrameError> {
        let mut out = Vec::new();
        for payload in self.from_pipe.feed(bytes)? {
            out.push(Out::ToBrowser(encode_frame(&payload, MAX_TO_BROWSER)?));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameDecoder;

    const ID: &str = "abcdefghijklmnopabcdefghijklmnop";

    fn origin() -> String {
        format!("chrome-extension://{ID}/")
    }

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn secret() -> InstallSecret {
        InstallSecret::from_bytes([7; 32])
    }

    fn frame(v: serde_json::Value) -> Vec<u8> {
        encode_frame(v.to_string().as_bytes(), MAX_TO_BROWSER).unwrap()
    }

    fn payloads(out: &[Out], browser: bool) -> Vec<serde_json::Value> {
        let mut v = Vec::new();
        for o in out {
            let bytes = match (o, browser) {
                (Out::ToBrowser(b), true) | (Out::ToPipe(b), false) => b,
                _ => continue,
            };
            let mut d = FrameDecoder::new(MAX_TO_BROWSER);
            for p in d.feed(bytes).unwrap() {
                v.push(serde_json::from_slice(&p).unwrap());
            }
        }
        v
    }

    #[test]
    fn origin_syntax_is_exact() {
        assert!(is_extension_origin(&origin()));
        for bad in [
            "chrome-extension://*/",
            "chrome-extension://abcdefghijklmnopabcdefghijklmno/",
            "chrome-extension://abcdefghijklmnopabcdefghijklmnopa/",
            "chrome-extension://ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP/",
            "chrome-extension://abcdefghijklmnopabcdefghijklmnoq/",
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/x",
            "http://abcdefghijklmnopabcdefghijklmnop/",
            "",
        ] {
            assert!(!is_extension_origin(bad), "{bad:?}");
        }
    }

    #[test]
    fn parse_origin_takes_exactly_one_well_formed_origin_and_ignores_other_arguments() {
        let o = origin();
        assert_eq!(parse_origin(&args(&[&o])), Some(o.clone()));
        assert_eq!(
            parse_origin(&args(&[&o, "--parent-window=1234"])),
            Some(o.clone())
        );
        assert_eq!(
            parse_origin(&args(&["--parent-window=1234", &o])),
            Some(o.clone())
        );
        assert_eq!(parse_origin(&args(&[])), None);
        assert_eq!(parse_origin(&args(&["--parent-window=1234"])), None);
        assert_eq!(parse_origin(&args(&["chrome-extension://*/"])), None);
        assert_eq!(parse_origin(&args(&["chrome-extension://short/"])), None);
        let other = format!("chrome-extension://{}/", "b".repeat(32));
        assert_eq!(
            parse_origin(&args(&[&o, &other])),
            None,
            "two origins are ambiguous"
        );
        assert_eq!(
            parse_origin(&args(&[&o, &o])),
            None,
            "a repeated origin is still two arguments"
        );
    }

    #[test]
    fn the_manifest_lists_exact_origins_and_nothing_else() {
        let m = native_manifest("C:\\Velqra\\velqra-host.exe", &[origin()]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&m).unwrap();
        assert_eq!(v["name"], HOST_NAME);
        assert_eq!(v["type"], "stdio");
        assert_eq!(v["path"], "C:\\Velqra\\velqra-host.exe");
        assert_eq!(v["allowed_origins"], json!([origin()]));
        assert!(!m.contains('*'));
        assert_eq!(
            v.as_object().unwrap().len(),
            5,
            "name, description, path, type, allowed_origins: {v}"
        );
        assert!(
            native_manifest("p", &[]).is_err(),
            "a host that anyone may start"
        );
        assert!(native_manifest("p", &["chrome-extension://*/".to_string()]).is_err());
        assert!(native_manifest("", &[origin()]).is_err());
    }

    #[test]
    fn the_relay_refuses_an_origin_that_is_not_allowed() {
        let other = format!("chrome-extension://{}/", "b".repeat(32));
        assert!(HostRelay::new(&other, &[origin()], Some(secret())).is_err());
        assert!(HostRelay::new(
            "chrome-extension://*/",
            &["chrome-extension://*/".to_string()],
            None
        )
        .is_err());
        assert!(HostRelay::new(&origin(), &[origin()], Some(secret())).is_ok());
    }

    #[test]
    fn the_attach_frame_names_the_verified_origin() {
        let r = HostRelay::new(&origin(), &[origin()], None).unwrap();
        let mut d = FrameDecoder::new(MAX_HANDSHAKE);
        let p = d.feed(&r.attach_frame()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&p[0]).unwrap();
        assert_eq!(v, json!({"t": "attach", "origin": origin()}));
    }

    #[test]
    fn pairing_is_answered_locally_and_never_forwarded() {
        let mut r = HostRelay::new(&origin(), &[origin()], Some(secret())).unwrap();
        let out = r.from_browser(&frame(json!({"t": "pair"}))).unwrap();
        assert!(
            payloads(&out, false).is_empty(),
            "the pair request reached the core"
        );
        let back = payloads(&out, true);
        assert_eq!(
            back,
            vec![json!({"t": "paired", "secret": b64_encode(&[7; 32])})]
        );
    }

    #[test]
    fn pairing_without_a_secret_is_refused_with_a_fixed_code() {
        let mut r = HostRelay::new(&origin(), &[origin()], None).unwrap();
        let out = r.from_browser(&frame(json!({"t": "pair"}))).unwrap();
        assert_eq!(
            payloads(&out, true),
            vec![json!({"t": "reject", "code": "no_secret"})]
        );
    }

    #[test]
    fn a_pair_request_with_extra_fields_is_not_a_pair_request() {
        let mut r = HostRelay::new(&origin(), &[origin()], Some(secret())).unwrap();
        let out = r
            .from_browser(&frame(json!({"t": "pair", "x": 1})))
            .unwrap();
        assert!(
            payloads(&out, true).is_empty(),
            "answered a malformed pair request with the secret"
        );
        assert_eq!(
            payloads(&out, false).len(),
            1,
            "it is passed on and the core will reject it"
        );
    }

    #[test]
    fn other_frames_are_forwarded_byte_for_byte_and_split_input_works() {
        let mut r = HostRelay::new(&origin(), &[origin()], Some(secret())).unwrap();
        let f = frame(json!({"t": "hello", "v": [1], "cn": "AAAA"}));
        let mut out = Vec::new();
        for b in &f {
            out.extend(r.from_browser(&[*b]).unwrap());
        }
        assert_eq!(out, vec![Out::ToPipe(f)]);
    }

    #[test]
    fn oversize_frames_from_the_browser_are_refused_from_the_header() {
        let mut r = HostRelay::new(&origin(), &[origin()], None).unwrap();
        let too_big = (MAX_ENVELOPE as u32 + 1).to_ne_bytes();
        assert_eq!(r.from_browser(&too_big), Err(FrameError::TooLarge));
    }

    #[test]
    fn frames_from_the_pipe_are_limited_to_what_chrome_accepts() {
        let mut r = HostRelay::new(&origin(), &[origin()], None).unwrap();
        let ok = encode_frame(&vec![b'a'; 1000], MAX_TO_BROWSER).unwrap();
        assert_eq!(r.from_pipe(&ok).unwrap(), vec![Out::ToBrowser(ok.clone())]);
        // Chrome accepts up to 1 MiB from a host, more than the 256 KiB the core accepts from the browser
        let big = encode_frame(&vec![b'a'; 300_000], MAX_TO_BROWSER).unwrap();
        assert_eq!(
            r.from_pipe(&big).unwrap(),
            vec![Out::ToBrowser(big.clone())]
        );
        let too_big = (MAX_TO_BROWSER as u32 + 1).to_ne_bytes();
        assert_eq!(r.from_pipe(&too_big), Err(FrameError::TooLarge));
    }

    #[test]
    fn the_relay_never_prints_the_secret() {
        let r = HostRelay::new(&origin(), &[origin()], Some(secret())).unwrap();
        let d = format!("{r:?}");
        assert!(d.contains("redacted") && !d.contains("[7"), "{d}");
    }

    #[test]
    fn debug_output_of_relay_results_never_contains_frame_bytes() {
        // the pairing reply carries the install secret: its framed bytes must not be printable
        let mut r = HostRelay::new(&origin(), &[origin()], Some(secret())).unwrap();
        let out = r.from_browser(&frame(json!({"t": "pair"}))).unwrap();
        let shown = format!("{out:?}");
        let b64 = b64_encode(&[7; 32]);
        let decimal_secret = format!("{:?}", &[7u8; 32][..8]); // "[7, 7, 7, ..."
        let frame_bytes = match &out[0] {
            Out::ToBrowser(b) => format!("{:?}", &b[..12]),
            Out::ToPipe(_) => panic!("pairing is answered to the browser"),
        };
        assert!(!shown.contains(&b64), "base64 secret in Debug: {shown}");
        assert!(
            !shown.contains(&decimal_secret),
            "decimal secret bytes in Debug: {shown}"
        );
        assert!(
            !shown.contains(frame_bytes.trim_start_matches('[').trim_end_matches(']')),
            "frame bytes in Debug: {shown}"
        );
        assert!(
            shown.contains("ToBrowser") && shown.contains("bytes"),
            "Debug should still say what happened: {shown}"
        );
    }
}
