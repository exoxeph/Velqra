// SPDX-License-Identifier: GPL-3.0-only
//! A strict parser for the URLs the browser hands us. The browser has already normalised the URL, so
//! anything unusual (spaces, controls, non-ASCII, bad ports, bad hosts, credentials) is refused
//! instead of being "fixed". The result is a value that can be logged only as `redacted()`.

use std::net::Ipv6Addr;

pub const MAX_URL_BYTES: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlError {
    /// Credentials in the URL (kept separate: callers map it to a distinct error kind).
    Userinfo,
    /// Anything else; the reason is a fixed phrase and never contains the input.
    Invalid(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DownloadUrl {
    pub scheme: Scheme,
    /// Lower-case; an IPv6 literal is stored with its brackets.
    pub host: String,
    pub port: Option<u16>,
    /// Always starts with `/`; the fragment is dropped because it is never sent to a server.
    pub path_and_query: String,
}

impl std::fmt::Debug for DownloadUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DownloadUrl({})", self.redacted())
    }
}

impl DownloadUrl {
    /// Scheme and host only: safe for logs and error text.
    pub fn redacted(&self) -> String {
        format!("{}://{}", self.scheme.as_str(), self.host)
    }

    /// `scheme://host:port` with the default port filled in: the key for per-origin connection limits.
    pub fn origin(&self) -> String {
        format!(
            "{}://{}:{}",
            self.scheme.as_str(),
            self.host,
            self.port.unwrap_or(self.scheme.default_port())
        )
    }

    /// The normalised URL (fragment removed, host lower-cased).
    pub fn canonical(&self) -> String {
        let port = self.port.map(|p| format!(":{p}")).unwrap_or_default();
        format!(
            "{}://{}{}{}",
            self.scheme.as_str(),
            self.host,
            port,
            self.path_and_query
        )
    }
}

fn invalid(why: &'static str) -> UrlError {
    UrlError::Invalid(why)
}

fn parse_port(text: &str) -> Result<u16, UrlError> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) || text.len() > 5 {
        return Err(invalid("bad port"));
    }
    match text.parse::<u32>() {
        Ok(p) if (1..=65535).contains(&p) => Ok(p as u16),
        _ => Err(invalid("bad port")),
    }
}

fn is_ipv4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
                && p.parse::<u16>().is_ok_and(|v| v <= 255)
        })
}

fn check_domain(host: &str) -> Result<(), UrlError> {
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.is_empty() || name.len() > 253 {
        return Err(invalid("bad host"));
    }
    for label in name.split('.') {
        let well_formed = !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !well_formed {
            return Err(invalid("bad host"));
        }
    }
    // a name whose last label is all digits must be a complete dotted-quad address, as browsers read it
    let last = name.rsplit('.').next().unwrap_or("");
    if last.bytes().all(|b| b.is_ascii_digit()) && !is_ipv4(name) {
        return Err(invalid("bad host"));
    }
    Ok(())
}

pub fn parse_download_url(input: &str) -> Result<DownloadUrl, UrlError> {
    if input.len() > MAX_URL_BYTES {
        return Err(invalid("url too long"));
    }
    if !input.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(invalid("url has a space, control or non-ascii character"));
    }
    if input.contains(char::from(92u8)) {
        return Err(invalid("url has a backslash"));
    }
    let (scheme_text, rest) = input
        .split_once("://")
        .ok_or_else(|| invalid("url is not absolute"))?;
    let scheme = match scheme_text.to_ascii_lowercase().as_str() {
        "http" => Scheme::Http,
        "https" => Scheme::Https,
        _ => return Err(invalid("only http and https urls are accepted")),
    };
    let rest = rest.split('#').next().unwrap_or("");
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    if authority.contains('@') {
        return Err(UrlError::Userinfo);
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let close = inner.find(']').ok_or_else(|| invalid("bad host"))?;
        let addr: Ipv6Addr = inner[..close].parse().map_err(|_| invalid("bad host"))?;
        let after = &inner[close + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => Some(parse_port(p)?),
            None if after.is_empty() => None,
            None => return Err(invalid("bad host")),
        };
        (format!("[{addr}]"), port)
    } else {
        let (host_part, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(parse_port(p)?)),
            None => (authority, None),
        };
        if host_part.is_empty() {
            return Err(invalid("url has no host"));
        }
        let host = host_part.to_ascii_lowercase();
        check_domain(&host)?;
        (host, port)
    };
    // every percent sign must start a two-digit escape
    let b = tail.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        if c == b'%'
            && !(i + 2 < b.len() && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit())
        {
            return Err(invalid("bad percent escape"));
        }
    }
    let path_and_query = match tail {
        "" => "/".to_string(),
        t if t.starts_with('?') => format!("/{t}"),
        t => t.to_string(),
    };
    Ok(DownloadUrl {
        scheme,
        host,
        port,
        path_and_query,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ok(s: &str) -> DownloadUrl {
        parse_download_url(s).unwrap_or_else(|e| panic!("{s:?} was refused: {e:?}"))
    }

    fn bad(s: &str) {
        assert!(parse_download_url(s).is_err(), "{s:?} was accepted");
    }

    #[test]
    fn ordinary_urls_are_accepted_and_normalised() {
        let u = ok("HTTPS://EXAMPLE.com:8443/x/y.zip?a=1&b=%20#frag");
        assert_eq!(
            (u.scheme, u.host.as_str(), u.port),
            (Scheme::Https, "example.com", Some(8443))
        );
        assert_eq!(
            u.path_and_query, "/x/y.zip?a=1&b=%20",
            "the fragment is dropped"
        );
        assert_eq!(ok("http://example.com").path_and_query, "/");
        assert_eq!(ok("https://example.com?x=1").path_and_query, "/?x=1");
        assert_eq!(ok("http://127.0.0.1:8080/").host, "127.0.0.1");
        assert_eq!(ok("http://[::1]/a").host, "[::1]");
        assert_eq!(ok("https://[2001:db8::1]:443/p").port, Some(443));
        assert_eq!(ok("https://a.b-c.d/%E4%BD%A0").path_and_query, "/%E4%BD%A0");
        assert_eq!(ok("https://example.com./x").host, "example.com.");
        assert_eq!(ok("https://my_host.local/x").host, "my_host.local");
        assert_eq!(ok("https://localhost:3000/a").host, "localhost");
    }

    #[test]
    fn malformed_authorities_are_refused() {
        for s in [
            "https://[",
            "https://[::1",
            "https://[zz]/",
            "https://[::1%25eth0]/",
            "https://[::1]x/",
            "https://host:99999/",
            "https://host:65536/",
            "https://host:0/",
            "https://host:/",
            "https://host:12a/",
            "https://host:-1/",
            "https://ho st/",
            "https:///x",
            "http://",
            "https://host..com/",
            "https://.host.com/",
            "https://-bad.com/",
            "https://bad-.com/",
            "https://ho$t.com/",
            "https://1.2.3.4.5/",
            "https://999.1.1.1/",
            "https://1.2.3/",
            "https://01.2.3.4/",
            "https://1.2.3.04/",
        ] {
            bad(s);
        }
        bad(&format!("https://{}.com/", "a".repeat(64)));
        bad(&format!("https://{}/", ["abcdefghi"; 30].join(".")));
    }

    #[test]
    fn credentials_are_a_distinct_error() {
        for s in [
            "https://user@host/",
            "https://user:pw@host/",
            "https://@host/",
            "https://host@evil.com/",
        ] {
            assert_eq!(parse_download_url(s), Err(UrlError::Userinfo), "{s}");
        }
    }

    #[test]
    fn other_schemes_and_odd_characters_are_refused() {
        for s in [
            "ftp://host/",
            "file:///c:/x",
            "data:text/plain,hi",
            "javascript:alert(1)",
            "blob:https://host/uuid",
            "host/path",
            "",
            "https:/host/",
            "https//host/",
            "https://host/a b",
            "https://host/a\tb",
            "https://host/\u{7}",
            "https://host/a\nb",
            "https://host/\\a",
            "https://host/%zz",
            "https://host/%4",
            "https://host/%",
            "https://exämple.com/",
            "https://host/ü",
            "https://host/\u{202e}x",
        ] {
            bad(s);
        }
    }

    #[test]
    fn length_is_bounded() {
        let long_ok = format!(
            "https://h/{}",
            "a".repeat(MAX_URL_BYTES - "https://h/".len())
        );
        assert!(parse_download_url(&long_ok).is_ok());
        bad(&format!("{long_ok}a"));
    }

    #[test]
    fn the_redacted_form_shows_scheme_and_host_only() {
        let u = ok("https://Files.Example.com:8443/secret/path.zip?token=S3CR3T#x");
        assert_eq!(u.redacted(), "https://files.example.com");
        assert!(!format!("{u:?}").contains("S3CR3T") && !format!("{u:?}").contains("secret"));
        assert_eq!(u.origin(), "https://files.example.com:8443");
        assert_eq!(ok("http://a.test/x").origin(), "http://a.test:80");
        assert_eq!(ok("https://a.test/x").origin(), "https://a.test:443");
    }

    #[test]
    fn parsing_the_canonical_form_gives_the_same_value() {
        for s in [
            "HTTPS://EXAMPLE.com:8443/x?y=1#f",
            "http://[::1]:81/a%20b",
            "https://a.test",
        ] {
            let u = ok(s);
            assert_eq!(ok(&u.canonical()), u);
        }
    }

    proptest! {
        #[test]
        fn arbitrary_text_never_panics_and_accepted_urls_are_stable(s in "\\PC{0,200}") {
            if let Ok(u) = parse_download_url(&s) {
                prop_assert_eq!(parse_download_url(&u.canonical()).unwrap(), u);
            }
        }

        #[test]
        fn urls_built_from_url_like_pieces_never_panic(
            scheme in "(http|https|HTTP|ftp|)",
            host in "[a-zA-Z0-9.\\[\\]:@%-]{0,40}",
            path in "[ -~]{0,60}",
        ) {
            let _ = parse_download_url(&format!("{scheme}://{host}/{path}"));
        }
    }
}
