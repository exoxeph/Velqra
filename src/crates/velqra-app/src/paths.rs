// SPDX-License-Identifier: GPL-3.0-only
//! Where Velqra keeps its files and how the two programs agree on names. Every decision is a pure
//! function of explicit inputs; the thin `*_from_env` wrappers are the only code that reads the
//! environment, so tests never have to change process-wide state.

use crate::protector::UserProtector;
use std::io;
use std::path::{Path, PathBuf};
use velqra_bridge::host::is_extension_origin;
use velqra_bridge::secret::InstallSecret;
use velqra_core::file_vault::Protector;

/// The stable origin of the development extension (derived from the key in its manifest).
pub const DEV_EXTENSION_ORIGIN: &str = "chrome-extension://lclcokjjakhkabiokkmoaggpdlpaleaf/";

/// `VELQRA_HOME`, else `<LOCALAPPDATA>\Velqra`. No fallback to the current directory: files with a
/// secret in them must never end up wherever the process happened to start.
fn nonempty(v: Option<&str>) -> Option<&str> {
    v.filter(|s| !s.is_empty())
}

pub fn home_from(velqra_home: Option<&str>, local_app_data: Option<&str>) -> io::Result<PathBuf> {
    if let Some(h) = velqra_home {
        // an explicit but empty override is a mistake, not a request to fall back
        return nonempty(Some(h))
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "VELQRA_HOME is empty"));
    }
    nonempty(local_app_data)
        .map(|d| PathBuf::from(d).join("Velqra"))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no home directory: set VELQRA_HOME or LOCALAPPDATA",
            )
        })
}

/// The per-user pipe suffix: an explicit override, else the user name, both validated by `pipe_name`.
pub fn pipe_name_from(
    override_suffix: Option<&str>,
    user_name: Option<&str>,
) -> io::Result<String> {
    match (override_suffix, user_name) {
        (Some(o), _) => velqra_ipc::pipe_name(o),
        (None, Some(u)) => velqra_ipc::pipe_name(u),
        (None, None) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no user name for the pipe",
        )),
    }
}

/// Comma separated list; entries that are not exact extension origins are dropped (never widened).
/// Without a usable list only the development extension is allowed.
pub fn allowed_origins_from(list: Option<&str>) -> Vec<String> {
    let parsed: Vec<String> = list
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|o| is_extension_origin(o))
        .map(str::to_string)
        .collect();
    if parsed.is_empty() {
        vec![DEV_EXTENSION_ORIGIN.to_string()]
    } else {
        parsed
    }
}

pub fn secret_path(home: &Path) -> PathBuf {
    home.join("install-secret")
}

/// The core's settings file; only the core reads it.
pub fn settings_path(home: &Path) -> PathBuf {
    home.join("settings.json")
}

/// Where finished downloads go unless the settings name a folder: with an explicit `VELQRA_HOME`
/// (tests, development) always inside that home, so a test run can never write into a real
/// Downloads folder; otherwise `<USERPROFILE>\Downloads\Velqra`.
pub fn default_download_root(
    velqra_home: Option<&str>,
    user_profile: Option<&str>,
    home: &Path,
) -> PathBuf {
    match (velqra_home, nonempty(user_profile)) {
        (None, Some(profile)) => PathBuf::from(profile).join("Downloads").join("Velqra"),
        _ => home.join("downloads"),
    }
}

/// Directory of protected per-secret files (task contexts and download URLs).
pub fn vault_dir(home: &Path) -> PathBuf {
    home.join("vault")
}

pub fn db_path(home: &Path) -> PathBuf {
    home.join("core.db")
}

/// The secret file is `dpapi1:` + base64 of a current-user DPAPI blob. Files written before this
/// change hold the bare base64 key; they are accepted once and rewritten protected.
const SECRET_PREFIX: &str = "dpapi1:";
const SECRET_CONTEXT: &[u8] = b"install-secret";
const MAX_SECRET_FILE: usize = 4096;

fn damaged() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "the install secret file is damaged",
    )
}

fn key_from(bytes: Vec<u8>) -> io::Result<InstallSecret> {
    <[u8; 32]>::try_from(bytes)
        .map(InstallSecret::from_bytes)
        .map_err(|_| damaged())
}

fn protected_text(secret: &InstallSecret) -> io::Result<String> {
    let blob = UserProtector::default()
        .protect(secret.expose(), SECRET_CONTEXT)
        .map_err(io::Error::other)?;
    Ok(format!(
        "{SECRET_PREFIX}{}
",
        velqra_bridge::handshake::b64_encode(&blob)
    ))
}

/// Replaces the file with a complete protected copy in one step (readers see the old or the new).
fn rewrite_protected(home: &Path, secret: &InstallSecret) -> io::Result<()> {
    let tmp = home.join(format!(
        "install-secret.tmp-{}-{:x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::write(&tmp, protected_text(secret)?)?;
    let moved = std::fs::rename(&tmp, secret_path(home));
    if moved.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    moved
}

/// `Ok(None)` when no secret has been created yet; an error when the file exists but is not a secret.
pub fn load_secret(home: &Path) -> io::Result<Option<InstallSecret>> {
    // a real file is a few hundred bytes; the cap keeps a corrupt one from costing its size in memory
    let text = match velqra_core::bounded::read_file_capped(&secret_path(home), MAX_SECRET_FILE) {
        Ok(bytes) => String::from_utf8(bytes).map_err(|_| damaged())?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.kind() == io::ErrorKind::FileTooLarge => return Err(damaged()),
        Err(e) => return Err(e),
    };
    let text = text.trim();
    if let Some(body) = text.strip_prefix(SECRET_PREFIX) {
        let blob = velqra_bridge::handshake::b64_decode(body).ok_or_else(damaged)?;
        let plain = UserProtector::default()
            .unprotect(&blob, SECRET_CONTEXT)
            .map_err(|_| damaged())?;
        return key_from(plain).map(Some);
    }
    let legacy = velqra_bridge::handshake::b64_decode(text).ok_or_else(damaged)?;
    let secret = key_from(legacy)?;
    rewrite_protected(home, &secret)?;
    Ok(Some(secret))
}

/// Creates the secret exactly once (even if two processes race) and returns it.
pub fn ensure_secret(home: &Path) -> io::Result<InstallSecret> {
    std::fs::create_dir_all(home)?;
    if let Some(s) = load_secret(home)? {
        return Ok(s);
    }
    let fresh = InstallSecret::generate(&mut rand::rngs::OsRng);
    let text = protected_text(&fresh)?;
    // write a complete file first, then publish it with a hard link: that fails if the target already
    // exists, so racing creators cannot replace each other's secret and readers never see a partial file
    let tmp = home.join(format!(
        "install-secret.tmp-{}-{:x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::write(&tmp, text)?;
    let published = std::fs::hard_link(&tmp, secret_path(home));
    let _ = std::fs::remove_file(&tmp);
    match published {
        Ok(()) => Ok(fresh),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            load_secret(home)?.ok_or_else(|| io::Error::other("the install secret vanished"))
        }
        Err(e) => Err(e),
    }
}

pub fn home_dir() -> io::Result<PathBuf> {
    home_from(
        std::env::var("VELQRA_HOME").ok().as_deref(),
        std::env::var("LOCALAPPDATA").ok().as_deref(),
    )
}

pub fn pipe_name() -> io::Result<String> {
    pipe_name_from(
        std::env::var("VELQRA_PIPE").ok().as_deref(),
        std::env::var("USERNAME").ok().as_deref(),
    )
}

pub fn allowed_origins() -> Vec<String> {
    allowed_origins_from(std::env::var("VELQRA_ALLOWED_ORIGINS").ok().as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_prefers_the_override_then_local_app_data_and_never_the_current_directory() {
        assert_eq!(
            home_from(Some("C:/x"), Some("C:/y")).unwrap(),
            PathBuf::from("C:/x")
        );
        assert_eq!(
            home_from(None, Some("C:/y")).unwrap(),
            PathBuf::from("C:/y").join("Velqra")
        );
        assert!(home_from(None, None).is_err());
        assert!(
            home_from(Some(""), None).is_err(),
            "an empty override is not a path"
        );
        assert!(home_from(None, Some("")).is_err());
        assert!(
            home_from(Some(""), Some("C:/y")).is_err(),
            "an empty override must not fall back to LOCALAPPDATA"
        );
    }

    #[test]
    fn pipe_names_come_from_the_override_or_the_user_and_are_validated() {
        let n = pipe_name_from(Some("test-1"), Some("alice")).unwrap();
        assert!(n.ends_with("velqra-core-v1-test-1"), "{n}");
        let n = pipe_name_from(None, Some("alice")).unwrap();
        assert!(n.ends_with("velqra-core-v1-alice"), "{n}");
        assert!(pipe_name_from(None, None).is_err());
        assert!(
            pipe_name_from(Some("a/b"), Some("alice")).is_err(),
            "a bad override must not silently fall back"
        );
        assert!(
            pipe_name_from(None, Some("Domain User")).is_err(),
            "a user name that is not a plain token"
        );
    }

    #[test]
    fn the_allowlist_keeps_only_exact_origins_and_defaults_to_the_dev_extension() {
        let good = format!("chrome-extension://{}/", "b".repeat(32));
        assert_eq!(
            allowed_origins_from(Some(&format!("{good}, {DEV_EXTENSION_ORIGIN}"))),
            vec![good.clone(), DEV_EXTENSION_ORIGIN.to_string()]
        );
        assert_eq!(
            allowed_origins_from(Some("chrome-extension://*/,http://x/,")),
            vec![DEV_EXTENSION_ORIGIN.to_string()]
        );
        assert_eq!(
            allowed_origins_from(None),
            vec![DEV_EXTENSION_ORIGIN.to_string()]
        );
        assert_eq!(
            allowed_origins_from(Some("")),
            vec![DEV_EXTENSION_ORIGIN.to_string()]
        );
        assert!(is_extension_origin(DEV_EXTENSION_ORIGIN));
    }

    #[test]
    fn the_secret_is_created_once_and_read_back_identically() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_secret(dir.path()).unwrap().is_none());
        let a = ensure_secret(dir.path()).unwrap();
        let b = ensure_secret(dir.path()).unwrap();
        assert_eq!(a.expose(), b.expose());
        assert_eq!(
            load_secret(dir.path()).unwrap().unwrap().expose(),
            a.expose()
        );
        assert_ne!(a.expose(), &[0u8; 32]);
    }

    #[test]
    fn a_damaged_secret_file_is_an_error_not_a_new_secret() {
        for junk in ["", "AAAA", "not base64 at all!!", &"A".repeat(200)] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(secret_path(dir.path()), junk).unwrap();
            assert!(load_secret(dir.path()).is_err(), "{junk:?}");
            assert!(
                ensure_secret(dir.path()).is_err(),
                "silently replaced a damaged secret: {junk:?}"
            );
            assert_eq!(
                std::fs::read_to_string(secret_path(dir.path())).unwrap(),
                junk,
                "the damaged file was overwritten"
            );
        }
    }

    fn legacy_text(secret: &[u8; 32]) -> String {
        format!(
            "{}
",
            velqra_bridge::handshake::b64_encode(secret)
        )
    }

    #[test]
    fn the_secret_file_holds_a_protected_blob_not_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let s = ensure_secret(dir.path()).unwrap();
        let bytes = std::fs::read(secret_path(dir.path())).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.starts_with("dpapi1:"), "{text}");
        let b64 = velqra_bridge::handshake::b64_encode(s.expose());
        assert!(!text.contains(&b64), "the key is in the file as base64");
        assert!(
            !bytes.windows(32).any(|w| w == s.expose()),
            "the raw key is in the file"
        );
        assert_eq!(
            load_secret(dir.path()).unwrap().unwrap().expose(),
            s.expose()
        );
    }

    #[test]
    fn a_legacy_plaintext_secret_is_accepted_once_and_rewritten_protected() {
        let dir = tempfile::tempdir().unwrap();
        let key = [7u8; 32];
        std::fs::write(secret_path(dir.path()), legacy_text(&key)).unwrap();
        let got = load_secret(dir.path()).unwrap().unwrap();
        assert_eq!(got.expose(), &key, "the existing pairing keeps working");
        let after = std::fs::read_to_string(secret_path(dir.path())).unwrap();
        assert!(after.starts_with("dpapi1:"), "{after}");
        assert!(!after.contains(velqra_bridge::handshake::b64_encode(&key).as_str()));
        assert_eq!(load_secret(dir.path()).unwrap().unwrap().expose(), &key);
        assert_eq!(ensure_secret(dir.path()).unwrap().expose(), &key);
    }

    #[test]
    fn concurrent_upgrades_of_a_legacy_file_all_agree() {
        let dir = tempfile::tempdir().unwrap();
        let key = [9u8; 32];
        std::fs::write(secret_path(dir.path()), legacy_text(&key)).unwrap();
        let path = dir.path().to_path_buf();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let p = path.clone();
                std::thread::spawn(move || *load_secret(&p).unwrap().unwrap().expose())
            })
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), key);
        }
        assert!(std::fs::read_to_string(secret_path(&path))
            .unwrap()
            .starts_with("dpapi1:"));
        assert_eq!(load_secret(&path).unwrap().unwrap().expose(), &key);
    }

    #[test]
    fn a_damaged_protected_blob_is_an_error_and_the_file_is_untouched() {
        let dir = tempfile::tempdir().unwrap();
        ensure_secret(dir.path()).unwrap();
        let good = std::fs::read_to_string(secret_path(dir.path())).unwrap();
        let body = good.trim().strip_prefix("dpapi1:").unwrap().to_string();
        let mut flipped = body.clone().into_bytes();
        let mid = flipped.len() / 2;
        flipped[mid] = if flipped[mid] == b'A' { b'B' } else { b'A' };
        let bad_cases = [
            "dpapi1:".to_string(),
            "dpapi1:!!!!".to_string(),
            format!("dpapi1:{}", &body[..body.len() - 8]),
            format!("dpapi1:{}", String::from_utf8(flipped).unwrap()),
        ];
        for bad in bad_cases {
            std::fs::write(secret_path(dir.path()), &bad).unwrap();
            assert!(load_secret(dir.path()).is_err(), "{bad}");
            assert!(ensure_secret(dir.path()).is_err(), "replaced: {bad}");
            assert_eq!(
                std::fs::read_to_string(secret_path(dir.path())).unwrap(),
                bad
            );
        }
    }

    #[test]
    fn a_blob_made_for_another_purpose_is_refused() {
        use crate::protector::UserProtector;
        use velqra_core::file_vault::Protector;
        let dir = tempfile::tempdir().unwrap();
        let other = UserProtector::default()
            .protect(&[5u8; 32], b"something-else")
            .unwrap();
        std::fs::write(
            secret_path(dir.path()),
            format!("dpapi1:{}", velqra_bridge::handshake::b64_encode(&other)),
        )
        .unwrap();
        assert!(load_secret(dir.path()).is_err());
    }

    #[test]
    fn two_racing_creators_end_up_with_the_same_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let p = path.clone();
                std::thread::spawn(move || *ensure_secret(&p).unwrap().expose())
            })
            .collect();
        let secrets: Vec<[u8; 32]> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(
            secrets.windows(2).all(|w| w[0] == w[1]),
            "racing creators disagreed"
        );
    }

    #[test]
    fn the_secret_file_never_shows_up_in_the_database_path_or_names() {
        let dir = tempfile::tempdir().unwrap();
        assert_ne!(secret_path(dir.path()), db_path(dir.path()));
        assert!(db_path(dir.path()).ends_with("core.db"));
    }
}

#[cfg(test)]
mod download_root_tests {
    use super::*;

    #[test]
    fn an_explicit_home_keeps_downloads_inside_it_and_the_default_uses_the_profile() {
        let home = Path::new(r"C:\h\velqra");
        assert_eq!(
            default_download_root(Some(r"C:\h\velqra"), Some(r"C:\Users\me"), home),
            home.join("downloads")
        );
        assert_eq!(
            default_download_root(None, Some(r"C:\Users\me"), home),
            Path::new(r"C:\Users\me").join("Downloads").join("Velqra")
        );
        assert_eq!(
            default_download_root(None, None, home),
            home.join("downloads")
        );
        assert_eq!(
            default_download_root(None, Some(""), home),
            home.join("downloads")
        );
        assert!(settings_path(home).ends_with("settings.json"));
    }
}
