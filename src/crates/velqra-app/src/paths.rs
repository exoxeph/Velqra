// SPDX-License-Identifier: GPL-3.0-only
//! Where Velqra keeps its files and how the two programs agree on names. Every decision is a pure
//! function of explicit inputs; the thin `*_from_env` wrappers are the only code that reads the
//! environment, so tests never have to change process-wide state.

use std::io;
use std::path::{Path, PathBuf};
use velqra_bridge::host::is_extension_origin;
use velqra_bridge::secret::InstallSecret;

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

pub fn db_path(home: &Path) -> PathBuf {
    home.join("core.db")
}

/// `Ok(None)` when no secret has been created yet; an error when the file exists but is not a secret.
pub fn load_secret(home: &Path) -> io::Result<Option<InstallSecret>> {
    let text = match std::fs::read_to_string(secret_path(home)) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let bytes = velqra_bridge::handshake::b64_decode(text.trim())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the install secret file is damaged",
            )
        })?;
    Ok(Some(InstallSecret::from_bytes(bytes)))
}

/// Creates the secret exactly once (even if two processes race) and returns it.
pub fn ensure_secret(home: &Path) -> io::Result<InstallSecret> {
    std::fs::create_dir_all(home)?;
    if let Some(s) = load_secret(home)? {
        return Ok(s);
    }
    let fresh = InstallSecret::generate(&mut rand::rngs::OsRng);
    let text = format!(
        "{}
",
        velqra_bridge::handshake::b64_encode(fresh.expose())
    );
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
