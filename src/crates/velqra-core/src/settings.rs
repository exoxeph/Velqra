// SPDX-License-Identifier: GPL-3.0-only
//! The core's own settings, read from `settings.json` in the Velqra home directory. Only the core
//! reads this file; the extension gets a read-only snapshot and no message can change anything.
//! Loading is strict: an unknown key, a wrong type or a bad value refuses the whole file, the
//! defaults stay in force, and a fixed phrase says so. Error text never contains file content.

use crate::bounded::read_file_capped;
use crate::destination::{default_categories, Category, DestinationPolicy};
use crate::path_policy::validate_filename;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use velqra_protocol::download_url::parse_download_url;
use velqra_protocol::{parse_strict_json, CaptureMode, SettingsSnapshot};

pub const MAX_SETTINGS_BYTES: usize = 64 * 1024;
const MAX_SUFFIXES: usize = 256;
const MAX_SITES: usize = 512;
const MAX_CATEGORIES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SettingsError(pub &'static str);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Downloads running at once.
    pub max_active: u32,
    /// Download tasks to one origin at once.
    pub per_origin: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_active: 3,
            per_origin: 4,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
    pub mode: CaptureMode,
    /// Suffixes handed to Velqra (lower-case, no dot). Documents are opt-in.
    pub extensions: Vec<String>,
    pub excluded_sites: Vec<String>,
    pub allowed_sites: Vec<String>,
    /// Absolute folder for finished downloads; the app supplies a default when absent.
    pub destination_root: Option<String>,
    pub categories: Vec<Category>,
    pub limits: Limits,
    /// Segments/connections per transfer; independent from task scheduling, off at 1.
    pub segments: u32,
}

impl Default for Settings {
    fn default() -> Self {
        let exts = [
            "zip", "7z", "tar", "gz", "bz2", "xz", "zst", "exe", "msi", "msix", "iso", "img",
            "mp3", "m4a", "flac", "wav", "ogg", "opus", "mp4", "mkv", "webm",
        ];
        Self {
            mode: CaptureMode::On,
            extensions: exts.iter().map(|e| e.to_string()).collect(),
            excluded_sites: Vec::new(),
            allowed_sites: Vec::new(),
            destination_root: None,
            categories: default_categories(),
            limits: Limits::default(),
            segments: 1,
        }
    }
}

/// What loading produced: always usable settings, plus a fixed phrase when the file was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Loaded {
    pub settings: Settings,
    pub problem: Option<&'static str>,
}

fn plain_suffix(s: &str) -> bool {
    (1..=16).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// `host` or `*.host`, lower-case, no port, no scheme, no path.
fn valid_site(s: &str) -> bool {
    let host = s.strip_prefix("*.").unwrap_or(s);
    if host.is_empty() || host != host.to_ascii_lowercase() || host.contains([':', '/', '@']) {
        return false;
    }
    parse_download_url(&format!("https://{host}/")).is_ok_and(|u| u.host == host)
}

impl Settings {
    pub fn validate(&self) -> Result<(), SettingsError> {
        let bad = |why: &'static str| Err(SettingsError(why));
        if self.extensions.len() > MAX_SUFFIXES || !self.extensions.iter().all(|e| plain_suffix(e))
        {
            return bad("capture suffixes must be lower-case letters and digits");
        }
        for sites in [&self.excluded_sites, &self.allowed_sites] {
            if sites.len() > MAX_SITES || !sites.iter().all(|s| valid_site(s)) {
                return bad("site entries must be lower-case host names");
            }
        }
        if let Some(root) = &self.destination_root {
            let p = Path::new(root);
            let plain = !root.is_empty()
                && root.len() <= 240
                && !root.contains('\0')
                && p.is_absolute()
                && p.components().all(|c| !matches!(c, Component::ParentDir));
            if !plain {
                return bad("the destination folder must be an absolute path without ..");
            }
        }
        if self.categories.len() > MAX_CATEGORIES {
            return bad("too many categories");
        }
        for c in &self.categories {
            if validate_filename(&c.folder).is_err() {
                return bad("a category folder is not a valid folder name");
            }
            if c.extensions.len() > MAX_SUFFIXES || !c.extensions.iter().all(|e| plain_suffix(e)) {
                return bad("category suffixes must be lower-case letters and digits");
            }
        }
        if !(1..=16).contains(&self.segments) {
            return bad("segments must be between 1 and 16");
        }
        let range = 1..=16;
        if !range.contains(&self.limits.max_active) || !range.contains(&self.limits.per_origin) {
            return bad("limits must be between 1 and 16");
        }
        Ok(())
    }

    /// Strict parse: size, syntax, duplicate keys, unknown keys, types, then values.
    pub fn parse(text: &[u8]) -> Result<Settings, SettingsError> {
        if text.len() > MAX_SETTINGS_BYTES {
            return Err(SettingsError("the settings file is too large"));
        }
        let value = parse_strict_json(text)
            .map_err(|_| SettingsError("the settings file is not valid JSON"))?;
        // serde would also build a struct from an array, so the shape is checked first
        let object = |v: &serde_json::Value| v.is_object();
        let shape_ok = object(&value)
            && value.get("limits").is_none_or(object)
            && value
                .get("categories")
                .is_none_or(|c| c.as_array().is_some_and(|a| a.iter().all(object)));
        if !shape_ok {
            return Err(SettingsError("the settings file has the wrong shape"));
        }
        let settings: Settings = serde_json::from_value(value)
            .map_err(|_| SettingsError("the settings file has an unknown key or a wrong type"))?;
        settings.validate()?;
        Ok(settings)
    }

    /// A missing file means the defaults and no problem; anything else refused means the defaults and a phrase.
    pub fn load_file(path: &Path) -> Loaded {
        match read_file_capped(path, MAX_SETTINGS_BYTES) {
            Ok(bytes) => match Settings::parse(&bytes) {
                Ok(settings) => Loaded {
                    settings,
                    problem: None,
                },
                Err(e) => Loaded {
                    settings: Settings::default(),
                    problem: Some(e.0),
                },
            },
            Err(e) if e.kind() == std::io::ErrorKind::FileTooLarge => Loaded {
                settings: Settings::default(),
                problem: Some("the settings file is too large"),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Loaded {
                settings: Settings::default(),
                problem: None,
            },
            Err(_) => Loaded {
                settings: Settings::default(),
                problem: Some("the settings file could not be read"),
            },
        }
    }

    /// The part the extension may see: no folders.
    pub fn snapshot(&self, problem: Option<&str>) -> SettingsSnapshot {
        SettingsSnapshot {
            transfer_capable: true,
            mode: self.mode,
            extensions: self.extensions.clone(),
            excluded_sites: self.excluded_sites.clone(),
            allowed_sites: self.allowed_sites.clone(),
            problem: problem.map(str::to_string),
        }
    }

    pub fn destination_policy(&self, default_root: PathBuf) -> DestinationPolicy {
        DestinationPolicy {
            root: self
                .destination_root
                .as_ref()
                .map(PathBuf::from)
                .unwrap_or(default_root),
            categories: self.categories.clone(),
            fallback_folder: "Other".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Settings, SettingsError> {
        Settings::parse(text.as_bytes())
    }

    #[test]
    fn segmentation_is_separate_validated_and_defaults_off() {
        assert_eq!(
            parse(r#"{"limits":{"per_origin":16}}"#).unwrap().segments,
            1
        );
        assert_eq!(parse(r#"{"segments":3}"#).unwrap().segments, 3);
        for bad in ["0", "17", "-1", "true", "1.5"] {
            assert!(parse(&format!("{{\"segments\":{bad}}}")).is_err());
        }
    }

    #[test]
    fn the_defaults_equal_the_spec_list() {
        let s = Settings::default();
        assert_eq!(s.mode, CaptureMode::On);
        assert_eq!(
            s.extensions.join(","),
            "zip,7z,tar,gz,bz2,xz,zst,exe,msi,msix,iso,img,mp3,m4a,flac,wav,ogg,opus,mp4,mkv,webm"
        );
        for opt_in in ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "epub"] {
            assert!(!s.extensions.iter().any(|e| e == opt_in), "{opt_in}");
        }
        assert_eq!((s.limits.max_active, s.limits.per_origin), (3, 4));
        assert!(s.excluded_sites.is_empty() && s.allowed_sites.is_empty());
        assert!(s.destination_root.is_none());
        assert!(s.validate().is_ok());
    }

    #[test]
    fn an_empty_object_and_a_partial_file_fill_in_the_defaults() {
        assert_eq!(parse("{}").unwrap(), Settings::default());
        let s =
            parse(r#"{"mode":"per_site","allowed_sites":["a.example","*.b.example"]}"#).unwrap();
        assert_eq!(s.mode, CaptureMode::PerSite);
        assert_eq!(s.allowed_sites.len(), 2);
        assert_eq!(s.extensions, Settings::default().extensions);
        let s = parse(r#"{"limits":{"max_active":5}}"#).unwrap();
        assert_eq!((s.limits.max_active, s.limits.per_origin), (5, 4));
    }

    #[test]
    fn a_full_valid_file_round_trips() {
        let s = Settings {
            mode: CaptureMode::Off,
            excluded_sites: vec!["x.example".into()],
            destination_root: Some(r"C:\Users\me\Downloads\Velqra".into()),
            ..Settings::default()
        };
        let text = serde_json::to_string(&s).unwrap();
        assert_eq!(parse(&text).unwrap(), s);
    }

    #[test]
    fn unknown_keys_wrong_types_and_duplicates_are_refused() {
        for bad in [
            r#"{"nope":1}"#,
            r#"{"mode":"always"}"#,
            r#"{"mode":1}"#,
            r#"{"extensions":"zip"}"#,
            r#"{"limits":{"max_active":3,"colour":"red"}}"#,
            r#"{"mode":"on","mode":"off"}"#,
            r#"{"categories":[{"folder":"A","extensions":[],"x":1}]}"#,
            r#"[]"#,
            r#"{"limits":[3,4]}"#,
            r#"{"limits":3}"#,
            r#"{"categories":[["Docs",["pdf"]]]}"#,
            r#"{"categories":{"folder":"A","extensions":[]}}"#,
            r#"null"#,
            "",
            "{",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn suffixes_follow_the_final_suffix_rules() {
        for bad in [
            "Zip",
            ".zip",
            "z/ip",
            "",
            "a b",
            "z\u{ef}p",
            "tar.gz",
            &"x".repeat(17),
        ] {
            let text = serde_json::json!({ "extensions": [bad] }).to_string();
            assert!(parse(&text).is_err(), "{bad:?}");
        }
        assert!(parse(r#"{"extensions":["zip","7z","mp4"]}"#).is_ok());
        let many: Vec<String> = (0..257).map(|i| format!("a{i}")).collect();
        let text = serde_json::json!({ "extensions": many }).to_string();
        assert!(parse(&text).is_err());
    }

    #[test]
    fn site_entries_are_lower_case_host_names_or_wildcards() {
        for good in [
            "example.com",
            "a.b.example",
            "*.example.com",
            "localhost",
            "127.0.0.1",
        ] {
            let text = serde_json::json!({ "excluded_sites": [good] }).to_string();
            assert!(parse(&text).is_ok(), "{good}");
        }
        for bad in [
            "Example.com",
            "http://example.com",
            "example.com:8080",
            "example.com/x",
            "user@example.com",
            "*",
            "*.",
            "*.*.example.com",
            "exa mple.com",
            "",
            "-bad.com",
            "[::1]",
            "*example.com",
        ] {
            let text = serde_json::json!({ "allowed_sites": [bad] }).to_string();
            assert!(parse(&text).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_destination_root_must_be_absolute_and_plain() {
        for bad in ["", "downloads", r"..\x", r"C:\a\..\b", "C:rel"] {
            let text = serde_json::json!({ "destination_root": bad }).to_string();
            assert!(parse(&text).is_err(), "{bad:?}");
        }
        assert!(parse(r#"{"destination_root":"C:\\Users\\me\\Downloads"}"#).is_ok());
    }

    #[test]
    fn category_folders_and_limits_are_validated() {
        for bad in ["", "..", "a/b", "CON", "x.", "a:b"] {
            let text =
                serde_json::json!({"categories":[{"folder":bad,"extensions":["zip"]}]}).to_string();
            assert!(parse(&text).is_err(), "{bad:?}");
        }
        for limits in [
            r#"{"max_active":0}"#,
            r#"{"max_active":17}"#,
            r#"{"per_origin":0}"#,
            r#"{"per_origin":-1}"#,
        ] {
            assert!(
                parse(&format!(r#"{{"limits":{limits}}}"#)).is_err(),
                "{limits}"
            );
        }
        assert!(parse(r#"{"limits":{"max_active":16,"per_origin":1}}"#).is_ok());
    }

    #[test]
    fn a_damaged_file_keeps_the_defaults_and_reports_without_echoing_content() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("settings.json");
        let missing = Settings::load_file(&path);
        assert_eq!(
            missing,
            Loaded {
                settings: Settings::default(),
                problem: None
            }
        );
        std::fs::write(&path, br#"{"mode":"S3CR3T-NOT-A-MODE"}"#).unwrap();
        let bad = Settings::load_file(&path);
        assert_eq!(bad.settings, Settings::default());
        let problem = bad.problem.expect("reported");
        assert!(!problem.contains("S3CR3T"), "{problem}");
        std::fs::write(&path, vec![b' '; MAX_SETTINGS_BYTES + 1]).unwrap();
        assert!(Settings::load_file(&path).problem.is_some());
        std::fs::write(&path, br#"{"mode":"off"}"#).unwrap();
        let good = Settings::load_file(&path);
        assert_eq!((good.settings.mode, good.problem), (CaptureMode::Off, None));
        let unreadable = Settings::load_file(d.path()); // a directory is not a readable file
        assert!(unreadable.problem.is_some() && unreadable.settings == Settings::default());
    }

    #[test]
    fn the_snapshot_carries_no_folder_and_the_policy_uses_the_override_or_the_default() {
        let s = Settings {
            destination_root: Some(r"C:\secret-folder-name\dl".into()),
            ..Settings::default()
        };
        let snap = s.snapshot(Some("settings file refused"));
        let text = serde_json::to_string(&snap).unwrap();
        assert!(
            !text.contains("secret-folder-name") && !text.contains("Compressed"),
            "{text}"
        );
        assert_eq!(snap.problem.as_deref(), Some("settings file refused"));
        assert_eq!(
            s.destination_policy(PathBuf::from(r"C:\default")).root,
            PathBuf::from(r"C:\secret-folder-name\dl")
        );
        let d = Settings::default();
        assert_eq!(
            d.destination_policy(PathBuf::from(r"C:\default")).root,
            PathBuf::from(r"C:\default")
        );
        assert_eq!(
            d.destination_policy(PathBuf::from("x")).categories,
            default_categories()
        );
    }
}
