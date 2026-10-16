// SPDX-License-Identifier: GPL-3.0-only
//! Where a download will be written. The core picks `root/<category>/<name>` at Prepare, from its own
//! settings and the file name alone, and holds the choice as a reservation. Page messages never
//! name a folder.

use crate::path_policy::{
    finalize_check, fold_key, sanitize_filename, validate_filename, validate_root, MAX_NAME_UNITS,
};
use crate::store::Reservation;
use crate::write_probe::dir_is_writable;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Category {
    pub folder: String,
    /// Lower-case suffixes without the dot; only the final suffix of a name is looked at.
    pub extensions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestinationPolicy {
    pub root: PathBuf,
    pub categories: Vec<Category>,
    pub fallback_folder: String,
}

/// The built-in folders and the final suffixes that select them (our own list, see the spec).
pub fn default_categories() -> Vec<Category> {
    let cat = |folder: &str, exts: &[&str]| Category {
        folder: folder.to_string(),
        extensions: exts.iter().map(|e| e.to_string()).collect(),
    };
    vec![
        cat(
            "Compressed",
            &["zip", "7z", "tar", "gz", "bz2", "xz", "zst"],
        ),
        cat("Programs", &["exe", "msi", "msix"]),
        cat("Disk Images", &["iso", "img"]),
        cat("Music", &["mp3", "m4a", "flac", "wav", "ogg", "opus"]),
        cat("Video", &["mp4", "mkv", "webm"]),
        cat(
            "Documents",
            &["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "epub"],
        ),
    ]
}

/// How many " (n)" suffixes are tried before Prepare gives up.
const MAX_SUFFIX: u32 = 999;
/// .velqra-part (12) + .stale-9999 (11) + .aria2 (6).
pub const INTERNAL_SUFFIX_UNITS: usize = 29;
pub const MAX_FINAL_NAME_UNITS: usize = MAX_NAME_UNITS - INTERNAL_SUFFIX_UNITS;

impl DestinationPolicy {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            categories: default_categories(),
            fallback_folder: "Other".to_string(),
        }
    }

    /// Every folder name must be a plain valid Windows name and the root a real directory.
    pub fn validate(&self) -> Result<(), String> {
        validate_root(&self.root).map_err(|e| format!("destination root: {e:?}"))?;
        let folders = self
            .categories
            .iter()
            .map(|c| c.folder.as_str())
            .chain(std::iter::once(self.fallback_folder.as_str()));
        for folder in folders {
            validate_filename(folder).map_err(|e| format!("category folder: {e:?}"))?;
        }
        for ext in self.categories.iter().flat_map(|c| &c.extensions) {
            let plain = !ext.is_empty()
                && *ext == ext.to_lowercase()
                && !ext.contains(|c: char| c == '.' || c.is_whitespace());
            if !plain {
                return Err("category suffixes are lower-case and carry no dot".into());
            }
        }
        Ok(())
    }

    pub fn category_for(&self, filename: &str) -> &str {
        let ext = match filename.rfind('.') {
            Some(i) if i > 0 && i + 1 < filename.len() => filename[i + 1..].to_lowercase(),
            _ => return &self.fallback_folder,
        };
        self.categories
            .iter()
            .find(|c| c.extensions.contains(&ext))
            .map(|c| c.folder.as_str())
            .unwrap_or(&self.fallback_folder)
    }

    /// Picks the first free name and returns it as a reservation; `reserved` says whether another task
    /// already holds a folded key. `None` means no valid destination exists.
    pub fn choose(&self, filename: &str, reserved: &dyn Fn(&str) -> bool) -> Option<Reservation> {
        self.choose_with(filename, reserved, &dir_is_writable)
    }

    /// `choose` with the writability probe supplied, so a test can watch where the probe goes.
    pub(crate) fn choose_with(
        &self,
        filename: &str,
        reserved: &dyn Fn(&str) -> bool,
        probe: &dyn Fn(&Path) -> std::io::Result<()>,
    ) -> Option<Reservation> {
        validate_root(&self.root).ok()?;
        // The fence is keyed on the physical folder, not on how the root happens to be spelled: a
        // junction above the root or a drive letter mapped onto it must not open a second fence.
        let real_root = self.root.canonicalize().ok()?;
        let name = sanitize_filename(filename);
        if name.encode_utf16().count() > MAX_FINAL_NAME_UNITS {
            return None;
        }
        let folder = self.category_for(&name).to_string();
        let dir = self.root.join(&folder);
        let (stem, ext) = match name.rfind('.') {
            Some(i) if i > 0 && i + 1 < name.len() => name.split_at(i),
            _ => (name.as_str(), ""),
        };
        let mut probed = false;
        for n in 0..=MAX_SUFFIX {
            let candidate = if n == 0 {
                name.clone()
            } else {
                suffixed(stem, ext, n)?
            };
            if validate_filename(&candidate).is_err() {
                continue;
            }
            let path = dir.join(&candidate);
            // a link or junction on the way (including the category folder) refuses the whole policy
            finalize_check(&self.root, &path).ok()?;
            if !probed {
                // only after the link check, so the probe can never be sent through a junction
                let probe_dir = if dir.is_dir() { &dir } else { &self.root };
                probe(probe_dir).ok()?;
                probed = true;
            }
            let key = fold_key(&real_root.join(&folder).join(&candidate).to_string_lossy());
            if reserved(&key) || exists(&path) || exists(&control_file(&path)) {
                continue;
            }
            return Some(Reservation {
                path: path.to_string_lossy().into_owned(),
                key,
                released: false,
            });
        }
        None
    }
}

/// `stem (n).ext`, with the stem shortened so the whole name stays within 255 UTF-16 units.
fn suffixed(stem: &str, ext: &str, n: u32) -> Option<String> {
    let tail = format!(" ({n}){ext}");
    let room = MAX_FINAL_NAME_UNITS.checked_sub(tail.encode_utf16().count())?;
    let mut kept = String::new();
    let mut units = 0;
    for c in stem.chars() {
        units += c.len_utf16();
        if units > room {
            break;
        }
        kept.push(c);
    }
    let kept = kept.trim_end_matches([' ', '.']);
    (!kept.is_empty()).then(|| format!("{kept}{tail}"))
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// aria2 keeps `<name>.aria2` beside a partial download; a leftover one means the name is in use.
fn control_file(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".aria2");
    PathBuf::from(os)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn policy(dir: &Path) -> DestinationPolicy {
        DestinationPolicy::new(dir.to_path_buf())
    }
    fn none(_: &str) -> bool {
        false
    }
    fn path_of(r: &Reservation) -> PathBuf {
        PathBuf::from(&r.path)
    }

    #[test]
    fn the_category_comes_from_the_final_suffix_only_and_ignores_case() {
        let d = tempfile::tempdir().unwrap();
        let p = policy(d.path());
        for (name, want) in [
            ("a.zip", "Compressed"),
            ("A.ZIP", "Compressed"),
            ("archive.tar.gz", "Compressed"),
            ("archive.zip.txt", "Other"),
            ("setup.EXE", "Programs"),
            ("movie.mkv", "Video"),
            ("song.flac", "Music"),
            ("disk.iso", "Disk Images"),
            ("report.pdf", "Documents"),
            ("noextension", "Other"),
            (".zip", "Other"),
            ("trailing.", "Other"),
        ] {
            assert_eq!(p.category_for(name), want, "{name}");
        }
    }

    #[test]
    fn a_free_name_is_reserved_under_root_and_category() {
        let d = tempfile::tempdir().unwrap();
        let r = policy(d.path()).choose("a.zip", &none).unwrap();
        assert_eq!(path_of(&r), d.path().join("Compressed").join("a.zip"));
        assert!(!r.released);
        let physical = d
            .path()
            .canonicalize()
            .unwrap()
            .join("Compressed")
            .join("a.zip");
        assert_eq!(r.key, fold_key(&physical.to_string_lossy()));
    }

    #[test]
    fn an_existing_file_directory_or_leftover_control_file_forces_a_suffix() {
        let d = tempfile::tempdir().unwrap();
        let cat = d.path().join("Compressed");
        fs::create_dir(&cat).unwrap();
        fs::write(cat.join("a.zip"), b"mine").unwrap();
        fs::create_dir(cat.join("a (1).zip")).unwrap();
        fs::write(cat.join("a (2).zip.aria2"), b"partial").unwrap();
        let r = policy(d.path()).choose("a.zip", &none).unwrap();
        assert_eq!(path_of(&r), cat.join("a (3).zip"));
        assert_eq!(fs::read(cat.join("a.zip")).unwrap(), b"mine", "untouched");
    }

    #[test]
    fn another_reservation_forces_a_suffix_including_case_and_normalisation_twins() {
        let d = tempfile::tempdir().unwrap();
        let p = policy(d.path());
        let first = p.choose("Caf\u{e9}.zip", &none).unwrap();
        let taken = [first.key.clone()];
        let held = |k: &str| taken.iter().any(|t| t == k);
        let second = p.choose("Caf\u{e9}.zip", &held).unwrap();
        assert!(
            second.path.ends_with("Caf\u{e9} (1).zip"),
            "{}",
            second.path
        );
        // the same name in other case and in decomposed form lands on the same key
        let twin_case = p.choose("CAF\u{c9}.ZIP", &held).unwrap();
        assert!(twin_case.path.ends_with(" (1).ZIP"), "{}", twin_case.path);
        let twin_nfd = p.choose("Cafe\u{301}.zip", &held).unwrap();
        assert_eq!(twin_nfd.key, second.key, "NFD collapses to the NFC name");
    }

    #[test]
    fn names_are_sanitised_before_they_are_used() {
        let d = tempfile::tempdir().unwrap();
        let p = policy(d.path());
        let r = p.choose("CON.txt", &none).unwrap();
        assert!(r.path.ends_with("_CON.txt"), "{}", r.path);
        let r = p.choose("a<b>c:d.zip", &none).unwrap();
        assert!(r.path.ends_with("a_b_c_d.zip"), "{}", r.path);
        let r = p.choose("../../x.zip", &none).unwrap();
        assert_eq!(path_of(&r), d.path().join("Compressed").join("x.zip"));
        let r = p.choose("", &none).unwrap();
        assert!(r.path.ends_with("download"), "{}", r.path);
    }

    #[test]
    fn a_long_name_with_a_suffix_preserves_the_internal_budget() {
        let d = tempfile::tempdir().unwrap();
        let p = policy(d.path());
        let long = format!("{}.zip", "x".repeat(222));
        let first = p.choose(&long, &none).unwrap();
        let held_key = first.key.clone();
        let second = p.choose(&long, &|k: &str| k == held_key).unwrap();
        for r in [&first, &second] {
            let name = path_of(r)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            assert!(
                name.encode_utf16().count() <= MAX_FINAL_NAME_UNITS,
                "{}",
                name.len()
            );
            assert!(name.ends_with(".zip"));
        }
        assert_ne!(first.key, second.key);
    }

    #[test]
    fn when_every_suffix_is_taken_there_is_no_destination() {
        let d = tempfile::tempdir().unwrap();
        let p = policy(d.path());
        assert!(p.choose("a.zip", &|_: &str| true).is_none());
    }

    #[test]
    fn a_missing_root_a_file_root_or_a_junction_category_is_refused() {
        let d = tempfile::tempdir().unwrap();
        assert!(policy(&d.path().join("nope"))
            .choose("a.zip", &none)
            .is_none());
        let file = d.path().join("f");
        fs::write(&file, b"x").unwrap();
        assert!(policy(&file).choose("a.zip", &none).is_none());
        assert!(policy(&file).validate().is_err());
        assert!(policy(&d.path().join("nope")).validate().is_err());
        assert!(policy(d.path()).validate().is_ok());
        // a junction where the category folder should be would send the download elsewhere
        let outside = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(d.path().join("Compressed"))
            .arg(outside.path())
            .output()
            .unwrap();
        assert!(status.status.success(), "mklink failed");
        assert!(policy(d.path()).choose("a.zip", &none).is_none());
        assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
    }

    #[test]
    fn bad_folder_names_in_the_policy_are_rejected() {
        let d = tempfile::tempdir().unwrap();
        for bad in ["", "..", "a/b", "CON", "x.", "a:b"] {
            let mut p = policy(d.path());
            p.categories[0].folder = bad.to_string();
            assert!(p.validate().is_err(), "{bad:?}");
            let mut p = policy(d.path());
            p.fallback_folder = bad.to_string();
            assert!(p.validate().is_err(), "{bad:?}");
        }
        let mut p = policy(d.path());
        p.categories[0].extensions.push("Zip".into());
        assert!(p.validate().is_err(), "extensions must be lower-case");
        p.categories[0].extensions = vec![".zip".into()];
        assert!(p.validate().is_err(), "extensions carry no dot");
    }

    #[cfg(windows)]
    #[test]
    fn an_unwritable_root_or_category_folder_is_refused_before_anything_is_decided() {
        struct Restore(PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = std::process::Command::new("icacls")
                    .arg(&self.0)
                    .args(["/remove:d", "*S-1-1-0"])
                    .output();
            }
        }
        let deny = |dir: &Path| {
            let out = std::process::Command::new("icacls")
                .arg(dir)
                .args(["/deny", "*S-1-1-0:(WD,AD)"])
                .output()
                .unwrap();
            assert!(out.status.success());
            Restore(dir.to_path_buf())
        };
        let d = tempfile::tempdir().unwrap();
        // the category folder does not exist yet, so the root must allow creating it
        let bare = d.path().join("bare");
        fs::create_dir_all(&bare).unwrap();
        assert!(policy(&bare).choose("a.zip", &none).is_some());
        {
            let _g = deny(&bare);
            assert!(policy(&bare).choose("a.zip", &none).is_none(), "root");
        }
        // the category folder exists, so that is the folder that has to be writable
        let root = d.path().join("dl");
        fs::create_dir_all(root.join("Compressed")).unwrap();
        {
            let _g = deny(&root.join("Compressed"));
            assert!(policy(&root).choose("a.zip", &none).is_none(), "category");
            assert!(
                policy(&root).choose("a.txt", &none).is_some(),
                "other categories are unaffected"
            );
        }
        assert!(policy(&root).choose("a.zip", &none).is_some());
    }

    /// Two spellings of one folder (a junction above the root, or a drive letter mapped onto it)
    /// must never hand out the same physical file twice.
    #[test]
    fn root_aliases_share_one_reservation_fence() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        fs::create_dir_all(real.join("dl")).unwrap();
        let alias = d.path().join("alias");
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&alias)
            .arg(&real)
            .output()
            .unwrap();
        assert!(made.status.success(), "mklink failed");
        let first = policy(&real.join("dl")).choose("same.zip", &none).unwrap();
        let held = first.key.clone();
        let taken = |k: &str| k == held;
        let via_alias = policy(&alias.join("dl"))
            .choose("same.zip", &taken)
            .unwrap();
        assert_ne!(via_alias.key, first.key, "same physical file, same key");
        assert!(
            via_alias.path.ends_with("same (1).zip"),
            "{}",
            via_alias.path
        );
        // and the other way round
        let second = policy(&alias.join("dl"))
            .choose("other.zip", &none)
            .unwrap();
        let held2 = second.key.clone();
        let again = policy(&real.join("dl"))
            .choose("other.zip", &|k: &str| k == held2)
            .unwrap();
        assert!(again.path.ends_with("other (1).zip"), "{}", again.path);
    }

    #[test]
    fn a_mapped_drive_letter_shares_the_fence_with_the_real_path() {
        struct Unmap(String);
        impl Drop for Unmap {
            fn drop(&mut self) {
                let _ = std::process::Command::new("subst")
                    .args([&self.0, "/D"])
                    .output();
            }
        }
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("dl");
        fs::create_dir_all(&real).unwrap();
        let letter = ('R'..='Z')
            .map(|c| format!("{c}:"))
            .find(|l| !Path::new(&format!("{l}\\")).exists())
            .expect("a free drive letter");
        let mapped = std::process::Command::new("subst")
            .arg(&letter)
            .arg(&real)
            .output()
            .unwrap();
        assert!(mapped.status.success(), "subst failed");
        let _guard = Unmap(letter.clone());
        let a = policy(&real).choose("same.zip", &none).unwrap();
        let held = a.key.clone();
        let b = policy(Path::new(&format!("{letter}\\")))
            .choose("same.zip", &|k: &str| k == held)
            .unwrap();
        assert_ne!(a.key, b.key);
        assert!(b.path.ends_with("same (1).zip"), "{}", b.path);
    }

    #[test]
    fn the_probe_never_runs_before_the_link_check() {
        let d = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let seen = std::cell::RefCell::new(Vec::<PathBuf>::new());
        let spy = |dir: &Path| {
            seen.borrow_mut().push(dir.to_path_buf());
            Ok(())
        };
        // a junction in the category position: refused, and the probe is never aimed anywhere
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(d.path().join("Compressed"))
            .arg(outside.path())
            .output()
            .unwrap();
        assert!(made.status.success());
        assert!(policy(d.path()).choose_with("a.zip", &none, &spy).is_none());
        assert!(seen.borrow().is_empty(), "probed {:?}", seen.borrow());
        // a normal category: probed exactly once, in the folder that will hold the file
        assert!(policy(d.path()).choose_with("a.txt", &none, &spy).is_some());
        assert_eq!(*seen.borrow(), vec![d.path().to_path_buf()]);
    }
}
