// SPDX-License-Identifier: GPL-3.0-only
//! Windows-safe file names and destination roots. Every name that comes from a server or a page is
//! only a suggestion: `sanitize_filename` turns it into a name that is safe on NTFS, and
//! `validate_filename` accepts only names that are already in exactly that form.

use std::path::Path;
use unicode_normalization::UnicodeNormalization;

/// NTFS allows 255 UTF-16 code units per path component.
pub const MAX_NAME_UNITS: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    Empty,
    TooLong,
    BadCharacter,
    Separator,
    TrailingDotOrSpace,
    Reserved,
    Bidi,
    NotNormalized,
    NotCanonical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootError {
    NotAbsolute,
    Missing,
    NotDirectory,
    /// Device paths, verbatim prefixes or `..` components.
    Unsafe,
    /// The root itself is a symbolic link or junction.
    Reparse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    /// The path is not inside the root.
    Escape,
    /// A component between the root and the file is a link or junction.
    Reparse,
    /// The file name part is not canonical.
    BadName,
}

fn is_bidi(c: char) -> bool {
    matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200e}' | '\u{200f}' | '\u{61c}')
}

fn is_invalid(c: char) -> bool {
    matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')
}

fn is_separator(c: char) -> bool {
    c == '/' || c == '\\'
}

fn units(s: &str) -> usize {
    s.encode_utf16().count()
}

/// `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9` (also with the superscript digits), `CONIN$`
/// and `CONOUT$`, whatever follows the first dot and whatever spaces precede it.
fn is_reserved(name: &str) -> bool {
    let stem = name
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    let c: Vec<char> = stem.chars().collect();
    c.len() == 4
        && (c[..3] == ['C', 'O', 'M'] || c[..3] == ['L', 'P', 'T'])
        && matches!(c[3], '1'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}')
}

fn truncate_units(s: &str, max: usize) -> String {
    let mut out = String::new();
    let mut used = 0;
    for ch in s.chars() {
        let n = ch.len_utf16();
        if used + n > max {
            break;
        }
        used += n;
        out.push(ch);
    }
    out
}

/// A name that is safe to create on NTFS, derived deterministically from any input.
pub fn sanitize_filename(raw: &str) -> String {
    let composed: String = raw.nfc().collect();
    // a suggested name may carry directories: only the last component is a file name
    let base = composed.rsplit(is_separator).next().unwrap_or("");
    let mut cleaned = String::new();
    for c in base.chars() {
        if is_bidi(c) {
            continue;
        }
        cleaned.push(if c.is_control() || is_invalid(c) {
            '_'
        } else {
            c
        });
    }
    let mut name = cleaned
        .trim_start_matches(' ')
        .trim_end_matches(['.', ' '])
        .to_string();
    if name.is_empty() {
        name = "download".to_string();
    }
    if is_reserved(&name) {
        name.insert(0, '_');
    }
    if units(&name) > MAX_NAME_UNITS {
        let keep_ext = name
            .rfind('.')
            .filter(|&i| i > 0 && units(&name[i..]) <= 20);
        name = match keep_ext {
            Some(i) => {
                let ext = name[i..].to_string();
                let stem = truncate_units(&name[..i], MAX_NAME_UNITS - units(&ext));
                format!("{}{ext}", stem.trim_end_matches(['.', ' ']))
            }
            None => truncate_units(&name, MAX_NAME_UNITS)
                .trim_end_matches(['.', ' '])
                .to_string(),
        };
    }
    if name.is_empty() {
        name = "download".to_string();
    }
    name
}

/// Accepts only names that `sanitize_filename` would leave unchanged.
pub fn validate_filename(name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if units(name) > MAX_NAME_UNITS {
        return Err(NameError::TooLong);
    }
    if name.chars().any(is_separator) {
        return Err(NameError::Separator);
    }
    if name.chars().any(is_bidi) {
        return Err(NameError::Bidi);
    }
    if name.chars().any(|c| c.is_control() || is_invalid(c)) {
        return Err(NameError::BadCharacter);
    }
    if name.starts_with(' ') || name.ends_with(['.', ' ']) {
        return Err(NameError::TrailingDotOrSpace);
    }
    if is_reserved(name) {
        return Err(NameError::Reserved);
    }
    if name.nfc().collect::<String>() != name {
        return Err(NameError::NotNormalized);
    }
    if sanitize_filename(name) != name {
        return Err(NameError::NotCanonical);
    }
    Ok(())
}

/// Two names with the same key are the same file on a case-insensitive, normalising filesystem.
pub fn fold_key(name: &str) -> String {
    name.to_lowercase().nfc().collect()
}

fn is_link(path: &Path) -> std::io::Result<bool> {
    let meta = std::fs::symlink_metadata(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        Ok(meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    }
    #[cfg(not(windows))]
    {
        Ok(meta.file_type().is_symlink())
    }
}

pub fn validate_root(root: &Path) -> Result<(), RootError> {
    use std::path::{Component, Prefix};
    for c in root.components() {
        match c {
            Component::ParentDir => return Err(RootError::Unsafe),
            Component::Prefix(p)
                if matches!(
                    p.kind(),
                    Prefix::Verbatim(_)
                        | Prefix::VerbatimUNC(..)
                        | Prefix::VerbatimDisk(_)
                        | Prefix::DeviceNS(_)
                ) =>
            {
                return Err(RootError::Unsafe)
            }
            _ => {}
        }
    }
    if !root.is_absolute() {
        return Err(RootError::NotAbsolute);
    }
    match is_link(root) {
        Err(_) => return Err(RootError::Missing),
        Ok(true) => return Err(RootError::Reparse),
        Ok(false) => {}
    }
    if !root.is_dir() {
        return Err(RootError::NotDirectory);
    }
    Ok(())
}

/// Checked right before a file is finalised: the path must be inside `root` and no directory between
/// them may be a link or junction (which could redirect the write elsewhere).
pub fn finalize_check(root: &Path, path: &Path) -> Result<(), PathError> {
    use std::path::Component;
    let rel = path.strip_prefix(root).map_err(|_| PathError::Escape)?;
    if rel.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(PathError::Escape);
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(PathError::BadName)?;
    validate_filename(name).map_err(|_| PathError::BadName)?;
    // no link or junction on the way down, including the root itself and an existing target
    let mut current = root.to_path_buf();
    if is_link(&current).map_err(|_| PathError::Reparse)? {
        return Err(PathError::Reparse);
    }
    for part in rel.components() {
        current.push(part);
        match is_link(&current) {
            Ok(true) => return Err(PathError::Reparse),
            Ok(false) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err(PathError::Reparse),
        }
    }
    // and the real location of the parent is still under the real root (8.3 names, casing, mounts)
    if let (Some(parent), Ok(real_root)) = (path.parent(), root.canonicalize()) {
        if let Ok(real_parent) = parent.canonicalize() {
            if !real_parent.starts_with(&real_root) {
                return Err(PathError::Escape);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::process::{Command, Stdio};

    fn units(s: &str) -> usize {
        s.encode_utf16().count()
    }

    #[test]
    fn ordinary_names_are_unchanged() {
        for n in [
            "report.pdf",
            "archive.tar.gz",
            "Ünïcode.txt",
            ".hidden",
            "a b c.txt",
            "x",
            "日本語.mp3",
        ] {
            assert_eq!(sanitize_filename(n), n);
            assert_eq!(validate_filename(n), Ok(()), "{n}");
        }
    }

    #[test]
    fn decomposed_text_is_composed() {
        assert_eq!(sanitize_filename("e\u{301}.txt"), "\u{e9}.txt");
        assert_eq!(
            validate_filename("e\u{301}.txt"),
            Err(NameError::NotNormalized)
        );
    }

    #[test]
    fn directories_in_a_suggested_name_are_dropped() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("a\\b\\c.zip"), "c.zip");
        assert_eq!(sanitize_filename("C:\\Windows\\win.ini"), "win.ini");
        assert_eq!(sanitize_filename("/abs/path/file.bin"), "file.bin");
        assert_eq!(sanitize_filename("dir/"), "download");
        assert_eq!(sanitize_filename(".."), "download");
        assert_eq!(sanitize_filename("."), "download");
        assert_eq!(sanitize_filename("..."), "download");
        assert_eq!(validate_filename("a/b"), Err(NameError::Separator));
        assert_eq!(validate_filename("a\\b"), Err(NameError::Separator));
        assert_eq!(validate_filename(".."), Err(NameError::TrailingDotOrSpace));
    }

    #[test]
    fn alternate_streams_and_wildcards_are_neutralised() {
        assert_eq!(sanitize_filename("a.txt:evil"), "a.txt_evil");
        assert_eq!(sanitize_filename("a.txt:evil:$DATA"), "a.txt_evil_$DATA");
        assert_eq!(sanitize_filename("C:evil.txt"), "C_evil.txt");
        assert_eq!(sanitize_filename("a<b>c\"d|e?f*g.txt"), "a_b_c_d_e_f_g.txt");
        for bad in ["a.txt:evil", "a<b", "a|b", "a?b", "a*b", "a\"b"] {
            assert_eq!(
                validate_filename(bad),
                Err(NameError::BadCharacter),
                "{bad}"
            );
        }
    }

    #[test]
    fn control_and_direction_characters_are_removed_or_replaced() {
        assert_eq!(sanitize_filename("a\tb"), "a_b");
        assert_eq!(sanitize_filename("a\u{7}b\u{0}c"), "a_b_c");
        assert_eq!(sanitize_filename("a\u{85}b"), "a_b");
        assert_eq!(
            sanitize_filename("invoice\u{202e}fdp.exe"),
            "invoicefdp.exe"
        );
        assert_eq!(sanitize_filename("x\u{2066}y\u{2069}.txt"), "xy.txt");
        assert_eq!(validate_filename("a\tb"), Err(NameError::BadCharacter));
        assert_eq!(validate_filename("a\u{202e}b"), Err(NameError::Bidi));
    }

    #[test]
    fn trailing_dots_and_spaces_and_leading_spaces_do_not_survive() {
        assert_eq!(sanitize_filename("name. . "), "name");
        assert_eq!(sanitize_filename("name.txt."), "name.txt");
        assert_eq!(sanitize_filename("  lead.txt"), "lead.txt");
        // Windows does not treat a non-breaking space as a space, so it is an ordinary character
        assert_eq!(sanitize_filename("\u{a0}nbsp.txt"), "\u{a0}nbsp.txt");
        assert_eq!(
            validate_filename("name."),
            Err(NameError::TrailingDotOrSpace)
        );
        assert_eq!(
            validate_filename("name "),
            Err(NameError::TrailingDotOrSpace)
        );
        assert_eq!(
            validate_filename(" lead"),
            Err(NameError::TrailingDotOrSpace)
        );
    }

    #[test]
    fn device_names_are_reserved_with_any_extension_and_spacing() {
        for (raw, want) in [
            ("CON", "_CON"),
            ("con.txt", "_con.txt"),
            ("CON .zip", "_CON .zip"),
            ("PRN.tar.gz", "_PRN.tar.gz"),
            ("aux", "_aux"),
            ("NUL.", "_NUL"),
            ("COM1", "_COM1"),
            ("com9.log", "_com9.log"),
            ("COM\u{b9}.txt", "_COM\u{b9}.txt"),
            ("COM\u{b2}", "_COM\u{b2}"),
            ("LPT9.log", "_LPT9.log"),
            ("lpt\u{b3}.x", "_lpt\u{b3}.x"),
            ("CONIN$", "_CONIN$"),
            ("conout$.txt", "_conout$.txt"),
        ] {
            assert_eq!(sanitize_filename(raw), want, "{raw}");
        }
        for fine in [
            "COM10",
            "CONSOLE.txt",
            "NULL.txt",
            "COM0.txt",
            "AUXILIARY",
            "myCON.txt",
            "LPT.txt",
        ] {
            assert_eq!(sanitize_filename(fine), fine, "{fine}");
            assert_eq!(validate_filename(fine), Ok(()));
        }
        for reserved in ["CON", "con.txt", "COM1", "COM\u{b9}.txt", "LPT9.log"] {
            assert_eq!(
                validate_filename(reserved),
                Err(NameError::Reserved),
                "{reserved}"
            );
        }
    }

    #[test]
    fn length_is_bounded_in_utf16_units_and_keeps_the_extension() {
        let long = format!("{}.zip", "a".repeat(300));
        let s = sanitize_filename(&long);
        assert!(
            units(&s) <= MAX_NAME_UNITS && s.ends_with(".zip"),
            "{}",
            s.len()
        );
        let emoji = format!("{}.mp4", "\u{1F600}".repeat(200));
        let s = sanitize_filename(&emoji);
        assert!(units(&s) <= MAX_NAME_UNITS && s.ends_with(".mp4"));
        assert!(s.starts_with('\u{1F600}'));
        assert_eq!(validate_filename(&"a".repeat(256)), Err(NameError::TooLong));
        assert_eq!(validate_filename(&"a".repeat(255)), Ok(()));
        let huge_ext = format!("a.{}", "b".repeat(400));
        assert!(units(&sanitize_filename(&huge_ext)) <= MAX_NAME_UNITS);
    }

    #[test]
    fn empty_results_become_download() {
        for raw in ["", " ", "   ", "\u{202e}", "?*", ". .", "\u{0}"] {
            let s = sanitize_filename(raw);
            assert!(
                !s.is_empty() && validate_filename(&s).is_ok(),
                "{raw:?} -> {s:?}"
            );
        }
        assert_eq!(validate_filename(""), Err(NameError::Empty));
    }

    #[test]
    fn names_that_differ_only_by_case_or_composition_share_a_key() {
        assert_eq!(fold_key("File.TXT"), fold_key("file.txt"));
        assert_eq!(fold_key("e\u{301}.txt"), fold_key("\u{e9}.txt"));
        assert_eq!(fold_key("E\u{301}.TXT"), fold_key("\u{e9}.txt"));
        assert_ne!(fold_key("a.txt"), fold_key("b.txt"));
        assert_ne!(fold_key("a.txt"), fold_key("a.txt2"));
    }

    proptest! {
        #[test]
        fn sanitising_any_text_gives_a_valid_stable_name(raw in "\\PC{0,400}") {
            let s = sanitize_filename(&raw);
            prop_assert_eq!(validate_filename(&s), Ok(()), "{:?} -> {:?}", raw, s);
            prop_assert_eq!(sanitize_filename(&s), s.clone());
            prop_assert!(units(&s) <= MAX_NAME_UNITS);
            prop_assert!(!s.contains(['/', '\\', ':', '<', '>', '"', '|', '?', '*']));
        }

        #[test]
        fn names_with_hostile_characters_never_panic(raw in "[ -~\u{80}-\u{2fff}\u{202a}-\u{202e}]{0,120}") {
            let _ = sanitize_filename(&raw);
            let _ = validate_filename(&raw);
            let _ = fold_key(&raw);
        }
    }

    // ---- roots and finalisation, against the real filesystem ----

    fn junction(link: &Path, target: &Path) {
        let ok = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        assert!(ok, "could not create a junction for the test");
    }

    #[test]
    fn a_root_must_be_an_existing_absolute_plain_directory() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(validate_root(dir.path()), Ok(()));
        assert_eq!(
            validate_root(Path::new("relative\\dir")),
            Err(RootError::NotAbsolute)
        );
        assert_eq!(
            validate_root(&dir.path().join("missing")),
            Err(RootError::Missing)
        );
        let file = dir.path().join("f.txt");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(validate_root(&file), Err(RootError::NotDirectory));
        assert_eq!(
            validate_root(&dir.path().join("..\\x")),
            Err(RootError::Unsafe)
        );
        assert_eq!(
            validate_root(Path::new("\\\\.\\C:\\x")),
            Err(RootError::Unsafe)
        );
        assert_eq!(
            validate_root(Path::new("\\\\?\\C:\\Users")),
            Err(RootError::Unsafe)
        );
    }

    #[test]
    fn a_root_that_is_a_junction_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("link");
        junction(&link, &target);
        assert_eq!(validate_root(&link), Err(RootError::Reparse));
    }

    #[test]
    fn finalisation_accepts_paths_inside_the_root_and_rejects_everything_else() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("dl");
        std::fs::create_dir_all(root.join("Archives")).unwrap();
        assert_eq!(
            finalize_check(&root, &root.join("Archives").join("a.zip")),
            Ok(())
        );
        assert_eq!(finalize_check(&root, &root.join("a.zip")), Ok(()));
        assert_eq!(
            finalize_check(&root, &root.join("..\\evil.zip")),
            Err(PathError::Escape)
        );
        assert_eq!(
            finalize_check(&root, &dir.path().join("dl-evil\\a.zip")),
            Err(PathError::Escape),
            "prefix sibling"
        );
        assert_eq!(
            finalize_check(&root, &dir.path().join("other.zip")),
            Err(PathError::Escape)
        );
        assert_eq!(
            finalize_check(&root, &root.join("sub\\..\\..\\x.zip")),
            Err(PathError::Escape)
        );
        assert_eq!(
            finalize_check(&root, &root.join("a.txt:stream")),
            Err(PathError::BadName)
        );
        assert_eq!(
            finalize_check(&root, &root.join("CON.txt")),
            Err(PathError::BadName)
        );
    }

    #[test]
    fn a_junction_inside_the_root_cannot_redirect_a_write() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("dl");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        junction(&root.join("Archives"), &outside);
        assert_eq!(
            finalize_check(&root, &root.join("Archives").join("a.zip")),
            Err(PathError::Reparse)
        );
        // an ordinary sibling directory is still fine
        std::fs::create_dir(root.join("Plain")).unwrap();
        assert_eq!(
            finalize_check(&root, &root.join("Plain").join("a.zip")),
            Ok(())
        );
    }

    #[test]
    fn a_dot_dot_that_stays_inside_the_root_is_still_refused_by_the_lexical_guard() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("sub")).unwrap();
        let sneaky = d.path().join("sub").join("..").join("a.zip");
        // canonically this is root\a.zip, so only the component check can see the trick
        assert_eq!(finalize_check(d.path(), &sneaky), Err(PathError::Escape));
        assert!(finalize_check(d.path(), &d.path().join("sub").join("a.zip")).is_ok());
    }
}
