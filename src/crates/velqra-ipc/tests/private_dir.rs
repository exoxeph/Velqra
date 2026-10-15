// SPDX-License-Identifier: GPL-3.0-only
//! A folder that holds a short-lived secret must not inherit its parent's access list: on a machine
//! where %LOCALAPPDATA% also grants another account group read access, an inherited list would let
//! that group read the file while it exists.
#![cfg(windows)]

use velqra_ipc::{current_user_sid, make_private_dir};

fn acl_lines(path: &std::path::Path) -> Vec<String> {
    let out = std::process::Command::new("icacls")
        .arg(path)
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains(":("))
        .map(|l| l.trim().to_string())
        .collect()
}

#[test]
fn a_private_dir_grants_only_the_current_user_and_system_and_inherits_nothing() {
    let parent = tempfile::tempdir().unwrap();
    let dir = parent.path().join("run").join("nested");
    make_private_dir(&dir).unwrap();
    assert!(dir.is_dir());
    let lines = acl_lines(&dir);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines.iter().all(|l| !l.contains("(I)")),
        "inherited entries remain: {lines:?}"
    );
    assert!(lines.iter().any(|l| l.contains("SYSTEM")), "{lines:?}");
    let _ = current_user_sid().unwrap();
    // a file made inside carries the same protected list, not the parent's
    let file = dir.join("secret.conf");
    std::fs::write(&file, b"x").unwrap();
    let file_lines = acl_lines(&file);
    assert_eq!(file_lines.len(), 2, "{file_lines:?}");
    assert!(
        file_lines
            .iter()
            .all(|l| !l.contains("Administrators") && !l.contains("Authenticated")),
        "{file_lines:?}"
    );
}

#[test]
fn it_is_safe_to_repeat_and_tightens_a_folder_that_already_exists() {
    let parent = tempfile::tempdir().unwrap();
    let dir = parent.path().join("existing");
    std::fs::create_dir(&dir).unwrap();
    let before = acl_lines(&dir).len();
    make_private_dir(&dir).unwrap();
    make_private_dir(&dir).unwrap();
    let after = acl_lines(&dir);
    assert_eq!(after.len(), 2, "before {before}, after {after:?}");
}

#[test]
fn a_path_that_is_a_file_is_refused() {
    let parent = tempfile::tempdir().unwrap();
    let f = parent.path().join("f");
    std::fs::write(&f, b"x").unwrap();
    assert!(make_private_dir(&f).is_err());
}
