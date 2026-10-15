// SPDX-License-Identifier: GPL-3.0-only
//! A6: Prepare picks and holds the destination file. Only the core's own settings and the file name
//! decide the path; two tasks never share one; abort gives the name back and never touches a file.
use std::path::{Path, PathBuf};
use velqra_core::destination::DestinationPolicy;
use velqra_core::file_vault::{FileVault, Protector};
use velqra_core::store::{MemStore, SqliteStore, Store};
use velqra_core::vault::MemVault;
use velqra_core::Core;
use velqra_protocol::*;

struct Scramble;
impl Protector for Scramble {
    fn protect(&self, plain: &[u8], _: &[u8]) -> Result<Vec<u8>, String> {
        Ok(plain.iter().map(|b| b ^ 0xa7).collect())
    }
    fn unprotect(&self, blob: &[u8], _: &[u8]) -> Result<Vec<u8>, String> {
        Ok(blob.iter().map(|b| b ^ 0xa7).collect())
    }
}

fn env(request_id: &str, body: Message) -> Envelope {
    Envelope {
        version: PROTOCOL_VERSION,
        message_id: format!("m-{request_id}-{}", body.kind()),
        session_id: "s".into(),
        request_id: request_id.into(),
        generation: 1,
        body,
    }
}

fn body(key: &str, filename: &str) -> PrepareBody {
    PrepareBody {
        download_key: key.into(),
        url: format!("https://x.test/{key}"),
        filename: filename.into(),
        context: Secret("ctx".into()),
    }
}

fn open(db: &Path, vault: &Path, root: &Path) -> Core<SqliteStore> {
    Core::with_vault(
        SqliteStore::open(db).unwrap(),
        Box::new(FileVault::open(vault, Scramble).unwrap()),
    )
    .with_destination(DestinationPolicy::new(root.to_path_buf()))
}

fn prepare(core: &mut Core<impl Store>, rid: &str, filename: &str) -> Envelope {
    core.handle(&env(rid, Message::Prepare(body(rid, filename))), 1)
}

fn path_of(core: &Core<impl Store>, rid: &str) -> PathBuf {
    let rec = core.store.get_by_request(rid).unwrap().unwrap();
    PathBuf::from(rec.destination.expect("a reservation").path)
}

fn count(dir: &Path) -> usize {
    std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(0)
}

#[test]
fn same_name_prepares_get_different_paths_and_an_existing_file_forces_a_suffix() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("dl");
    std::fs::create_dir_all(root.join("Compressed")).unwrap();
    std::fs::write(root.join("Compressed").join("a.zip"), b"mine").unwrap();
    let mut core = open(&d.path().join("c.db"), &d.path().join("v"), &root);
    for rid in ["r1", "r2", "r3"] {
        assert!(matches!(
            prepare(&mut core, rid, "a.zip").body,
            Message::Prepared(_)
        ));
    }
    let names: Vec<_> = ["r1", "r2", "r3"]
        .iter()
        .map(|r| {
            path_of(&core, r)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(names, ["a (1).zip", "a (2).zip", "a (3).zip"]);
    assert_eq!(
        std::fs::read(root.join("Compressed").join("a.zip")).unwrap(),
        b"mine"
    );
}

#[test]
fn case_and_normalisation_twins_collide() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("dl");
    std::fs::create_dir_all(&root).unwrap();
    let mut core = open(&d.path().join("c.db"), &d.path().join("v"), &root);
    prepare(&mut core, "r1", "Caf\u{e9}.zip");
    prepare(&mut core, "r2", "CAF\u{c9}.ZIP");
    prepare(&mut core, "r3", "Cafe\u{301}.zip");
    let paths: Vec<_> = ["r1", "r2", "r3"]
        .iter()
        .map(|r| path_of(&core, r))
        .collect();
    let keys: std::collections::HashSet<_> = paths
        .iter()
        .map(|p| velqra_core::path_policy::fold_key(&p.to_string_lossy()))
        .collect();
    assert_eq!(
        keys.len(),
        3,
        "three tasks, three distinct names: {paths:?}"
    );
}

#[test]
fn a_missing_root_refuses_prepare_with_a_fixed_error_and_leaves_nothing_behind() {
    let d = tempfile::tempdir().unwrap();
    let vault = d.path().join("v");
    let mut core = open(&d.path().join("c.db"), &vault, &d.path().join("absent"));
    let out = prepare(&mut core, "r1", "a.zip");
    assert!(
        matches!(&out.body, Message::Error(e) if e.kind == ErrorKind::NoDestination),
        "{:?}",
        out.body
    );
    assert!(
        core.store.get_by_request("r1").unwrap().is_none(),
        "no record"
    );
    assert_eq!(count(&vault), 0, "no vault entries");
    assert!(
        !d.path().join("absent").exists(),
        "the root is not created for the page"
    );
}

#[test]
fn reservations_survive_a_restart() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("dl");
    std::fs::create_dir_all(&root).unwrap();
    let (db, vault) = (d.path().join("c.db"), d.path().join("v"));
    {
        let mut core = open(&db, &vault, &root);
        prepare(&mut core, "r1", "a.zip");
    }
    let mut core = open(&db, &vault, &root);
    prepare(&mut core, "r2", "a.zip");
    assert!(path_of(&core, "r2").ends_with("a (1).zip"));
    // a retry of the same request returns the same reservation instead of a new one
    prepare(&mut core, "r1", "a.zip");
    assert!(path_of(&core, "r1").ends_with("a.zip"));
}

#[test]
fn abort_releases_the_name_and_never_touches_a_file() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("dl");
    std::fs::create_dir_all(&root).unwrap();
    let mut core = open(&d.path().join("c.db"), &d.path().join("v"), &root);
    let Message::Prepared(receipt) = prepare(&mut core, "r1", "a.zip").body else {
        panic!("prepare failed")
    };
    let first = path_of(&core, "r1");
    let abort = AbortBody {
        receipt: Some(RequestRef {
            task_id: receipt.task_id,
            fingerprint: receipt.fingerprint,
        }),
    };
    core.handle(&env("r1", Message::Abort(abort)), 5);
    let rec = core.store.get_by_request("r1").unwrap().unwrap();
    assert!(rec.destination.unwrap().released);
    prepare(&mut core, "r2", "a.zip");
    assert_eq!(
        path_of(&core, "r2"),
        first,
        "the released name is available again"
    );
    assert_eq!(count(&root), 0, "the core created and deleted no files");
}

#[test]
fn concurrent_cores_over_one_database_never_double_reserve() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("dl");
    std::fs::create_dir_all(&root).unwrap();
    let db = d.path().join("c.db");
    SqliteStore::open(&db).unwrap();
    let handles: Vec<_> = (0..6)
        .map(|t| {
            let (db, vault, root) = (db.clone(), d.path().join(format!("v{t}")), root.clone());
            std::thread::spawn(move || {
                let mut core = open(&db, &vault, &root);
                (0..5)
                    .map(|i| {
                        let rid = format!("t{t}-{i}");
                        let out = prepare(&mut core, &rid, "same.zip");
                        let why = match &out.body {
                            Message::Error(e) => format!("{:?}: {}", e.kind, e.detail),
                            _ => String::new(),
                        };
                        assert!(matches!(out.body, Message::Prepared(_)), "{why}");
                        path_of(&core, &rid)
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let all: Vec<PathBuf> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    let unique: std::collections::HashSet<_> = all.iter().collect();
    assert_eq!(unique.len(), 30, "{all:?}");
}

#[test]
fn a_core_without_a_policy_reserves_nothing() {
    let mut core = Core::with_vault(MemStore::default(), Box::new(MemVault::default()));
    prepare(&mut core, "r1", "a.zip");
    assert!(core
        .store
        .get_by_request("r1")
        .unwrap()
        .unwrap()
        .destination
        .is_none());
}

#[test]
fn no_core_source_deletes_truncates_or_creates_user_files() {
    // The vault removes only its own entries; everything else in the crate must never remove, truncate,
    // rename or create a file. Test modules are cut off before scanning.
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let banned = [
        "remove_file",
        "remove_dir",
        "File::create",
        "fs::write",
        "set_len",
        "fs::rename",
        "fs::copy",
        "OpenOptions",
    ];
    let mut scanned = 0;
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        // the vault removes only its own entries; the probe creates one delete-on-close file of its own
        if name == "file_vault.rs" || name == "write_probe.rs" {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let production = text.split("#[cfg(test)]").next().unwrap();
        for word in banned {
            assert!(!production.contains(word), "{} uses {word}", path.display());
        }
        scanned += 1;
    }
    assert!(
        scanned >= 6,
        "the scan must actually read the crate sources"
    );
}

#[test]
fn a_root_setting_that_changes_spelling_between_restarts_cannot_double_reserve() {
    let d = tempfile::tempdir().unwrap();
    let real = d.path().join("real");
    std::fs::create_dir_all(real.join("dl")).unwrap();
    let alias = d.path().join("alias");
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&alias)
        .arg(&real)
        .output()
        .unwrap();
    assert!(made.status.success());
    let (db, vault) = (d.path().join("c.db"), d.path().join("v"));
    {
        let mut core = open(&db, &vault, &real.join("dl"));
        prepare(&mut core, "r1", "same.zip");
    }
    let mut core = open(&db, &vault, &alias.join("dl"));
    prepare(&mut core, "r2", "same.zip");
    let (a, b) = (path_of(&core, "r1"), path_of(&core, "r2"));
    // the category folder does not exist (Prepare creates nothing), so resolve the root and re-append
    let physical = |p: &PathBuf| {
        let category = p.parent().unwrap();
        std::fs::canonicalize(category.parent().unwrap())
            .unwrap()
            .join(category.file_name().unwrap())
            .join(p.file_name().unwrap())
    };
    assert_ne!(
        physical(&a),
        physical(&b),
        "{a:?} and {b:?} are one physical file"
    );
}

#[test]
fn the_engine_request_carries_the_reserved_path_and_the_context_text() {
    use velqra_core::{Engine, EngineError, EngineRequest};
    #[derive(Default)]
    struct Capture(Vec<EngineRequest>);
    impl Engine for Capture {
        fn submit(&mut self, r: &EngineRequest) -> Result<(), EngineError> {
            self.0.push(r.clone());
            Ok(())
        }
        fn finished(&mut self, _: &str) -> Option<bool> {
            None
        }
    }
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("dl");
    std::fs::create_dir_all(&root).unwrap();
    let mut core = open(&d.path().join("c.db"), &d.path().join("v"), &root);
    let Message::Prepared(receipt) = prepare(&mut core, "r1", "a.zip").body else {
        panic!("prepare failed")
    };
    let rr = RequestRef {
        task_id: receipt.task_id,
        fingerprint: receipt.fingerprint,
    };
    core.handle(&env("r1", Message::BeginHandoff(rr.clone())), 2);
    core.handle(
        &env(
            "r1",
            Message::Commit(CommitBody {
                cancel: CancelEvidence::Confirmed,
                receipt: rr,
            }),
        ),
        3,
    );
    let mut engine = Capture::default();
    core.pump(&mut engine).unwrap();
    let req = &engine.0[0];
    assert_eq!(
        req.destination.as_deref().map(std::path::Path::new),
        Some(path_of(&core, "r1").as_path())
    );
    assert_eq!(req.context.as_deref(), Some("ctx"));
    assert!(!format!("{req:?}").contains("ctx"), "Debug stays redacted");
}
