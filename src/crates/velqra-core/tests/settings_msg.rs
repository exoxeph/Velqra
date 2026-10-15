// SPDX-License-Identifier: GPL-3.0-only
//! A7: the extension can read the core's settings and cannot change them.
use velqra_core::settings::{Loaded, Settings};
use velqra_core::store::MemStore;
use velqra_core::vault::MemVault;
use velqra_core::Core;
use velqra_protocol::*;

fn env(body: Message) -> Envelope {
    Envelope {
        version: PROTOCOL_VERSION,
        message_id: "m1".into(),
        session_id: "s".into(),
        request_id: "r1".into(),
        generation: 1,
        body,
    }
}

fn core(loaded: Loaded) -> Core<MemStore> {
    Core::with_vault(MemStore::default(), Box::new(MemVault::default())).with_settings(loaded)
}

#[test]
fn settings_get_returns_a_snapshot_of_the_loaded_settings() {
    let s = Settings {
        mode: CaptureMode::PerSite,
        allowed_sites: vec!["*.example.com".into()],
        destination_root: Some(r"C:\private-folder-name\dl".into()),
        ..Settings::default()
    };
    let mut c = core(Loaded {
        settings: s,
        problem: None,
    });
    let out = c.handle(&env(Message::SettingsGet(Empty {})), 1);
    let Message::SettingsReply(snap) = &out.body else {
        panic!("{:?}", out.body)
    };
    assert_eq!(snap.mode, CaptureMode::PerSite);
    assert_eq!(snap.allowed_sites, ["*.example.com"]);
    assert_eq!(snap.extensions, Settings::default().extensions);
    assert_eq!(snap.problem, None);
    let wire = serde_json::to_string(&out).unwrap();
    assert!(
        !wire.contains("private-folder-name"),
        "folders never leave the core"
    );
}

#[test]
fn a_refused_settings_file_is_reported_with_the_defaults_in_force() {
    let mut c = core(Loaded {
        settings: Settings::default(),
        problem: Some("the settings file has the wrong shape"),
    });
    let out = c.handle(&env(Message::SettingsGet(Empty {})), 1);
    let Message::SettingsReply(snap) = out.body else {
        panic!("not a reply")
    };
    assert_eq!(snap.mode, CaptureMode::On);
    assert_eq!(
        snap.problem.as_deref(),
        Some("the settings file has the wrong shape")
    );
}

#[test]
fn a_core_without_loaded_settings_answers_with_the_defaults() {
    let mut c = Core::new(MemStore::default());
    let out = c.handle(&env(Message::SettingsGet(Empty {})), 1);
    let Message::SettingsReply(snap) = out.body else {
        panic!("not a reply")
    };
    assert_eq!(snap, Settings::default().snapshot(None));
}

#[test]
fn sending_a_reply_type_never_changes_anything_and_is_an_error() {
    let mut c = core(Loaded {
        settings: Settings::default(),
        problem: None,
    });
    let mut forged = Settings::default().snapshot(None);
    forged.mode = CaptureMode::Off;
    forged.extensions = vec!["pdf".into()];
    let out = c.handle(&env(Message::SettingsReply(forged)), 1);
    assert!(matches!(out.body, Message::Error(_)), "{:?}", out.body);
    let after = c.handle(&env(Message::SettingsGet(Empty {})), 2);
    let Message::SettingsReply(snap) = after.body else {
        panic!("not a reply")
    };
    assert_eq!(snap, Settings::default().snapshot(None));
}
