// SPDX-License-Identifier: GPL-3.0-only
use velqra_core::store::{MemStore, Store};
use velqra_core::Core;
use velqra_protocol::*;

const URL: &str = "https://x.test/a.zip";

fn env(rid: &str, generation: u32, body: Message) -> Envelope {
    Envelope {
        version: PROTOCOL_VERSION,
        message_id: format!("m-{rid}-{}", body.kind()),
        session_id: "s1".into(),
        request_id: rid.into(),
        generation,
        body,
    }
}

fn prepare_body(url: &str) -> PrepareBody {
    PrepareBody {
        download_key: "d1".into(),
        url: url.into(),
        filename: "a.zip".into(),
        context: Secret("S3CR3T-SENTINEL".into()),
    }
}

fn rref() -> RequestRef {
    RequestRef {
        task_id: 1,
        fingerprint: fingerprint(&prepare_body(URL)),
    }
}

fn prep(rid: &str) -> Envelope {
    env(rid, 1, Message::Prepare(prepare_body(URL)))
}
fn begin(rid: &str) -> Envelope {
    env(rid, 1, Message::BeginHandoff(rref()))
}
fn commit(rid: &str) -> Envelope {
    env(
        rid,
        1,
        Message::Commit(CommitBody {
            cancel: CancelEvidence::Confirmed,
            receipt: rref(),
        }),
    )
}
fn abort(rid: &str) -> Envelope {
    env(
        rid,
        1,
        Message::Abort(AbortBody {
            receipt: Some(rref()),
        }),
    )
}
fn abort_unknown(rid: &str) -> Envelope {
    env(rid, 1, Message::Abort(AbortBody { receipt: None }))
}
fn reconcile(rid: &str, owner: OwnerEvidence) -> Envelope {
    env(
        rid,
        1,
        Message::Reconcile(ReconcileBody {
            owner,
            receipt: rref(),
        }),
    )
}

fn state_of(reply: &Envelope) -> TaskState {
    match &reply.body {
        Message::Prepared(r)
        | Message::Armed(r)
        | Message::Committed(r)
        | Message::Aborted(r)
        | Message::Reconciled(r)
        | Message::StatusReply(r) => r.state,
        other => panic!("not a receipt reply: {other:?}"),
    }
}

fn error_of(reply: &Envelope) -> ErrorKind {
    match &reply.body {
        Message::Error(e) => e.kind,
        other => panic!("not an error: {other:?}"),
    }
}

fn core() -> Core<MemStore> {
    Core::new(MemStore::default())
}

fn armed(c: &mut Core<MemStore>, rid: &str) {
    c.handle(&prep(rid), 1);
    c.handle(&begin(rid), 2);
}

#[test]
fn happy_path_prepare_arm_commit() {
    let mut c = core();
    assert_eq!(state_of(&c.handle(&prep("r1"), 1)), TaskState::Prepared);
    assert_eq!(state_of(&c.handle(&begin("r1"), 2)), TaskState::Armed);
    assert_eq!(state_of(&c.handle(&commit("r1"), 3)), TaskState::Committed);
    let rec = c.store.get_by_request("r1").unwrap().unwrap();
    assert_eq!(rec.dispatch_attempt.as_deref(), Some("t1-g1"));
}

#[test]
fn prepare_is_idempotent_and_rejects_payload_change() {
    let mut c = core();
    let a = c.handle(&prep("r1"), 1);
    let b = c.handle(&prep("r1"), 2);
    assert_eq!(a.body, b.body);
    let changed = env(
        "r1",
        1,
        Message::Prepare(prepare_body("https://x.test/OTHER.zip")),
    );
    assert_eq!(error_of(&c.handle(&changed, 3)), ErrorKind::PayloadMismatch);
}

#[test]
fn commit_requires_arming_and_is_idempotent() {
    let mut c = core();
    c.handle(&prep("r1"), 1);
    assert_eq!(error_of(&c.handle(&commit("r1"), 2)), ErrorKind::NotArmed);
    c.handle(&begin("r1"), 3);
    let first = c.handle(&commit("r1"), 4);
    let second = c.handle(&commit("r1"), 5);
    assert_eq!(first.body, second.body);
}

#[test]
fn stale_generation_is_rejected() {
    let mut c = core();
    c.handle(&prep("r1"), 1);
    let stale = env("r1", 2, Message::BeginHandoff(rref()));
    assert_eq!(error_of(&c.handle(&stale, 2)), ErrorKind::StaleGeneration);
}

#[test]
fn abort_fences_later_commit_and_arming() {
    let mut c = core();
    c.handle(&prep("r1"), 1);
    assert_eq!(state_of(&c.handle(&abort("r1"), 2)), TaskState::Aborted);
    assert_eq!(error_of(&c.handle(&begin("r1"), 3)), ErrorKind::Aborted);
    assert_eq!(error_of(&c.handle(&commit("r1"), 4)), ErrorKind::Aborted);
}

#[test]
fn abort_of_unknown_request_creates_a_tombstone_that_fences_a_late_prepare() {
    let mut c = core();
    assert_eq!(
        state_of(&c.handle(&abort_unknown("r9"), 1)),
        TaskState::Aborted
    );
    // the delayed prepare finally arrives: it must not create a live task
    assert_eq!(state_of(&c.handle(&prep("r9"), 2)), TaskState::Aborted);
    assert_eq!(error_of(&c.handle(&begin("r9"), 3)), ErrorKind::Aborted);
}

#[test]
fn committed_task_cannot_be_aborted() {
    let mut c = core();
    armed(&mut c, "r1");
    c.handle(&commit("r1"), 3);
    assert_eq!(error_of(&c.handle(&abort("r1"), 4)), ErrorKind::WrongState);
}

#[test]
fn storage_failure_replies_error_and_leaves_nothing_written() {
    let mut c = core();
    c.store.fail_puts = 1;
    assert_eq!(error_of(&c.handle(&prep("r1"), 1)), ErrorKind::Storage);
    assert!(c.store.get_by_request("r1").unwrap().is_none());
    // a retry succeeds and yields a normal receipt
    assert_eq!(state_of(&c.handle(&prep("r1"), 2)), TaskState::Prepared);
}

#[test]
fn reconcile_resolves_ambiguity() {
    let mut c = core();
    armed(&mut c, "r1");
    assert_eq!(
        state_of(&c.handle(&reconcile("r1", OwnerEvidence::Unknown), 3)),
        TaskState::OwnershipUnknown
    );
    assert_eq!(
        state_of(&c.handle(&reconcile("r1", OwnerEvidence::BrowserOwns), 4)),
        TaskState::Aborted
    );
}

#[test]
fn reconcile_app_owns_commits_from_unknown_after_arming() {
    let mut c = core();
    armed(&mut c, "r2");
    c.handle(&reconcile("r2", OwnerEvidence::Unknown), 3);
    assert_eq!(
        state_of(&c.handle(&reconcile("r2", OwnerEvidence::AppOwns), 4)),
        TaskState::Committed
    );
}

#[test]
fn unarmed_reconcile_cannot_reach_committed() {
    // review C2: Prepared -> OwnershipUnknown -> Committed must not be possible
    let mut c = core();
    c.handle(&prep("r1"), 1);
    assert_eq!(
        error_of(&c.handle(&reconcile("r1", OwnerEvidence::Unknown), 2)),
        ErrorKind::NotArmed
    );
    assert_eq!(
        error_of(&c.handle(&reconcile("r1", OwnerEvidence::AppOwns), 3)),
        ErrorKind::NotArmed
    );
    let rec = c.store.get_by_request("r1").unwrap().unwrap();
    assert_eq!(rec.state, TaskState::Prepared);
    assert!(rec.dispatch_attempt.is_none());
}

#[test]
fn every_follow_up_must_name_the_matching_receipt() {
    // review C2/C3: wrong task id or fingerprint must never change state
    let mut c = core();
    armed(&mut c, "r1");
    let bad = [
        RequestRef {
            task_id: 2,
            fingerprint: rref().fingerprint,
        },
        RequestRef {
            task_id: 1,
            fingerprint: "00".into(),
        },
    ];
    for r in bad {
        let msgs = [
            Message::BeginHandoff(r.clone()),
            Message::Commit(CommitBody {
                cancel: CancelEvidence::Confirmed,
                receipt: r.clone(),
            }),
            Message::Abort(AbortBody {
                receipt: Some(r.clone()),
            }),
            Message::Reconcile(ReconcileBody {
                owner: OwnerEvidence::AppOwns,
                receipt: r.clone(),
            }),
        ];
        for m in msgs {
            assert_eq!(
                error_of(&c.handle(&env("r1", 1, m), 5)),
                ErrorKind::IdentityMismatch
            );
        }
    }
    assert_eq!(
        c.store.get_by_request("r1").unwrap().unwrap().state,
        TaskState::Armed
    );
}

#[test]
fn late_reconcile_after_commit_reports_the_committed_state() {
    let mut c = core();
    armed(&mut c, "r1");
    c.handle(&commit("r1"), 3);
    assert_eq!(
        state_of(&c.handle(&reconcile("r1", OwnerEvidence::Unknown), 4)),
        TaskState::Committed
    );
}

#[test]
fn abort_with_browser_evidence_resolves_an_unknown_ownership() {
    let mut c = core();
    armed(&mut c, "r1");
    c.handle(&reconcile("r1", OwnerEvidence::Unknown), 3);
    assert_eq!(state_of(&c.handle(&abort("r1"), 4)), TaskState::Aborted);
}

#[test]
fn expired_tombstones_are_compacted_but_still_fence_the_request() {
    // review I2: purging must not revive an aborted identity
    let mut c = core();
    c.handle(&prep("r1"), 100);
    c.handle(&abort("r1"), 100);
    assert_eq!(c.purge_tombstones(100 + 10, 3600).unwrap(), 0);
    assert_eq!(c.purge_tombstones(100 + 3600, 3600).unwrap(), 1);
    assert_eq!(
        c.purge_tombstones(100 + 7200, 3600).unwrap(),
        0,
        "already compacted"
    );
    assert_eq!(state_of(&c.handle(&prep("r1"), 9000)), TaskState::Aborted);
    assert_eq!(error_of(&c.handle(&begin("r1"), 9001)), ErrorKind::Aborted);
}

#[test]
fn retention_arithmetic_never_overflows() {
    // review M3
    let mut c = core();
    c.handle(&prep("r1"), u64::MAX - 1);
    c.handle(&abort("r1"), u64::MAX - 1);
    assert_eq!(c.purge_tombstones(u64::MAX, u64::MAX).unwrap(), 0);
    assert_eq!(
        c.purge_tombstones(0, 3600).unwrap(),
        0,
        "backwards clock must not purge"
    );
}

#[test]
fn the_core_validates_typed_envelopes_itself() {
    // review I5: constructed envelopes cannot bypass wire validation
    let mut c = core();
    let mut bad_version = prep("r1");
    bad_version.version = 99;
    assert_eq!(error_of(&c.handle(&bad_version, 1)), ErrorKind::BadVersion);
    let traversal = env(
        "r2",
        1,
        Message::Prepare(PrepareBody {
            download_key: "d".into(),
            url: URL.into(),
            filename: "..".into(),
            context: Secret("x".into()),
        }),
    );
    assert!(matches!(c.handle(&traversal, 1).body, Message::Error(_)));
    assert!(c.store.get_by_request("r1").unwrap().is_none());
    assert!(c.store.get_by_request("r2").unwrap().is_none());
}

#[test]
fn records_keep_the_request_but_never_the_secret_context() {
    let mut c = core();
    c.handle(&prep("r1"), 1);
    let rec = c.store.get_by_request("r1").unwrap().unwrap();
    let text = serde_json::to_string(&rec).unwrap();
    assert!(!text.contains("S3CR3T-SENTINEL"));
    let req = rec.request.expect("request metadata is stored");
    assert_eq!(
        (req.filename.as_str(), req.download_key.as_str()),
        ("a.zip", "d1")
    );
    assert!(!text.contains(URL), "the url is held by reference only");
    assert_eq!(c.vault.get(&req.url_ref).unwrap().0, URL);
    let cref = rec.context_ref.expect("context is stored by reference");
    assert_eq!(c.vault.get(&cref).unwrap().0, "S3CR3T-SENTINEL");
}

#[test]
fn abort_releases_the_stored_context() {
    let mut c = core();
    c.handle(&prep("r1"), 1);
    let cref = c
        .store
        .get_by_request("r1")
        .unwrap()
        .unwrap()
        .context_ref
        .unwrap();
    c.handle(&abort("r1"), 2);
    assert!(c.vault.get(&cref).is_none());
}

#[test]
fn tombstones_are_purged_only_by_compaction_not_deletion_of_identity() {
    let mut c = core();
    c.handle(&prep("r1"), 100);
    c.handle(&abort("r1"), 100);
    c.purge_tombstones(100 + 3600, 3600).unwrap();
    let rec = c
        .store
        .get_by_request("r1")
        .unwrap()
        .expect("fence is kept");
    assert!(rec.compacted && rec.request.is_none() && rec.context_ref.is_none());
}
