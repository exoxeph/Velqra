// SPDX-License-Identifier: GPL-3.0-only
//! Fault matrices over the honest handshake + prepare/begin/commit flow.
use std::collections::HashSet;
use velqra_bridge::handshake::b64_encode;
use velqra_bridge::sim::*;
use velqra_bridge::testkit::*;
use velqra_protocol::*;

#[test]
fn the_checker_flags_deliberately_wrong_traces() {
    let sent = vec![envelope("sid1", "m1", "r", Message::Status(Empty {}))];
    let issued: HashSet<String> = ["sid1".to_string()].into();
    assert!(check_call(&sent[0], &issued, &sent).is_empty());
    // a session id the server never issued
    let forged = envelope("sid9", "m1", "r", Message::Status(Empty {}));
    assert!(check_call(
        &forged,
        &[("sid9".to_string())]
            .into_iter()
            .filter(|_| false)
            .collect(),
        &sent
    )
    .iter()
    .any(|v| v.starts_with("B1")));
    // issued session but an envelope the client never sent
    let fabricated = envelope("sid1", "m2", "r", Message::Status(Empty {}));
    assert!(check_call(&fabricated, &issued, &sent)
        .iter()
        .any(|v| v.starts_with("B2")));
    // same ids, different body
    let tampered = envelope("sid1", "m1", "r", Message::Health(Empty {}));
    assert!(check_call(&tampered, &issued, &sent)
        .iter()
        .any(|v| v.starts_with("B2")));
}

#[test]
fn the_secret_detector_sees_raw_and_base64_secrets() {
    let key = *secret().expose();
    assert!(leaks_secret(&key));
    assert!(leaks_secret(format!("x{}y", b64_encode(&key)).as_bytes()));
    assert!(!leaks_secret(b"nothing to see"));
}

#[test]
fn the_honest_run_completes_with_three_backend_calls_and_no_violations() {
    let r = run_plan(vec![], true);
    assert!(r.completed && !r.gave_up, "{r:?}");
    assert_eq!(r.backend_calls, 3, "prepare, begin_handoff, commit");
    assert!(r.violations.is_empty(), "{:?}", r.violations);
    assert_eq!(
        r.points.len(),
        11,
        "attach, hello, challenge, auth, ready and three request/reply pairs: {:?}",
        r.points
    );
}

#[test]
fn every_single_fault_at_every_point_keeps_all_invariants_and_the_client_completes() {
    let s = exhaustive();
    assert!(
        s.runs >= 4 * s.points,
        "{} runs for {} points",
        s.runs,
        s.points
    );
    assert!(
        s.violations.is_empty(),
        "{} violations, first: {:?}",
        s.violations.len(),
        s.violations.first()
    );
    assert_eq!(s.not_completed, 0);
}

#[test]
fn every_pair_of_faults_keeps_all_invariants_and_the_client_completes() {
    let s = exhaustive_pairs();
    assert!(s.runs >= 1000, "only {} runs", s.runs);
    assert!(
        s.violations.is_empty(),
        "{} violations, first: {:?}",
        s.violations.len(),
        s.violations.first()
    );
}

#[test]
fn seeded_multi_fault_runs_keep_all_invariants_and_report_actual_injections() {
    let horizon = run_plan(vec![], true).points.len() * 2;
    let seeds: u64 = std::env::var("VELQRA_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1500);
    let mut by_count = [0usize; 6];
    let mut failures = Vec::new();
    for seed in 0..seeds {
        for n in [2usize, 3, 4] {
            let r = seeded(seed, n, horizon);
            assert!(r.injected.len() <= n, "more faults than planned");
            by_count[r.injected.len().min(5)] += 1;
            if !r.violations.is_empty() {
                failures.push(format!(
                    "seed={seed} faults={n} injected={:?}: {:?}",
                    r.injected, r.violations
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} failing runs, first: {}",
        failures.len(),
        failures[0]
    );
    assert!(
        by_count[0] > 0,
        "some planned faults miss their point and the harness must say so: {by_count:?}"
    );
    assert!(
        by_count[2] + by_count[3] + by_count[4] > 100,
        "multi-fault runs are the bulk: {by_count:?}"
    );
}

#[test]
fn the_same_seed_gives_the_same_run() {
    let a = seeded(42, 3, 40);
    let b = seeded(42, 3, 40);
    assert_eq!(format!("{:?}", a.injected), format!("{:?}", b.injected));
    assert_eq!(
        (a.ticks, a.completed, a.backend_calls),
        (b.ticks, b.completed, b.backend_calls)
    );
}
