// SPDX-License-Identifier: GPL-3.0-only
use velqra_sim::invariants::check;
use velqra_sim::scenarios::{baseline, seeded};

#[test]
fn seeded_multi_fault_runs_keep_all_invariants() {
    let (_, points) = baseline();
    let horizon = points.len() * 2;
    let seeds: u64 = std::env::var("VELQRA_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000);
    let mut failures = Vec::new();
    for seed in 0..seeds {
        for nfaults in [2usize, 3, 4] {
            let r = seeded(seed, nfaults, horizon);
            let v = check(&r);
            if !v.is_empty() {
                failures.push(format!(
                    "seed={seed} faults={nfaults} injected={:?}: {v:?}",
                    r.injected
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
}

#[test]
fn same_seed_gives_the_same_run() {
    let a = seeded(42, 3, 80);
    let b = seeded(42, 3, 80);
    assert_eq!(format!("{:?}", a.injected), format!("{:?}", b.injected));
    assert_eq!(a.ticks, b.ticks);
}

#[test]
fn seeds_report_what_was_actually_injected_not_only_what_was_planned() {
    let (_, points) = baseline();
    let horizon = points.len() * 2;
    let mut by_count = [0usize; 5];
    for seed in 0..500 {
        let r = seeded(seed, 3, horizon);
        assert!(r.injected.len() <= 3, "more faults than planned");
        by_count[r.injected.len()] += 1;
    }
    assert!(
        by_count[0] > 0,
        "some planned faults miss their point, and the harness must say so"
    );
    assert!(
        by_count[2] + by_count[3] > 100,
        "multi-fault runs are the bulk: {by_count:?}"
    );
}
