// SPDX-License-Identifier: GPL-3.0-only
use velqra_sim::scenarios::{baseline, exhaustive};

#[test]
fn baseline_is_clean_and_names_many_fault_points() {
    let (r, points) = baseline();
    assert!(velqra_sim::invariants::check(&r).is_empty());
    assert!(points.len() >= 25, "only {} fault points", points.len());
}

#[test]
fn every_single_fault_at_every_point_keeps_all_invariants() {
    let s = exhaustive();
    assert!(s.runs >= 60, "only {} runs", s.runs);
    assert!(
        s.violations.is_empty(),
        "{} violations, first: {:?}",
        s.violations.len(),
        s.violations.first()
    );
}

#[test]
fn every_pair_of_faults_keeps_all_invariants() {
    let s = velqra_sim::scenarios::exhaustive_pairs();
    assert!(s.runs >= 1000, "only {} runs", s.runs);
    assert!(
        s.violations.is_empty(),
        "{} violations, first: {:?}",
        s.violations.len(),
        s.violations.iter().take(3).collect::<Vec<_>>()
    );
}
