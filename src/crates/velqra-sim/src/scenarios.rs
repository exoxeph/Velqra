// SPDX-License-Identifier: GPL-3.0-only
//! Scenario runners: baseline, named faults, exhaustive single-fault matrix, seeded runs.

use crate::fault::{Choice, FaultCtl, FaultKind, PointInfo};
use crate::invariants::{check, classify, Outcome};
use crate::world::{RunRecord, World};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

pub fn run_with(
    plan_idx: Vec<(usize, Choice)>,
    plan_name: Vec<(String, usize, FaultKind)>,
    record: bool,
    core_down_until: u64,
) -> (RunRecord, Vec<PointInfo>) {
    let fc = Rc::new(RefCell::new(FaultCtl::with_plans(
        plan_idx, plan_name, record,
    )));
    let mut w = World::new_core_down(fc.clone(), core_down_until);
    let r = w.run();
    let points = fc.borrow().points.clone();
    (r, points)
}

/// Runs with some points permanently faulty (a broken disk). A trailing `*` matches a prefix.
pub fn run_persistent(
    persistent: &[(&str, FaultKind)],
    plan_name: Vec<(String, usize, FaultKind)>,
) -> RunRecord {
    let mut ctl = FaultCtl::with_plans(vec![], plan_name, false);
    for (n, k) in persistent {
        ctl = ctl.persistent(n, *k);
    }
    let fc = Rc::new(RefCell::new(ctl));
    World::new_core_down(fc, 0).run()
}

pub fn baseline() -> (RunRecord, Vec<PointInfo>) {
    run_with(vec![], vec![], true, 0)
}

pub fn by_name(name: &str, occurrence: usize, kind: FaultKind) -> RunRecord {
    run_with(vec![], vec![(name.to_string(), occurrence, kind)], false, 0).0
}

pub struct Summary {
    pub runs: usize,
    pub points: usize,
    pub outcomes: HashMap<Outcome, usize>,
    pub violations: Vec<String>,
}

/// Every fault kind at every fault point reached by the happy path, one fault per run.
pub fn exhaustive() -> Summary {
    let (_, points) = baseline();
    let mut s = Summary {
        runs: 0,
        points: points.len(),
        outcomes: HashMap::new(),
        violations: Vec::new(),
    };
    for (idx, p) in points.iter().enumerate() {
        for kind in &p.kinds {
            let (r, _) = run_with(vec![(idx, Choice::Kind(*kind))], vec![], false, 0);
            s.runs += 1;
            *s.outcomes.entry(classify(&r)).or_insert(0) += 1;
            for v in check(&r) {
                s.violations
                    .push(format!("point #{idx} {} + {kind:?}: {v}", p.name));
            }
        }
    }
    s
}

/// `nfaults` random faults over the first `horizon` fault points, reproducible from `seed`.
pub fn seeded(seed: u64, nfaults: usize, horizon: usize) -> RunRecord {
    let mut rng = StdRng::seed_from_u64(seed);
    let plan: Vec<(usize, Choice)> = (0..nfaults)
        .map(|_| (rng.gen_range(0..horizon), Choice::Pick(rng.gen())))
        .collect();
    run_with(plan, vec![], false, 0).0
}

/// Depth-2 exhaustive: for every first fault, every fault kind at every point reached
/// after it (points are taken from the faulty run itself, so recovery paths are covered).
pub fn exhaustive_pairs() -> Summary {
    let (_, base_points) = baseline();
    let mut s = Summary {
        runs: 0,
        points: base_points.len(),
        outcomes: HashMap::new(),
        violations: Vec::new(),
    };
    for (i1, p1) in base_points.iter().enumerate() {
        for k1 in &p1.kinds {
            let (_, points) = run_with(vec![(i1, Choice::Kind(*k1))], vec![], true, 0);
            for (i2, p2) in points.iter().enumerate().skip(i1 + 1) {
                for k2 in &p2.kinds {
                    let plan = vec![(i1, Choice::Kind(*k1)), (i2, Choice::Kind(*k2))];
                    let (r, _) = run_with(plan, vec![], false, 0);
                    s.runs += 1;
                    *s.outcomes.entry(classify(&r)).or_insert(0) += 1;
                    for v in check(&r) {
                        s.violations.push(format!(
                            "#{i1} {} + {k1:?} then #{i2} {} + {k2:?}: {v}",
                            p1.name, p2.name
                        ));
                    }
                }
            }
        }
    }
    s
}
