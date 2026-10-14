// SPDX-License-Identifier: GPL-3.0-only
//! Names every boundary ("fault point") and decides, from a plan, which fault hits it.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use velqra_core::store::{Record, Store, StoreError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FaultKind {
    CrashBefore,
    CrashAfter,
    Loss,
    Duplicate,
    Delay,
    StorageError,
    LostReply,
    BrowserUnknownApplied,
    BrowserUnknownNotApplied,
    RaceComplete,
    UserCancelFirst,
    EngineReject,
    ItemErased,
}

#[derive(Clone, Copy, Debug)]
pub enum Choice {
    Kind(FaultKind),
    /// Pick the (n mod len)-th applicable kind at the point that is hit.
    Pick(u32),
}

#[derive(Clone, Debug)]
pub struct PointInfo {
    pub name: String,
    pub kinds: Vec<FaultKind>,
}

#[derive(Default)]
pub struct FaultCtl {
    counter: usize,
    name_counts: HashMap<String, usize>,
    /// Faults by global point index.
    pub plan_idx: Vec<(usize, Choice)>,
    /// Faults by (point name, 1-based occurrence).
    pub plan_name: Vec<(String, usize, FaultKind)>,
    /// Faults applied at EVERY occurrence of a point (a permanently broken disk, for example).
    pub plan_persistent: Vec<(String, FaultKind)>,
    pub record: bool,
    pub points: Vec<PointInfo>,
    pub injected: Vec<(String, FaultKind)>,
}

impl FaultCtl {
    /// Builds a controller from explicit plans (used by the scenario runners).
    pub fn with_plans(
        plan_idx: Vec<(usize, Choice)>,
        plan_name: Vec<(String, usize, FaultKind)>,
        record: bool,
    ) -> Self {
        Self {
            plan_idx,
            plan_name,
            record,
            ..Default::default()
        }
    }

    /// Marks a point as permanently faulty.
    pub fn persistent(mut self, name: &str, kind: FaultKind) -> Self {
        self.plan_persistent.push((name.to_string(), kind));
        self
    }

    pub fn check(&mut self, name: &str, kinds: &[FaultKind]) -> Option<FaultKind> {
        let idx = self.counter;
        self.counter += 1;
        let occurrence = {
            let c = self.name_counts.entry(name.to_string()).or_insert(0);
            *c += 1;
            *c
        };
        if self.record {
            self.points.push(PointInfo {
                name: name.to_string(),
                kinds: kinds.to_vec(),
            });
        }
        let mut hit = None;
        for (i, choice) in &self.plan_idx {
            if *i == idx {
                hit = match choice {
                    Choice::Kind(k) => kinds.contains(k).then_some(*k),
                    Choice::Pick(p) => {
                        if kinds.is_empty() {
                            None
                        } else {
                            Some(kinds[*p as usize % kinds.len()])
                        }
                    }
                };
            }
        }
        for (n, occ, k) in &self.plan_name {
            if n == name && *occ == occurrence && kinds.contains(k) {
                hit = Some(*k);
            }
        }
        for (n, k) in &self.plan_persistent {
            let matches = n == name || n.strip_suffix('*').is_some_and(|pre| name.starts_with(pre));
            if matches && kinds.contains(k) {
                hit = Some(*k);
            }
        }
        if let Some(k) = hit {
            self.injected.push((name.to_string(), k));
        }
        hit
    }
}

pub type Fc = Rc<RefCell<FaultCtl>>;

/// Store wrapper whose `put` can fail at the fault point "core.store.put".
pub struct FaultyStore<S: Store> {
    pub inner: S,
    fc: Fc,
}

impl<S: Store> FaultyStore<S> {
    pub fn new(inner: S, fc: Fc) -> Self {
        Self { inner, fc }
    }
}

impl<S: Store> Store for FaultyStore<S> {
    fn get_by_request(&self, r: &str) -> Result<Option<Record>, StoreError> {
        self.inner.get_by_request(r)
    }
    fn get_by_task(&self, t: u64) -> Result<Option<Record>, StoreError> {
        self.inner.get_by_task(t)
    }
    fn put(&mut self, record: &Record) -> Result<(), StoreError> {
        if self
            .fc
            .borrow_mut()
            .check("core.store.put", &[FaultKind::StorageError])
            .is_some()
        {
            return Err(StoreError::Io("injected storage error".into()));
        }
        self.inner.put(record)
    }
    fn insert(&mut self, record: &Record) -> Result<(), StoreError> {
        if self
            .fc
            .borrow_mut()
            .check("core.store.put", &[FaultKind::StorageError])
            .is_some()
        {
            return Err(StoreError::Io("injected storage error".into()));
        }
        self.inner.insert(record)
    }
    fn next_task_id(&self) -> Result<u64, StoreError> {
        self.inner.next_task_id()
    }
    fn all(&self) -> Result<Vec<Record>, StoreError> {
        self.inner.all()
    }
    fn remove(&mut self, t: u64) -> Result<(), StoreError> {
        self.inner.remove(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_plan_hits_the_nth_point_and_respects_applicable_kinds() {
        let mut f = FaultCtl::default();
        f.plan_idx.push((1, Choice::Kind(FaultKind::Loss)));
        assert_eq!(f.check("a", &[FaultKind::Loss]), None);
        assert_eq!(f.check("b", &[FaultKind::Loss]), Some(FaultKind::Loss));
        assert_eq!(f.check("c", &[FaultKind::Loss]), None);
        let mut g = FaultCtl::default();
        g.plan_idx.push((0, Choice::Kind(FaultKind::Loss)));
        assert_eq!(g.check("a", &[FaultKind::CrashBefore]), None); // not applicable
    }

    #[test]
    fn name_plan_counts_occurrences_per_name() {
        let mut f = FaultCtl::default();
        f.plan_name.push(("x".into(), 2, FaultKind::Loss));
        assert_eq!(f.check("x", &[FaultKind::Loss]), None);
        assert_eq!(f.check("y", &[FaultKind::Loss]), None);
        assert_eq!(f.check("x", &[FaultKind::Loss]), Some(FaultKind::Loss));
    }

    #[test]
    fn recording_lists_every_point_with_its_kinds() {
        let mut f = FaultCtl {
            record: true,
            ..Default::default()
        };
        f.check("p", &[FaultKind::Loss, FaultKind::Delay]);
        assert_eq!(f.points.len(), 1);
        assert_eq!(f.points[0].kinds.len(), 2);
    }

    #[test]
    fn pick_chooses_among_applicable_kinds() {
        let mut f = FaultCtl::default();
        f.plan_idx.push((0, Choice::Pick(5)));
        let k = f.check("p", &[FaultKind::Loss, FaultKind::Delay]);
        assert_eq!(k, Some(FaultKind::Delay)); // 5 % 2 == 1
    }
}
