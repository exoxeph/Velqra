// SPDX-License-Identifier: GPL-3.0-only
use velqra_core::store::{MemStore, Record, SqliteStore, Store};
use velqra_protocol::TaskState;

fn rec(id: u64, rid: &str) -> Record {
    Record::new(id, rid, 1, "fp", TaskState::Prepared)
}

fn conformance<S: Store>(mut s: S) {
    assert_eq!(s.next_task_id().unwrap(), 1);
    assert!(s.get_by_request("r1").unwrap().is_none());
    s.put(&rec(1, "r1")).unwrap();
    assert_eq!(s.next_task_id().unwrap(), 2);
    assert_eq!(s.get_by_request("r1").unwrap().unwrap().task_id, 1);
    assert_eq!(s.get_by_task(1).unwrap().unwrap().request_id, "r1");
    let mut r = rec(1, "r1");
    r.state = TaskState::Armed;
    r.history.push(TaskState::Armed);
    s.put(&r).unwrap();
    assert_eq!(s.get_by_task(1).unwrap().unwrap().state, TaskState::Armed);
    s.put(&rec(2, "r2")).unwrap();
    assert_eq!(s.all().unwrap().len(), 2);
    s.remove(2).unwrap();
    assert_eq!(s.all().unwrap().len(), 1);
    // ids are never reused after a remove
    assert_eq!(s.next_task_id().unwrap(), 3);
}

#[test]
fn mem_store_conforms() {
    conformance(MemStore::default());
}

#[test]
fn sqlite_store_conforms_and_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("core.db");
    conformance(SqliteStore::open(&path).unwrap());
    let reopened = SqliteStore::open(&path).unwrap();
    assert_eq!(reopened.all().unwrap().len(), 1);
    assert_eq!(reopened.next_task_id().unwrap(), 3);
}

#[test]
fn mem_store_can_inject_put_failures_without_writing() {
    let mut s = MemStore::default();
    s.fail_puts = 1;
    assert!(s.put(&rec(1, "r1")).is_err());
    assert!(s.get_by_request("r1").unwrap().is_none());
    assert!(s.put(&rec(1, "r1")).is_ok());
}

fn insert_never_overwrites<S: Store>(mut s: S) {
    s.insert(&rec(1, "r1")).unwrap();
    assert_eq!(
        s.insert(&rec(1, "other")).unwrap_err(),
        velqra_core::store::StoreError::Conflict
    );
    assert_eq!(
        s.insert(&rec(2, "r1")).unwrap_err(),
        velqra_core::store::StoreError::Conflict
    );
    assert_eq!(s.get_by_task(1).unwrap().unwrap().request_id, "r1");
    assert_eq!(s.all().unwrap().len(), 1);
}

#[test]
fn insert_conflicts_instead_of_overwriting_in_both_stores() {
    insert_never_overwrites(MemStore::default());
    let dir = tempfile::tempdir().unwrap();
    insert_never_overwrites(SqliteStore::open(&dir.path().join("c.db")).unwrap());
}

#[test]
fn two_sqlite_connections_cannot_overwrite_each_other() {
    // review M2: both read the same next id; the second writer must get a Conflict, not replace A
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c.db");
    let mut a = SqliteStore::open(&path).unwrap();
    let mut b = SqliteStore::open(&path).unwrap();
    let (ida, idb) = (a.next_task_id().unwrap(), b.next_task_id().unwrap());
    assert_eq!(ida, idb);
    a.insert(&rec(ida, "from-a")).unwrap();
    assert_eq!(
        b.insert(&rec(idb, "from-b")).unwrap_err(),
        velqra_core::store::StoreError::Conflict
    );
    assert_eq!(a.get_by_request("from-a").unwrap().unwrap().task_id, ida);
    assert_eq!(b.next_task_id().unwrap(), ida + 1);
}
