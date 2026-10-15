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

fn with_key(id: u64, rid: &str, key: &str) -> Record {
    use velqra_core::store::Reservation;
    let mut r = rec(id, rid);
    r.destination = Some(Reservation {
        path: format!("C:/dl/{key}"),
        key: key.to_string(),
        released: false,
    });
    r
}

fn reservations_are_unique<S: Store>(mut s: S) {
    use velqra_core::store::StoreError::Conflict;
    s.insert(&with_key(1, "r1", "k1")).unwrap();
    assert!(s.is_reserved("k1").unwrap());
    assert!(!s.is_reserved("k2").unwrap());
    assert_eq!(s.insert(&with_key(2, "r2", "k1")).unwrap_err(), Conflict);
    assert!(s.get_by_request("r2").unwrap().is_none(), "nothing written");
    s.insert(&with_key(2, "r2", "k2")).unwrap();
    // an update may not take another task's reservation, and a failed update changes nothing
    assert_eq!(s.put(&with_key(2, "r2", "k1")).unwrap_err(), Conflict);
    assert_eq!(
        s.get_by_task(2).unwrap().unwrap().destination.unwrap().key,
        "k2"
    );
    assert!(
        s.get_by_task(1).is_ok_and(|r| r.is_some()),
        "the owner survived"
    );
    // records without a destination never collide with each other
    s.insert(&rec(3, "r3")).unwrap();
    s.insert(&rec(4, "r4")).unwrap();
    // releasing frees the key; removing does too
    let mut released = with_key(1, "r1", "k1");
    released.destination.as_mut().unwrap().released = true;
    s.put(&released).unwrap();
    assert!(!s.is_reserved("k1").unwrap());
    s.insert(&with_key(5, "r5", "k1")).unwrap();
    s.remove(5).unwrap();
    assert!(!s.is_reserved("k1").unwrap());
    s.remove(2).unwrap();
    assert!(!s.is_reserved("k2").unwrap());
}

#[test]
fn mem_store_reservations_are_unique() {
    reservations_are_unique(MemStore::default());
}

#[test]
fn sqlite_store_reservations_are_unique_and_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("core.db");
    reservations_are_unique(SqliteStore::open(&path).unwrap());
    let mut s = SqliteStore::open(&path).unwrap();
    s.insert(&with_key(10, "r10", "kk")).unwrap();
    drop(s);
    let mut again = SqliteStore::open(&path).unwrap();
    assert!(again.is_reserved("kk").unwrap());
    assert_eq!(
        again.insert(&with_key(11, "r11", "kk")).unwrap_err(),
        velqra_core::store::StoreError::Conflict
    );
}

#[test]
fn two_sqlite_connections_cannot_double_reserve() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("core.db");
    SqliteStore::open(&path).unwrap(); // create the schema once
    let handles: Vec<_> = (0..8u64)
        .map(|i| {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut s = SqliteStore::open(&path).unwrap();
                s.insert(&with_key(100 + i, &format!("r{i}"), "same"))
                    .is_ok()
            })
        })
        .collect();
    let wins = handles
        .into_iter()
        .filter(|_| true)
        .map(|h| h.join().unwrap())
        .filter(|w| *w)
        .count();
    assert_eq!(wins, 1, "exactly one connection got the destination");
}

#[test]
fn an_old_database_without_the_reservation_column_is_upgraded_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("core.db");
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE records(task_id INTEGER PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, json TEXT NOT NULL);
             CREATE TABLE meta(id INTEGER PRIMARY KEY CHECK(id = 1), next INTEGER NOT NULL);
             INSERT INTO meta VALUES(1, 2);",
        )
        .unwrap();
        let json = serde_json::to_string(&rec(1, "old")).unwrap();
        c.execute("INSERT INTO records VALUES(1, 'old', ?1)", [json])
            .unwrap();
    }
    let mut s = SqliteStore::open(&path).unwrap();
    assert_eq!(s.get_by_request("old").unwrap().unwrap().task_id, 1);
    s.insert(&with_key(2, "new", "k")).unwrap();
    assert!(s.is_reserved("k").unwrap());
}
