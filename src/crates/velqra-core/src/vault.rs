// SPDX-License-Identifier: GPL-3.0-only
//! Protected context storage. The core keeps only a reference; the secret itself lives here.
//! M0 ships an in-memory vault; the product uses a current-user protected store (DPAPI on Windows).

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use velqra_protocol::Secret;

pub trait SecretVault {
    /// Stores `secret` for `task_id` and returns an opaque reference.
    fn put(&self, task_id: u64, secret: &Secret) -> Result<String, String>;
    fn get(&self, reference: &str) -> Option<Secret>;
    fn remove(&self, reference: &str);
}

/// In-memory vault. Clones share the same storage, which models a vault that outlives a core restart.
#[derive(Clone, Default)]
pub struct MemVault {
    inner: Rc<RefCell<HashMap<String, Secret>>>,
    next: Rc<Cell<u64>>,
}

impl MemVault {
    /// Number of stored contexts (tests use it to prove nothing leaks or disappears).
    pub fn len(&self) -> usize {
        self.inner.borrow().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl SecretVault for MemVault {
    fn put(&self, task_id: u64, secret: &Secret) -> Result<String, String> {
        // unique per allocation: a task that lost an id race can never overwrite or remove another's context
        let n = self.next.get() + 1;
        self.next.set(n);
        let reference = format!("ctx-{task_id}-{n}");
        self.inner
            .borrow_mut()
            .insert(reference.clone(), secret.clone());
        Ok(reference)
    }
    fn get(&self, reference: &str) -> Option<Secret> {
        self.inner.borrow().get(reference).cloned()
    }
    fn remove(&self, reference: &str) {
        self.inner.borrow_mut().remove(reference);
    }
}
