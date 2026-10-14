// SPDX-License-Identifier: GPL-3.0-only
//! A tiny model of a browser download.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BState {
    InProgress,
    Paused,
    Cancelled,
    Completed,
    Erased,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Actor {
    Ext,
    User,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PauseOutcome {
    Paused,
    AlreadyDone,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelOutcome {
    Cancelled,
    AlreadyCompleted,
    AlreadyCancelled,
    Unknown,
    Crashed,
}

#[derive(Clone, Debug)]
pub struct FakeBrowser {
    pub state: BState,
    pub cancelled_by: Option<Actor>,
}

impl FakeBrowser {
    pub fn new() -> Self {
        Self {
            state: BState::InProgress,
            cancelled_by: None,
        }
    }
}

impl Default for FakeBrowser {
    fn default() -> Self {
        Self::new()
    }
}
