// SPDX-License-Identifier: GPL-3.0-only
//! The simulated world: browser + extension agent + network + core + engine, driven by ticks.

use crate::browser::{Actor, BState, CancelOutcome, FakeBrowser, PauseOutcome};
use crate::engine::FakeEngine;
use crate::fault::{FaultKind, FaultyStore, Fc};
use velqra_core::store::{MemStore, Store};
use velqra_core::{Core, DispatchEvent};
use velqra_protocol::*;

pub const PRE_DEADLINE: u64 = 6;
pub const RESEND_EVERY: u64 = 3;
pub const DOWN_TICKS: u64 = 2;
pub const MAX_TICKS: u64 = 400;
/// Consecutive failed journal writes after which the extension stops trying and shows a hold.
pub const HOLD_AFTER: u32 = 5;
pub const SENTINEL: &str = "S3CR3T-SENTINEL";
const REQUEST_ID: &str = "req-1";
const SESSION_ID: &str = "s1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JState {
    Seen,
    Paused,
    PrepareSent,
    ReceiptStored,
    CancelIntentStored,
    CancelRequested,
    CancelConfirmed,
    CommitSent,
    HandedOff,
    Returning,
    Returned,
    ReconcileRequired,
}

impl JState {
    pub fn name(&self) -> &'static str {
        match self {
            JState::Seen => "seen",
            JState::Paused => "paused",
            JState::PrepareSent => "prepare_sent",
            JState::ReceiptStored => "receipt_stored",
            JState::CancelIntentStored => "cancel_intent_stored",
            JState::CancelRequested => "cancel_requested",
            JState::CancelConfirmed => "cancel_confirmed",
            JState::CommitSent => "commit_sent",
            JState::HandedOff => "handed_off",
            JState::Returning => "returning",
            JState::Returned => "returned",
            JState::ReconcileRequired => "reconcile_required",
        }
    }
    fn terminal(&self) -> bool {
        matches!(
            self,
            JState::HandedOff | JState::Returned | JState::ReconcileRequired
        )
    }
}

/// What the extension keeps on disk: the step it reached and the receipt it was given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Journal {
    pub state: JState,
    pub receipt: Option<RequestRef>,
}

/// One extension-initiated browser cancel, with what was durable at that moment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancelEvent {
    pub journal: Option<JState>,
    pub core: Option<TaskState>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Core,
    Ext,
}

struct InFlight {
    at: u64,
    seq: u64,
    to: Side,
    env: Envelope,
}

#[derive(Default)]
struct ExtVol {
    pending: Option<Message>,
    waiting_since: u64,
    last_sent: Option<u64>,
    aborting: bool,
    /// The extension gave up journaling and is showing a visible hold.
    held: bool,
}

enum Jw {
    Ok,
    Crashed,
    Failed,
}

#[derive(Clone, Debug)]
pub struct RunRecord {
    pub quiesced: bool,
    pub ticks: u64,
    pub ext_final: Option<JState>,
    pub core_final: Option<TaskState>,
    pub core_history: Vec<TaskState>,
    pub engine_attempts: Vec<String>,
    pub browser_final: BState,
    pub browser_cancelled_by: Option<Actor>,
    /// Every extension-initiated cancel, in order.
    pub cancels: Vec<CancelEvent>,
    /// Every engine submission the core made, with the record state at that moment.
    pub dispatches: Vec<DispatchEvent>,
    /// Calls that actually reached the engine (counted by the engine itself, not by the core).
    pub engine_calls: usize,
    pub held: bool,
    pub acked_prepares: Vec<String>,
    pub trace_leaks_secret: bool,
    pub injected: Vec<(String, FaultKind)>,
}

pub fn prepare_body() -> PrepareBody {
    PrepareBody {
        download_key: "d1".into(),
        url: "https://x.test/a.zip".into(),
        filename: "a.zip".into(),
        context: Secret(SENTINEL.into()),
    }
}

pub struct World {
    pub tick: u64,
    seq: u64,
    fc: Fc,
    net: Vec<InFlight>,
    pub browser: FakeBrowser,
    journal: Option<Journal>,
    ext: ExtVol,
    ever_held: bool,
    /// Consecutive failed journal writes; a soft recovery keeps it, a crash clears it.
    fail_streak: u32,
    ext_down_until: u64,
    ext_recover_pending: bool,
    pub core: Core<FaultyStore<MemStore>>,
    core_down_until: u64,
    pub engine: FakeEngine,
    pub trace: Vec<String>,
    acked: Vec<String>,
    cancels: Vec<CancelEvent>,
    dispatches: Vec<DispatchEvent>,
    expected_fp: String,
}

impl World {
    pub fn new(fc: Fc) -> Self {
        Self::new_core_down(fc, 0)
    }

    pub fn new_core_down(fc: Fc, until_tick: u64) -> Self {
        Self {
            tick: 0,
            seq: 0,
            net: Vec::new(),
            browser: FakeBrowser::new(),
            journal: None,
            ext: ExtVol::default(),
            ever_held: false,
            fail_streak: 0,
            ext_down_until: 0,
            ext_recover_pending: false,
            core: Core::new(FaultyStore::new(MemStore::default(), fc.clone())),
            core_down_until: until_tick,
            engine: FakeEngine::new(fc.clone()),
            fc,
            trace: Vec::new(),
            acked: Vec::new(),
            cancels: Vec::new(),
            dispatches: Vec::new(),
            expected_fp: fingerprint(&prepare_body()),
        }
    }

    fn log(&mut self, line: String) {
        self.trace.push(format!("[{}] {line}", self.tick));
    }

    fn core_state(&self) -> Option<TaskState> {
        self.core
            .store
            .inner
            .get_by_request(REQUEST_ID)
            .ok()
            .flatten()
            .map(|r| r.state)
    }

    // ---------- test hooks ----------

    pub fn journal_state(&self) -> Option<JState> {
        self.journal.as_ref().map(|j| j.state)
    }

    pub fn journal_receipt(&self) -> Option<RequestRef> {
        self.journal.as_ref().and_then(|j| j.receipt.clone())
    }

    pub fn is_held(&self) -> bool {
        self.ext.held
    }

    /// Kind of the message the extension is still trying to get acknowledged.
    pub fn pending_kind(&self) -> Option<&'static str> {
        self.ext.pending.as_ref().map(|m| m.kind())
    }

    /// Hands a message straight to the extension agent, as if the network delivered it now.
    pub fn feed_ext(&mut self, env: Envelope) {
        self.ext_on_message(env);
    }

    /// An envelope with this run's ids, for building forged or stale replies in tests.
    pub fn make_env(&mut self, body: Message) -> Envelope {
        self.mk_env(body)
    }

    // ---------- network ----------

    fn mk_env(&mut self, body: Message) -> Envelope {
        self.seq += 1;
        Envelope {
            version: PROTOCOL_VERSION,
            message_id: format!("m{}", self.seq),
            session_id: SESSION_ID.into(),
            request_id: REQUEST_ID.into(),
            generation: 1,
            body,
        }
    }

    /// Queues `env` for delivery, applying network faults at `point`.
    /// Returns the fault that was applied (crash kinds are left to the caller).
    fn net_send(
        &mut self,
        to: Side,
        env: Envelope,
        point: &str,
        extra: &[FaultKind],
    ) -> Option<FaultKind> {
        let mut kinds = vec![FaultKind::Loss, FaultKind::Duplicate, FaultKind::Delay];
        kinds.extend_from_slice(extra);
        let k = self.fc.borrow_mut().check(point, &kinds);
        let line = format!("send to {to:?} {env:?} fault={k:?}");
        self.log(line);
        let copies = match k {
            Some(FaultKind::Loss) | Some(FaultKind::CrashAfter) => 0,
            Some(FaultKind::Duplicate) => 2,
            _ => 1,
        };
        let at = self.tick + if k == Some(FaultKind::Delay) { 8 } else { 1 };
        for _ in 0..copies {
            self.seq += 1;
            self.net.push(InFlight {
                at,
                seq: self.seq,
                to,
                env: env.clone(),
            });
        }
        k
    }

    fn deliver_due(&mut self) {
        let mut due: Vec<InFlight> = Vec::new();
        let mut rest = Vec::new();
        for m in self.net.drain(..) {
            if m.at <= self.tick {
                due.push(m);
            } else {
                rest.push(m);
            }
        }
        self.net = rest;
        due.sort_by_key(|m| (m.at, m.seq));
        for m in due {
            match m.to {
                Side::Core => self.core_deliver(m.env),
                Side::Ext => {
                    if self.tick >= self.ext_down_until && !self.ext_recover_pending {
                        self.ext_on_message(m.env);
                    } else {
                        self.log("ext down: message dropped".into());
                    }
                }
            }
        }
    }

    // ---------- core ----------

    fn core_deliver(&mut self, env: Envelope) {
        if self.tick < self.core_down_until {
            self.log("core down: message dropped".into());
            return;
        }
        let kind = env.body.kind();
        if self
            .fc
            .borrow_mut()
            .check(&format!("core.handle.{kind}"), &[FaultKind::CrashBefore])
            .is_some()
        {
            self.core_down_until = self.tick + DOWN_TICKS;
            self.log("core crashed before handling".into());
            return;
        }
        let rep = self.core.handle(&env, self.tick);
        if let Message::Prepared(r) = &rep.body {
            if r.state == TaskState::Prepared {
                self.acked.push(env.request_id.clone());
            }
        }
        let point = format!("core.reply.{}", rep.body.kind());
        // CrashAfter: state was persisted above, the reply is not sent (net_send drops it).
        let k = self.net_send(Side::Ext, rep, &point, &[FaultKind::CrashAfter]);
        if k == Some(FaultKind::CrashAfter) {
            self.core_down_until = self.tick + DOWN_TICKS;
            self.log("core crashed after persisting, before replying".into());
        }
    }

    fn core_tick(&mut self) {
        if self.tick < self.core_down_until {
            return;
        }
        let _ = self.core.pump(&mut self.engine);
        self.dispatches.append(&mut self.core.dispatch_log);
    }

    // ---------- extension agent ----------

    fn ext_crash(&mut self) {
        self.ext_down_until = self.tick + DOWN_TICKS;
        self.ext = ExtVol::default();
        self.fail_streak = 0;
        self.ext_recover_pending = true;
        self.log("extension worker crashed".into());
    }

    fn jw(&mut self, state: JState) -> Jw {
        let receipt = self.journal_receipt();
        self.jw_with(state, receipt)
    }

    fn jw_with(&mut self, state: JState, receipt: Option<RequestRef>) -> Jw {
        let name = format!("ext.journal.{}", state.name());
        let k = self.fc.borrow_mut().check(
            &name,
            &[
                FaultKind::CrashBefore,
                FaultKind::CrashAfter,
                FaultKind::StorageError,
            ],
        );
        match k {
            Some(FaultKind::CrashBefore) => {
                self.ext_crash();
                Jw::Crashed
            }
            Some(FaultKind::StorageError) => {
                self.fail_streak += 1;
                if self.fail_streak >= HOLD_AFTER && !self.ext.held {
                    self.enter_hold();
                }
                Jw::Failed
            }
            _ => {
                self.fail_streak = 0;
                self.journal = Some(Journal { state, receipt });
                if k == Some(FaultKind::CrashAfter) {
                    self.ext_crash();
                    Jw::Crashed
                } else {
                    Jw::Ok
                }
            }
        }
    }

    /// The journal keeps failing: stop the handoff, make the situation visible, and tell the
    /// core what we know without journaling (before the cancel gate: give the download back;
    /// after it: ask the core to surface the ownership question).
    fn enter_hold(&mut self) {
        let state = self.journal_state();
        if matches!(state, Some(JState::HandedOff | JState::Returned)) {
            return;
        }
        self.ext.held = true;
        self.ever_held = true;
        self.ext.last_sent = None;
        self.log("journal keeps failing: extension is holding".into());
        let post_cancel = matches!(
            state,
            Some(
                JState::CancelRequested
                    | JState::CancelConfirmed
                    | JState::CommitSent
                    | JState::ReconcileRequired
            )
        );
        let receipt = self.journal_receipt();
        match (post_cancel, receipt) {
            (true, Some(r)) => {
                self.ext.aborting = false;
                self.ext.pending = Some(Message::Reconcile(ReconcileBody {
                    owner: OwnerEvidence::Unknown,
                    receipt: r,
                }));
            }
            _ => {
                self.browser_resume();
                self.ext.aborting = true;
                self.ext.pending = Some(Message::Abort(AbortBody {
                    receipt: self.journal_receipt(),
                }));
            }
        }
    }

    fn ext_send(&mut self, body: Message) {
        let kind = body.kind();
        if self
            .fc
            .borrow_mut()
            .check(&format!("ext.send.{kind}"), &[FaultKind::CrashBefore])
            .is_some()
        {
            self.ext_crash();
            return;
        }
        let env = self.mk_env(body);
        let point = format!("net.ext_to_core.{kind}");
        self.net_send(Side::Core, env, &point, &[]);
        self.ext.last_sent = Some(self.tick);
    }

    fn browser_pause(&mut self) -> PauseOutcome {
        let k = self.fc.borrow_mut().check(
            "browser.pause",
            &[
                FaultKind::RaceComplete,
                FaultKind::BrowserUnknownApplied,
                FaultKind::BrowserUnknownNotApplied,
            ],
        );
        match k {
            Some(FaultKind::RaceComplete) => {
                self.browser.state = BState::Completed;
                PauseOutcome::AlreadyDone
            }
            Some(FaultKind::BrowserUnknownApplied) => {
                if self.browser.state == BState::InProgress {
                    self.browser.state = BState::Paused;
                }
                PauseOutcome::Unknown
            }
            Some(FaultKind::BrowserUnknownNotApplied) => PauseOutcome::Unknown,
            _ => match self.browser.state {
                BState::InProgress => {
                    self.browser.state = BState::Paused;
                    PauseOutcome::Paused
                }
                BState::Paused => PauseOutcome::Paused,
                _ => PauseOutcome::AlreadyDone,
            },
        }
    }

    fn browser_resume(&mut self) {
        if self.browser.state == BState::Paused {
            self.browser.state = BState::InProgress;
        }
    }

    fn browser_cancel(&mut self) -> CancelOutcome {
        let evidence = CancelEvent {
            journal: self.journal_state(),
            core: self.core_state(),
        };
        self.cancels.push(evidence);
        let k = self.fc.borrow_mut().check(
            "browser.cancel",
            &[
                FaultKind::BrowserUnknownApplied,
                FaultKind::BrowserUnknownNotApplied,
                FaultKind::RaceComplete,
                FaultKind::UserCancelFirst,
                FaultKind::CrashBefore,
                FaultKind::CrashAfter,
            ],
        );
        match k {
            Some(FaultKind::CrashBefore) => {
                self.ext_crash();
                return CancelOutcome::Crashed;
            }
            Some(FaultKind::RaceComplete) => {
                self.browser.state = BState::Completed;
                return CancelOutcome::AlreadyCompleted;
            }
            Some(FaultKind::UserCancelFirst) => {
                self.browser.state = BState::Cancelled;
                self.browser.cancelled_by = Some(Actor::User);
                return CancelOutcome::AlreadyCancelled;
            }
            _ => {}
        }
        if k != Some(FaultKind::BrowserUnknownNotApplied) {
            match self.browser.state {
                BState::Paused | BState::InProgress => {
                    self.browser.state = BState::Cancelled;
                    self.browser.cancelled_by = Some(Actor::Ext);
                }
                BState::Completed => return CancelOutcome::AlreadyCompleted,
                BState::Cancelled | BState::Erased => return CancelOutcome::AlreadyCancelled,
            }
        }
        match k {
            Some(FaultKind::BrowserUnknownApplied) | Some(FaultKind::BrowserUnknownNotApplied) => {
                CancelOutcome::Unknown
            }
            Some(FaultKind::CrashAfter) => {
                self.ext_crash();
                CancelOutcome::Crashed
            }
            _ => CancelOutcome::Cancelled,
        }
    }

    fn ext_start(&mut self) {
        if let Jw::Ok = self.jw(JState::Seen) {
            self.log("extension saw the download".into());
        }
    }

    fn begin_abort(&mut self, resume: bool) {
        if resume {
            self.browser_resume();
        }
        self.ext.aborting = true;
        self.ext.pending = Some(Message::Abort(AbortBody {
            receipt: self.journal_receipt(),
        }));
        self.ext.last_sent = None;
        let _ = self.jw(JState::Returning);
    }

    fn reconcile_msg(&self) -> Option<Message> {
        self.journal_receipt().map(|r| {
            Message::Reconcile(ReconcileBody {
                owner: OwnerEvidence::Unknown,
                receipt: r,
            })
        })
    }

    fn commit_msg(&self) -> Option<Message> {
        self.journal_receipt().map(|r| {
            Message::Commit(CommitBody {
                cancel: CancelEvidence::Confirmed,
                receipt: r,
            })
        })
    }

    fn begin_reconcile(&mut self) {
        let Some(msg) = self.reconcile_msg() else {
            self.enter_hold();
            return;
        };
        self.ext.pending = Some(msg);
        self.ext.last_sent = None;
        let _ = self.jw(JState::ReconcileRequired);
    }

    fn ext_recover(&mut self) {
        self.ext_recover_pending = false;
        self.ext = ExtVol::default();
        let Some(state) = self.journal_state() else {
            self.ext_start();
            return;
        };
        if !matches!(state, JState::HandedOff | JState::Returned)
            && self
                .fc
                .borrow_mut()
                .check("ext.recover.browser", &[FaultKind::ItemErased])
                .is_some()
        {
            // the browser no longer lists the item: whether our cancel happened is unknowable
            self.browser.state = BState::Erased;
        }
        let b = self.browser.state;
        match state {
            JState::Seen | JState::Paused => {
                self.browser_resume();
                let _ = self.jw(JState::Returned);
            }
            JState::PrepareSent | JState::ReceiptStored => self.begin_abort(true),
            JState::CancelIntentStored => match b {
                BState::Paused | BState::InProgress => self.begin_abort(true),
                BState::Erased => self.begin_reconcile(),
                BState::Completed | BState::Cancelled => self.begin_abort(false),
            },
            JState::CancelRequested => match b {
                BState::Paused | BState::InProgress => self.begin_abort(true),
                BState::Completed => self.begin_abort(false),
                BState::Cancelled | BState::Erased => self.begin_reconcile(),
            },
            JState::CancelConfirmed => {}
            JState::CommitSent => self.ext.pending = self.commit_msg(),
            JState::Returning => {
                self.ext.aborting = true;
                self.ext.pending = Some(Message::Abort(AbortBody {
                    receipt: self.journal_receipt(),
                }));
            }
            JState::ReconcileRequired => self.ext.pending = self.reconcile_msg(),
            JState::HandedOff | JState::Returned => {}
        }
    }

    /// A reply is believed only if it carries this run's identity.
    fn envelope_ok(&self, env: &Envelope) -> bool {
        env.version == PROTOCOL_VERSION
            && env.session_id == SESSION_ID
            && env.request_id == REQUEST_ID
            && env.generation == 1
    }

    /// A receipt must name the request we hold (or, before we hold one, match what we sent).
    fn receipt_ok(&self, r: &Receipt) -> bool {
        match self.journal.as_ref().and_then(|j| j.receipt.as_ref()) {
            Some(k) => r.task_id == k.task_id && r.fingerprint == k.fingerprint,
            None => {
                r.fingerprint == self.expected_fp
                    || (r.state == TaskState::Aborted && r.fingerprint.is_empty())
            }
        }
    }

    /// States that answer a `Reconcile(Unknown)`: the app owns it, or it surfaced the question.
    fn answers_reconcile(s: TaskState) -> bool {
        Self::handed_over(s) || s == TaskState::OwnershipUnknown
    }

    fn handed_over(s: TaskState) -> bool {
        matches!(
            s,
            TaskState::Committed | TaskState::Transferring | TaskState::Done | TaskState::Failed
        )
    }

    fn ext_on_message(&mut self, env: Envelope) {
        let line = format!("ext got {env:?}");
        self.log(line);
        if !self.envelope_ok(&env) {
            return;
        }
        if self.ext.held {
            match &env.body {
                Message::Aborted(r)
                    if self.ext.aborting && r.state == TaskState::Aborted && self.receipt_ok(r) =>
                {
                    self.ext.pending = None;
                }
                Message::Reconciled(r)
                    if !self.ext.aborting
                        && self.receipt_ok(r)
                        && Self::answers_reconcile(r.state) =>
                {
                    self.ext.pending = None;
                }
                _ => {}
            }
            return;
        }
        let Some(state) = self.journal_state() else {
            return;
        };
        if self.ext.aborting {
            if let Message::Aborted(r) = &env.body {
                if r.state == TaskState::Aborted && self.receipt_ok(r) {
                    // keep retrying the abort until the final state is durably journaled
                    if let Jw::Ok = self.jw(JState::Returned) {
                        self.ext.pending = None;
                        self.ext.aborting = false;
                    }
                }
            }
            return;
        }
        match (state, &env.body) {
            (JState::PrepareSent, Message::Prepared(r)) if self.receipt_ok(r) => {
                if r.state == TaskState::Prepared {
                    match self.jw_with(JState::ReceiptStored, Some(r.as_ref())) {
                        Jw::Ok => {
                            self.ext.pending = Some(Message::BeginHandoff(r.as_ref()));
                            self.ext.waiting_since = self.tick;
                            self.ext.last_sent = None;
                        }
                        Jw::Failed => self.begin_abort(true),
                        Jw::Crashed => {}
                    }
                } else {
                    self.begin_abort(true);
                }
            }
            (JState::PrepareSent, Message::Error(_)) => self.begin_abort(true),
            (JState::ReceiptStored, Message::Armed(r))
                if r.state == TaskState::Armed && self.receipt_ok(r) =>
            {
                self.ext.pending = None;
                if let Jw::Failed = self.jw(JState::CancelIntentStored) {
                    self.begin_abort(true);
                }
            }
            (JState::ReceiptStored, Message::Error(_)) => self.begin_abort(true),
            (JState::CommitSent, Message::Committed(r))
                if Self::handed_over(r.state) && self.receipt_ok(r) =>
            {
                // keep resending the (idempotent) commit until HandedOff is durably journaled
                if let Jw::Ok = self.jw(JState::HandedOff) {
                    self.ext.pending = None;
                }
            }
            (JState::CancelRequested | JState::CommitSent, Message::Reconciled(r))
                if self.receipt_ok(r) && Self::answers_reconcile(r.state) =>
            {
                // the journal write for ReconcileRequired failed earlier; clear the pending
                // message and let the stale-journal rule decide again (or finish if the app owns it)
                if Self::handed_over(r.state) {
                    if let Jw::Ok = self.jw(JState::HandedOff) {
                        self.ext.pending = None;
                    }
                } else {
                    self.ext.pending = None;
                }
            }
            // a storage error is transient: the pending commit keeps being resent
            (JState::CommitSent, Message::Error(e)) if e.kind != ErrorKind::Storage => {
                self.begin_reconcile()
            }
            (JState::ReconcileRequired, Message::Reconciled(r))
                if self.receipt_ok(r) && Self::answers_reconcile(r.state) =>
            {
                if Self::handed_over(r.state) {
                    if let Jw::Ok = self.jw(JState::HandedOff) {
                        self.ext.pending = None;
                    }
                } else {
                    self.ext.pending = None;
                }
            }
            _ => {}
        }
    }

    fn resend_pending(&mut self) {
        if let Some(msg) = self.ext.pending.clone() {
            let due = match self.ext.last_sent {
                None => true,
                Some(t) => self.tick.saturating_sub(t) >= RESEND_EVERY,
            };
            if due {
                self.ext_send(msg);
            }
        }
    }

    fn ext_advance(&mut self) {
        if self.tick < self.ext_down_until {
            return;
        }
        if self.ext_recover_pending {
            self.ext_recover();
            return;
        }
        if self.ext.held {
            self.resend_pending();
            return;
        }
        let Some(state) = self.journal_state() else {
            self.ext_start();
            return;
        };
        if !self.ext.aborting {
            match state {
                JState::Seen => match self.browser_pause() {
                    PauseOutcome::Paused => {
                        let _ = self.jw(JState::Paused);
                    }
                    PauseOutcome::AlreadyDone => {
                        let _ = self.jw(JState::Returned);
                    }
                    PauseOutcome::Unknown => {
                        self.browser_resume();
                        let _ = self.jw(JState::Returned);
                    }
                },
                JState::Paused => match self.jw(JState::PrepareSent) {
                    Jw::Ok => {
                        self.ext.waiting_since = self.tick;
                        self.ext.pending = Some(Message::Prepare(prepare_body()));
                        self.ext.last_sent = None;
                    }
                    Jw::Failed => {
                        self.browser_resume();
                        let _ = self.jw(JState::Returned);
                    }
                    Jw::Crashed => {}
                },
                JState::CancelIntentStored => {
                    match self.jw(JState::CancelRequested) {
                        Jw::Ok => {}
                        Jw::Failed => {
                            self.begin_abort(true);
                            return;
                        }
                        Jw::Crashed => return,
                    }
                    match self.browser_cancel() {
                        CancelOutcome::Cancelled => match self.jw(JState::CancelConfirmed) {
                            Jw::Ok | Jw::Crashed => {}
                            Jw::Failed => self.begin_reconcile(),
                        },
                        CancelOutcome::AlreadyCompleted | CancelOutcome::AlreadyCancelled => {
                            self.begin_abort(false)
                        }
                        CancelOutcome::Unknown => self.begin_reconcile(),
                        CancelOutcome::Crashed => {}
                    }
                }
                JState::CancelRequested | JState::CommitSent if self.ext.pending.is_none() => {
                    // a journal write failed earlier and nothing is pending: decide again from the journal
                    self.ext_recover_pending = true;
                }
                JState::CancelConfirmed => {
                    if let Jw::Ok = self.jw(JState::CommitSent) {
                        self.ext.pending = self.commit_msg();
                        self.ext.last_sent = None;
                    }
                }
                _ => {}
            }
        }
        // pre-cancel deadline
        if matches!(state, JState::PrepareSent | JState::ReceiptStored)
            && !self.ext.aborting
            && !self.ext.held
            && self.tick.saturating_sub(self.ext.waiting_since) > PRE_DEADLINE
        {
            self.begin_abort(true);
        }
        if self.ext.held {
            return;
        }
        self.resend_pending();
    }

    // ---------- run ----------

    fn quiescent(&self) -> bool {
        let settled = self.journal_state().map(|j| j.terminal()).unwrap_or(false) || self.ext.held;
        let ext_done = settled && self.ext.pending.is_none();
        let engine_idle = self
            .core
            .store
            .all()
            .map(|all| {
                all.iter()
                    .all(|r| !matches!(r.state, TaskState::Committed | TaskState::Transferring))
            })
            .unwrap_or(false);
        ext_done
            && !self.ext_recover_pending
            && self.tick >= self.ext_down_until
            && self.net.is_empty()
            && self.tick >= self.core_down_until
            && engine_idle
    }

    /// One scheduler step. Public so tests can stop the world at an interesting moment.
    pub fn step(&mut self) {
        self.tick += 1;
        self.deliver_due();
        self.ext_advance();
        self.core_tick();
    }

    pub fn is_quiescent(&self) -> bool {
        self.quiescent()
    }

    pub fn run(&mut self) -> RunRecord {
        let mut quiesced = false;
        while self.tick < MAX_TICKS {
            self.step();
            if self.quiescent() {
                quiesced = true;
                break;
            }
        }
        self.record(quiesced)
    }

    pub fn record(&self, quiesced: bool) -> RunRecord {
        let rec = self
            .core
            .store
            .inner
            .get_by_request(REQUEST_ID)
            .ok()
            .flatten();
        let leaks = self.trace.iter().any(|l| l.contains(SENTINEL));
        RunRecord {
            quiesced,
            ticks: self.tick,
            ext_final: self.journal_state(),
            core_final: rec.as_ref().map(|r| r.state),
            core_history: rec.map(|r| r.history).unwrap_or_default(),
            engine_attempts: self.engine.submitted.clone(),
            browser_final: self.browser.state,
            browser_cancelled_by: self.browser.cancelled_by,
            cancels: self.cancels.clone(),
            dispatches: self.dispatches.clone(),
            engine_calls: self.engine.calls,
            held: self.ever_held,
            acked_prepares: self.acked.clone(),
            trace_leaks_secret: leaks,
            injected: self.fc.borrow().injected.clone(),
        }
    }
}
