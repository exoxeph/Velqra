// SPDX-License-Identifier: GPL-3.0-only
//! The queue half of `Core`: which waiting task starts next, how many may run, what happens when
//! a running task stops. A child module of `core`, so it works on the same private state.
//!
//! One pump has two phases. First it settles what is already running or unclear (finished, failed,
//! lost by the engine, interrupted and due a retry). Then it starts waiting tasks, best first,
//! while the global and per-site limits allow.

use super::*;
use std::cmp::Reverse;
use std::collections::HashMap;
use velqra_protocol::download_url::parse_download_url;

/// Transient failures retried before the task is given up on.
const MAX_RETRIES: u32 = 5;
/// First retry delay in seconds; each later one doubles.
const RETRY_BASE_SECS: u64 = 5;

/// Seconds to wait before retry number `retry` (1-based): 5, 10, 20, 40, 80, ...
pub(crate) fn backoff_secs(retry: u32) -> u64 {
    RETRY_BASE_SECS << retry.saturating_sub(1).min(16)
}

fn phrase_ok(reason: &str) -> bool {
    !reason.is_empty() && reason.len() <= 64 && !reason.chars().any(char::is_control)
}

impl<S: Store> Core<S> {
    /// Settles running tasks, then starts waiting ones. `now` is the caller's clock in seconds.
    pub fn pump_at(
        &mut self,
        engine: &mut dyn Engine,
        now: u64,
    ) -> Result<Vec<DispatchEvent>, StoreError> {
        let mut events = Vec::new();
        if self.poll_interval == 0 || now >= self.last_poll.saturating_add(self.poll_interval) {
            self.last_poll = now;
            self.settle(engine, now)?;
        }
        self.start_waiting(engine, now, &mut events)?;
        Ok(events)
    }

    /// Phase one: tasks the engine may already hold.
    fn settle(&mut self, engine: &mut dyn Engine, now: u64) -> Result<(), StoreError> {
        for mut rec in self.store.all()? {
            let Some(attempt) = rec.dispatch_attempt.clone() else {
                continue;
            };
            match rec.state {
                TaskState::Committed if rec.engine_ambiguous && !rec.held => {
                    // The last reply was lost. Establish what the engine holds before any new submit.
                    match engine.status(&attempt) {
                        Ok(EngineStatus::Active { .. } | EngineStatus::Paused) => {
                            rec.engine_ambiguous = false;
                            set(&mut rec, TaskState::Transferring);
                        }
                        Ok(EngineStatus::Done) => {
                            rec.engine_ambiguous = false;
                            set(&mut rec, TaskState::Done);
                        }
                        Ok(EngineStatus::Failed(_)) => {
                            rec.engine_ambiguous = false;
                            rec.fail_reason = Some("transfer failed".into());
                            set(&mut rec, TaskState::Failed);
                        }
                        Ok(EngineStatus::Interrupted) => {
                            rec.engine_ambiguous = false;
                            self.schedule_retry(&mut rec, now);
                        }
                        Ok(EngineStatus::Unknown) if rec.engine_resubmits < 1 => {
                            // proven absent: the start phase submits once more, same attempt id
                            rec.engine_resubmits += 1;
                            rec.engine_ambiguous = false;
                        }
                        Ok(EngineStatus::Unknown) | Err(_) => {
                            rec.engine_queries += 1;
                            if rec.engine_queries >= MAX_STATUS_QUERIES {
                                rec.held = true;
                                rec.fail_reason = Some("engine identity unprovable".into());
                            }
                        }
                    }
                    self.store.put(&rec)?;
                }
                TaskState::Transferring => match engine.poll(&attempt) {
                    Poll::Done => {
                        set(&mut rec, TaskState::Done);
                        self.store.put(&rec)?;
                    }
                    Poll::Failed => {
                        rec.fail_reason = Some("transfer failed".into());
                        set(&mut rec, TaskState::Failed);
                        self.store.put(&rec)?;
                    }
                    Poll::Interrupted => {
                        self.schedule_retry(&mut rec, now);
                        self.store.put(&rec)?;
                    }
                    Poll::Forgotten => self.redispatch(engine, rec, attempt)?,
                    Poll::Running | Poll::Unreachable => {}
                },
                _ => {}
            }
        }
        Ok(())
    }

    /// The engine lost a running task (its process restarted). The attempt id is still ours: submit
    /// the same task again, a few times at most.
    fn redispatch(
        &mut self,
        engine: &mut dyn Engine,
        mut rec: Record,
        attempt: String,
    ) -> Result<(), StoreError> {
        if rec.engine_redispatches >= MAX_REDISPATCHES {
            rec.fail_reason = Some("engine lost the task".into());
            set(&mut rec, TaskState::Failed);
            return self.store.put(&rec);
        }
        rec.engine_redispatches += 1;
        self.store.put(&rec)?;
        match self.engine_request(&rec, attempt) {
            Err(why) => {
                rec.fail_reason = Some(why.into());
                set(&mut rec, TaskState::Failed);
                self.store.put(&rec)
            }
            Ok(request) => {
                if let Err(EngineError::Rejected | EngineError::Unsupported) =
                    engine.submit(&request)
                {
                    rec.fail_reason = Some("engine rejected the task".into());
                    set(&mut rec, TaskState::Failed);
                    self.store.put(&rec)?;
                }
                Ok(())
            }
        }
    }

    /// A transient failure: back in the queue under a fresh attempt id after a growing delay, or
    /// failed for good once the retries are used up.
    fn schedule_retry(&mut self, rec: &mut Record, now: u64) {
        rec.retries += 1;
        if rec.retries > MAX_RETRIES {
            rec.fail_reason = Some("transfer failed after retries".into());
            set(rec, TaskState::Failed);
            return;
        }
        rec.retry_at = now.saturating_add(backoff_secs(rec.retries));
        // aria2 keeps the stopped task under its old id, so the new attempt gets a new one
        rec.dispatch_attempt = Some(format!(
            "t{}-g{}-r{}",
            rec.task_id, rec.generation, rec.retries
        ));
        rec.engine_redispatches = 0;
        rec.engine_resubmits = 0;
        rec.engine_queries = 0;
        rec.queued_reason = Some("waiting to retry".into());
        set(rec, TaskState::Committed);
    }

    /// The site a task downloads from, kept in memory only (the host never goes into the database).
    fn origin_of(&mut self, rec: &Record) -> Option<String> {
        if let Some(o) = self.origin_cache.get(&rec.task_id) {
            return Some(o.clone());
        }
        let url_ref = &rec.request.as_ref()?.url_ref;
        let url = self.vault.get(url_ref)?;
        let origin = parse_download_url(&url.0).ok()?.origin();
        self.origin_cache.insert(rec.task_id, origin.clone());
        Some(origin)
    }

    /// Phase two: start waiting tasks, best first, while the limits allow.
    fn start_waiting(
        &mut self,
        engine: &mut dyn Engine,
        now: u64,
        events: &mut Vec<DispatchEvent>,
    ) -> Result<(), StoreError> {
        let records = self.store.all()?;
        // the cache only needs live tasks
        let live: std::collections::HashSet<u64> = records
            .iter()
            .filter(|r| matches!(r.state, TaskState::Committed | TaskState::Transferring))
            .map(|r| r.task_id)
            .collect();
        self.origin_cache.retain(|id, _| live.contains(id));

        let mut active = 0u32;
        let mut per_site: HashMap<String, u32> = HashMap::new();
        for r in &records {
            let running = r.state == TaskState::Transferring
                || (r.state == TaskState::Committed && r.engine_ambiguous && !r.held);
            if running {
                active += 1;
                if let Some(o) = self.origin_of(r) {
                    *per_site.entry(o).or_default() += 1;
                }
            }
        }
        let mut waiting: Vec<Record> = records
            .into_iter()
            .filter(|r| {
                r.state == TaskState::Committed
                    && !r.held
                    && !r.engine_ambiguous
                    && r.dispatch_attempt.is_some()
            })
            .collect();
        waiting.sort_by_key(|r| (Reverse(r.priority), r.task_id));

        for mut rec in waiting {
            if rec.paused {
                continue; // shows its pause reason, not a queue reason
            }
            let origin = self.origin_of(&rec);
            let blocked: Option<&'static str> = if rec.retry_at > now {
                Some("waiting to retry")
            } else if active >= self.max_active {
                Some("waiting for a free slot")
            } else if origin
                .as_ref()
                .is_some_and(|o| per_site.get(o).copied().unwrap_or(0) >= self.per_origin)
            {
                Some("waiting for a free connection to this site")
            } else {
                None
            };
            if let Some(why) = blocked {
                if rec.queued_reason.as_deref() != Some(why) {
                    rec.queued_reason = Some(why.into());
                    self.store.put(&rec)?;
                }
                continue;
            }
            rec.queued_reason = None;
            let attempt = rec.dispatch_attempt.clone().unwrap_or_default();
            let request = match self.engine_request(&rec, attempt) {
                Ok(r) => r,
                Err(why) => {
                    rec.fail_reason = Some(why.into());
                    set(&mut rec, TaskState::Failed);
                    self.store.put(&rec)?;
                    continue;
                }
            };
            let event = DispatchEvent {
                task_id: rec.task_id,
                state_before: rec.state,
            };
            self.dispatch_log.push(event.clone());
            events.push(event);
            match engine.submit(&request) {
                Ok(()) => {
                    set(&mut rec, TaskState::Transferring);
                    active += 1;
                    if let Some(o) = origin {
                        *per_site.entry(o).or_default() += 1;
                    }
                }
                Err(EngineError::ReplyLost) => {
                    rec.engine_ambiguous = true;
                    active += 1;
                    if let Some(o) = origin {
                        *per_site.entry(o).or_default() += 1;
                    }
                }
                Err(EngineError::Rejected | EngineError::Unsupported) => {
                    rec.fail_reason = Some("engine rejected the task".into());
                    set(&mut rec, TaskState::Failed);
                }
            }
            self.store.put(&rec)?;
        }
        Ok(())
    }

    fn queued_record(&self, task_id: u64) -> Result<Record, StoreError> {
        self.store
            .get_by_task(task_id)?
            .ok_or_else(|| StoreError::Io("no such task".into()))
    }

    /// Higher numbers start first.
    pub fn set_priority(&mut self, task_id: u64, priority: i32) -> Result<(), StoreError> {
        let mut rec = self.queued_record(task_id)?;
        rec.priority = priority;
        self.store.put(&rec)
    }

    /// Holds a waiting task, or pauses a running one in the engine. A paused task keeps its slot.
    pub fn pause_task(
        &mut self,
        engine: &mut dyn Engine,
        task_id: u64,
        reason: &str,
    ) -> Result<(), StoreError> {
        if !phrase_ok(reason) {
            return Err(StoreError::Io("pause reason must be a short phrase".into()));
        }
        let mut rec = self.queued_record(task_id)?;
        match rec.state {
            TaskState::Committed => {}
            TaskState::Transferring => {
                let attempt = rec.dispatch_attempt.clone().unwrap_or_default();
                engine
                    .pause(&attempt)
                    .map_err(|_| StoreError::Io("the engine could not pause the task".into()))?;
            }
            _ => return Err(StoreError::Io("this task cannot be paused".into())),
        }
        rec.paused = true;
        rec.pause_reason = Some(reason.to_string());
        self.store.put(&rec)
    }

    pub fn resume_task(&mut self, engine: &mut dyn Engine, task_id: u64) -> Result<(), StoreError> {
        let mut rec = self.queued_record(task_id)?;
        if rec.state == TaskState::Transferring && rec.paused {
            let attempt = rec.dispatch_attempt.clone().unwrap_or_default();
            engine
                .resume(&attempt)
                .map_err(|_| StoreError::Io("the engine could not resume the task".into()))?;
        }
        rec.paused = false;
        rec.pause_reason = None;
        self.store.put(&rec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backoff_doubles_from_five_seconds_and_cannot_overflow() {
        assert_eq!(
            (1..=5).map(backoff_secs).collect::<Vec<_>>(),
            [5, 10, 20, 40, 80]
        );
        assert_eq!(backoff_secs(0), 5, "retry 0 is treated like the first");
        assert!(backoff_secs(u32::MAX) > 0);
    }

    #[test]
    fn pause_reasons_are_short_plain_phrases() {
        assert!(phrase_ok("paused by the user"));
        assert!(!phrase_ok(""));
        assert!(!phrase_ok(&"x".repeat(65)));
        assert!(!phrase_ok("line\nbreak"));
    }
}
