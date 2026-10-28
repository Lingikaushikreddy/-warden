//! An audit log held only while it is in use.
//!
//! [`LeasedAuditLog`] opens the log (taking its exclusive lock and
//! verifying the chain) on the first append and drops it on
//! [`AuditSink::release`]. The engine releases it when it finishes a
//! message, so other writers (`warden undo`, `warden run`) can use the log
//! while the agent is idle; they fail fast with a lock error while it is
//! handling a message.
//!
//! Cost: every reopen verifies the whole chain, so each message pays a
//! read of the log, linear in its size.
//!
//! Reopening picks up entries other writers appended in between: the chain
//! continues from the log's real head, not from a stale in-memory one.

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use warden_core::{AuditLog, Tier};

use crate::engine::AuditSink;

/// How long an append waits for another writer by default.
pub const DEFAULT_LEASE_WAIT: Duration = Duration::from_secs(2);
/// How often a locked log is retried while waiting.
const RETRY_EVERY: Duration = Duration::from_millis(100);

/// The audit log at `path`, opened on demand and released between messages.
pub struct LeasedAuditLog {
    path: PathBuf,
    wait: Duration,
    log: Option<AuditLog>,
}

impl fmt::Debug for LeasedAuditLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeasedAuditLog")
            .field("path", &self.path)
            .field("wait", &self.wait)
            .field("open", &self.log.is_some())
            .finish()
    }
}

impl LeasedAuditLog {
    /// Nothing is opened until [`open_now`](Self::open_now) or the first
    /// append.
    pub fn new(path: PathBuf) -> LeasedAuditLog {
        LeasedAuditLog {
            path,
            wait: DEFAULT_LEASE_WAIT,
            log: None,
        }
    }

    /// How long an append waits for a log locked by another writer before
    /// failing (default [`DEFAULT_LEASE_WAIT`]).
    pub fn with_wait(mut self, d: Duration) -> Self {
        self.wait = d;
        self
    }

    /// Open the log now, without waiting: the startup check. A broken log
    /// (`InvalidData`) or one locked by another writer (`WouldBlock`) is
    /// refused. The log stays open until [`AuditSink::release`].
    pub fn open_now(&mut self) -> io::Result<()> {
        if self.log.is_none() {
            self.log = Some(AuditLog::open(&self.path)?);
        }
        Ok(())
    }

    /// The open log, opening it if needed. A log locked by another writer
    /// is retried every [`RETRY_EVERY`] until the wait runs out, then the
    /// `WouldBlock` error is returned. Blocks: call it off the async
    /// runtime.
    fn open_waiting(&mut self) -> io::Result<&mut AuditLog> {
        if self.log.is_none() {
            let deadline = Instant::now() + self.wait;
            let log = loop {
                match AuditLog::open(&self.path) {
                    Ok(log) => break log,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        let left = deadline.saturating_duration_since(Instant::now());
                        if left.is_zero() {
                            return Err(e);
                        }
                        std::thread::sleep(left.min(RETRY_EVERY));
                    }
                    Err(e) => return Err(e),
                }
            };
            self.log = Some(log);
        }
        self.log
            .as_mut()
            .ok_or_else(|| io::Error::other("audit log not open"))
    }
}

impl AuditSink for LeasedAuditLog {
    fn append(
        &mut self,
        action_id: &str,
        summary: &str,
        tier: Tier,
        decision: &str,
    ) -> io::Result<()> {
        let res = self
            .open_waiting()?
            .append(action_id, summary, tier, decision)
            .map(drop);
        if res.is_err() {
            // The file may now end in a partial line: reopen (and
            // re-verify) before the next append instead of trusting it.
            self.log = None;
        }
        res
    }

    fn release(&mut self) {
        self.log = None;
    }
}
