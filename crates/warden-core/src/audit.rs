//! Tamper-evident, append-only audit log.
//!
//! # Format
//!
//! One JSON object per line (JSON Lines), every line terminated by `\n`.
//! Each object is an [`AuditEntry`] serialized by `serde_json` in field
//! order. JSON string escaping guarantees that newlines (and every other
//! control character) inside `action_id`, `summary` or `decision` never
//! split an entry across lines.
//!
//! # Hash chain
//!
//! `hash` is lowercase hex `sha256` over this exact byte layout:
//!
//! ```text
//! b"warden/audit/v1\0"                         16-byte domain prefix
//! u64_be(len(prev_hash)) || prev_hash          ASCII hex bytes
//! u64_be(index)                                8 bytes
//! u64_be(timestamp_ms)                         8 bytes
//! u64_be(len(action_id)) || action_id          UTF-8 bytes
//! u64_be(len(summary))   || summary            UTF-8 bytes
//! tier_byte(tier)                              1 byte: Auto=0 Yes=1 YesPin=2 Blocked=3
//! u64_be(len(decision))  || decision           UTF-8 bytes
//! ```
//!
//! Every variable-length field is length-prefixed, so moving bytes between
//! adjacent fields always changes the hash. The first entry's `prev_hash`
//! is 64 ASCII zeros; every later entry's `prev_hash` is the previous
//! entry's `hash`. The layout is pinned by a golden test.
//!
//! # Verification
//!
//! [`AuditLog::verify`] walks the file and reports the first position
//! whose line is not a well-formed, canonically encoded entry with the
//! expected `index`, `prev_hash` and `hash`. "Index" in a report means the
//! zero-based line position, which equals the entry index for a good log.
//! Blank lines, invalid UTF-8, invalid JSON, unknown or duplicate fields,
//! trailing garbage and an unterminated final line (including a missing
//! `\n` after an otherwise good last entry) are all reported as broken.
//!
//! # Known limits
//!
//! A hash chain detects edits, deletion of entries in the middle and
//! reordering. It does NOT detect truncation of whole trailing entries,
//! nor wholesale replacement of the file by an attacker who can write it
//! (they can simply recompute the chain). Detecting those needs an
//! external anchor, such as periodically storing the latest hash
//! somewhere the attacker cannot write, signed. That is out of scope here;
//! [`AuditLog::head`] exposes `(next index, last hash)` so a caller can
//! build one.
//!
//! The exclusive lock taken by [`AuditLog::open`] is advisory
//! (`File::try_lock`): it stops a second cooperating writer, not an
//! attacker.

use crate::approval::tier_byte;
use crate::policy::Tier;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Domain separation prefix for entry hashes.
pub const AUDIT_DOMAIN: &[u8] = b"warden/audit/v1\0";

/// `prev_hash` of the first entry.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One audit record (one line of the log).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    pub index: u64,
    pub timestamp_ms: u64,
    pub action_id: String,
    pub summary: String,
    pub tier: Tier,
    pub decision: String,
    pub prev_hash: String,
    pub hash: String,
}

impl AuditEntry {
    /// The hash this entry should carry, from every field except `hash`.
    /// See the module doc for the exact byte layout.
    pub fn compute_hash(&self) -> String {
        fn var(h: &mut Sha256, bytes: &[u8]) {
            h.update((bytes.len() as u64).to_be_bytes());
            h.update(bytes);
        }
        let mut h = Sha256::new();
        h.update(AUDIT_DOMAIN);
        var(&mut h, self.prev_hash.as_bytes());
        h.update(self.index.to_be_bytes());
        h.update(self.timestamp_ms.to_be_bytes());
        var(&mut h, self.action_id.as_bytes());
        var(&mut h, self.summary.as_bytes());
        h.update([tier_byte(self.tier)]);
        var(&mut h, self.decision.as_bytes());
        hex::encode(h.finalize())
    }
}

/// Result of [`AuditLog::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyReport {
    Ok {
        entries: u64,
    },
    Broken {
        first_bad_index: u64,
        reason: String,
    },
}

/// Milliseconds since the Unix epoch.
pub type Clock = Box<dyn Fn() -> u64 + Send>;

/// An open, exclusively locked, append-only audit log.
pub struct AuditLog {
    file: File,
    next_index: u64,
    last_hash: String,
    clock: Clock,
    /// Set when an append fails part-way; the file may then end in a
    /// partial line, so further appends are refused.
    poisoned: bool,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("next_index", &self.next_index)
            .field("last_hash", &self.last_hash)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

fn system_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

impl AuditLog {
    /// Open (or create) the log at `path`, using the system clock.
    pub fn open(path: &Path) -> io::Result<AuditLog> {
        Self::open_with_clock(path, Box::new(system_clock_ms))
    }

    /// Open (or create) the log at `path` with an injected clock.
    ///
    /// Takes an advisory exclusive lock (fails with `WouldBlock` if another
    /// handle holds it), then verifies the existing content through the
    /// locked handle; a broken log fails with `InvalidData` and is left
    /// untouched.
    pub fn open_with_clock(path: &Path, clock: Clock) -> io::Result<AuditLog> {
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!("audit log {} is locked by another writer", path.display()),
                ));
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(e),
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        match walk(&bytes) {
            Walk::Ok { entries, last_hash } => Ok(AuditLog {
                file,
                next_index: entries,
                last_hash,
                clock,
                poisoned: false,
            }),
            Walk::Broken {
                first_bad_index,
                reason,
            } => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "audit log {} is broken at index {first_bad_index}: {reason}",
                    path.display()
                ),
            )),
        }
    }

    /// `(next index, last hash)`: what an external anchor should record.
    pub fn head(&self) -> (u64, String) {
        (self.next_index, self.last_hash.clone())
    }

    /// Append one entry. The whole line plus `\n` goes out in a single
    /// buffer, then the file is flushed and `sync_data`'d before returning.
    pub fn append(
        &mut self,
        action_id: &str,
        summary: &str,
        tier: Tier,
        decision: &str,
    ) -> io::Result<AuditEntry> {
        if self.poisoned {
            return Err(io::Error::other(
                "audit log poisoned by an earlier failed append; reopen to verify",
            ));
        }
        let mut entry = AuditEntry {
            index: self.next_index,
            timestamp_ms: (self.clock)(),
            action_id: action_id.to_owned(),
            summary: summary.to_owned(),
            tier,
            decision: decision.to_owned(),
            prev_hash: self.last_hash.clone(),
            hash: String::new(),
        };
        entry.hash = entry.compute_hash();
        let mut line = serde_json::to_vec(&entry).map_err(io::Error::other)?;
        line.push(b'\n');

        let res = self
            .file
            .write_all(&line)
            .and_then(|()| self.file.flush())
            .and_then(|()| self.file.sync_data());
        if let Err(e) = res {
            self.poisoned = true;
            return Err(e);
        }
        self.next_index += 1;
        self.last_hash.clone_from(&entry.hash);
        Ok(entry)
    }

    /// Verify the log at `path` without opening it for writing (no lock).
    /// I/O errors (e.g. missing file) are `Err`; any content problem is
    /// `Ok(VerifyReport::Broken { .. })`. Never panics on file content.
    pub fn verify(path: &Path) -> io::Result<VerifyReport> {
        let bytes = std::fs::read(path)?;
        Ok(match walk(&bytes) {
            Walk::Ok { entries, .. } => VerifyReport::Ok { entries },
            Walk::Broken {
                first_bad_index,
                reason,
            } => VerifyReport::Broken {
                first_bad_index,
                reason,
            },
        })
    }
}

enum Walk {
    Ok {
        entries: u64,
        last_hash: String,
    },
    Broken {
        first_bad_index: u64,
        reason: String,
    },
}

fn walk(bytes: &[u8]) -> Walk {
    let broken = |i: u64, reason: String| Walk::Broken {
        first_bad_index: i,
        reason,
    };
    let mut prev = GENESIS_HASH.to_owned();
    let mut i: u64 = 0;
    let mut rest = bytes;
    while !rest.is_empty() {
        let (line, terminated) = match rest.iter().position(|&b| b == b'\n') {
            Some(p) => {
                let l = &rest[..p];
                rest = &rest[p + 1..];
                (l, true)
            }
            None => {
                let l = rest;
                rest = &[];
                (l, false)
            }
        };
        if line.is_empty() {
            return broken(i, "blank line".into());
        }
        let text = match std::str::from_utf8(line) {
            Ok(t) => t,
            Err(e) => return broken(i, format!("invalid UTF-8: {e}")),
        };
        let entry: AuditEntry = match serde_json::from_str(text) {
            Ok(e) => e,
            Err(e) => return broken(i, format!("invalid entry JSON: {e}")),
        };
        if entry.index != i {
            return broken(
                i,
                format!("non-sequential index: expected {i}, found {}", entry.index),
            );
        }
        if entry.prev_hash != prev {
            return broken(i, "prev_hash does not match previous entry's hash".into());
        }
        if entry.compute_hash() != entry.hash {
            return broken(i, "hash does not match entry contents".into());
        }
        match serde_json::to_string(&entry) {
            Ok(canon) if canon.as_bytes() == line => {}
            _ => return broken(i, "entry is not canonically encoded".into()),
        }
        if !terminated {
            return broken(i, "last entry is missing its trailing newline".into());
        }
        prev = entry.hash;
        i += 1;
    }
    Walk::Ok {
        entries: i,
        last_hash: prev,
    }
}
