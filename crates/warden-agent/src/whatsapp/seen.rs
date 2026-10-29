//! The persisted set of owner WhatsApp message ids already taken:
//! `<home>/whatsapp-seen`.
//!
//! Meta retries webhooks, so the same message can arrive twice. The channel
//! records a batch's new owner ids here BEFORE it queues any of them (at
//! most once, like the Telegram offset). Strangers' ids are not recorded: a
//! replayed stranger message costs only a (rate-limited) audit entry, and a
//! flood of them must not push an owner's id out.
//!
//! Each entry is the SHA-256 of a `wamid` and the message's time (Unix ms,
//! capped at the local clock, and clamped to it again on open). Eviction is
//! age-aware: beyond [`MAX_SEEN`] entries, only entries older than the
//! caller's keep time (the channel's `max_message_age`, after which a
//! redelivery is stale and never acted on anyway) are dropped, oldest
//! first. Younger entries are kept, up to the
//! hard cap [`MAX_SEEN_HARD`]; beyond that the oldest by time go.
//!
//! File format: the 8-byte magic [`SEEN_MAGIC`], then 40-byte entries (32
//! hash bytes, 8 bytes big-endian ms), oldest first. Only hashes are
//! stored, never the ids. An empty file reads as empty. A file without the
//! magic (such as the earlier 32-byte-hash format) is refused as
//! `InvalidData` with a hint to delete it; it is not migrated. The file
//! follows the private state file rules (no symlinks, mode 0600, atomic
//! replace).

use crate::state;
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// File name under the Warden home directory.
pub const SEEN_FILE: &str = "whatsapp-seen";

/// Entries kept regardless of age; past this, only entries older than the
/// keep time are dropped.
pub const MAX_SEEN: usize = 1024;

/// Most entries ever kept; past this the oldest go whatever their age.
pub const MAX_SEEN_HARD: usize = 4096;

/// The first 8 bytes of the file.
pub const SEEN_MAGIC: &[u8; 8] = b"WDNSEEN2";

const ENTRY: usize = 40;

type Hash = [u8; 32];

fn hash(wamid: &str) -> Hash {
    Sha256::digest(wamid.as_bytes()).into()
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// The seen-message file for one home directory, and its contents.
#[derive(Debug)]
pub struct SeenStore {
    path: PathBuf,
    /// `(hash, ms)`, sorted by ms, oldest first.
    seen: Vec<(Hash, u64)>,
}

impl SeenStore {
    /// Open the store: empty when the file is missing or empty;
    /// `InvalidData` when it does not start with [`SEEN_MAGIC`], its entries
    /// are not whole 40-byte records, it holds more than [`MAX_SEEN_HARD`]
    /// (or it is a symlink or not a regular file); `PermissionDenied` when
    /// group or others have access. Entry times later than the local clock
    /// are clamped to it (see [`Self::open_at`]).
    pub fn open(home: &Path) -> io::Result<SeenStore> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        SeenStore::open_at(home, now_ms)
    }

    /// [`Self::open`] with the local clock given (Unix ms). Every entry time
    /// later than `now_ms` is clamped to it: recorded times are capped at
    /// the clock, so a later one means a crafted or damaged file, and an
    /// entry that never ages would let a file of them crowd every real id
    /// out at the hard cap, which would end deduplication.
    pub fn open_at(home: &Path, now_ms: u64) -> io::Result<SeenStore> {
        let path = home.join(SEEN_FILE);
        let bytes = state::read_private(&path, SEEN_MAGIC.len() + ENTRY * MAX_SEEN_HARD)?
            .unwrap_or_default();
        if bytes.is_empty() {
            return Ok(SeenStore {
                path,
                seen: Vec::new(),
            });
        }
        let Some(body) = bytes.strip_prefix(SEEN_MAGIC.as_slice()) else {
            return Err(invalid(
                "the WhatsApp seen file has an old or unknown format; delete whatsapp-seen in the Warden home and start again",
            ));
        };
        if body.len() % ENTRY != 0 {
            return Err(invalid("the WhatsApp seen file is not whole entries"));
        }
        let mut seen: Vec<(Hash, u64)> = body
            .chunks_exact(ENTRY)
            .map(|c| {
                let mut h = [0u8; 32];
                h.copy_from_slice(&c[..32]);
                let mut t = [0u8; 8];
                t.copy_from_slice(&c[32..]);
                (h, u64::from_be_bytes(t).min(now_ms))
            })
            .collect();
        seen.sort_by_key(|&(_, t)| t);
        Ok(SeenStore { path, seen })
    }

    /// Whether `wamid` was recorded.
    pub fn contains(&self, wamid: &str) -> bool {
        let h = hash(wamid);
        self.seen.iter().any(|(s, _)| *s == h)
    }

    /// How many entries are held.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// True when nothing is held.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Add `(wamid, ms)` entries, evict, and replace the file atomically.
    /// The in-memory set changes only after the write succeeds.
    ///
    /// Precondition: `ms` is the message's time capped at `now_ms`, and the
    /// caller has already dropped ids it [`Self::contains`] (an id recorded
    /// twice is kept twice and costs two entries).
    ///
    /// Eviction: while more than [`MAX_SEEN`] are held, the oldest entry is
    /// dropped only if it is older than `keep_ms` (`ms + keep_ms < now_ms`);
    /// then, while more than [`MAX_SEEN_HARD`] are held, the oldest is
    /// dropped regardless.
    pub fn record(&mut self, entries: &[(&str, u64)], now_ms: u64, keep_ms: u64) -> io::Result<()> {
        let mut next = self.seen.clone();
        next.extend(entries.iter().map(|&(w, t)| (hash(w), t)));
        next.sort_by_key(|&(_, t)| t);
        let excess = next.len().saturating_sub(MAX_SEEN);
        let expired = next
            .iter()
            .take(excess)
            .take_while(|&&(_, t)| t.saturating_add(keep_ms) < now_ms)
            .count();
        next.drain(..expired);
        let hard_excess = next.len().saturating_sub(MAX_SEEN_HARD);
        next.drain(..hard_excess);
        let mut bytes = Vec::with_capacity(SEEN_MAGIC.len() + ENTRY * next.len());
        bytes.extend_from_slice(SEEN_MAGIC);
        for (h, t) in &next {
            bytes.extend_from_slice(h);
            bytes.extend_from_slice(&t.to_be_bytes());
        }
        state::write_atomic(&self.path, &bytes)?;
        self.seen = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    const NOW: u64 = 1_800_000_000_000;
    const KEEP: u64 = 120_000;

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn ids(prefix: &str, n: usize) -> Vec<String> {
        (0..n).map(|i| format!("wamid.{prefix}{i}")).collect()
    }

    fn at(ids: &[String], t: u64) -> Vec<(&str, u64)> {
        ids.iter().map(|s| (s.as_str(), t)).collect()
    }

    #[test]
    fn seen_roundtrip_and_0600() {
        let home = tempfile::tempdir().unwrap();
        let mut s = SeenStore::open(home.path()).unwrap();
        assert!(!s.contains("wamid.A"));
        s.record(&[("wamid.A", NOW), ("wamid.B", NOW)], NOW, KEEP)
            .unwrap();
        assert!(s.contains("wamid.A") && s.contains("wamid.B"));
        assert!(!s.contains("wamid.C"));
        let p = home.path().join(SEEN_FILE);
        assert_eq!(mode(&p), 0o600);
        assert_eq!(fs::metadata(&p).unwrap().len(), 8 + 2 * 40);

        let s2 = SeenStore::open(home.path()).unwrap();
        assert!(s2.contains("wamid.A") && s2.contains("wamid.B"));
        assert!(!s2.contains("wamid.C"));

        // Recording nothing still works; a group-readable file is refused.
        let mut s3 = SeenStore::open(home.path()).unwrap();
        s3.record(&[], NOW, KEEP).unwrap();
        assert!(s3.contains("wamid.A"));
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            SeenStore::open(home.path()).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    /// Old entries beyond 1024 go, oldest first.
    #[test]
    fn seen_drops_expired_entries_beyond_1024_oldest_first() {
        let home = tempfile::tempdir().unwrap();
        let mut s = SeenStore::open(home.path()).unwrap();
        let old = ids("old", 1000);
        s.record(&at(&old, NOW - 10 * KEEP), NOW, KEEP).unwrap();
        let fresh = ids("new", 100);
        s.record(&at(&fresh, NOW), NOW, KEEP).unwrap();
        assert_eq!(s.len(), MAX_SEEN);
        for (i, id) in old.iter().enumerate() {
            assert_eq!(s.contains(id), i >= 1100 - MAX_SEEN, "{id}");
        }
        assert!(fresh.iter().all(|id| s.contains(id)));
        let p = home.path().join(SEEN_FILE);
        assert_eq!(fs::metadata(&p).unwrap().len(), 8 + 40 * MAX_SEEN as u64);
        let reopened = SeenStore::open(home.path()).unwrap();
        assert_eq!(reopened.len(), MAX_SEEN);
        assert!(!reopened.contains("wamid.old0"));
        assert!(reopened.contains("wamid.new99"));
    }

    /// Integration finding I1: entries younger than the keep time are never
    /// evicted below the hard cap, whatever the count.
    #[test]
    fn seen_keeps_young_entries_past_1024() {
        let home = tempfile::tempdir().unwrap();
        let mut s = SeenStore::open(home.path()).unwrap();
        s.record(&[("wamid.owner", NOW - KEEP)], NOW, KEEP).unwrap();
        let flood = ids("f", 3000);
        s.record(&at(&flood, NOW), NOW, KEEP).unwrap();
        assert_eq!(s.len(), 3001);
        assert!(s.contains("wamid.owner"));
        assert!(SeenStore::open(home.path())
            .unwrap()
            .contains("wamid.owner"));
        // Once it is older than the keep time it may go.
        s.record(&[("wamid.x", NOW + 1)], NOW + 1, KEEP).unwrap();
        assert!(!s.contains("wamid.owner"));
    }

    /// Past the hard cap the oldest go by time, not by insertion order.
    #[test]
    fn seen_hard_cap_evicts_oldest_by_time() {
        let home = tempfile::tempdir().unwrap();
        let mut s = SeenStore::open(home.path()).unwrap();
        let young = ids("y", MAX_SEEN_HARD);
        s.record(&at(&young, NOW), NOW, KEEP).unwrap();
        // Recorded later but stamped earlier: evicted first.
        s.record(&[("wamid.early", NOW - 1)], NOW, KEEP).unwrap();
        assert_eq!(s.len(), MAX_SEEN_HARD);
        assert!(!s.contains("wamid.early"));
        assert!(young.iter().all(|id| s.contains(id)));
        s.record(&[("wamid.late", NOW + 5)], NOW + 5, KEEP).unwrap();
        assert_eq!(s.len(), MAX_SEEN_HARD);
        assert!(s.contains("wamid.late"));
        let p = home.path().join(SEEN_FILE);
        assert_eq!(
            fs::metadata(&p).unwrap().len(),
            8 + 40 * MAX_SEEN_HARD as u64
        );
        assert_eq!(SeenStore::open(home.path()).unwrap().len(), MAX_SEEN_HARD);
    }

    #[test]
    fn seen_file_with_bad_shape_is_invalid_data() {
        let home = tempfile::tempdir().unwrap();
        let p = home.path().join(SEEN_FILE);
        let with_magic = |n: usize| {
            let mut b = SEEN_MAGIC.to_vec();
            b.resize(8 + n, 0);
            b
        };
        let bad = [
            vec![0u8; 1],
            vec![0u8; 32],
            vec![0u8; 64],
            vec![0u8; 40],
            b"WDNSEEN1".to_vec(),
            with_magic(1),
            with_magic(39),
            with_magic(41),
            with_magic(40 * MAX_SEEN_HARD + 40),
        ];
        for b in bad {
            state::write_atomic(&p, &b).unwrap();
            assert_eq!(
                SeenStore::open(home.path()).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{}",
                b.len()
            );
        }
        // Empty, magic only and exactly full are fine.
        for b in [Vec::new(), with_magic(0), with_magic(40 * MAX_SEEN_HARD)] {
            state::write_atomic(&p, &b).unwrap();
            SeenStore::open(home.path()).unwrap();
        }
    }

    /// The earlier format (bare 32-byte hashes) is refused with a hint, not
    /// misread.
    #[test]
    fn old_format_seen_file_is_refused_with_a_hint() {
        let home = tempfile::tempdir().unwrap();
        let p = home.path().join(SEEN_FILE);
        state::write_atomic(&p, &[7u8; 32 * 5]).unwrap();
        let e = SeenStore::open(home.path()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(e.to_string().contains("delete whatsapp-seen"), "{e}");
    }

    #[test]
    fn seen_file_holds_no_wamid_text() {
        let home = tempfile::tempdir().unwrap();
        let mut s = SeenStore::open(home.path()).unwrap();
        let id = "wamid.HBgLMTU1NTEyMzQ1NjcVAgASGBQzQTk=";
        s.record(&[(id, NOW)], NOW, KEEP).unwrap();
        let bytes = fs::read(home.path().join(SEEN_FILE)).unwrap();
        assert_eq!(bytes.len(), 48);
        assert!(!bytes.windows(5).any(|w| w == b"wamid"));
        assert!(!bytes.windows(id.len()).any(|w| w == id.as_bytes()));
        assert_eq!(&bytes[..8], SEEN_MAGIC);
        assert_eq!(&bytes[8..40], hash(id).as_slice());
        assert_eq!(&bytes[40..], NOW.to_be_bytes().as_slice());
    }

    /// Final review C3: a file whose entries claim far-future times cannot
    /// crowd real ids out. On open they are clamped to the clock, so they
    /// age like any other entry and are evicted before younger real ids.
    #[test]
    fn far_future_times_are_clamped_on_open() {
        let home = tempfile::tempdir().unwrap();
        let p = home.path().join(SEEN_FILE);
        let mut bytes = SEEN_MAGIC.to_vec();
        for i in 0..MAX_SEEN_HARD {
            bytes.extend_from_slice(&hash(&format!("wamid.crafted{i}")));
            bytes.extend_from_slice(&u64::MAX.to_be_bytes());
        }
        state::write_atomic(&p, &bytes).unwrap();
        let mut s = SeenStore::open_at(home.path(), NOW).unwrap();
        assert_eq!(s.len(), MAX_SEEN_HARD);
        // Later, a real owner id arrives: it is the youngest and is kept.
        let later = NOW + KEEP + 1;
        s.record(&[("wamid.real", later)], later, KEEP).unwrap();
        assert!(s.contains("wamid.real"));
        assert_eq!(s.len(), MAX_SEEN);
        // Written back clamped.
        let saved = fs::read(&p).unwrap();
        assert!(!saved.windows(8).any(|w| w == u64::MAX.to_be_bytes()));
        // `open` clamps against the real clock too.
        state::write_atomic(&p, &bytes).unwrap();
        let mut s = SeenStore::open(home.path()).unwrap();
        s.record(&[("wamid.real", u64::MAX - 1)], u64::MAX - 1, KEEP)
            .unwrap();
        assert!(s.contains("wamid.real"));
    }

    #[test]
    fn failed_record_leaves_memory_unchanged() {
        let home = tempfile::tempdir().unwrap();
        let mut s = SeenStore::open(home.path()).unwrap();
        s.record(&[("wamid.A", NOW)], NOW, KEEP).unwrap();
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let err = s.record(&[("wamid.B", NOW)], NOW, KEEP);
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(err.is_err(), "write into a 0500 home must fail");
        assert!(s.contains("wamid.A"));
        assert!(!s.contains("wamid.B"));
        let reopened = SeenStore::open(home.path()).unwrap();
        assert!(reopened.contains("wamid.A") && !reopened.contains("wamid.B"));
    }
}
