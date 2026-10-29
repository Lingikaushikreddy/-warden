//! The persisted set of WhatsApp message ids already taken:
//! `<home>/whatsapp-seen`, the SHA-256 of each of the last [`MAX_SEEN`]
//! `wamid`s, 32 bytes each, oldest first.
//!
//! Meta retries webhooks, so the same message can arrive twice. The channel
//! records a batch's new ids here BEFORE it queues any of them (at most
//! once, like the Telegram offset). Only hashes are stored, never the ids.
//! The file follows the private state file rules (no symlinks, mode 0600,
//! atomic replace).

use crate::state;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};

/// File name under the Warden home directory.
pub const SEEN_FILE: &str = "whatsapp-seen";

/// How many message ids are remembered; the oldest is dropped first.
pub const MAX_SEEN: usize = 1024;

type Hash = [u8; 32];

fn hash(wamid: &str) -> Hash {
    Sha256::digest(wamid.as_bytes()).into()
}

/// The seen-message file for one home directory, and its contents.
#[derive(Debug)]
pub struct SeenStore {
    path: PathBuf,
    /// Oldest first.
    seen: VecDeque<Hash>,
}

impl SeenStore {
    /// Open the store: empty when the file is missing; `InvalidData` when
    /// its length is not a multiple of 32 or is above `32 * MAX_SEEN` (or
    /// it is a symlink or not a regular file); `PermissionDenied` when
    /// group or others have access.
    pub fn open(home: &Path) -> io::Result<SeenStore> {
        let path = home.join(SEEN_FILE);
        let bytes = state::read_private(&path, 32 * MAX_SEEN)?.unwrap_or_default();
        if bytes.len() % 32 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "seen file is not a whole number of 32-byte hashes",
            ));
        }
        let seen = bytes
            .chunks_exact(32)
            .map(|c| {
                let mut h = [0u8; 32];
                h.copy_from_slice(c);
                h
            })
            .collect();
        Ok(SeenStore { path, seen })
    }

    /// Whether `wamid` was recorded.
    pub fn contains(&self, wamid: &str) -> bool {
        self.seen.contains(&hash(wamid))
    }

    /// Append the hash of each id, drop the oldest beyond [`MAX_SEEN`], and
    /// replace the file atomically. The in-memory set changes only after
    /// the write succeeds.
    pub fn record(&mut self, wamids: &[&str]) -> io::Result<()> {
        let mut next = self.seen.clone();
        next.extend(wamids.iter().map(|w| hash(w)));
        let excess = next.len().saturating_sub(MAX_SEEN);
        next.drain(..excess);
        let bytes: Vec<u8> = next.iter().flatten().copied().collect();
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

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn seen_roundtrip_and_0600() {
        let home = tempfile::tempdir().unwrap();
        let mut s = SeenStore::open(home.path()).unwrap();
        assert!(!s.contains("wamid.A"));
        s.record(&["wamid.A", "wamid.B"]).unwrap();
        assert!(s.contains("wamid.A") && s.contains("wamid.B"));
        assert!(!s.contains("wamid.C"));
        let p = home.path().join(SEEN_FILE);
        assert_eq!(mode(&p), 0o600);
        assert_eq!(fs::metadata(&p).unwrap().len(), 64);

        let s2 = SeenStore::open(home.path()).unwrap();
        assert!(s2.contains("wamid.A") && s2.contains("wamid.B"));
        assert!(!s2.contains("wamid.C"));

        // Recording nothing still works; a group-readable file is refused.
        let mut s3 = SeenStore::open(home.path()).unwrap();
        s3.record(&[]).unwrap();
        assert!(s3.contains("wamid.A"));
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            SeenStore::open(home.path()).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn seen_keeps_the_newest_1024() {
        let home = tempfile::tempdir().unwrap();
        let mut s = SeenStore::open(home.path()).unwrap();
        let ids: Vec<String> = (0..1100).map(|i| format!("wamid.{i}")).collect();
        let first: Vec<&str> = ids[..1000].iter().map(String::as_str).collect();
        s.record(&first).unwrap();
        let rest: Vec<&str> = ids[1000..].iter().map(String::as_str).collect();
        s.record(&rest).unwrap();
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(s.contains(id), i >= 1100 - MAX_SEEN, "{id}");
        }
        let p = home.path().join(SEEN_FILE);
        assert_eq!(fs::metadata(&p).unwrap().len(), 32 * MAX_SEEN as u64);
        let reopened = SeenStore::open(home.path()).unwrap();
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(reopened.contains(id), i >= 1100 - MAX_SEEN, "{id}");
        }
        // One batch larger than the cap keeps only its newest ids.
        let home2 = tempfile::tempdir().unwrap();
        let mut big = SeenStore::open(home2.path()).unwrap();
        let all: Vec<&str> = ids.iter().map(String::as_str).collect();
        big.record(&all).unwrap();
        assert!(!big.contains("wamid.0"));
        assert!(big.contains("wamid.1099"));
        assert!(big.contains(&format!("wamid.{}", 1100 - MAX_SEEN)));
    }

    #[test]
    fn seen_file_with_bad_length_is_invalid_data() {
        let home = tempfile::tempdir().unwrap();
        let p = home.path().join(SEEN_FILE);
        for len in [1, 31, 33, 32 * MAX_SEEN + 32, 32 * MAX_SEEN + 1] {
            state::write_atomic(&p, &vec![0u8; len]).unwrap();
            assert_eq!(
                SeenStore::open(home.path()).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{len}"
            );
        }
        // Empty and exactly full are fine.
        for len in [0, 32 * MAX_SEEN] {
            state::write_atomic(&p, &vec![0u8; len]).unwrap();
            SeenStore::open(home.path()).unwrap();
        }
    }

    #[test]
    fn seen_file_holds_no_wamid_text() {
        let home = tempfile::tempdir().unwrap();
        let mut s = SeenStore::open(home.path()).unwrap();
        let id = "wamid.HBgLMTU1NTEyMzQ1NjcVAgASGBQzQTk=";
        s.record(&[id]).unwrap();
        let bytes = fs::read(home.path().join(SEEN_FILE)).unwrap();
        assert_eq!(bytes.len(), 32);
        assert!(!bytes.windows(5).any(|w| w == b"wamid"));
        assert!(!bytes.windows(id.len()).any(|w| w == id.as_bytes()));
        assert_eq!(bytes, hash(id).to_vec());
    }

    #[test]
    fn failed_record_leaves_memory_unchanged() {
        let home = tempfile::tempdir().unwrap();
        let mut s = SeenStore::open(home.path()).unwrap();
        s.record(&["wamid.A"]).unwrap();
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let err = s.record(&["wamid.B"]);
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(err.is_err(), "write into a 0500 home must fail");
        assert!(s.contains("wamid.A"));
        assert!(!s.contains("wamid.B"));
        let reopened = SeenStore::open(home.path()).unwrap();
        assert!(reopened.contains("wamid.A") && !reopened.contains("wamid.B"));
    }
}
