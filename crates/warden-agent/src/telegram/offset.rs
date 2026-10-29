//! The persisted `getUpdates` offset: `<home>/telegram-offset`, 8 bytes,
//! the next offset as a big-endian `i64`.
//!
//! Delivery is at most once: the caller saves the offset past a batch
//! before acting on any update in it. The file follows the private state
//! file rules (no symlinks, mode 0600, atomic replace).

use crate::state;
use std::io;
use std::path::{Path, PathBuf};

/// File name under the Warden home directory.
pub const OFFSET_FILE: &str = "telegram-offset";

/// The offset file for one home directory.
#[derive(Debug)]
pub struct OffsetStore {
    path: PathBuf,
}

impl OffsetStore {
    /// Open the store and read the saved offset: 0 when the file is
    /// missing, `InvalidData` when it is not exactly 8 bytes (or is a
    /// symlink or not a regular file), `PermissionDenied` when group or
    /// others have access.
    pub fn open(home: &Path) -> io::Result<(OffsetStore, i64)> {
        let path = home.join(OFFSET_FILE);
        let offset = match state::read_private(&path, 8)? {
            None => 0,
            Some(bytes) => {
                let b: [u8; 8] = bytes.as_slice().try_into().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "offset file is not 8 bytes")
                })?;
                i64::from_be_bytes(b)
            }
        };
        Ok((OffsetStore { path }, offset))
    }

    /// Persist `next` atomically (mode 0600) before the batch is acted on.
    pub fn save(&mut self, next: i64) -> io::Result<()> {
        state::write_atomic(&self.path, &next.to_be_bytes())
    }
}
