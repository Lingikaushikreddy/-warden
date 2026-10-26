//! The CLI PIN: a random 16-byte salt and `sha256(salt || pin)`, stored in
//! `<home>/pin` with mode `0o600`.
//!
//! File format, one line: `v1 <salt hex> <hash hex>\n`.
//!
//! Limits (see docs/SECURITY-NOTES.md, "CLI PIN"): salted sha256 is fast, so
//! anyone who can read the file can guess a short PIN offline; there is no
//! attempt rate-limit. Plan 2 replaces this with keychain-backed storage.

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

/// Minimum PIN length in characters.
pub const MIN_PIN_LEN: usize = 6;
const VERSION: &str = "v1";
const SALT_LEN: usize = 16;

/// Why a PIN could not be stored.
#[derive(Debug)]
pub enum SetPinError {
    TooShort,
    Exists,
    Io(io::Error),
}

impl From<io::Error> for SetPinError {
    fn from(e: io::Error) -> Self {
        SetPinError::Io(e)
    }
}

/// Result of checking a PIN.
#[derive(Debug, PartialEq, Eq)]
pub enum PinCheck {
    Match,
    Mismatch,
    /// No PIN has been set with `init-pin`.
    NotSet,
}

fn digest(salt: &[u8], pin: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(pin.as_bytes());
    h.finalize().into()
}

/// Compare two 32-byte digests without an early exit.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

#[cfg(unix)]
fn private_file(opts: &mut OpenOptions) -> &mut OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;
    opts.mode(0o600)
}

#[cfg(not(unix))]
fn private_file(opts: &mut OpenOptions) -> &mut OpenOptions {
    opts
}

/// Store a new PIN at `path`. Refuses to replace an existing one unless
/// `force`. The file is created `0o600`; with `force` the new file is written
/// next to it and renamed over it.
pub fn set_pin(path: &Path, pin: &str, force: bool) -> Result<(), SetPinError> {
    if pin.chars().count() < MIN_PIN_LEN {
        return Err(SetPinError::TooShort);
    }
    if !force && fs::symlink_metadata(path).is_ok() {
        return Err(SetPinError::Exists);
    }
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let line = format!(
        "{VERSION} {} {}\n",
        hex::encode(salt),
        hex::encode(digest(&salt, pin))
    );

    let mut suffix = [0u8; 8];
    OsRng.fill_bytes(&mut suffix);
    let tmp = path.with_file_name(format!("pin.tmp-{}", hex::encode(suffix)));
    let res = (|| {
        let mut f = private_file(OpenOptions::new().write(true).create_new(true)).open(&tmp)?;
        f.write_all(line.as_bytes())?;
        f.sync_all()?;
        drop(f);
        if force {
            fs::rename(&tmp, path)
        } else {
            // hard_link fails if `path` appeared meanwhile: never overwrite.
            fs::hard_link(&tmp, path)?;
            fs::remove_file(&tmp)
        }
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    match res {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(SetPinError::Exists),
        other => Ok(other?),
    }
}

/// Check `pin` against the PIN stored at `path`. A missing file is
/// [`PinCheck::NotSet`]; a malformed file is an `InvalidData` error.
pub fn check_pin(path: &Path, pin: &str) -> io::Result<PinCheck> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(PinCheck::NotSet),
        Err(e) => return Err(e),
    };
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "pin file is malformed");
    let mut parts = text.trim_end_matches('\n').split(' ');
    let (Some(VERSION), Some(salt), Some(hash), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad());
    };
    let salt = hex::decode(salt).map_err(|_| bad())?;
    let stored: [u8; 32] = hex::decode(hash)
        .map_err(|_| bad())?
        .try_into()
        .map_err(|_| bad())?;
    if salt.len() != SALT_LEN {
        return Err(bad());
    }
    Ok(if ct_eq(&digest(&salt, pin), &stored) {
        PinCheck::Match
    } else {
        PinCheck::Mismatch
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_mismatch() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("pin");
        assert_eq!(check_pin(&p, "123456").unwrap(), PinCheck::NotSet);
        set_pin(&p, "123456", false).unwrap();
        assert_eq!(check_pin(&p, "123456").unwrap(), PinCheck::Match);
        assert_eq!(check_pin(&p, "123457").unwrap(), PinCheck::Mismatch);
        assert!(matches!(
            set_pin(&p, "654321", false),
            Err(SetPinError::Exists)
        ));
        set_pin(&p, "654321", true).unwrap();
        assert_eq!(check_pin(&p, "654321").unwrap(), PinCheck::Match);
    }

    #[test]
    fn same_pin_gets_a_fresh_salt() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("a"), d.path().join("b"));
        set_pin(&a, "123456", false).unwrap();
        set_pin(&b, "123456", false).unwrap();
        assert_ne!(fs::read(&a).unwrap(), fs::read(&b).unwrap());
    }

    #[test]
    fn malformed_file_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("pin");
        fs::write(&p, "v1 zz 00\n").unwrap();
        assert!(check_pin(&p, "123456").is_err());
    }

    #[test]
    fn short_pin_is_rejected() {
        let d = tempfile::tempdir().unwrap();
        assert!(matches!(
            set_pin(&d.path().join("pin"), "12345", false),
            Err(SetPinError::TooShort)
        ));
    }
}
