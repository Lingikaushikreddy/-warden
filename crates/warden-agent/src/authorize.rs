//! Persisted approvals and the [`Authorized`] token.
//!
//! [`Authorized`] is the compile-time gate in front of the executor: it has a
//! private field and no public constructor, so the only ways to get one are
//! [`ApproverStore::authorize`] (sign, redeem, and durably record a fresh
//! approval) and [`ApproverStore::authorize_auto`] (actions classified
//! `Auto`). `Blocked` actions can never be authorized.
//!
//! [`ApproverStore`] keeps the approver state in a directory (`home`, created
//! 0700 if missing):
//!
//! - `approver.key`: the ed25519 signing key, exactly 32 raw bytes, 0600.
//!   Created from the OS RNG if missing. An existing key of the wrong size is
//!   `InvalidData`, and one with any group/other permission bit is
//!   `PermissionDenied`; neither is repaired (fail closed).
//! - `spent-nonces`: append-only records `nonce (16) || expires_at_ms (8, BE)`,
//!   0600. A length that is not a multiple of 24 (a torn write) is
//!   `InvalidData` and is not repaired. Records with `expires_at_ms <= now_ms`
//!   are dropped on open (their approvals can no longer be redeemed) by an
//!   atomic rewrite: temp file, `sync_all`, rename, directory fsync.
//! - `approver.lock`: an exclusive advisory lock held for the store's
//!   lifetime, so two agents cannot share one store (`WouldBlock`).
//!
//! Persist-before-execute (docs/SECURITY-NOTES.md, "Contract for the agent
//! crate"): after a successful redeem, the nonce record is appended and
//! `sync_data`'d BEFORE a token is returned. If that fails, no token is
//! returned and the nonce stays spent in memory, so the approval is burned
//! rather than replayable.
//!
//! The expiry used for pruning is only as good as `now_ms`: it must be
//! milliseconds since the Unix epoch from a sane clock. A clock that jumps
//! forward on open prunes records early; their approvals are then refused as
//! `Expired` on a sane clock, but could be replayed if the clock later goes
//! back. This module does not read the clock.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use warden_core::{classify, Action, Approval, ApprovalError, Approver, PolicyConfig, Tier};

const KEY_FILE: &str = "approver.key";
const SPENT_FILE: &str = "spent-nonces";
const LOCK_FILE: &str = "approver.lock";
const SPENT_TMP: &str = "spent-nonces.tmp";
const RECORD_LEN: usize = 24;

/// SHA-256 of `action.canonical_bytes()`: the hash an approval binds to.
pub fn action_hash(action: &Action) -> [u8; 32] {
    Sha256::digest(action.canonical_bytes()).into()
}

/// Proof that one action was authorized. Only this module can build one.
///
/// Deliberately not `Clone`/`Copy`: one token, one execution.
///
/// Code outside this module cannot build one:
///
/// ```compile_fail
/// let _ = warden_agent::authorize::Authorized { action_hash: [0u8; 32] };
/// ```
///
/// and cannot duplicate one:
///
/// ```compile_fail
/// fn dup(t: &warden_agent::authorize::Authorized) -> warden_agent::authorize::Authorized {
///     t.clone()
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct Authorized {
    action_hash: [u8; 32],
}

impl Authorized {
    /// The [`action_hash`] of the action this token authorizes.
    pub fn action_hash(&self) -> &[u8; 32] {
        &self.action_hash
    }
}

/// Why an action was not authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizeError {
    /// Granting or redeeming the approval failed (includes `Blocked`).
    Approval(ApprovalError),
    /// The approval was redeemed but its nonce could not be recorded durably.
    /// No token was issued and the approval is burned.
    Persist(io::ErrorKind),
    /// `authorize_auto` was asked for an action that is not `Auto`.
    NotAuto,
}

impl fmt::Display for AuthorizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthorizeError::Approval(e) => write!(f, "approval refused: {e}"),
            AuthorizeError::Persist(kind) => {
                write!(f, "could not persist the spent approval nonce: {kind}")
            }
            AuthorizeError::NotAuto => {
                write!(f, "action needs approval: it is not classified Auto")
            }
        }
    }
}

impl std::error::Error for AuthorizeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AuthorizeError::Approval(e) => Some(e),
            _ => None,
        }
    }
}

/// The approver plus its on-disk key, spent-nonce log and lock.
pub struct ApproverStore {
    home: PathBuf,
    approver: Approver,
    /// Holds the exclusive advisory lock until the store is dropped.
    _lock: File,
    #[cfg(feature = "test-hooks")]
    last_approval: Option<Approval>,
}

impl fmt::Debug for ApproverStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Approver`'s Debug prints only the verifying key and a count.
        f.debug_struct("ApproverStore")
            .field("home", &self.home)
            .field("approver", &self.approver)
            .finish_non_exhaustive()
    }
}

fn fsync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn lock(home: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(home.join(LOCK_FILE))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "approver store is in use by another process",
        )),
        Err(TryLockError::Error(e)) => Err(e),
    }
}

fn load_or_create_key(home: &Path) -> io::Result<SigningKey> {
    let path = home.join(KEY_FILE);
    match File::open(&path) {
        Ok(mut f) => {
            let meta = f.metadata()?;
            if !meta.is_file() {
                return Err(invalid("approver key is not a regular file"));
            }
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "approver key is readable or writable by group or others",
                ));
            }
            if meta.len() != 32 {
                return Err(invalid("approver key must be exactly 32 bytes"));
            }
            let mut bytes = [0u8; 32];
            f.read_exact(&mut bytes)?;
            // A file that grew after the length check is also refused.
            if f.read(&mut [0u8; 1])? != 0 {
                return Err(invalid("approver key must be exactly 32 bytes"));
            }
            Ok(SigningKey::from_bytes(&bytes))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let key = SigningKey::generate(&mut OsRng);
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            f.write_all(&key.to_bytes())?;
            f.sync_all()?;
            fsync_dir(home)?;
            Ok(key)
        }
        Err(e) => Err(e),
    }
}

/// Read the spent log, dropping expired records (atomic rewrite if any were).
fn load_spent(home: &Path, now_ms: u64) -> io::Result<Vec<[u8; 16]>> {
    let path = home.join(SPENT_FILE);
    let bytes = match fs::read(&path) {
        Ok(b) => {
            if !fs::metadata(&path)?.is_file() {
                return Err(invalid("spent-nonce log is not a regular file"));
            }
            b
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?
                .sync_all()?;
            fsync_dir(home)?;
            Vec::new()
        }
        Err(e) => return Err(e),
    };
    if bytes.len() % RECORD_LEN != 0 {
        return Err(invalid(
            "spent-nonce log has a partial record (torn write?)",
        ));
    }
    let mut kept = Vec::with_capacity(bytes.len());
    let mut nonces = Vec::with_capacity(bytes.len() / RECORD_LEN);
    for rec in bytes.chunks_exact(RECORD_LEN) {
        let mut exp = [0u8; 8];
        exp.copy_from_slice(&rec[16..]);
        if u64::from_be_bytes(exp) <= now_ms {
            continue;
        }
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&rec[..16]);
        nonces.push(nonce);
        kept.extend_from_slice(rec);
    }
    if kept.len() != bytes.len() {
        let tmp = home.join(SPENT_TMP);
        // A stale temp file from a crashed rewrite is never part of the log.
        match fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&kept)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, &path)?;
        fsync_dir(home)?;
    }
    Ok(nonces)
}

impl ApproverStore {
    /// Open (or create) the store in `home`. `now_ms` (milliseconds since the
    /// Unix epoch) decides which spent records have expired and are dropped.
    pub fn open(home: &Path, now_ms: u64) -> io::Result<ApproverStore> {
        DirBuilder::new().recursive(true).mode(0o700).create(home)?;
        let lock = lock(home)?;
        let key = load_or_create_key(home)?;
        let spent = load_spent(home, now_ms)?;
        Ok(ApproverStore {
            home: home.to_path_buf(),
            approver: Approver::from_signing_key_with_spent(key, spent),
            _lock: lock,
            #[cfg(feature = "test-hooks")]
            last_approval: None,
        })
    }

    /// Grant and redeem an approval for `action` at the tier `classify`
    /// gives it under `cfg`, record its nonce durably, then return the token.
    ///
    /// `Blocked` actions are refused before any state changes. A persist
    /// failure returns [`AuthorizeError::Persist`] and no token; the nonce
    /// stays spent in memory (fail closed).
    pub fn authorize(
        &mut self,
        action: &Action,
        cfg: &PolicyConfig,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<Authorized, AuthorizeError> {
        let tier = classify(action, cfg);
        if tier == Tier::Blocked {
            return Err(AuthorizeError::Approval(ApprovalError::Blocked));
        }
        let approval = self
            .approver
            .grant(action, tier, now_ms, ttl_ms)
            .map_err(AuthorizeError::Approval)?;
        self.approver
            .redeem(action, cfg, &approval, now_ms)
            .map_err(AuthorizeError::Approval)?;
        let persisted = self.append_record(&approval);
        #[cfg(feature = "test-hooks")]
        {
            self.last_approval = Some(approval.clone());
        }
        persisted.map_err(|e| AuthorizeError::Persist(e.kind()))?;
        Ok(Authorized {
            action_hash: approval.action_hash,
        })
    }

    /// A token for an action that needs no approval (`classify == Auto`).
    pub fn authorize_auto(
        action: &Action,
        cfg: &PolicyConfig,
    ) -> Result<Authorized, AuthorizeError> {
        if classify(action, cfg) != Tier::Auto {
            return Err(AuthorizeError::NotAuto);
        }
        Ok(Authorized {
            action_hash: action_hash(action),
        })
    }

    /// Append one record and `sync_data` it. Never creates the log: a log
    /// that vanished after open is an error, not a fresh start.
    fn append_record(&self, approval: &Approval) -> io::Result<()> {
        let mut rec = [0u8; RECORD_LEN];
        rec[..16].copy_from_slice(&approval.nonce);
        rec[16..].copy_from_slice(&approval.expires_at_ms.to_be_bytes());
        let mut f = OpenOptions::new()
            .append(true)
            .open(self.home.join(SPENT_FILE))?;
        f.write_all(&rec)?;
        f.sync_data()
    }

    /// The approval most recently granted by `authorize`.
    #[cfg(feature = "test-hooks")]
    pub fn last_approval_for_test(&self) -> Option<&Approval> {
        self.last_approval.as_ref()
    }

    /// The in-memory spent set, sorted.
    #[cfg(feature = "test-hooks")]
    pub fn spent_for_test(&self) -> Vec<[u8; 16]> {
        self.approver.spent()
    }

    /// Redeem against the store's in-memory approver without persisting.
    #[cfg(feature = "test-hooks")]
    pub fn redeem_for_test(
        &mut self,
        action: &Action,
        cfg: &PolicyConfig,
        approval: &Approval,
        now_ms: u64,
    ) -> Result<(), ApprovalError> {
        self.approver.redeem(action, cfg, approval, now_ms)
    }
}
