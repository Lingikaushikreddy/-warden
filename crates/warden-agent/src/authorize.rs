//! Persisted approvals and the [`Authorized`] token.
//!
//! [`Authorized`] is the compile-time gate in front of the executor: it has
//! private fields and no public constructor, so the only ways to get one are
//! [`ApproverStore::authorize`] (sign, redeem, and durably record a fresh
//! approval) and [`ApproverStore::authorize_auto`] (actions classified
//! `Auto`). `Blocked` actions can never be authorized. A token carries the
//! action hash, the tier and an expiry; the executor checks the expiry.
//!
//! [`ApproverStore`] keeps the approver state in a directory (`home`, created
//! 0700 if missing). `home` must be on a local filesystem: the lock is an
//! advisory `flock`, which network filesystems may not honour. Every file is
//! opened with `O_NOFOLLOW | O_NONBLOCK` and checked through its handle: it
//! must be a regular file with no group/other permission bits
//! (`InvalidData` / `PermissionDenied` otherwise, never repaired).
//!
//! - `approver.lock`: an exclusive advisory lock held for the store's
//!   lifetime, so two agents cannot share one store (`WouldBlock`).
//! - `approver.key`: the ed25519 signing key, exactly 32 raw bytes, 0600.
//!   Created atomically from the OS RNG (temp file, `sync_all`, `hard_link`,
//!   directory fsync) only when missing; a leftover `approver.key.tmp` from a
//!   crash is removed on open. A key of the wrong size is `InvalidData`.
//! - `spent-nonces`: append-only records `nonce (16) || expires_at_ms (8, BE)`,
//!   0600. Created only together with a new key: a missing log next to an
//!   existing key is `NotFound` (fail closed, a lost log must not reset the
//!   spent set). A length that is not a multiple of 24 is `InvalidData`.
//!   Records with `expires_at_ms + MAX_SKEW_MS <= now_ms` are dropped on open
//!   by an atomic rewrite (temp file, `sync_all`, rename, directory fsync).
//!
//! Persist-before-execute (docs/SECURITY-NOTES.md, "Contract for the agent
//! crate"): after a successful redeem, the nonce record is appended and
//! `sync_data`'d BEFORE a token is returned. If that fails, no token is
//! returned, the nonce stays spent in memory (the approval is burned), the
//! store tries to truncate the log back to its previous length, and the store
//! is poisoned: every later `authorize` returns [`AuthorizeError::Poisoned`]
//! until the store is reopened (which re-validates the log).
//!
//! Pruning is only as good as `now_ms`: it must be milliseconds since the
//! Unix epoch from a sane clock. A clock that jumps forward on open prunes
//! records early; a later clock rollback could then let those approvals be
//! replayed. This module does not read the clock.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use warden_core::{
    classify, Action, Approval, ApprovalError, Approver, PolicyConfig, Tier, MAX_SKEW_MS,
    MAX_TTL_MS,
};
use zeroize::Zeroizing;

const KEY_FILE: &str = "approver.key";
const KEY_TMP: &str = "approver.key.tmp";
const SPENT_FILE: &str = "spent-nonces";
const SPENT_TMP: &str = "spent-nonces.tmp";
const LOCK_FILE: &str = "approver.lock";
const RECORD_LEN: usize = 24;

/// Never follow a symlink in the final component; never block opening a FIFO.
const OPEN_FLAGS: i32 = libc::O_NOFOLLOW | libc::O_NONBLOCK;

/// SHA-256 of `action.canonical_bytes()`: the hash an approval binds to.
pub fn action_hash(action: &Action) -> [u8; 32] {
    Sha256::digest(action.canonical_bytes()).into()
}

/// Proof that one action was authorized. Only this module can build one.
///
/// Deliberately not `Clone`/`Copy`: one token, one execution. It is
/// time-limited ([`Authorized::expires_at_ms`], checked by the executor) but
/// NOT bound to a [`PolicyConfig`]: the executor must act under the same
/// policy that was passed to `authorize`.
///
/// Code outside this module cannot build one:
///
/// ```compile_fail
/// let _ = warden_agent::authorize::Authorized {
///     action_hash: [0u8; 32],
///     tier: warden_core::Tier::Auto,
///     expires_at_ms: 0,
/// };
/// ```
///
/// and cannot duplicate one:
///
/// ```compile_fail
/// fn dup(t: &warden_agent::authorize::Authorized) -> warden_agent::authorize::Authorized {
///     t.clone()
/// }
/// ```
#[must_use = "an Authorized token is the only way to run an action"]
#[derive(Debug, PartialEq, Eq)]
pub struct Authorized {
    action_hash: [u8; 32],
    tier: Tier,
    expires_at_ms: u64,
}

impl Authorized {
    /// The [`action_hash`] of the action this token authorizes.
    pub fn action_hash(&self) -> &[u8; 32] {
        &self.action_hash
    }

    /// The tier the action was classified at when authorized.
    pub fn tier(&self) -> Tier {
        self.tier
    }

    /// Milliseconds since the Unix epoch at which the token stops being valid
    /// (`now_ms + ttl_ms` at authorization).
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

/// Why an action was not authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizeError {
    /// Granting or redeeming the approval failed (includes `Blocked` and
    /// `BadTtl`).
    Approval(ApprovalError),
    /// The approval was redeemed but its nonce could not be recorded durably.
    /// No token was issued, the approval is burned, and the store is now
    /// poisoned.
    Persist(io::ErrorKind),
    /// `authorize_auto` was asked for an action that is not `Auto`.
    NotAuto,
    /// An earlier append to the spent-nonce log failed; reopen the store.
    Poisoned,
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
            AuthorizeError::Poisoned => write!(
                f,
                "approver store poisoned by an earlier failed write; reopen it"
            ),
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
    /// Set on any failed append; blocks `authorize` until reopen.
    poisoned: bool,
    #[cfg(feature = "test-hooks")]
    last_approval: Option<Approval>,
    #[cfg(feature = "test-hooks")]
    fail_next_append: Option<usize>,
}

impl fmt::Debug for ApproverStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Approver`'s Debug prints only the verifying key and a count.
        f.debug_struct("ApproverStore")
            .field("home", &self.home)
            .field("approver", &self.approver)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

fn fsync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// fstat the handle: a regular file with no group/other permission bits.
fn check_private_file(f: &File, what: &'static str) -> io::Result<Metadata> {
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{what} is not a regular file"),
        ));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{what} is accessible by group or others"),
        ));
    }
    Ok(meta)
}

fn create_private(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(OPEN_FLAGS)
        .open(path)
}

fn lock(home: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(OPEN_FLAGS)
        .open(home.join(LOCK_FILE))?;
    check_private_file(&file, "approver lock file")?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "approver store is in use by another process",
        )),
        Err(TryLockError::Error(e)) => Err(e),
    }
}

/// The existing key, or `None` if there is no key file.
fn read_key(home: &Path) -> io::Result<Option<SigningKey>> {
    let mut f = match OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_FLAGS)
        .open(home.join(KEY_FILE))
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let meta = check_private_file(&f, "approver key")?;
    if meta.len() != 32 {
        return Err(invalid("approver key must be exactly 32 bytes"));
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    f.read_exact(&mut bytes[..])?;
    // A file that grew after the length check is also refused.
    if f.read(&mut [0u8; 1])? != 0 {
        return Err(invalid("approver key must be exactly 32 bytes"));
    }
    Ok(Some(SigningKey::from_bytes(&bytes)))
}

/// Create the key atomically: temp file, sync, hard link (fails if a key
/// exists), remove the temp, fsync the directory.
fn create_key(home: &Path) -> io::Result<SigningKey> {
    let key = SigningKey::generate(&mut OsRng);
    let tmp = home.join(KEY_TMP);
    {
        let mut f = create_private(&tmp)?;
        let bytes = Zeroizing::new(key.to_bytes());
        f.write_all(&bytes[..])?;
        f.sync_all()?;
    }
    fs::hard_link(&tmp, home.join(KEY_FILE))?;
    fs::remove_file(&tmp)?;
    fsync_dir(home)?;
    Ok(key)
}

/// Create an empty spent log if there is none (only called with a new key).
fn ensure_spent_log(home: &Path) -> io::Result<()> {
    match create_private(&home.join(SPENT_FILE)) {
        Ok(f) => {
            f.sync_all()?;
            fsync_dir(home)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

/// Read the spent log, dropping expired records (atomic rewrite if any were).
/// A missing log is `NotFound`.
fn load_spent(home: &Path, now_ms: u64) -> io::Result<Vec<[u8; 16]>> {
    let path = home.join(SPENT_FILE);
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_FLAGS)
        .open(&path)?;
    let meta = check_private_file(&f, "spent-nonce log")?;
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    f.read_to_end(&mut bytes)?;
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
        // Same tolerance as redeem's skew: keep anything that might still be
        // redeemable on a slightly different clock.
        if u64::from_be_bytes(exp).saturating_add(MAX_SKEW_MS) <= now_ms {
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
        remove_if_exists(&tmp)?;
        {
            let mut t = create_private(&tmp)?;
            t.write_all(&kept)?;
            t.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        fsync_dir(home)?;
    }
    Ok(nonces)
}

impl ApproverStore {
    /// Open (or create) the store in `home`, which must be on a local
    /// filesystem. `now_ms` (milliseconds since the Unix epoch) decides which
    /// spent records have expired and are dropped.
    pub fn open(home: &Path, now_ms: u64) -> io::Result<ApproverStore> {
        DirBuilder::new().recursive(true).mode(0o700).create(home)?;
        let lock = lock(home)?;
        remove_if_exists(&home.join(KEY_TMP))?;
        let key = match read_key(home)? {
            Some(key) => key,
            None => {
                // Log first: a crash between the two leaves a log without a
                // key (recoverable), never a key without a log.
                ensure_spent_log(home)?;
                create_key(home)?
            }
        };
        let spent = load_spent(home, now_ms)?;
        Ok(ApproverStore {
            home: home.to_path_buf(),
            approver: Approver::from_signing_key_with_spent(key, spent),
            _lock: lock,
            poisoned: false,
            #[cfg(feature = "test-hooks")]
            last_approval: None,
            #[cfg(feature = "test-hooks")]
            fail_next_append: None,
        })
    }

    /// Grant and redeem an approval for `action` at the tier `classify`
    /// gives it under `cfg`, record its nonce durably, then return the token.
    ///
    /// **This does not verify consent.** The caller must already have
    /// collected the user's consent matching the action's tier (a yes for
    /// `Yes`; a yes plus the PIN for `YesPin`) before calling it. The token
    /// expires at `now_ms + ttl_ms` but is not bound to `cfg`: the executor
    /// must act under the same policy.
    ///
    /// `Blocked` actions are refused before any state changes. A persist
    /// failure returns [`AuthorizeError::Persist`] and no token; the nonce
    /// stays spent in memory and the store is poisoned (fail closed).
    pub fn authorize(
        &mut self,
        action: &Action,
        cfg: &PolicyConfig,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<Authorized, AuthorizeError> {
        if self.poisoned {
            return Err(AuthorizeError::Poisoned);
        }
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
        if let Err(e) = persisted {
            self.poisoned = true;
            return Err(AuthorizeError::Persist(e.kind()));
        }
        Ok(Authorized {
            action_hash: approval.action_hash,
            tier,
            expires_at_ms: approval.expires_at_ms,
        })
    }

    /// A token for an action that needs no approval (`classify == Auto`),
    /// expiring at `now_ms + ttl_ms` with the same TTL rules as `grant`
    /// (`BadTtl` for 0, above `MAX_TTL_MS`, or overflow). Needs no store, so
    /// it works even while a store is poisoned.
    pub fn authorize_auto(
        action: &Action,
        cfg: &PolicyConfig,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<Authorized, AuthorizeError> {
        if classify(action, cfg) != Tier::Auto {
            return Err(AuthorizeError::NotAuto);
        }
        if ttl_ms == 0 || ttl_ms > MAX_TTL_MS {
            return Err(AuthorizeError::Approval(ApprovalError::BadTtl));
        }
        let expires_at_ms = now_ms
            .checked_add(ttl_ms)
            .ok_or(AuthorizeError::Approval(ApprovalError::BadTtl))?;
        Ok(Authorized {
            action_hash: action_hash(action),
            tier: Tier::Auto,
            expires_at_ms,
        })
    }

    /// Append one record and `sync_data` it. Never creates the log: a log
    /// that vanished after open is an error, not a fresh start. On a failed
    /// write or sync, try to truncate back to the previous length.
    fn append_record(&mut self, approval: &Approval) -> io::Result<()> {
        let mut rec = [0u8; RECORD_LEN];
        rec[..16].copy_from_slice(&approval.nonce);
        rec[16..].copy_from_slice(&approval.expires_at_ms.to_be_bytes());
        let mut f = OpenOptions::new()
            .append(true)
            .custom_flags(OPEN_FLAGS)
            .open(self.home.join(SPENT_FILE))?;
        let prev_len = check_private_file(&f, "spent-nonce log")?.len();
        let res = self.write_record(&mut f, &rec).and_then(|()| f.sync_data());
        if res.is_err() {
            // Best effort; the caller poisons the store either way.
            let _ = f.set_len(prev_len).and_then(|()| f.sync_data());
        }
        res
    }

    #[cfg(not(feature = "test-hooks"))]
    fn write_record(&mut self, f: &mut File, rec: &[u8]) -> io::Result<()> {
        f.write_all(rec)
    }

    #[cfg(feature = "test-hooks")]
    fn write_record(&mut self, f: &mut File, rec: &[u8]) -> io::Result<()> {
        if let Some(n) = self.fail_next_append.take() {
            f.write_all(&rec[..n.min(rec.len())])?;
            return Err(io::Error::other("injected append failure (test hook)"));
        }
        f.write_all(rec)
    }

    /// The approval most recently granted by `authorize`.
    #[cfg(feature = "test-hooks")]
    pub fn last_approval_for_test(&self) -> Option<&Approval> {
        self.last_approval.as_ref()
    }

    /// Make the next append write `bytes_written_before_error` bytes of the
    /// record and then fail.
    #[cfg(feature = "test-hooks")]
    pub fn fail_next_append_for_test(&mut self, bytes_written_before_error: usize) {
        self.fail_next_append = Some(bytes_written_before_error);
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
