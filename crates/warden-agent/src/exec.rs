//! The executor: the only agent code that touches the user's disk.
//!
//! [`Executor::run`] takes an [`Authorized`] token **by value**, so a token
//! runs at most one action, and there is no other public way to reach the
//! file operations below. All functions are blocking; call them from async
//! code through `spawn_blocking`.
//!
//! # Checks, in order
//!
//! 1. The token has not expired (`expires_at_ms > now_ms`), else
//!    [`ExecError::TokenExpired`].
//! 2. The token was issued for this action (`action_hash`) and the tool maps
//!    to exactly this action (`to_action(tool, &action.id)` has identical
//!    canonical bytes), else [`ExecError::TokenMismatch`]. A token for action
//!    A therefore cannot run tool B, and a tool cannot run under an action
//!    that describes something else.
//! 3. Path checks (every tool):
//!    - the path must lie lexically under the root (as given to
//!      [`Executor::new`] or in canonical form), AND the canonical form of
//!      its deepest existing ancestor joined with the rest must lie under the
//!      canonical root ([`ExecError::OutsideRoot`]);
//!    - no existing component below the root may be a symlink
//!      (`symlink_metadata`, [`ExecError::Symlink`]); symlinks are never
//!      followed, not even to targets inside the root;
//!    - a path equal to or inside a `protected` directory is
//!      [`ExecError::Protected`]. Protected paths must exist when the
//!      executor is built ([`Executor::new`] fails with `NotFound`
//!      otherwise) and are resolved again on every call (deepest existing
//!      ancestor canonicalized), so a protected directory that was removed
//!      and re-created, or whose spelling differs (case, Unicode
//!      normalization, `/tmp` vs `/private/tmp`), is still matched. The
//!      tool path is compared in its lexical and its canonical form;
//!    - the root itself is never written or deleted ([`ExecError::Protected`]).
//! 4. The operation. No filesystem write happens before steps 1-3 pass.
//!
//! # Operations
//!
//! - `read_file`: opened with `O_NOFOLLOW | O_NONBLOCK` (a FIFO cannot block
//!   the open), `fstat` through the handle must say regular file, at most
//!   `max_bytes` are read through that handle and converted lossily to
//!   UTF-8; a longer file gets a trailing `\n[truncated at <n> bytes]`.
//! - `list_dir`: at most [`MAX_LIST_ENTRIES`] names, sorted by raw bytes,
//!   with control and invisible/format characters escaped as `\u{..}`, a
//!   trailing `/` for directories and `@` for symlinks (never followed). A
//!   name's own trailing `@` and leading `[` are escaped (`\u{40}`,
//!   `\u{5b}`) so a name cannot imitate a marker or the overflow line. Only
//!   the smallest names are kept in memory (bounded heap).
//! - `write_file` / `delete_file`: the target must be a regular file with
//!   link count 1 (or absent, for a write into an existing parent). The
//!   snapshot is taken first (it records absence for a new file); a write
//!   then goes through a randomly named temp file in the same directory
//!   (`create_new`, `0o600`, `O_NOFOLLOW`), gets its final mode (an existing
//!   file's mode masked with `0o777`, else `0o600`), is synced, renamed over
//!   the target; then `record_after`, then the directory is fsynced. A
//!   failed directory fsync does not fail the run (the change is already
//!   visible and recorded): the output says `(directory sync failed)`. Any
//!   failure after the snapshot and before the rename completes still
//!   reports the snapshot id ([`ExecFailure::snapshot`]), and the temp file
//!   is removed.
//!
//! Error messages never contain file contents.
//!
//! # Known limits
//!
//! - **TOCTOU (parent swap).** The path checks are `symlink_metadata` /
//!   `canonicalize` followed by a path-based open, rename or unlink. Only the
//!   final component of a read and the temp file are opened with
//!   `O_NOFOLLOW`. A process that can write inside the root can replace a
//!   parent directory with a symlink between the checks and the operation
//!   and redirect one read, write or delete outside the root. This window is
//!   NOT closed: closing it needs an `openat`-style walk from a root
//!   directory handle (for example `rustix` or `cap-std`), a later item.
//! - **Hard links** are checked by link count before the snapshot of a
//!   write or delete; a link created concurrently is not caught (same
//!   TOCTOU class). Reads do not check link counts: a hard-linked file
//!   inside the root is readable.
//! - **Test hooks.** With the `test-hooks` feature, `*_for_test` methods can
//!   inject a write failure, a directory-sync failure or a callback right
//!   before the rename. They run after every check and the snapshot, and
//!   cannot create tokens. Never enable the feature in a shipped build.
//! - **Where state lives.** The snapshot store and the approver home must be
//!   outside the root, or listed in `protected`; otherwise an authorized
//!   write could edit the approver key, the spent-nonce log or snapshot
//!   manifests.

use crate::authorize::{action_hash, Authorized};
use crate::tools::{is_forbidden_path_char, to_action, Tool, MAX_READ_BYTES, MAX_WRITE_BYTES};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::BinaryHeap;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use warden_core::{normalize, Action, SnapshotError, SnapshotId, SnapshotStore};

/// Most entries `list_dir` returns.
pub const MAX_LIST_ENTRIES: usize = 500;

const TMP_PREFIX: &str = ".warden-tmp-";

/// What a successful tool run produced.
#[derive(Debug)]
pub struct ToolOutput {
    /// Text for the model (file contents for `read_file`).
    pub text: String,
    /// The snapshot taken before a write or delete.
    pub snapshot: Option<SnapshotId>,
}

/// Why a tool run was refused or failed.
#[derive(Debug)]
pub enum ExecError {
    /// The token's `expires_at_ms` is at or before `now_ms`.
    TokenExpired,
    /// The token, the action and the tool do not all describe one action.
    TokenMismatch,
    /// The path is not under the executor's root.
    OutsideRoot,
    /// The path is the root itself (for writes and deletes) or inside a
    /// protected directory.
    Protected,
    /// The path is or passes through a symlink.
    Symlink,
    /// The target is not of the kind the tool needs (regular file or
    /// directory).
    NotAFile,
    /// The request exceeds a size cap.
    TooLarge,
    /// The target has more than one hard link.
    HardLink,
    /// Taking or completing the snapshot failed.
    Snapshot(SnapshotError),
    /// Another I/O error.
    Io(io::ErrorKind),
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecError::TokenExpired => write!(f, "authorization expired"),
            ExecError::TokenMismatch => {
                write!(f, "authorization does not match this action and tool")
            }
            ExecError::OutsideRoot => write!(f, "path is outside the allowed root"),
            ExecError::Protected => write!(f, "path is protected"),
            ExecError::Symlink => write!(f, "refusing to follow a symlink"),
            ExecError::NotAFile => write!(f, "not a file of the expected kind"),
            ExecError::TooLarge => write!(f, "request too large"),
            ExecError::HardLink => write!(f, "refusing a hard-linked file"),
            ExecError::Snapshot(e) => write!(f, "snapshot failed: {e}"),
            ExecError::Io(kind) => write!(f, "I/O error: {kind}"),
        }
    }
}

impl std::error::Error for ExecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ExecError::Snapshot(e) => Some(e),
            _ => None,
        }
    }
}

/// The error of [`Executor::run`]: what went wrong, and the snapshot id if a
/// snapshot was taken before the failure (so the change can be undone).
#[derive(Debug)]
pub struct ExecFailure {
    pub error: ExecError,
    pub snapshot: Option<SnapshotId>,
}

impl fmt::Display for ExecFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.snapshot {
            Some(id) => write!(f, "{} (snapshot {})", self.error, id.0),
            None => write!(f, "{}", self.error),
        }
    }
}

impl std::error::Error for ExecFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<ExecError> for ExecFailure {
    fn from(error: ExecError) -> Self {
        ExecFailure {
            error,
            snapshot: None,
        }
    }
}

fn io_err(e: &io::Error) -> ExecError {
    if e.raw_os_error() == Some(libc::ELOOP) {
        ExecError::Symlink
    } else {
        ExecError::Io(e.kind())
    }
}

/// `p` is `base` or below it, by whole components.
fn within(p: &Path, base: &Path) -> bool {
    p.starts_with(base)
}

/// A path that passed the checks.
struct Checked {
    /// Canonical root joined with the relative path.
    path: PathBuf,
    /// `symlink_metadata` of the final component, if it exists.
    meta: Option<Metadata>,
}

/// Called with the target path right before the rename (test-hooks only).
#[cfg(feature = "test-hooks")]
pub type RenameHook = Box<dyn Fn(&Path) + Send + Sync>;

/// Runs authorized tools under one root.
pub struct Executor {
    /// Canonical.
    root: PathBuf,
    /// The root as given, lexically normalized.
    root_lexical: PathBuf,
    /// Each protected path lexically normalized, as given. Re-resolved on
    /// every check.
    protected_lexical: Vec<PathBuf>,
    /// The lexical forms plus their canonical forms at `new()`.
    protected: Vec<PathBuf>,
    snapshots: SnapshotStore,
    #[cfg(feature = "test-hooks")]
    hooks: TestHooks,
}

#[cfg(feature = "test-hooks")]
#[derive(Default)]
struct TestHooks {
    before_rename: Option<RenameHook>,
    fail_write_after: std::sync::Mutex<Option<usize>>,
    fail_dir_sync: std::sync::atomic::AtomicBool,
}

impl fmt::Debug for Executor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Executor")
            .field("root", &self.root)
            .field("root_lexical", &self.root_lexical)
            .field("protected", &self.protected)
            .field("protected_lexical", &self.protected_lexical)
            .field("snapshots", &self.snapshots)
            .finish_non_exhaustive()
    }
}

impl Executor {
    /// `root` is canonicalized and must be a directory. Each `protected`
    /// path must be absolute and must already exist (`NotFound` otherwise):
    /// create the approver home and the snapshot directory before building
    /// the executor. Protected paths are kept lexically normalized and in
    /// canonical form, and are resolved again on every call.
    pub fn new(
        root: &Path,
        protected: Vec<PathBuf>,
        snapshots: SnapshotStore,
    ) -> io::Result<Executor> {
        let canon = fs::canonicalize(root)?;
        if !fs::metadata(&canon)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "executor root is not a directory",
            ));
        }
        let root_lexical = normalize(root).unwrap_or_else(|| canon.clone());
        let mut prot = Vec::with_capacity(protected.len() * 2);
        let mut prot_lex = Vec::with_capacity(protected.len());
        for p in protected {
            let lex = normalize(&p).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "protected paths must be absolute",
                )
            })?;
            // Fails with NotFound if the protected path does not exist.
            prot.push(fs::canonicalize(&lex)?);
            prot.push(lex.clone());
            prot_lex.push(lex);
        }
        Ok(Executor {
            root: canon,
            root_lexical,
            protected_lexical: prot_lex,
            protected: prot,
            snapshots,
            #[cfg(feature = "test-hooks")]
            hooks: TestHooks::default(),
        })
    }

    /// Run `tool` for `action` under the token `auth`, which is consumed.
    ///
    /// `now_ms` is milliseconds since the Unix epoch. Blocking.
    ///
    /// A token cannot be used twice: `run` takes it by value.
    ///
    /// ```compile_fail
    /// use warden_agent::authorize::Authorized;
    /// use warden_agent::exec::Executor;
    /// use warden_agent::tools::Tool;
    /// use warden_core::Action;
    /// fn twice(e: &Executor, a: &Action, t: &Tool, auth: Authorized) {
    ///     let _ = e.run(a, t, auth, 0);
    ///     let _ = e.run(a, t, auth, 0);
    /// }
    /// ```
    ///
    /// whereas a single use compiles:
    ///
    /// ```
    /// use warden_agent::authorize::Authorized;
    /// use warden_agent::exec::Executor;
    /// use warden_agent::tools::Tool;
    /// use warden_core::Action;
    /// fn once(e: &Executor, a: &Action, t: &Tool, auth: Authorized) {
    ///     let _ = e.run(a, t, auth, 0);
    /// }
    /// ```
    pub fn run(
        &self,
        action: &Action,
        tool: &Tool,
        auth: Authorized,
        now_ms: u64,
    ) -> Result<ToolOutput, ExecFailure> {
        if auth.expires_at_ms() <= now_ms {
            return Err(ExecError::TokenExpired.into());
        }
        if action_hash(action) != *auth.action_hash()
            || to_action(tool, &action.id).canonical_bytes() != action.canonical_bytes()
        {
            return Err(ExecError::TokenMismatch.into());
        }
        drop(auth);
        match tool {
            Tool::ReadFile { path, max_bytes } => {
                self.read_file(path, *max_bytes).map_err(Into::into)
            }
            Tool::ListDir { path } => self.list_dir(path).map_err(Into::into),
            Tool::WriteFile { path, content } => self.write_file(path, content),
            Tool::DeleteFile { path } => self.delete_file(path),
        }
    }

    /// Run `hook` with the target path right before the rename of every
    /// later write. It cannot create tokens or skip any check: it runs after
    /// all checks and the snapshot.
    #[cfg(feature = "test-hooks")]
    pub fn before_rename_hook_for_test(&mut self, hook: RenameHook) {
        self.hooks.before_rename = Some(hook);
    }

    /// Make the next write to a temp file write `n` bytes and then fail.
    #[cfg(feature = "test-hooks")]
    pub fn fail_write_after_for_test(&mut self, n: usize) {
        *self.hooks.fail_write_after.get_mut().unwrap() = Some(n);
    }

    /// Make the directory fsync after the next rename fail.
    #[cfg(feature = "test-hooks")]
    pub fn fail_dir_sync_for_test(&mut self) {
        *self.hooks.fail_dir_sync.get_mut() = true;
    }

    /// Every form a protected path has right now: as given, canonical at
    /// `new()`, and canonical now (deepest existing ancestor re-resolved), so
    /// a protected directory that was replaced or re-created is still
    /// matched.
    fn protected_now(&self) -> Result<Vec<PathBuf>, ExecError> {
        let mut out = self.protected.clone();
        for p in &self.protected_lexical {
            out.push(resolve_deepest(p).map_err(|e| io_err(&e))?);
        }
        Ok(out)
    }

    /// Path checks shared by every tool (see the module docs).
    fn check(&self, raw: &Path) -> Result<Checked, ExecError> {
        let lex = normalize(raw).ok_or(ExecError::OutsideRoot)?;
        let protected = self.protected_now()?;
        let is_protected = |p: &Path| protected.iter().any(|base| within(p, base));
        if is_protected(&lex) {
            return Err(ExecError::Protected);
        }
        let rel = lex
            .strip_prefix(&self.root)
            .or_else(|_| lex.strip_prefix(&self.root_lexical))
            .map_err(|_| ExecError::OutsideRoot)?
            .to_path_buf();
        if !rel.components().all(|c| matches!(c, Component::Normal(_))) {
            return Err(ExecError::OutsideRoot);
        }

        // No existing component below the root may be a symlink.
        let mut cur = self.root.clone();
        let mut meta = None;
        let mut comps = rel.components().peekable();
        while let Some(c) = comps.next() {
            cur.push(c);
            match fs::symlink_metadata(&cur) {
                Ok(m) if m.file_type().is_symlink() => return Err(ExecError::Symlink),
                Ok(m) => {
                    if comps.peek().is_none() {
                        meta = Some(m);
                    } else if !m.is_dir() {
                        return Err(ExecError::NotAFile);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => break,
                Err(e) => return Err(io_err(&e)),
            }
        }

        // Canonical containment of the deepest existing ancestor.
        let full = self.root.join(&rel);
        let canon_full = resolve_deepest(&full).map_err(|e| io_err(&e))?;
        if !within(&canon_full, &self.root) {
            return Err(ExecError::OutsideRoot);
        }
        if is_protected(&canon_full) || is_protected(&full) {
            return Err(ExecError::Protected);
        }
        Ok(Checked { path: full, meta })
    }

    /// Checks for a write or delete target: not the root, regular file with
    /// link count 1 if it exists.
    fn check_mutable(&self, raw: &Path) -> Result<Checked, ExecError> {
        let c = self.check(raw)?;
        if c.path == self.root {
            return Err(ExecError::Protected);
        }
        if let Some(m) = &c.meta {
            if !m.is_file() {
                return Err(ExecError::NotAFile);
            }
            if m.nlink() != 1 {
                return Err(ExecError::HardLink);
            }
        }
        Ok(c)
    }

    fn read_file(&self, raw: &Path, max_bytes: u64) -> Result<ToolOutput, ExecError> {
        if max_bytes > MAX_READ_BYTES {
            return Err(ExecError::TooLarge);
        }
        let c = self.check(raw)?;
        match &c.meta {
            Some(m) if m.is_file() => {}
            Some(_) => return Err(ExecError::NotAFile),
            None => return Err(ExecError::Io(io::ErrorKind::NotFound)),
        }
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&c.path)
            .map_err(|e| io_err(&e))?;
        if !f.metadata().map_err(|e| io_err(&e))?.is_file() {
            return Err(ExecError::NotAFile);
        }
        let mut buf = Vec::new();
        // One extra byte tells whether the file is longer than max_bytes.
        f.take(max_bytes + 1)
            .read_to_end(&mut buf)
            .map_err(|e| io_err(&e))?;
        let truncated = buf.len() as u64 > max_bytes;
        buf.truncate(max_bytes as usize);
        let mut text = String::from_utf8_lossy(&buf).into_owned();
        if truncated {
            text.push_str(&format!("\n[truncated at {max_bytes} bytes]"));
        }
        Ok(ToolOutput {
            text,
            snapshot: None,
        })
    }

    fn list_dir(&self, raw: &Path) -> Result<ToolOutput, ExecError> {
        let c = self.check(raw)?;
        match &c.meta {
            Some(m) if m.is_dir() => {}
            Some(_) => return Err(ExecError::NotAFile),
            // The root itself has no recorded metadata (empty rel).
            None if c.path == self.root => {}
            None => return Err(ExecError::Io(io::ErrorKind::NotFound)),
        }
        // Max-heap of the MAX_LIST_ENTRIES smallest names, plus a count.
        let mut heap: BinaryHeap<(Vec<u8>, &'static str)> = BinaryHeap::new();
        let mut total = 0usize;
        for e in fs::read_dir(&c.path).map_err(|e| io_err(&e))? {
            let e = e.map_err(|e| io_err(&e))?;
            let ft = e.file_type().map_err(|e| io_err(&e))?;
            let mark = if ft.is_symlink() {
                "@"
            } else if ft.is_dir() {
                "/"
            } else {
                ""
            };
            total += 1;
            heap.push((e.file_name().as_bytes().to_vec(), mark));
            if heap.len() > MAX_LIST_ENTRIES {
                heap.pop();
            }
        }
        let mut lines: Vec<String> = heap
            .into_sorted_vec()
            .into_iter()
            .map(|(name, mark)| format!("{}{mark}", escape_name(OsStr::from_bytes(&name))))
            .collect();
        if total > MAX_LIST_ENTRIES {
            lines.push(format!(
                "[{} more entries not shown]",
                total - MAX_LIST_ENTRIES
            ));
        }
        Ok(ToolOutput {
            text: lines.join("\n"),
            snapshot: None,
        })
    }

    fn write_file(&self, raw: &Path, content: &str) -> Result<ToolOutput, ExecFailure> {
        if content.len() as u64 > MAX_WRITE_BYTES {
            return Err(ExecError::TooLarge.into());
        }
        let c = self.check_mutable(raw)?;
        let parent = c.path.parent().ok_or(ExecError::Protected)?;
        // `check` verified every existing component; the parent must exist.
        match fs::symlink_metadata(parent) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(ExecError::NotAFile.into()),
            Err(e) => return Err(io_err(&e).into()),
        }
        let mode = c
            .meta
            .as_ref()
            .map_or(0o600, |m| m.permissions().mode() & 0o777);

        let id = self
            .snapshots
            .snapshot(std::slice::from_ref(&c.path), &self.root)
            .map_err(ExecError::Snapshot)?;
        let fail = |error: ExecError| ExecFailure {
            error,
            snapshot: Some(id.clone()),
        };

        let tmp = parent.join(format!("{TMP_PREFIX}{}", random_hex()));
        if let Err(e) = self.write_and_rename(&tmp, &c.path, content.as_bytes(), mode) {
            let _ = fs::remove_file(&tmp);
            return Err(fail(io_err(&e)));
        }
        // The rename happened: record the after-state before anything else
        // can fail.
        self.snapshots
            .record_after(&id, &self.root)
            .map_err(|e| fail(ExecError::Snapshot(e)))?;
        let mut text = format!("wrote {} bytes", content.len());
        if self.sync_dir(parent).is_err() {
            text.push_str(" (directory sync failed)");
        }
        Ok(ToolOutput {
            text,
            snapshot: Some(id),
        })
    }

    fn delete_file(&self, raw: &Path) -> Result<ToolOutput, ExecFailure> {
        let c = self.check_mutable(raw)?;
        if c.meta.is_none() {
            return Err(ExecError::Io(io::ErrorKind::NotFound).into());
        }
        let parent = c.path.parent().ok_or(ExecError::Protected)?;
        let id = self
            .snapshots
            .snapshot(std::slice::from_ref(&c.path), &self.root)
            .map_err(ExecError::Snapshot)?;
        let fail = |error: ExecError| ExecFailure {
            error,
            snapshot: Some(id.clone()),
        };
        fs::remove_file(&c.path).map_err(|e| fail(io_err(&e)))?;
        self.snapshots
            .record_after(&id, &self.root)
            .map_err(|e| fail(ExecError::Snapshot(e)))?;
        let mut text = String::from("deleted");
        if self.sync_dir(parent).is_err() {
            text.push_str(" (directory sync failed)");
        }
        Ok(ToolOutput {
            text,
            snapshot: Some(id),
        })
    }

    /// Temp file (create_new, 0600, O_NOFOLLOW), write, final mode, sync,
    /// rename over `target`. The caller removes `tmp` on error.
    fn write_and_rename(
        &self,
        tmp: &Path,
        target: &Path,
        bytes: &[u8],
        mode: u32,
    ) -> io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(tmp)?;
        self.write_bytes(&mut f, bytes)?;
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
        drop(f);
        #[cfg(feature = "test-hooks")]
        if let Some(hook) = &self.hooks.before_rename {
            hook(target);
        }
        fs::rename(tmp, target)
    }

    #[cfg(not(feature = "test-hooks"))]
    fn write_bytes(&self, f: &mut File, bytes: &[u8]) -> io::Result<()> {
        f.write_all(bytes)
    }

    #[cfg(feature = "test-hooks")]
    fn write_bytes(&self, f: &mut File, bytes: &[u8]) -> io::Result<()> {
        let fail = self.hooks.fail_write_after.lock().unwrap().take();
        if let Some(n) = fail {
            f.write_all(&bytes[..n.min(bytes.len())])?;
            return Err(io::Error::other("injected write failure (test hook)"));
        }
        f.write_all(bytes)
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        #[cfg(feature = "test-hooks")]
        if self
            .hooks
            .fail_dir_sync
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(io::Error::other(
                "injected directory sync failure (test hook)",
            ));
        }
        File::open(dir)?.sync_all()
    }
}

/// Canonicalize the deepest existing ancestor of `p` and append the rest.
fn resolve_deepest(p: &Path) -> io::Result<PathBuf> {
    let mut existing = p;
    let mut rest: Vec<&OsStr> = Vec::new();
    let canon = loop {
        match fs::canonicalize(existing) {
            Ok(c) => break c,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let (Some(name), Some(parent)) = (existing.file_name(), existing.parent()) else {
                    return Err(e);
                };
                rest.push(name);
                existing = parent;
            }
            Err(e) => return Err(e),
        }
    };
    Ok(rest.iter().rev().fold(canon, |acc, n| acc.join(n)))
}

/// 8 random bytes from the OS RNG, hex-encoded.
fn random_hex() -> String {
    let mut b = [0u8; 8];
    OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A file name for display: lossy UTF-8, with `\`, control and
/// invisible/format characters escaped as `\u{..}`. A trailing `@` (the
/// symlink marker) and a leading `[` (the overflow line) are escaped too, so
/// a name cannot imitate either.
fn escape_name(name: &OsStr) -> String {
    let lossy = name.to_string_lossy();
    let last = lossy.chars().count().saturating_sub(1);
    let mut out = String::new();
    for (i, ch) in lossy.chars().enumerate() {
        if ch == '\\' {
            out.push_str("\\\\");
        } else if is_forbidden_path_char(ch) || (i == 0 && ch == '[') || (i == last && ch == '@') {
            out.push_str(&format!("\\u{{{:x}}}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
}
