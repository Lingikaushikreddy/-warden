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
//!      [`ExecError::Protected`], checked on both the lexical and the
//!      canonical form;
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
//!   trailing `/` for directories and `@` for symlinks (never followed).
//! - `write_file` / `delete_file`: the target must be a regular file with
//!   link count 1 (or absent, for a write into an existing parent). The
//!   snapshot is taken first (it records absence for a new file); a write
//!   then goes through a randomly named temp file in the same directory
//!   (`create_new`, `0o600`, `O_NOFOLLOW`), gets its final mode (an existing
//!   file's mode masked with `0o777`, else `0o600`), is synced, renamed over
//!   the target and the directory is fsynced; then `record_after`. Any
//!   failure after the snapshot still reports the snapshot id
//!   ([`ExecFailure::snapshot`]), and the temp file is removed.
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
//! - **Hard links** are checked by link count before the snapshot; a link
//!   created concurrently is not caught (same TOCTOU class).
//! - **Where state lives.** The snapshot store and the approver home must be
//!   outside the root, or listed in `protected`; otherwise an authorized
//!   write could edit the approver key, the spent-nonce log or snapshot
//!   manifests.

use crate::authorize::{action_hash, Authorized};
use crate::tools::{is_forbidden_path_char, to_action, Tool, MAX_READ_BYTES, MAX_WRITE_BYTES};
use rand::rngs::OsRng;
use rand::RngCore;
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

/// Runs authorized tools under one root.
#[derive(Debug)]
pub struct Executor {
    /// Canonical.
    root: PathBuf,
    /// The root as given, lexically normalized.
    root_lexical: PathBuf,
    /// Canonical form of each protected path that exists, plus the lexically
    /// normalized form of every protected path.
    protected: Vec<PathBuf>,
    snapshots: SnapshotStore,
}

impl Executor {
    /// `root` is canonicalized and must be a directory. Each `protected`
    /// path must be absolute; it is kept lexically normalized and, if it
    /// exists, also in canonical form.
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
        for p in protected {
            let lex = normalize(&p).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "protected paths must be absolute",
                )
            })?;
            match fs::canonicalize(&lex) {
                Ok(c) => prot.push(c),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            prot.push(lex);
        }
        Ok(Executor {
            root: canon,
            root_lexical,
            protected: prot,
            snapshots,
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

    fn is_protected(&self, p: &Path) -> bool {
        self.protected.iter().any(|base| within(p, base))
    }

    /// Path checks shared by every tool (see the module docs).
    fn check(&self, raw: &Path) -> Result<Checked, ExecError> {
        let lex = normalize(raw).ok_or(ExecError::OutsideRoot)?;
        if self.is_protected(&lex) {
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
        let mut existing = full.as_path();
        let mut rest: Vec<&OsStr> = Vec::new();
        let canon = loop {
            match fs::canonicalize(existing) {
                Ok(c) => break c,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    rest.push(existing.file_name().ok_or(ExecError::OutsideRoot)?);
                    existing = existing.parent().ok_or(ExecError::OutsideRoot)?;
                }
                Err(e) => return Err(io_err(&e)),
            }
        };
        let canon_full = rest.iter().rev().fold(canon, |acc, n| acc.join(n));
        if !within(&canon_full, &self.root) {
            return Err(ExecError::OutsideRoot);
        }
        if self.is_protected(&canon_full) || self.is_protected(&full) {
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
        if c.meta.is_none() {
            return Err(ExecError::Io(io::ErrorKind::NotFound));
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
        let mut entries = Vec::new();
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
            entries.push((e.file_name(), mark));
        }
        entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        let mut lines: Vec<String> = entries
            .iter()
            .take(MAX_LIST_ENTRIES)
            .map(|(name, mark)| format!("{}{mark}", escape_name(name)))
            .collect();
        if entries.len() > MAX_LIST_ENTRIES {
            lines.push(format!(
                "[{} more entries not shown]",
                entries.len() - MAX_LIST_ENTRIES
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
        if let Err(e) = write_atomic(&tmp, &c.path, parent, content.as_bytes(), mode) {
            let _ = fs::remove_file(&tmp);
            return Err(fail(io_err(&e)));
        }
        self.snapshots
            .record_after(&id, &self.root)
            .map_err(|e| fail(ExecError::Snapshot(e)))?;
        Ok(ToolOutput {
            text: format!("wrote {} bytes", content.len()),
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
        File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|e| fail(io_err(&e)))?;
        self.snapshots
            .record_after(&id, &self.root)
            .map_err(|e| fail(ExecError::Snapshot(e)))?;
        Ok(ToolOutput {
            text: "deleted".into(),
            snapshot: Some(id),
        })
    }
}

/// Temp file (create_new, 0600, O_NOFOLLOW), write, final mode, sync,
/// rename over `target`, fsync the directory.
fn write_atomic(tmp: &Path, target: &Path, dir: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(tmp)?;
    f.write_all(bytes)?;
    f.set_permissions(fs::Permissions::from_mode(mode))?;
    f.sync_all()?;
    drop(f);
    fs::rename(tmp, target)?;
    File::open(dir)?.sync_all()
}

/// 8 random bytes from the OS RNG, hex-encoded.
fn random_hex() -> String {
    let mut b = [0u8; 8];
    OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A file name for display: lossy UTF-8, with `\`, control and
/// invisible/format characters escaped as `\u{..}`.
fn escape_name(name: &OsStr) -> String {
    let mut out = String::new();
    for ch in name.to_string_lossy().chars() {
        if ch == '\\' {
            out.push_str("\\\\");
        } else if is_forbidden_path_char(ch) {
            out.push_str(&format!("\\u{{{:x}}}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
}
