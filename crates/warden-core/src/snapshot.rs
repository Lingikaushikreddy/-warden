//! Content-addressed snapshots of files and a guarded restore.
//!
//! # Layout
//!
//! ```text
//! <store>/lock                   advisory lock held by every operation
//! <store>/blobs/<sha256>         file bytes, named by lowercase hex sha256
//! <store>/manifests/<id>.json    one manifest per snapshot
//! ```
//!
//! A [`SnapshotId`] is 32 lowercase hex characters (16 bytes from the OS
//! RNG). Ids and blob names are validated before they are used as file
//! names, so a tampered manifest or an id like `../x` cannot leave the
//! store directory.
//!
//! # Snapshot
//!
//! [`SnapshotStore::snapshot`] canonicalizes `allowed_root` once and
//! records that canonical root in the manifest. Each path must be
//! absolute, free of `..`, and lexically under either the given or the
//! canonical root. Every parent directory between the root and the file is
//! checked with `symlink_metadata`; a symlinked parent or target is
//! [`SnapshotError::Symlink`], a directory or other non-regular file is
//! [`SnapshotError::NotAFile`]. A path that does not exist (including one
//! whose parent directory does not exist) is recorded with `existed:
//! false`. Files larger than the store's cap
//! ([`SnapshotStore::DEFAULT_MAX_FILE_SIZE`] by default) are
//! [`SnapshotError::TooLarge`]. Unix permission bits are recorded.
//!
//! # Restore
//!
//! The manifest on disk is untrusted. [`SnapshotStore::restore`] runs in
//! two phases:
//!
//! 1. Verify, touching nothing: the recorded root must still canonicalize
//!    to itself; every entry path must be absolute, contain only normal
//!    components below the root, and have no symlinked parent or target;
//!    every blob must hash to its name; and, if
//!    [`SnapshotStore::record_after`] was called and `force` is false,
//!    every file's current state must equal its recorded after-state
//!    (otherwise [`SnapshotError::ChangedSinceSnapshot`]).
//! 2. Apply: each file that existed is written to a temp file in its own
//!    directory (re-hashed while copying), given its recorded mode,
//!    fsynced and renamed over the target; each file that did not exist is
//!    removed if present. Missing parent directories are recreated.
//!
//! If `record_after` was never called, restore skips the changed-since
//! check.
//!
//! # Known limits
//!
//! - **TOCTOU.** Every symlink check is `symlink_metadata` followed later
//!   by use of the path. The crate forbids `unsafe` and has no `libc`
//!   dependency, so it cannot open with `O_NOFOLLOW` or use `openat`-style
//!   directory handles. Reads compare the `(dev, ino)` of the opened file
//!   with the earlier `symlink_metadata`, which detects a target swapped for
//!   a symlink between check and open. Writes go to a fresh `create_new`
//!   temp file and are moved into place with `rename`, which replaces a
//!   final-component symlink instead of following it. What remains open:
//!   a process that can write inside the root can swap a *parent*
//!   directory for a symlink between the check and the temp-file create
//!   or rename, and so redirect one write outside the root; and a target
//!   swapped for a FIFO between check and open can block a read.
//! - **Manifests are unauthenticated.** Anyone who can write the store
//!   directory can edit a manifest, including its recorded root, and so
//!   direct restore to any regular-file path the process can write (still
//!   no `..`, no symlinks, blob hashes verified). Keep the store directory
//!   writable only by the Warden process.
//! - **Apply is not transactional.** Phase 1 catches every condition this
//!   module can check; an I/O error in phase 2 (disk full, a racing
//!   writer) can still leave earlier entries restored and later ones not.
//! - **Locking is advisory** (`File::lock` on `<store>/lock`): it orders
//!   cooperating Warden processes, so `prune` never runs between a
//!   snapshot's blob writes and its manifest write. It does not stop other
//!   programs.
//! - Paths are stored as JSON strings; a non-UTF-8 path fails the snapshot
//!   with an `InvalidData` I/O error rather than being stored lossily.

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MANIFEST_VERSION: u32 = 1;
const TMP_PREFIX: &str = "tmp-";

/// Identifier of one snapshot: 32 lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotId(pub String);

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("path is outside the allowed root: {0}")]
    OutsideRoot(PathBuf),
    #[error("refusing to follow symlink: {0}")]
    Symlink(PathBuf),
    #[error("not a regular file: {0}")]
    NotAFile(PathBuf),
    #[error("file changed since the snapshot's recorded after-state: {0}")]
    ChangedSinceSnapshot(PathBuf),
    #[error("file exceeds the snapshot size cap: {0}")]
    TooLarge(PathBuf),
    #[error("blob is missing or does not match its hash: {0}")]
    CorruptBlob(String),
    #[error("snapshot manifest is malformed")]
    CorruptManifest,
    #[error("unknown snapshot")]
    UnknownSnapshot,
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum FileState {
    Absent,
    Present { sha256: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: PathBuf,
    existed: bool,
    sha256: Option<String>,
    mode: Option<u32>,
    after: Option<FileState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    id: String,
    created_unix_ms: u64,
    allowed_root: PathBuf,
    after_recorded: bool,
    entries: Vec<Entry>,
}

/// A directory of content-addressed blobs and snapshot manifests.
#[derive(Debug)]
pub struct SnapshotStore {
    dir: PathBuf,
    max_file_size: u64,
}

impl SnapshotStore {
    /// Default per-file size cap: 512 MiB.
    pub const DEFAULT_MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;

    /// Opens (creating if needed) a store rooted at `dir`.
    pub fn open(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir.join("blobs"))?;
        fs::create_dir_all(dir.join("manifests"))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            max_file_size: Self::DEFAULT_MAX_FILE_SIZE,
        })
    }

    /// Sets the per-file size cap in bytes.
    pub fn with_max_file_size(mut self, bytes: u64) -> Self {
        self.max_file_size = bytes;
        self
    }

    fn blobs_dir(&self) -> PathBuf {
        self.dir.join("blobs")
    }

    fn manifests_dir(&self) -> PathBuf {
        self.dir.join("manifests")
    }

    fn manifest_path(&self, id: &SnapshotId) -> Result<PathBuf, SnapshotError> {
        if !is_lower_hex(&id.0, 32) {
            return Err(SnapshotError::UnknownSnapshot);
        }
        Ok(self.manifests_dir().join(format!("{}.json", id.0)))
    }

    fn lock(&self) -> io::Result<File> {
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.dir.join("lock"))?;
        f.lock()?;
        Ok(f)
    }

    /// Records the current bytes of each path under `allowed_root`.
    pub fn snapshot(
        &self,
        paths: &[PathBuf],
        allowed_root: &Path,
    ) -> Result<SnapshotId, SnapshotError> {
        let _lock = self.lock()?;
        let root = fs::canonicalize(allowed_root)?;
        if !fs::symlink_metadata(&root)?.is_dir() {
            return Err(SnapshotError::NotAFile(root));
        }
        let mut entries = Vec::with_capacity(paths.len());
        for p in paths {
            if !p.is_absolute() {
                return Err(SnapshotError::OutsideRoot(p.clone()));
            }
            let rel = normal_rel(p, allowed_root)
                .or_else(|| normal_rel(p, &root))
                .ok_or_else(|| SnapshotError::OutsideRoot(p.clone()))?;
            let full = root.join(&rel);
            let state = match check_parents(&root, &rel)? {
                Parents::Missing => None,
                Parents::Present => self.store_blob(&full)?,
            };
            entries.push(match state {
                None => Entry {
                    path: full,
                    existed: false,
                    sha256: None,
                    mode: None,
                    after: None,
                },
                Some((hash, mode)) => Entry {
                    path: full,
                    existed: true,
                    sha256: Some(hash),
                    mode,
                    after: None,
                },
            });
        }
        let id = SnapshotId(random_hex(16));
        let manifest = Manifest {
            version: MANIFEST_VERSION,
            id: id.0.clone(),
            created_unix_ms: now_ms(),
            allowed_root: root,
            after_recorded: false,
            entries,
        };
        self.write_manifest(&id, &manifest)?;
        Ok(id)
    }

    /// Copies `full` into a blob. Returns `None` if the file does not exist.
    fn store_blob(&self, full: &Path) -> Result<Option<(String, Option<u32>)>, SnapshotError> {
        let tmp = self
            .blobs_dir()
            .join(format!("{TMP_PREFIX}{}", random_hex(16)));
        let mut out = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        let result = read_regular(full, &mut out, Some(self.max_file_size)).and_then(|r| {
            if r.is_some() {
                out.sync_all()?;
            }
            Ok(r)
        });
        drop(out);
        match result {
            Ok(Some((hash, mode))) => {
                fs::rename(&tmp, self.blobs_dir().join(&hash))?;
                sync_dir(&self.blobs_dir())?;
                Ok(Some((hash, mode)))
            }
            Ok(None) => {
                let _ = fs::remove_file(&tmp);
                Ok(None)
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                Err(e)
            }
        }
    }

    fn write_manifest(&self, id: &SnapshotId, m: &Manifest) -> Result<(), SnapshotError> {
        let final_path = self.manifest_path(id)?;
        let bytes = serde_json::to_vec_pretty(m)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let tmp = self
            .manifests_dir()
            .join(format!("{TMP_PREFIX}{}", random_hex(16)));
        let res = (|| -> io::Result<()> {
            let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            drop(f);
            fs::rename(&tmp, &final_path)?;
            sync_dir(&self.manifests_dir())
        })();
        if res.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        Ok(res?)
    }

    fn load_manifest(&self, id: &SnapshotId) -> Result<Manifest, SnapshotError> {
        let path = self.manifest_path(id)?;
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(SnapshotError::UnknownSnapshot)
            }
            Err(e) => return Err(e.into()),
        };
        let m: Manifest =
            serde_json::from_slice(&bytes).map_err(|_| SnapshotError::CorruptManifest)?;
        if m.id != id.0 {
            return Err(SnapshotError::CorruptManifest);
        }
        Ok(m)
    }

    /// Records each file's state after the change, for the changed-since
    /// check in [`SnapshotStore::restore`]. A missing file is recorded as
    /// absent.
    pub fn record_after(&self, id: &SnapshotId) -> Result<(), SnapshotError> {
        let _lock = self.lock()?;
        let mut m = self.load_manifest(id)?;
        let (root, rels) = validate_manifest(&m)?;
        for (entry, rel) in m.entries.iter_mut().zip(rels) {
            entry.after = Some(current_state(&root, &rel)?);
        }
        m.after_recorded = true;
        self.write_manifest(id, &m)
    }

    /// Writes every recorded file back and removes files recorded as
    /// absent. Returns the paths written or removed.
    pub fn restore(&self, id: &SnapshotId, force: bool) -> Result<Vec<PathBuf>, SnapshotError> {
        let _lock = self.lock()?;
        let m = self.load_manifest(id)?;
        let (root, rels) = validate_manifest(&m)?;

        // Phase 1: verify everything before touching the filesystem.
        for (entry, rel) in m.entries.iter().zip(&rels) {
            let full = root.join(rel);
            if let Parents::Present = check_parents(&root, rel)? {
                check_target(&full)?;
            }
            if m.after_recorded && !force {
                let after = entry.after.as_ref().ok_or(SnapshotError::CorruptManifest)?;
                if &current_state(&root, rel)? != after {
                    return Err(SnapshotError::ChangedSinceSnapshot(full));
                }
            }
            if let Some(hash) = &entry.sha256 {
                self.verify_blob(hash)?;
            }
        }

        // Phase 2: apply.
        let mut touched = Vec::new();
        for (entry, rel) in m.entries.iter().zip(&rels) {
            let full = root.join(rel);
            match &entry.sha256 {
                Some(hash) => {
                    ensure_parents(&root, rel)?;
                    self.write_back(&full, hash, entry.mode)?;
                    touched.push(full);
                }
                None => {
                    if let Parents::Missing = check_parents(&root, rel)? {
                        continue;
                    }
                    if check_target(&full)? {
                        fs::remove_file(&full)?;
                        if let Some(parent) = full.parent() {
                            sync_dir(parent)?;
                        }
                        touched.push(full);
                    }
                }
            }
        }
        Ok(touched)
    }

    fn open_blob(&self, hash: &str) -> Result<File, SnapshotError> {
        // `hash` was validated as 64 lowercase hex by validate_manifest.
        let path = self.blobs_dir().join(hash);
        let corrupt = || SnapshotError::CorruptBlob(hash.to_string());
        let meta = fs::symlink_metadata(&path).map_err(|_| corrupt())?;
        if !meta.is_file() {
            return Err(corrupt());
        }
        File::open(&path).map_err(|_| corrupt())
    }

    fn verify_blob(&self, hash: &str) -> Result<(), SnapshotError> {
        let f = self.open_blob(hash)?;
        let (got, _) = copy_hashing(f, &mut io::sink(), None, Path::new(hash))?;
        if got != hash {
            return Err(SnapshotError::CorruptBlob(hash.to_string()));
        }
        Ok(())
    }

    fn write_back(&self, full: &Path, hash: &str, mode: Option<u32>) -> Result<(), SnapshotError> {
        let parent = full.parent().ok_or(SnapshotError::CorruptManifest)?;
        let name = full
            .file_name()
            .ok_or(SnapshotError::CorruptManifest)?
            .to_string_lossy();
        let tmp = parent.join(format!(".{name}.warden-restore-{}", random_hex(8)));
        // create_new = O_CREAT|O_EXCL: never opens an existing file or link.
        let mut out = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        let res = (|| -> Result<(), SnapshotError> {
            let blob = self.open_blob(hash)?;
            let (got, _) = copy_hashing(blob, &mut out, None, full)?;
            if got != hash {
                return Err(SnapshotError::CorruptBlob(hash.to_string()));
            }
            set_mode(&out, mode)?;
            out.sync_all()?;
            // Re-check right before the rename; rename itself replaces a
            // final-component symlink rather than following it.
            check_target(full)?;
            fs::rename(&tmp, full)?;
            sync_dir(parent)?;
            Ok(())
        })();
        drop(out);
        if res.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        res
    }

    /// Deletes manifests whose recorded `created_unix_ms` is older than
    /// `older_than`, then blobs that no remaining manifest references.
    /// Returns the number of manifests deleted.
    ///
    /// Every manifest is parsed before anything is deleted; if any fails to
    /// parse, nothing is deleted and an `InvalidData` error is returned.
    pub fn prune(&self, older_than: Duration) -> io::Result<usize> {
        let _lock = self.lock()?;
        let corrupt = |name: &str| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("corrupt snapshot manifest {name}; nothing pruned"),
            )
        };
        let mut manifests = Vec::new();
        let mut stale_tmp = Vec::new();
        for dirent in fs::read_dir(self.manifests_dir())? {
            let dirent = dirent?;
            let name = dirent.file_name().to_string_lossy().into_owned();
            if name.starts_with(TMP_PREFIX) {
                stale_tmp.push(dirent.path());
                continue;
            }
            let Some(stem) = name.strip_suffix(".json") else {
                continue;
            };
            if !is_lower_hex(stem, 32) {
                continue;
            }
            let m: Manifest =
                serde_json::from_slice(&fs::read(dirent.path())?).map_err(|_| corrupt(&name))?;
            if m.id != stem || m.entries.iter().any(|e| !entry_hashes_valid(e)) {
                return Err(corrupt(&name));
            }
            manifests.push((dirent.path(), m));
        }

        let older_ms = u64::try_from(older_than.as_millis()).unwrap_or(u64::MAX);
        let cutoff = now_ms().saturating_sub(older_ms);
        let mut removed = 0;
        let mut referenced = HashSet::new();
        for (path, m) in manifests {
            if m.created_unix_ms < cutoff {
                fs::remove_file(&path)?;
                removed += 1;
            } else {
                referenced.extend(m.entries.into_iter().filter_map(|e| e.sha256));
            }
        }
        sync_dir(&self.manifests_dir())?;

        for dirent in fs::read_dir(self.blobs_dir())? {
            let dirent = dirent?;
            let name = dirent.file_name().to_string_lossy().into_owned();
            let orphan = is_lower_hex(&name, 64) && !referenced.contains(&name);
            // The lock excludes concurrent snapshots, so temp files are
            // leftovers from a crashed run.
            if orphan || name.starts_with(TMP_PREFIX) {
                fs::remove_file(dirent.path())?;
            }
        }
        for p in stale_tmp {
            fs::remove_file(p)?;
        }
        Ok(removed)
    }
}

enum Parents {
    Present,
    Missing,
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn entry_hashes_valid(e: &Entry) -> bool {
    let blob_ok = match (&e.sha256, e.existed) {
        (Some(h), true) => is_lower_hex(h, 64),
        (None, false) => true,
        _ => false,
    };
    let after_ok = match &e.after {
        Some(FileState::Present { sha256 }) => is_lower_hex(sha256, 64),
        _ => true,
    };
    blob_ok && after_ok
}

/// `path` relative to `root`, if `path` is strictly below `root` and the
/// remainder has only normal components.
fn normal_rel(path: &Path, root: &Path) -> Option<PathBuf> {
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return None;
    }
    let rel = path.strip_prefix(root).ok()?;
    let mut out = PathBuf::new();
    for c in rel.components() {
        match c {
            Component::Normal(n) => out.push(n),
            _ => return None,
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Checks the manifest's root and every entry; returns the root and each
/// entry's path relative to it.
fn validate_manifest(m: &Manifest) -> Result<(PathBuf, Vec<PathBuf>), SnapshotError> {
    if m.version != MANIFEST_VERSION {
        return Err(SnapshotError::CorruptManifest);
    }
    let root = &m.allowed_root;
    let root_is_plain = root.is_absolute()
        && root.components().all(|c| {
            matches!(
                c,
                Component::RootDir | Component::Prefix(_) | Component::Normal(_)
            )
        });
    if !root_is_plain {
        return Err(SnapshotError::OutsideRoot(root.clone()));
    }
    let mut rels = Vec::with_capacity(m.entries.len());
    for e in &m.entries {
        if !e.path.is_absolute() {
            return Err(SnapshotError::OutsideRoot(e.path.clone()));
        }
        let rel =
            normal_rel(&e.path, root).ok_or_else(|| SnapshotError::OutsideRoot(e.path.clone()))?;
        if !entry_hashes_valid(e) || (m.after_recorded && e.after.is_none()) {
            return Err(SnapshotError::CorruptManifest);
        }
        rels.push(rel);
    }
    // The root itself must not have become a symlink (or moved).
    if fs::canonicalize(root)? != *root {
        return Err(SnapshotError::Symlink(root.clone()));
    }
    Ok((root.clone(), rels))
}

/// Walks the directories between `root` and the final component of `rel`
/// without following symlinks.
fn check_parents(root: &Path, rel: &Path) -> Result<Parents, SnapshotError> {
    let mut cur = root.to_path_buf();
    let Some(parent) = rel.parent() else {
        return Ok(Parents::Present);
    };
    for c in parent.components() {
        cur.push(c);
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => return Err(SnapshotError::Symlink(cur)),
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(SnapshotError::NotAFile(cur)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Parents::Missing),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(Parents::Present)
}

/// Creates missing parent directories one at a time, refusing symlinks.
fn ensure_parents(root: &Path, rel: &Path) -> Result<(), SnapshotError> {
    let mut cur = root.to_path_buf();
    let Some(parent) = rel.parent() else {
        return Ok(());
    };
    for c in parent.components() {
        cur.push(c);
        match fs::create_dir(&cur) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let m = fs::symlink_metadata(&cur)?;
        if m.file_type().is_symlink() {
            return Err(SnapshotError::Symlink(cur));
        }
        if !m.is_dir() {
            return Err(SnapshotError::NotAFile(cur));
        }
    }
    Ok(())
}

/// Returns whether a regular file exists at `full`; errors for a symlink,
/// directory or other non-regular file.
fn check_target(full: &Path) -> Result<bool, SnapshotError> {
    match fs::symlink_metadata(full) {
        Ok(m) if m.file_type().is_symlink() => Err(SnapshotError::Symlink(full.to_path_buf())),
        Ok(m) if m.is_file() => Ok(true),
        Ok(_) => Err(SnapshotError::NotAFile(full.to_path_buf())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn current_state(root: &Path, rel: &Path) -> Result<FileState, SnapshotError> {
    if let Parents::Missing = check_parents(root, rel)? {
        return Ok(FileState::Absent);
    }
    Ok(
        match read_regular(&root.join(rel), &mut io::sink(), None)? {
            None => FileState::Absent,
            Some((sha256, _)) => FileState::Present { sha256 },
        },
    )
}

/// Streams a regular file into `sink` without following a final symlink.
/// Returns `None` if the file does not exist.
fn read_regular(
    path: &Path,
    sink: &mut dyn Write,
    cap: Option<u64>,
) -> Result<Option<(String, Option<u32>)>, SnapshotError> {
    let lmeta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if lmeta.file_type().is_symlink() {
        return Err(SnapshotError::Symlink(path.to_path_buf()));
    }
    if !lmeta.is_file() {
        return Err(SnapshotError::NotAFile(path.to_path_buf()));
    }
    if cap.is_some_and(|c| lmeta.len() > c) {
        return Err(SnapshotError::TooLarge(path.to_path_buf()));
    }
    let file = File::open(path)?;
    let fmeta = file.metadata()?;
    // Detect a swap between the symlink_metadata check and the open.
    if !same_file(&lmeta, &fmeta) {
        return Err(SnapshotError::Symlink(path.to_path_buf()));
    }
    let (hash, _) = copy_hashing(file, sink, cap, path)?;
    Ok(Some((hash, mode_of(&fmeta))))
}

fn copy_hashing(
    mut r: impl Read,
    w: &mut dyn Write,
    cap: Option<u64>,
    path: &Path,
) -> Result<(String, u64), SnapshotError> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        total += n as u64;
        if cap.is_some_and(|c| total > c) {
            return Err(SnapshotError::TooLarge(path.to_path_buf()));
        }
        hasher.update(&buf[..n]);
        w.write_all(&buf[..n])?;
    }
    Ok((hex::encode(hasher.finalize()), total))
}

#[cfg(unix)]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(_a: &fs::Metadata, b: &fs::Metadata) -> bool {
    b.is_file()
}

#[cfg(unix)]
fn mode_of(m: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(m.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn mode_of(_m: &fs::Metadata) -> Option<u32> {
    None
}

#[cfg(unix)]
fn set_mode(f: &File, mode: Option<u32>) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    match mode {
        Some(m) => f.set_permissions(fs::Permissions::from_mode(m & 0o7777)),
        None => Ok(()),
    }
}

#[cfg(not(unix))]
fn set_mode(_f: &File, _mode: Option<u32>) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

fn random_hex(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
