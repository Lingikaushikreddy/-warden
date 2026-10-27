//! Tests for the executor: the only agent code that touches the disk.
// Local exception to the crate's `forbid(unsafe_code)`: `libc::mkfifo`
// replaces spawning `mkfifo` (see `make_fifo`).
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use warden_agent::authorize::{ApproverStore, Authorized};
use warden_agent::exec::{ExecError, ExecFailure, Executor, ToolOutput};
use warden_agent::tools::{to_action, Tool};
use warden_core::{classify, Action, PolicyConfig, SnapshotStore, Tier};

const NOW: u64 = 1_700_000_000_000;
const TTL: u64 = 60_000;

struct Env {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    outside: PathBuf,
    snaps: PathBuf,
    cfg: PolicyConfig,
    store: ApproverStore,
    exec: Executor,
}

fn env_with(protected_in_root: bool) -> Env {
    env_custom(protected_in_root, None, |_, _| Vec::new())
}

/// `extra(tmp, root)` runs before `Executor::new` and returns more protected
/// paths. `snap_cap` sets the snapshot store's per-file size cap.
fn env_custom(
    protected_in_root: bool,
    snap_cap: Option<u64>,
    extra: impl FnOnce(&Path, &Path) -> Vec<PathBuf>,
) -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let outside = tmp.path().join("outside");
    let snaps = tmp.path().join("snaps");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&outside).unwrap();
    let home = if protected_in_root {
        root.join(".warden-home")
    } else {
        tmp.path().join("home")
    };
    let store = ApproverStore::open(&home, NOW).unwrap();
    let mut snapshots = SnapshotStore::open(&snaps).unwrap();
    if let Some(cap) = snap_cap {
        snapshots = snapshots.with_max_file_size(cap);
    }
    let mut protected = vec![home.clone(), snaps.clone()];
    protected.extend(extra(tmp.path(), &root));
    let exec = Executor::new(&root, protected, snapshots).unwrap();
    Env {
        cfg: PolicyConfig {
            allowed_roots: vec![root.clone()],
        },
        _tmp: tmp,
        root,
        outside,
        snaps,
        store,
        exec,
    }
}

fn env() -> Env {
    env_with(false)
}

impl Env {
    /// Authorize `tool` as action `id` with a real store (or `authorize_auto`).
    fn auth(&mut self, tool: &Tool, id: &str) -> (Action, Authorized) {
        let action = to_action(tool, id);
        let token = if classify(&action, &self.cfg) == Tier::Auto {
            ApproverStore::authorize_auto(&action, &self.cfg, NOW, TTL).unwrap()
        } else {
            self.store.authorize(&action, &self.cfg, NOW, TTL).unwrap()
        };
        (action, token)
    }

    fn run(&mut self, tool: Tool) -> Result<ToolOutput, ExecFailure> {
        let (action, token) = self.auth(&tool, "a1");
        self.exec.run(&action, &tool, token, NOW + 1)
    }

    fn p(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }
}

fn read(path: PathBuf, max_bytes: u64) -> Tool {
    Tool::ReadFile { path, max_bytes }
}

fn write(path: PathBuf, content: &str) -> Tool {
    Tool::WriteFile {
        path,
        content: content.into(),
    }
}

fn err(r: Result<ToolOutput, ExecFailure>) -> ExecError {
    match r {
        Ok(o) => panic!("expected an error, got output {:?}", o.text),
        Err(f) => f.error,
    }
}

/// Every file under `dir` (recursive) with its bytes or a marker.
fn tree(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd {
            let p = e.unwrap().path();
            let m = fs::symlink_metadata(&p).unwrap();
            if m.is_dir() {
                out.insert(p.clone(), b"<dir>".to_vec());
                stack.push(p);
            } else if m.file_type().is_symlink() {
                out.insert(p.clone(), b"<link>".to_vec());
            } else {
                out.insert(p.clone(), fs::read(&p).unwrap());
            }
        }
    }
    out
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

/// Root check without spawning `id` (see `make_fifo` for why tests here
/// do not spawn processes): a file we create is owned by our effective uid.
fn is_root_user() -> bool {
    use std::os::unix::fs::MetadataExt;
    let f = tempfile::NamedTempFile::new().unwrap();
    f.as_file().metadata().unwrap().uid() == 0
}

/// `mkfifo` without spawning a process: a forked child would share the open
/// file description of another test's `approver.lock` (and its `flock`) until
/// it execs, so a concurrent reopen could see `WouldBlock`.
fn make_fifo(path: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: `c` is a valid NUL-terminated path that outlives the call.
    if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn no_temp_files(dir: &Path) -> bool {
    tree(dir).keys().all(|p| {
        !p.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(".warden-tmp-")
    })
}

// ---- token checks ----

#[test]
fn token_for_other_action_is_token_mismatch() {
    let mut e = env();
    fs::write(e.p("a.txt"), "A").unwrap();
    fs::write(e.p("b.txt"), "B").unwrap();
    let ta = read(e.p("a.txt"), 10);
    let tb = read(e.p("b.txt"), 10);
    let (aa, tok) = e.auth(&ta, "a1");
    // Token for A, action and tool for B.
    let ab = to_action(&tb, "a1");
    assert!(matches!(
        err(e.exec.run(&ab, &tb, tok, NOW)),
        ExecError::TokenMismatch
    ));
    // Token and action for A, tool B.
    let (_, tok) = e.auth(&ta, "a1");
    assert!(matches!(
        err(e.exec.run(&aa, &tb, tok, NOW)),
        ExecError::TokenMismatch
    ));
    // Token for A, action A with a different id than the tool maps to.
    let (_, tok) = e.auth(&ta, "a2");
    assert!(matches!(
        err(e.exec.run(&aa, &ta, tok, NOW)),
        ExecError::TokenMismatch
    ));
}

#[test]
fn expired_token_is_refused_and_nothing_is_written() {
    let mut e = env();
    let t = write(e.p("new.txt"), "hello");
    let (a, tok) = e.auth(&t, "a1");
    let expires = tok.expires_at_ms();
    let before = (tree(&e.root), tree(&e.snaps));
    let f = e.exec.run(&a, &t, tok, expires).unwrap_err();
    assert!(matches!(f.error, ExecError::TokenExpired));
    assert!(f.snapshot.is_none());
    assert!(!e.p("new.txt").exists());
    assert_eq!(before, (tree(&e.root), tree(&e.snaps)));
}

/// Single use is enforced at compile time by the `compile_fail` doctest on
/// `Executor::run`; this only pins the by-value signature so a change to
/// `&Authorized` breaks the build here too.
#[test]
fn run_signature_takes_token_by_value() {
    let _f: fn(&Executor, &Action, &Tool, Authorized, u64) -> Result<ToolOutput, ExecFailure> =
        Executor::run;
}

#[test]
fn no_write_happens_on_token_mismatch() {
    let mut e = env();
    fs::write(e.p("keep.txt"), "original").unwrap();
    let ok = write(e.p("other.txt"), "x");
    let evil = write(e.p("keep.txt"), "overwritten");
    let (a_ok, tok) = e.auth(&ok, "a1");
    let before = (tree(&e.root), tree(&e.snaps));
    assert!(matches!(
        err(e.exec.run(&a_ok, &evil, tok, NOW)),
        ExecError::TokenMismatch
    ));
    assert_eq!(before, (tree(&e.root), tree(&e.snaps)));
}

// ---- read_file ----

#[test]
fn read_file_returns_the_whole_buffer_whatever_max_bytes_says() {
    // The cut to `max_bytes` happens in the engine, after redaction; the
    // executor never cuts inside the buffer.
    let mut e = env();
    fs::write(e.p("a.txt"), "hello world").unwrap();
    for n in [1, 5, 11, 100] {
        let out = e.run(read(e.p("a.txt"), n)).unwrap();
        assert_eq!(out.text, "hello world", "{n}");
        assert!(!out.truncated);
        assert!(out.snapshot.is_none());
    }
}

#[test]
fn read_file_reads_past_max_read_bytes_by_the_overlap_and_flags_longer_files() {
    use warden_agent::exec::{READ_BUFFER_BYTES, READ_OVERLAP_BYTES};
    use warden_agent::tools::MAX_READ_BYTES;
    assert_eq!(READ_BUFFER_BYTES, MAX_READ_BYTES + READ_OVERLAP_BYTES);
    let mut e = env();
    let exact = "y".repeat(READ_BUFFER_BYTES as usize);
    fs::write(e.p("exact.txt"), &exact).unwrap();
    let out = e.run(read(e.p("exact.txt"), 1)).unwrap();
    assert_eq!(out.text.len() as u64, READ_BUFFER_BYTES);
    assert!(!out.truncated);
    fs::write(e.p("long.txt"), format!("{exact}z")).unwrap();
    let out = e.run(read(e.p("long.txt"), MAX_READ_BYTES)).unwrap();
    assert_eq!(out.text.len() as u64, READ_BUFFER_BYTES);
    assert!(out.truncated);
}

#[test]
fn read_through_symlink_to_outside_root_is_refused() {
    let mut e = env();
    fs::write(e.outside.join("secret"), "SECRET").unwrap();
    symlink(e.outside.join("secret"), e.p("link")).unwrap();
    let r = e.run(read(e.p("link"), 100));
    match r {
        Err(f) => {
            assert!(matches!(f.error, ExecError::Symlink), "{:?}", f.error);
            assert!(!f.to_string().contains("SECRET"));
        }
        Ok(o) => panic!("read through symlink: {:?}", o.text),
    }
    // Also a symlink to a file inside the root is refused.
    fs::write(e.p("real"), "x").unwrap();
    symlink(e.p("real"), e.p("link2")).unwrap();
    assert!(matches!(
        err(e.run(read(e.p("link2"), 100))),
        ExecError::Symlink
    ));
}

#[test]
fn read_of_symlinked_parent_is_refused() {
    let mut e = env();
    fs::write(e.outside.join("secret"), "SECRET").unwrap();
    symlink(&e.outside, e.p("dir")).unwrap();
    let r = err(e.run(read(e.p("dir/secret"), 100)));
    assert!(matches!(r, ExecError::Symlink), "{r:?}");
}

#[test]
fn read_binary_file_is_lossy_not_panic() {
    let mut e = env();
    fs::write(e.p("bin"), [0xff, 0xfe, b'a', 0x00, 0xc3]).unwrap();
    let out = e.run(read(e.p("bin"), 100)).unwrap();
    assert!(out.text.contains('\u{fffd}'));
    assert!(out.text.contains('a'));
}

#[test]
fn read_fifo_is_not_a_file_and_does_not_hang() {
    let mut e = env();
    let fifo = e.p("fifo");
    make_fifo(&fifo).unwrap();
    let t = read(fifo, 100);
    let (a, tok) = e.auth(&t, "a1");
    let (tx, rx) = std::sync::mpsc::channel();
    let exec = e.exec;
    std::thread::spawn(move || {
        let r = exec.run(&a, &t, tok, NOW).map(|o| o.text);
        let _ = tx.send(r.map_err(|f| f.error));
    });
    let r = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("read of a FIFO hung");
    assert!(matches!(r, Err(ExecError::NotAFile)), "{r:?}");
}

#[test]
fn read_directory_is_not_a_file() {
    let mut e = env();
    fs::create_dir(e.p("d")).unwrap();
    assert!(matches!(
        err(e.run(read(e.p("d"), 100))),
        ExecError::NotAFile
    ));
}

// ---- list_dir ----

#[test]
fn list_dir_sorted_capped_at_500_and_escapes_names() {
    let mut e = env();
    let d = e.p("many");
    fs::create_dir(&d).unwrap();
    for i in 0..505 {
        fs::write(d.join(format!("f{i:04}")), "").unwrap();
    }
    fs::write(d.join("a\nb"), "").unwrap();
    fs::write(d.join("c\u{1b}[2Jd"), "").unwrap();
    let out = e.run(Tool::ListDir { path: d }).unwrap();
    let lines: Vec<&str> = out.text.lines().collect();
    assert_eq!(lines.len(), 501, "500 entries plus the overflow line");
    assert_eq!(lines[0], "a\\u{a}b");
    assert_eq!(lines[1], "c\\u{1b}[2Jd");
    assert_eq!(lines[2], "f0000");
    assert_eq!(lines[499], "f0497");
    assert_eq!(lines[500], "[7 more entries not shown]");
    assert!(!out.text.contains('\u{1b}'));
    let mut sorted = lines[..500].to_vec();
    sorted.sort();
    assert_eq!(sorted, lines[..500]);
}

#[test]
fn list_dir_escapes_invisible_characters() {
    let mut e = env();
    fs::write(e.p("x\u{202e}y"), "").unwrap();
    let out = e
        .run(Tool::ListDir {
            path: e.root.clone(),
        })
        .unwrap();
    assert_eq!(out.text, "x\\u{202e}y");
}

#[test]
fn list_dir_marks_directories_and_symlinks() {
    let mut e = env();
    fs::create_dir(e.p("sub")).unwrap();
    fs::write(e.p("file"), "").unwrap();
    symlink(&e.outside, e.p("link")).unwrap();
    let out = e
        .run(Tool::ListDir {
            path: e.root.clone(),
        })
        .unwrap();
    assert_eq!(out.text, "file\nlink@\nsub/");
}

#[test]
fn list_dir_of_file_is_not_a_file() {
    let mut e = env();
    fs::write(e.p("file"), "").unwrap();
    assert!(matches!(
        err(e.run(Tool::ListDir { path: e.p("file") })),
        ExecError::NotAFile
    ));
}

#[test]
fn list_dir_through_symlink_is_refused() {
    let mut e = env();
    fs::write(e.outside.join("secret"), "").unwrap();
    symlink(&e.outside, e.p("link")).unwrap();
    assert!(matches!(
        err(e.run(Tool::ListDir { path: e.p("link") })),
        ExecError::Symlink
    ));
}

// ---- write_file ----

#[test]
fn write_creates_snapshot_and_restore_undoes_it() {
    let mut e = env();
    fs::write(e.p("a.txt"), "before").unwrap();
    let out = e.run(write(e.p("a.txt"), "after!")).unwrap();
    assert_eq!(out.text, "wrote 6 bytes");
    assert_eq!(fs::read_to_string(e.p("a.txt")).unwrap(), "after!");
    let id = out.snapshot.expect("write returns a snapshot id");
    let store = SnapshotStore::open(&e.snaps).unwrap();
    store.restore(&id, &e.root, false).unwrap();
    assert_eq!(fs::read_to_string(e.p("a.txt")).unwrap(), "before");

    // A new file: the snapshot records absence, restore removes it.
    let out = e.run(write(e.p("new.txt"), "n")).unwrap();
    assert!(e.p("new.txt").exists());
    store
        .restore(&out.snapshot.unwrap(), &e.root, false)
        .unwrap();
    assert!(!e.p("new.txt").exists());
}

#[test]
fn write_new_file_is_0600() {
    let mut e = env();
    e.run(write(e.p("new.txt"), "x")).unwrap();
    assert_eq!(mode(&e.p("new.txt")), 0o600);
}

#[test]
fn write_preserves_existing_mode_masked() {
    let mut e = env();
    fs::write(e.p("a.sh"), "old").unwrap();
    fs::set_permissions(e.p("a.sh"), fs::Permissions::from_mode(0o4755)).unwrap();
    e.run(write(e.p("a.sh"), "new")).unwrap();
    assert_eq!(mode(&e.p("a.sh")), 0o755);
    fs::set_permissions(e.p("a.sh"), fs::Permissions::from_mode(0o640)).unwrap();
    e.run(write(e.p("a.sh"), "newer")).unwrap();
    assert_eq!(mode(&e.p("a.sh")), 0o640);
}

#[test]
fn write_to_hard_linked_file_is_refused() {
    let mut e = env();
    fs::write(e.outside.join("shared"), "outside").unwrap();
    fs::hard_link(e.outside.join("shared"), e.p("link")).unwrap();
    let before = tree(&e.snaps);
    let f = e.run(write(e.p("link"), "pwned")).unwrap_err();
    assert!(matches!(f.error, ExecError::HardLink), "{:?}", f.error);
    assert!(f.snapshot.is_none());
    assert_eq!(
        fs::read_to_string(e.outside.join("shared")).unwrap(),
        "outside"
    );
    assert_eq!(before, tree(&e.snaps));
}

#[test]
fn write_through_symlink_is_refused() {
    let mut e = env();
    fs::write(e.outside.join("target"), "outside").unwrap();
    symlink(e.outside.join("target"), e.p("link")).unwrap();
    assert!(matches!(
        err(e.run(write(e.p("link"), "pwned"))),
        ExecError::Symlink
    ));
    symlink(&e.outside, e.p("dirlink")).unwrap();
    assert!(matches!(
        err(e.run(write(e.p("dirlink/new"), "pwned"))),
        ExecError::Symlink
    ));
    assert_eq!(
        fs::read_to_string(e.outside.join("target")).unwrap(),
        "outside"
    );
    assert!(!e.outside.join("new").exists());
}

#[test]
fn write_to_directory_is_not_a_file() {
    let mut e = env();
    fs::create_dir(e.p("d")).unwrap();
    assert!(matches!(
        err(e.run(write(e.p("d"), "x"))),
        ExecError::NotAFile
    ));
}

#[test]
fn write_into_missing_parent_is_error_and_creates_nothing() {
    let mut e = env();
    let before = (tree(&e.root), tree(&e.snaps));
    let f = e.run(write(e.p("no/such/dir/a.txt"), "x")).unwrap_err();
    assert!(
        matches!(f.error, ExecError::Io(std::io::ErrorKind::NotFound)),
        "{:?}",
        f.error
    );
    assert!(f.snapshot.is_none());
    assert_eq!(before, (tree(&e.root), tree(&e.snaps)));
}

#[test]
fn write_failure_after_snapshot_returns_snapshot_id() {
    if is_root_user() {
        eprintln!("running as root: permissions are not enforced; skipping");
        return;
    }
    let mut e = env();
    let d = e.p("ro");
    fs::create_dir(&d).unwrap();
    fs::write(d.join("a.txt"), "original").unwrap();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o555)).unwrap();
    let r = e.run(write(d.join("a.txt"), "changed"));
    fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
    let f = r.unwrap_err();
    assert!(
        matches!(f.error, ExecError::Io(std::io::ErrorKind::PermissionDenied)),
        "{:?}",
        f.error
    );
    assert!(f.snapshot.is_some(), "the snapshot id must be reported");
    assert!(f.to_string().contains(&f.snapshot.as_ref().unwrap().0));
    assert_eq!(fs::read_to_string(d.join("a.txt")).unwrap(), "original");
    assert!(no_temp_files(&e.root));
}

#[test]
fn temp_files_are_not_left_behind() {
    let mut e = env();
    for i in 0..5 {
        e.run(write(e.p("a.txt"), &format!("v{i}"))).unwrap();
    }
    assert!(no_temp_files(&e.root));
    let names: Vec<_> = fs::read_dir(&e.root)
        .unwrap()
        .map(|x| x.unwrap().file_name())
        .collect();
    assert_eq!(names, vec![std::ffi::OsString::from("a.txt")]);
}

#[test]
fn write_too_large_is_refused() {
    let mut e = env();
    let big = "x".repeat(warden_agent::tools::MAX_WRITE_BYTES as usize + 1);
    assert!(matches!(
        err(e.run(write(e.p("big"), &big))),
        ExecError::TooLarge
    ));
    assert!(!e.p("big").exists());
}

// ---- delete_file ----

#[test]
fn delete_directory_is_not_a_file() {
    let mut e = env();
    fs::create_dir(e.p("d")).unwrap();
    let f = e.run(Tool::DeleteFile { path: e.p("d") }).unwrap_err();
    assert!(matches!(f.error, ExecError::NotAFile), "{:?}", f.error);
    assert!(f.snapshot.is_none());
    assert!(e.p("d").is_dir());
}

#[test]
fn delete_snapshots_then_removes_and_restore_brings_it_back() {
    let mut e = env();
    fs::write(e.p("a.txt"), "keep me").unwrap();
    let out = e.run(Tool::DeleteFile { path: e.p("a.txt") }).unwrap();
    assert_eq!(out.text, "deleted");
    assert!(!e.p("a.txt").exists());
    let store = SnapshotStore::open(&e.snaps).unwrap();
    store
        .restore(&out.snapshot.unwrap(), &e.root, false)
        .unwrap();
    assert_eq!(fs::read_to_string(e.p("a.txt")).unwrap(), "keep me");
}

#[test]
fn delete_symlink_and_hard_link_are_refused() {
    let mut e = env();
    fs::write(e.outside.join("t"), "x").unwrap();
    symlink(e.outside.join("t"), e.p("sl")).unwrap();
    assert!(matches!(
        err(e.run(Tool::DeleteFile { path: e.p("sl") })),
        ExecError::Symlink
    ));
    fs::hard_link(e.outside.join("t"), e.p("hl")).unwrap();
    assert!(matches!(
        err(e.run(Tool::DeleteFile { path: e.p("hl") })),
        ExecError::HardLink
    ));
    assert!(e.p("sl").exists() || fs::symlink_metadata(e.p("sl")).is_ok());
    assert!(e.p("hl").exists());
}

// ---- roots and protected paths ----

#[test]
fn path_outside_root_is_refused() {
    let mut e = env();
    fs::write(e.outside.join("x"), "x").unwrap();
    assert!(matches!(
        err(e.run(read(e.outside.join("x"), 10))),
        ExecError::OutsideRoot
    ));
    let before = tree(&e.outside);
    assert!(matches!(
        err(e.run(write(e.outside.join("x"), "pwned"))),
        ExecError::OutsideRoot
    ));
    assert!(matches!(
        err(e.run(Tool::DeleteFile {
            path: e.outside.join("x")
        })),
        ExecError::OutsideRoot
    ));
    assert_eq!(before, tree(&e.outside));
}

#[test]
fn protected_dir_is_refused_even_inside_root() {
    let mut e = env_with(true);
    let home = e.p(".warden-home");
    assert!(home.join("approver.key").exists());
    let key_before = fs::read(home.join("approver.key")).unwrap();
    assert!(matches!(
        err(e.run(read(home.join("approver.key"), 100))),
        ExecError::Protected
    ));
    assert!(matches!(
        err(e.run(Tool::ListDir { path: home.clone() })),
        ExecError::Protected
    ));
    assert!(matches!(
        err(e.run(write(home.join("approver.key"), "x"))),
        ExecError::Protected
    ));
    assert!(matches!(
        err(e.run(Tool::DeleteFile {
            path: home.join("spent-nonces")
        })),
        ExecError::Protected
    ));
    assert!(matches!(
        err(e.run(write(home.join("new"), "x"))),
        ExecError::Protected
    ));
    assert_eq!(fs::read(home.join("approver.key")).unwrap(), key_before);
    assert!(home.join("spent-nonces").exists());
    assert!(!home.join("new").exists());
}

#[test]
fn writing_the_root_itself_is_refused() {
    let mut e = env();
    let f = e.run(write(e.root.clone(), "x")).unwrap_err();
    assert!(matches!(f.error, ExecError::Protected), "{:?}", f.error);
    let f = e
        .run(Tool::DeleteFile {
            path: e.root.clone(),
        })
        .unwrap_err();
    assert!(matches!(f.error, ExecError::Protected), "{:?}", f.error);
    assert!(e.root.is_dir());
}

#[test]
fn errors_do_not_echo_file_contents() {
    const S: &str = "TOPSECRET";
    // Snapshot cap of 4 bytes so the Snapshot variant can be triggered.
    let mut e = env_custom(true, Some(4), |_, _| Vec::new());
    let home = e.p(".warden-home");
    fs::write(e.p("plain"), S).unwrap();
    fs::write(e.outside.join("s"), S).unwrap();
    fs::hard_link(e.outside.join("s"), e.p("hl")).unwrap();
    symlink(e.outside.join("s"), e.p("sl")).unwrap();
    fs::create_dir(e.p("d")).unwrap();
    fs::write(e.p("d/inner"), S).unwrap();

    let mut failures: Vec<ExecFailure> = Vec::new();
    // TokenExpired
    let t = write(e.p("plain"), S);
    let (a, tok) = e.auth(&t, "a1");
    let exp = tok.expires_at_ms();
    failures.push(e.exec.run(&a, &t, tok, exp).unwrap_err());
    // TokenMismatch
    let (a, tok) = e.auth(&t, "a1");
    failures.push(
        e.exec
            .run(&a, &write(e.p("plain"), "TOPSECRET2"), tok, NOW)
            .unwrap_err(),
    );
    // OutsideRoot, Protected, Symlink, NotAFile, TooLarge, HardLink, Snapshot, Io
    failures.push(e.run(read(e.outside.join("s"), 100)).unwrap_err());
    failures.push(e.run(write(home.join("approver.key"), S)).unwrap_err());
    failures.push(e.run(read(e.p("sl"), 100)).unwrap_err());
    failures.push(e.run(read(e.p("d"), 100)).unwrap_err());
    let big = S.repeat(200_000);
    failures.push(e.run(write(e.p("big"), &big)).unwrap_err());
    failures.push(e.run(write(e.p("hl"), S)).unwrap_err());
    failures.push(e.run(write(e.p("plain"), S)).unwrap_err());
    failures.push(e.run(write(e.p("missing/x"), S)).unwrap_err());

    let kinds: Vec<&str> = failures
        .iter()
        .map(|f| match f.error {
            ExecError::TokenExpired => "TokenExpired",
            ExecError::TokenMismatch => "TokenMismatch",
            ExecError::OutsideRoot => "OutsideRoot",
            ExecError::Protected => "Protected",
            ExecError::Symlink => "Symlink",
            ExecError::NotAFile => "NotAFile",
            ExecError::TooLarge => "TooLarge",
            ExecError::HardLink => "HardLink",
            ExecError::Snapshot(_) => "Snapshot",
            ExecError::Io(_) => "Io",
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "TokenExpired",
            "TokenMismatch",
            "OutsideRoot",
            "Protected",
            "Symlink",
            "NotAFile",
            "TooLarge",
            "HardLink",
            "Snapshot",
            "Io"
        ]
    );
    for f in &failures {
        for msg in [f.to_string(), f.error.to_string(), format!("{f:?}")] {
            assert!(!msg.contains(S), "{msg}");
        }
    }
}

// ---- review round 1: protected paths ----

/// True if `dir` on this filesystem treats `variant` as the name `real`.
fn same_entry(dir: &Path, real: &str, variant: &str) -> bool {
    fs::create_dir(dir.join(real)).unwrap();
    let ok = dir.join(variant).exists();
    fs::remove_dir(dir.join(real)).unwrap();
    ok
}

/// Protected dir `real` inside the root, created before `new()`, reached
/// through `variant`.
fn protected_variant_is_refused(real: &str, variant: &str) {
    let probe = tempfile::tempdir().unwrap();
    if !same_entry(probe.path(), real, variant) {
        eprintln!("filesystem treats {variant:?} and {real:?} as different names; skipping");
        return;
    }
    let mut e = env_custom(false, None, |_, root| {
        let p = root.join(real);
        fs::create_dir(&p).unwrap();
        fs::write(p.join("k"), "TOPSECRET").unwrap();
        vec![p]
    });
    let via = e.p(variant).join("k");
    assert!(via.exists());
    assert!(matches!(
        err(e.run(read(via.clone(), 100))),
        ExecError::Protected
    ));
    assert!(matches!(err(e.run(write(via, "x"))), ExecError::Protected));
    assert!(matches!(
        err(e.run(Tool::ListDir { path: e.p(variant) })),
        ExecError::Protected
    ));
    assert_eq!(
        fs::read_to_string(e.p(real).join("k")).unwrap(),
        "TOPSECRET"
    );
}

#[test]
fn protected_dir_case_variant_is_refused() {
    protected_variant_is_refused(".later", ".LATER");
}

#[test]
fn protected_dir_nfd_variant_is_refused() {
    protected_variant_is_refused("caf\u{e9}", "cafe\u{301}");
}

#[test]
fn protected_dir_other_prefix_spelling_is_refused() {
    // macOS: tempdirs live under /var -> /private/var. Elsewhere the
    // lexical and canonical spellings are usually identical.
    let mut e = env_with(true);
    let canon_root = fs::canonicalize(&e.root).unwrap();
    if canon_root == e.root {
        eprintln!("root has no symlinked prefix on this platform; skipping");
        return;
    }
    let canon_home = canon_root.join(".warden-home");
    for p in [
        canon_home.join("approver.key"),
        e.p(".warden-home/approver.key"),
    ] {
        assert!(matches!(err(e.run(read(p, 100))), ExecError::Protected));
    }
    // Protected given in canonical spelling, tool path lexical.
    let mut e = env_custom(false, None, |_, root| {
        let p = root.join("prot");
        fs::create_dir(&p).unwrap();
        vec![fs::canonicalize(&p).unwrap()]
    });
    fs::write(e.p("prot/k"), "x").unwrap();
    assert!(matches!(
        err(e.run(read(e.p("prot/k"), 100))),
        ExecError::Protected
    ));
}

#[test]
fn protected_dir_removed_and_recreated_is_still_refused() {
    let mut e = env_custom(false, None, |_, root| {
        let p = root.join("prot");
        fs::create_dir(&p).unwrap();
        vec![p]
    });
    fs::remove_dir(e.p("prot")).unwrap();
    fs::create_dir(e.p("prot")).unwrap();
    fs::write(e.p("prot/k"), "TOPSECRET").unwrap();
    assert!(matches!(
        err(e.run(read(e.p("prot/k"), 100))),
        ExecError::Protected
    ));
    assert!(matches!(
        err(e.run(write(e.p("prot/new"), "x"))),
        ExecError::Protected
    ));
    assert!(!e.p("prot/new").exists());
}

#[test]
fn protected_path_is_re_resolved_at_check_time() {
    // The protected path is given through an alias outside the root. After
    // `new()` the alias is pointed at another directory inside the root: the
    // name it now denotes must be protected (resolved per call), not only
    // what it denoted when `new()` ran.
    let mut e = env_custom(false, None, |tmp, root| {
        fs::create_dir_all(root.join("one/prot")).unwrap();
        fs::create_dir_all(root.join("two/prot")).unwrap();
        symlink(root.join("one"), tmp.join("alias")).unwrap();
        vec![tmp.join("alias/prot")]
    });
    let alias = e._tmp.path().join("alias");
    fs::remove_file(&alias).unwrap();
    symlink(e.p("two"), &alias).unwrap();
    fs::write(e.p("two/prot/k"), "TOPSECRET").unwrap();
    assert!(matches!(
        err(e.run(read(e.p("two/prot/k"), 100))),
        ExecError::Protected
    ));
}

#[test]
fn new_with_missing_protected_path_is_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    fs::create_dir(&root).unwrap();
    let snaps = SnapshotStore::open(&tmp.path().join("snaps")).unwrap();
    let r = Executor::new(&root, vec![root.join(".not-yet")], snaps);
    assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::NotFound);
}

// ---- review round 1: cleanup and rename failures (test hooks) ----

#[test]
fn write_is_atomic_when_rename_target_is_a_directory() {
    let mut e = env();
    fs::write(e.p("a.txt"), "original").unwrap();
    e.exec
        .before_rename_hook_for_test(Box::new(|target: &Path| {
            fs::remove_file(target).unwrap();
            fs::create_dir(target).unwrap();
            fs::write(target.join("inside"), "keep").unwrap();
        }));
    let f = e.run(write(e.p("a.txt"), "changed")).unwrap_err();
    assert!(matches!(f.error, ExecError::Io(_)), "{:?}", f.error);
    assert!(f.snapshot.is_some(), "snapshot id must be reported");
    assert!(e.p("a.txt").is_dir());
    assert_eq!(fs::read_to_string(e.p("a.txt/inside")).unwrap(), "keep");
    assert!(no_temp_files(&e.root));
}

#[test]
fn failure_during_write_leaves_no_temp_file() {
    let mut e = env();
    fs::write(e.p("a.txt"), "original").unwrap();
    e.exec.fail_write_after_for_test(3);
    let f = e.run(write(e.p("a.txt"), "changed content")).unwrap_err();
    assert!(matches!(f.error, ExecError::Io(_)), "{:?}", f.error);
    assert!(f.snapshot.is_some());
    assert_eq!(fs::read_to_string(e.p("a.txt")).unwrap(), "original");
    assert!(no_temp_files(&e.root));
    // The hook fires once; the next write goes through.
    e.run(write(e.p("a.txt"), "ok")).unwrap();
    assert_eq!(fs::read_to_string(e.p("a.txt")).unwrap(), "ok");
}

#[test]
fn directory_sync_failure_after_rename_is_success_with_warning() {
    let mut e = env();
    e.exec.fail_dir_sync_for_test();
    let out = e.run(write(e.p("a.txt"), "abc")).unwrap();
    assert_eq!(out.text, "wrote 3 bytes (directory sync failed)");
    assert_eq!(fs::read_to_string(e.p("a.txt")).unwrap(), "abc");
    // record_after ran: restore with force=false succeeds (after-state known).
    let store = SnapshotStore::open(&e.snaps).unwrap();
    store
        .restore(&out.snapshot.unwrap(), &e.root, false)
        .unwrap();
    assert!(!e.p("a.txt").exists());
}

// ---- review round 1: listing ambiguity ----

#[test]
fn list_dir_escapes_trailing_at_and_leading_bracket() {
    let mut e = env();
    fs::write(e.p("x@"), "").unwrap();
    fs::write(e.p("[3 more entries not shown]"), "").unwrap();
    fs::write(e.p("a[b@c"), "").unwrap();
    let out = e
        .run(Tool::ListDir {
            path: e.root.clone(),
        })
        .unwrap();
    assert_eq!(
        out.text,
        "\\u{5b}3 more entries not shown]\na[b@c\nx\\u{40}"
    );
}
