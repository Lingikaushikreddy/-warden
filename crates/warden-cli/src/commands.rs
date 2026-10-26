//! Command implementations. Every function returns an exit code; output goes
//! to stdout (results) and stderr (refusals and errors).
//!
//! Secrets policy: the PIN, its hash and write content never reach the audit
//! log, stdout or stderr. Audit summaries name the kind and target only.

use crate::cli::{AuditCommand, Cli, Command, Kind};
use crate::pin::{self, PinCheck, SetPinError};
use crate::{EXIT_BLOCKED, EXIT_DENIED, EXIT_ERROR, EXIT_OK};
use rand::rngs::OsRng;
use rand::RngCore;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use warden_core::{
    classify, Action, AuditLog, Capability, PolicyConfig, SnapshotError, SnapshotId, SnapshotStore,
    Tier, VerifyReport,
};

const PIN_ENV: &str = "WARDEN_PIN";
const NOT_EXECUTED: &str = "not executed (classify-only in this version)";

pub fn dispatch(cli: Cli) -> u8 {
    let home = match cli.home {
        Some(h) => absolute(&h),
        None => match std::env::var_os("HOME") {
            Some(h) => PathBuf::from(h).join(".warden"),
            None => {
                eprintln!("error: HOME is not set; pass --home <dir>");
                return EXIT_ERROR;
            }
        },
    };
    match cli.command {
        Command::Classify { root, kind, args } => cmd_classify(&root, kind, args),
        Command::Run {
            root,
            yes,
            pin,
            kind,
            args,
        } => cmd_run(&home, &root, yes, pin, kind, args),
        Command::Undo {
            snapshot_id,
            root,
            force,
        } => cmd_undo(&home, &snapshot_id, &root, force),
        Command::Audit {
            command: AuditCommand::Verify,
        } => cmd_audit_verify(&home),
        Command::Prune { days } => cmd_prune(&home, days),
        Command::InitPin { pin, force } => cmd_init_pin(&home, pin, force),
    }
}

// ---------------------------------------------------------------- helpers

/// Lexically normalize an absolute path (`.` dropped, `..` popped, never
/// above the root). Does not touch the filesystem.
fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Prefix(_) | Component::RootDir => out.push(c.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if out.components().count() > 1 {
                    out.pop();
                }
            }
            Component::Normal(s) => out.push(s),
        }
    }
    out
}

/// Resolve a relative path against the current directory, then normalize.
fn absolute(p: &Path) -> PathBuf {
    if p.is_absolute() {
        normalize(p)
    } else {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        normalize(&cwd.join(p))
    }
}

fn random_hex16() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Create the data directory `0o700` if it does not exist.
fn ensure_home(home: &Path) -> io::Result<()> {
    if home.is_dir() {
        return Ok(());
    }
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(home)
}

/// Open the audit log, failing closed: any error (including a broken log)
/// is reported and the caller must stop without changing anything.
fn open_audit(home: &Path) -> Result<AuditLog, u8> {
    if let Err(e) = ensure_home(home) {
        eprintln!("error: cannot create data dir {}: {e}", home.display());
        return Err(EXIT_ERROR);
    }
    let path = home.join("audit.jsonl");
    // Pre-create the log owner-only; warden-core would create it with the
    // default umask. An existing file is left as it is.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let _ = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path);
    }
    AuditLog::open(&path).map_err(|e| {
        eprintln!(
            "error: cannot open audit log {}: {e}\nrefusing to act without a working audit log; run `warden audit verify`",
            path.display()
        );
        EXIT_ERROR
    })
}

/// Append an audit entry; on failure report it and return the error code.
fn audit(
    log: &mut AuditLog,
    id: &str,
    summary: &str,
    tier: Tier,
    decision: &str,
) -> Result<(), u8> {
    log.append(id, summary, tier, decision)
        .map(drop)
        .map_err(|e| {
            eprintln!("error: cannot append to audit log: {e}");
            EXIT_ERROR
        })
}

/// What an action targets, after argument validation.
enum Target {
    Write { path: PathBuf, content: String },
    Delete { path: PathBuf },
    Read { path: PathBuf },
    Named(String),
    Nothing,
}

impl Target {
    fn path(&self) -> Option<&Path> {
        match self {
            Target::Write { path, .. } | Target::Delete { path } | Target::Read { path } => {
                Some(path)
            }
            _ => None,
        }
    }
}

/// Validate arguments for `kind`. `need_content` is false for `classify`,
/// which accepts `write <path>` without content.
fn parse_target(kind: Kind, args: Vec<OsString>, need_content: bool) -> Result<Target, String> {
    let n = args.len();
    let mut it = args.into_iter();
    let usage = |u: &str| Err(format!("usage: {} {u}", kind.name()));
    match kind {
        Kind::Write => {
            let ok = if need_content {
                n == 2
            } else {
                n == 1 || n == 2
            };
            if !ok {
                return usage("<path> <content>");
            }
            let path = absolute(Path::new(&it.next().unwrap_or_default()));
            let content = match it.next() {
                Some(c) => c
                    .into_string()
                    .map_err(|_| "write content must be valid UTF-8".to_owned())?,
                None => String::new(),
            };
            Ok(Target::Write { path, content })
        }
        Kind::Delete | Kind::Read => {
            if n != 1 {
                return usage("<path>");
            }
            let path = absolute(Path::new(&it.next().unwrap_or_default()));
            Ok(if kind == Kind::Delete {
                Target::Delete { path }
            } else {
                Target::Read { path }
            })
        }
        Kind::Message | Kind::Email | Kind::Install => {
            if n != 1 {
                return usage("<target>");
            }
            Ok(Target::Named(
                it.next().unwrap_or_default().to_string_lossy().into_owned(),
            ))
        }
        Kind::FormatDisk | Kind::Registry => {
            if n > 1 {
                return usage("[target]");
            }
            Ok(Target::Nothing)
        }
    }
}

fn capability(kind: Kind, target: &Target) -> Capability {
    let path = || target.path().map(Path::to_path_buf).unwrap_or_default();
    let name = || match target {
        Target::Named(s) => s.clone(),
        _ => String::new(),
    };
    match kind {
        Kind::Read => Capability::ReadPath(path()),
        Kind::Write => Capability::WritePath(path()),
        Kind::Delete => Capability::DeletePath(path()),
        Kind::Message => Capability::MessagePerson(name()),
        Kind::Email => Capability::SendEmail(name()),
        Kind::Install => Capability::InstallSoftware(name()),
        Kind::FormatDisk => Capability::FormatDisk,
        Kind::Registry => Capability::EditRegistry,
    }
}

/// Human-readable summary. Never includes write content or the PIN.
fn summary(kind: Kind, target: &Target) -> String {
    match target {
        Target::Write { path, .. } | Target::Delete { path } | Target::Read { path } => {
            format!("{} {}", kind.name(), path.display())
        }
        Target::Named(s) => format!("{} {s}", kind.name()),
        Target::Nothing => kind.name().to_owned(),
    }
}

/// The allowed roots for policy and the outside-root check: the root as
/// given (made absolute) and its canonical form, if it resolves.
fn roots(root: &Path) -> Vec<PathBuf> {
    let mut v = vec![absolute(root)];
    if let Ok(c) = fs::canonicalize(root) {
        if !v.contains(&c) {
            v.push(c);
        }
    }
    v
}

fn inside(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|r| path.starts_with(r))
}

fn build_action(kind: Kind, target: &Target) -> Action {
    Action {
        id: random_hex16(),
        summary: summary(kind, target),
        capabilities: vec![capability(kind, target)],
    }
}

// ---------------------------------------------------------------- commands

fn cmd_classify(root: &Path, kind: Kind, args: Vec<OsString>) -> u8 {
    let target = match parse_target(kind, args, false) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("error: {msg}");
            return EXIT_DENIED;
        }
    };
    let cfg = PolicyConfig {
        allowed_roots: roots(root),
    };
    println!("{:?}", classify(&build_action(kind, &target), &cfg));
    EXIT_OK
}

fn cmd_run(
    home: &Path,
    root: &Path,
    yes: bool,
    pin_flag: Option<String>,
    kind: Kind,
    args: Vec<OsString>,
) -> u8 {
    match run_inner(home, root, yes, pin_flag, kind, args) {
        Ok(code) | Err(code) => code,
    }
}

fn run_inner(
    home: &Path,
    root: &Path,
    yes: bool,
    pin_flag: Option<String>,
    kind: Kind,
    args: Vec<OsString>,
) -> Result<u8, u8> {
    let target = parse_target(kind, args, true).map_err(|msg| {
        eprintln!("error: {msg}");
        EXIT_DENIED
    })?;
    if !root.is_dir() {
        eprintln!("error: --root {} is not a directory", root.display());
        return Err(EXIT_DENIED);
    }
    let mut log = open_audit(home)?;

    let roots = roots(root);
    let action = build_action(kind, &target);
    let tier = classify(
        &action,
        &PolicyConfig {
            allowed_roots: roots.clone(),
        },
    );
    let (id, sum) = (action.id.as_str(), action.summary.as_str());
    let mut record = |decision: &str| audit(&mut log, id, sum, tier, decision);

    // 1. Blocked never runs.
    if tier == Tier::Blocked {
        record("refused: blocked")?;
        eprintln!("blocked: `{sum}` is never allowed (tier Blocked)");
        return Ok(EXIT_BLOCKED);
    }

    // 2. Approval.
    if tier >= Tier::Yes && !yes {
        record("refused: missing approval")?;
        eprintln!("refused: `{sum}` needs approval (tier {tier:?}); pass --yes");
        return Ok(EXIT_DENIED);
    }
    if tier == Tier::YesPin {
        let pin_path = home.join("pin");
        let supplied = pin_flag.or_else(|| std::env::var(PIN_ENV).ok());
        let check = match supplied {
            None if fs::symlink_metadata(&pin_path).is_err() => PinCheck::NotSet,
            None => {
                record("refused: missing approval")?;
                eprintln!(
                    "refused: `{sum}` needs --yes and a PIN (tier YesPin); set {PIN_ENV} or pass --pin"
                );
                return Ok(EXIT_DENIED);
            }
            Some(p) => match pin::check_pin(&pin_path, &p) {
                Ok(c) => c,
                Err(e) => {
                    record("failed: pin file unreadable")?;
                    eprintln!("error: cannot read PIN file {}: {e}", pin_path.display());
                    return Ok(EXIT_ERROR);
                }
            },
        };
        match check {
            PinCheck::Match => {}
            PinCheck::NotSet => {
                record("refused: no pin set")?;
                eprintln!(
                    "refused: `{sum}` needs a PIN (tier YesPin) but none is set; run `warden init-pin` first"
                );
                return Ok(EXIT_DENIED);
            }
            PinCheck::Mismatch => {
                record("refused: bad pin")?;
                eprintln!("refused: wrong PIN");
                return Ok(EXIT_DENIED);
            }
        }
    }

    // 3. Executed kinds must stay under --root.
    let executes = matches!(target, Target::Write { .. } | Target::Delete { .. });
    if executes {
        let path = target.path().unwrap_or(Path::new(""));
        if !inside(path, &roots) {
            record("refused: outside root")?;
            eprintln!(
                "refused: {} is outside --root {}",
                path.display(),
                root.display()
            );
            return Ok(EXIT_DENIED);
        }
    }

    // 4. Approved: audit before doing anything.
    record("approved")?;
    if !executes {
        record("not executed: classify-only")?;
        println!("{tier:?}");
        println!("{NOT_EXECUTED}");
        return Ok(EXIT_OK);
    }

    // 5. Snapshot, act, record after-state.
    let path = target.path().unwrap_or(Path::new("")).to_path_buf();
    let store = SnapshotStore::open(&home.join("snapshots")).map_err(|e| {
        let _ = record(&format!("failed: {:?}", e.kind()));
        eprintln!("error: cannot open snapshot store: {e}");
        EXIT_ERROR
    })?;
    let snap = match store.snapshot(std::slice::from_ref(&path), root) {
        Ok(s) => s,
        Err(SnapshotError::OutsideRoot(_)) => {
            record("refused: outside root")?;
            eprintln!("refused: {} is outside --root", path.display());
            return Ok(EXIT_DENIED);
        }
        Err(e) => {
            record(&format!("failed: snapshot {}", snapshot_err_label(&e)))?;
            eprintln!("error: snapshot failed, nothing changed: {e}");
            return Ok(EXIT_ERROR);
        }
    };

    let result = match &target {
        Target::Write { content, .. } => write_file(&path, content.as_bytes()),
        Target::Delete { .. } => fs::remove_file(&path),
        _ => unreachable!("only write and delete execute"),
    };
    if let Err(e) = result {
        record(&format!("failed: {:?}", e.kind()))?;
        eprintln!(
            "error: {} failed: {e} (snapshot {} taken before the attempt)",
            kind.name(),
            snap.0
        );
        return Ok(EXIT_ERROR);
    }
    let after = store.record_after(&snap, root);
    match after {
        Ok(()) => {
            record(&format!("executed snapshot={}", snap.0))?;
            println!("snapshot {}", snap.0);
            Ok(EXIT_OK)
        }
        Err(e) => {
            record(&format!(
                "executed snapshot={} after-state=unrecorded",
                snap.0
            ))?;
            println!("snapshot {}", snap.0);
            eprintln!(
                "warning: action done but its after-state was not recorded ({e}); undo will not detect later changes"
            );
            Ok(EXIT_ERROR)
        }
    }
}

fn snapshot_err_label(e: &SnapshotError) -> String {
    match e {
        SnapshotError::OutsideRoot(_) => "outside-root".into(),
        SnapshotError::Symlink(_) => "symlink".into(),
        SnapshotError::NotAFile(_) => "not-a-file".into(),
        SnapshotError::ChangedSinceSnapshot(_) => "changed-since-snapshot".into(),
        SnapshotError::TooLarge(_) => "too-large".into(),
        SnapshotError::CorruptBlob(_) => "corrupt-blob".into(),
        SnapshotError::CorruptManifest => "corrupt-manifest".into(),
        SnapshotError::UnknownSnapshot => "unknown-snapshot".into(),
        SnapshotError::Io(io) => format!("{:?}", io.kind()),
    }
}

fn write_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

fn cmd_undo(home: &Path, snapshot_id: &str, root: &Path, force: bool) -> u8 {
    let mut log = match open_audit(home) {
        Ok(l) => l,
        Err(c) => return c,
    };
    let id = random_hex16();
    let sum = format!("undo {snapshot_id}");
    // Keep untrusted input from bloating the log: ids are 32 hex chars.
    let sum = if snapshot_id.len() > 64 {
        "undo <invalid id>".to_owned()
    } else {
        sum
    };
    let mut record = |d: &str| audit(&mut log, &id, &sum, Tier::Yes, d);
    if let Err(c) = record("approved") {
        return c;
    }
    let store = match SnapshotStore::open(&home.join("snapshots")) {
        Ok(s) => s,
        Err(e) => {
            let _ = record(&format!("failed: {:?}", e.kind()));
            eprintln!("error: cannot open snapshot store: {e}");
            return EXIT_ERROR;
        }
    };
    let (decision, code, msg) =
        match store.restore(&SnapshotId(snapshot_id.to_owned()), root, force) {
            Ok(paths) => {
                println!("restored {}", paths.len());
                (format!("restored files={}", paths.len()), EXIT_OK, None)
            }
            Err(SnapshotError::OutsideRoot(p)) => (
                "refused: outside root".to_owned(),
                EXIT_DENIED,
                Some(format!(
                    "refused: --root does not match the snapshot's root ({})",
                    p.display()
                )),
            ),
            Err(e @ SnapshotError::ChangedSinceSnapshot(_)) => (
                "refused: changed since snapshot".to_owned(),
                EXIT_DENIED,
                Some(format!("refused: {e}; pass --force to restore anyway")),
            ),
            Err(e) => (
                format!("failed: {}", snapshot_err_label(&e)),
                EXIT_ERROR,
                Some(format!("error: undo failed: {e}")),
            ),
        };
    if let Err(c) = record(&decision) {
        return c;
    }
    if let Some(m) = msg {
        eprintln!("{m}");
    }
    code
}

fn cmd_audit_verify(home: &Path) -> u8 {
    let path = home.join("audit.jsonl");
    match AuditLog::verify(&path) {
        Ok(VerifyReport::Ok { entries }) => {
            println!("ok {entries}");
            EXIT_OK
        }
        Ok(VerifyReport::Broken {
            first_bad_index,
            reason,
        }) => {
            println!("broken {first_bad_index}: {reason}");
            EXIT_ERROR
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            println!("ok 0");
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: cannot read audit log {}: {e}", path.display());
            EXIT_ERROR
        }
    }
}

fn cmd_prune(home: &Path, days: u64) -> u8 {
    let Some(secs) = days.checked_mul(86_400) else {
        eprintln!("error: --days is too large");
        return EXIT_DENIED;
    };
    let mut log = match open_audit(home) {
        Ok(l) => l,
        Err(c) => return c,
    };
    let id = random_hex16();
    let sum = format!("prune --days {days}");
    let store = match SnapshotStore::open(&home.join("snapshots")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot open snapshot store: {e}");
            return EXIT_ERROR;
        }
    };
    match store.prune(Duration::from_secs(secs)) {
        Ok(n) => {
            if let Err(c) = audit(&mut log, &id, &sum, Tier::Auto, &format!("pruned {n}")) {
                return c;
            }
            println!("pruned {n}");
            EXIT_OK
        }
        Err(e) => {
            let _ = audit(
                &mut log,
                &id,
                &sum,
                Tier::Auto,
                &format!("failed: {:?}", e.kind()),
            );
            eprintln!("error: prune failed: {e}");
            EXIT_ERROR
        }
    }
}

fn cmd_init_pin(home: &Path, pin_arg: Option<String>, force: bool) -> u8 {
    let Some(pin) = pin_arg.or_else(|| std::env::var(PIN_ENV).ok()) else {
        eprintln!("error: give the PIN as an argument or in {PIN_ENV}");
        return EXIT_DENIED;
    };
    let mut log = match open_audit(home) {
        Ok(l) => l,
        Err(c) => return c,
    };
    let id = random_hex16();
    let decision = match pin::set_pin(&home.join("pin"), &pin, force) {
        Ok(()) => {
            println!("pin set");
            Ok("pin set")
        }
        Err(SetPinError::TooShort) => {
            eprintln!(
                "error: PIN must be at least {} characters",
                pin::MIN_PIN_LEN
            );
            Err((EXIT_DENIED, "refused: pin too short"))
        }
        Err(SetPinError::Exists) => {
            eprintln!("error: a PIN is already set; pass --force to replace it");
            Err((EXIT_DENIED, "refused: pin exists"))
        }
        Err(SetPinError::Io(e)) => {
            eprintln!("error: cannot write PIN file: {e}");
            Err((EXIT_ERROR, "failed: pin file write"))
        }
    };
    let (code, d) = match decision {
        Ok(d) => (EXIT_OK, d),
        Err((c, d)) => (c, d),
    };
    match audit(&mut log, &id, "init-pin", Tier::Auto, d) {
        Ok(()) => code,
        Err(c) => c,
    }
}
