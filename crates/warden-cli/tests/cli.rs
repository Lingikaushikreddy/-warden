//! End-to-end tests for the `warden` binary. Each test gets its own home and root.

use assert_cmd::Command;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const PIN: &str = "zq9-secret-771";
const WRONG_PIN: &str = "wrong-pin-338";

struct Env {
    home: TempDir,
    root: TempDir,
}

impl Env {
    fn new() -> Self {
        Env {
            home: tempfile::tempdir().unwrap(),
            root: tempfile::tempdir().unwrap(),
        }
    }
    fn home(&self) -> &Path {
        self.home.path()
    }
    fn root(&self) -> &Path {
        self.root.path()
    }
    fn file(&self, name: &str) -> PathBuf {
        self.root().join(name)
    }
    fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("warden").unwrap();
        c.env_remove("WARDEN_PIN");
        c.arg("--home").arg(self.home());
        c
    }
    fn audit_path(&self) -> PathBuf {
        self.home().join("audit.jsonl")
    }
    fn audit_text(&self) -> String {
        fs::read_to_string(self.audit_path()).unwrap_or_default()
    }
    fn decisions(&self) -> Vec<String> {
        self.audit_text()
            .lines()
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                v["decision"].as_str().unwrap().to_owned()
            })
            .collect()
    }
    fn init_pin(&self) {
        self.cmd().args(["init-pin", PIN]).assert().success();
    }
}

fn stdout(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn stderr(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn classify_prints_tier() {
    let e = Env::new();
    let cases = [
        ("read", vec![e.file("a.txt")], "Auto"),
        ("write", vec![e.file("a.txt")], "Yes"),
        ("delete", vec![e.file("a.txt")], "YesPin"),
        ("message", vec![PathBuf::from("alice")], "YesPin"),
        ("email", vec![PathBuf::from("a@b.c")], "YesPin"),
        ("install", vec![PathBuf::from("pkg")], "YesPin"),
        ("format-disk", vec![], "Blocked"),
        ("registry", vec![], "Blocked"),
    ];
    for (kind, args, tier) in cases {
        let out = e
            .cmd()
            .arg("classify")
            .arg("--root")
            .arg(e.root())
            .arg(kind)
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{kind}: {}", stderr(&out));
        assert_eq!(stdout(&out), format!("{tier}\n"), "{kind}");
    }
    // A read outside the root needs Yes.
    let out = e
        .cmd()
        .args(["classify", "--root"])
        .arg(e.root())
        .args(["read", "/etc/hosts"])
        .output()
        .unwrap();
    assert_eq!(stdout(&out), "Yes\n");
}

#[test]
fn blocked_exits_3_and_is_audited() {
    let e = Env::new();
    e.init_pin();
    let out = e
        .cmd()
        .args(["run", "--root"])
        .arg(e.root())
        .args(["--yes", "--pin", PIN, "format-disk"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(stderr(&out).to_lowercase().contains("blocked"));
    let d = e.decisions();
    assert_eq!(d.last().map(String::as_str), Some("refused: blocked"));
    assert!(!d.iter().any(|x| x == "approved"));
    assert!(
        !e.home().join("snapshots").join("manifests").exists()
            || fs::read_dir(e.home().join("snapshots").join("manifests"))
                .unwrap()
                .next()
                .is_none()
    );
}

#[test]
fn delete_without_pin_exits_2_and_changes_nothing() {
    let e = Env::new();
    e.init_pin();
    let f = e.file("a.txt");
    fs::write(&f, "keep me").unwrap();
    let out = e
        .cmd()
        .args(["run", "--root"])
        .arg(e.root())
        .args(["--yes", "delete"])
        .arg(&f)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert_eq!(fs::read_to_string(&f).unwrap(), "keep me");
    assert_eq!(
        e.decisions().last().map(String::as_str),
        Some("refused: missing approval")
    );
    // Without --yes too.
    let out = e
        .cmd()
        .args(["run", "--root"])
        .arg(e.root())
        .args(["--pin", PIN, "delete"])
        .arg(&f)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(fs::read_to_string(&f).unwrap(), "keep me");
}

#[test]
fn delete_with_pin_snapshots_then_undo_restores() {
    let e = Env::new();
    e.init_pin();
    let f = e.file("a.txt");
    fs::write(&f, "precious").unwrap();
    let out = e
        .cmd()
        .env("WARDEN_PIN", PIN)
        .args(["run", "--root"])
        .arg(e.root())
        .args(["--yes", "delete"])
        .arg(&f)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(!f.exists());
    let s = stdout(&out);
    let id = s
        .lines()
        .find_map(|l| l.strip_prefix("snapshot "))
        .expect("snapshot line")
        .to_owned();
    assert_eq!(id.len(), 32);
    let d = e.decisions();
    let n = d.len();
    assert_eq!(d[n - 2], "approved");
    assert_eq!(d[n - 1], format!("executed snapshot={id}"));

    let out = e
        .cmd()
        .args(["undo", &id, "--root"])
        .arg(e.root())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(fs::read_to_string(&f).unwrap(), "precious");
    e.cmd().args(["audit", "verify"]).assert().success();
}

#[test]
fn audit_verify_detects_tampering() {
    let e = Env::new();
    for _ in 0..3 {
        e.cmd()
            .args(["run", "--root"])
            .arg(e.root())
            .arg("format-disk")
            .assert()
            .code(3);
    }
    let out = e.cmd().args(["audit", "verify"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), "ok 3\n");

    let text = e.audit_text();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    lines[1] = lines[1].replace("refused: blocked", "refused: blockeD");
    fs::write(e.audit_path(), lines.join("\n") + "\n").unwrap();
    let out = e.cmd().args(["audit", "verify"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).starts_with("broken 1: "), "{}", stdout(&out));
}

#[test]
fn audit_verify_on_empty_home_is_ok_0() {
    let e = Env::new();
    let out = e.cmd().args(["audit", "verify"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), "ok 0\n");
}

#[test]
fn write_requires_yes() {
    let e = Env::new();
    let f = e.file("w.txt");
    fs::write(&f, "old").unwrap();
    let out = e
        .cmd()
        .args(["run", "--root"])
        .arg(e.root())
        .arg("write")
        .arg(&f)
        .arg("new")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(fs::read_to_string(&f).unwrap(), "old");
    assert_eq!(
        e.decisions().last().map(String::as_str),
        Some("refused: missing approval")
    );

    let out = e
        .cmd()
        .args(["run", "--root"])
        .arg(e.root())
        .args(["--yes", "write"])
        .arg(&f)
        .arg("new")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(fs::read_to_string(&f).unwrap(), "new");
    assert!(stdout(&out).starts_with("snapshot "));
}

#[test]
fn yespin_with_no_pin_set_fails_closed() {
    let e = Env::new();
    let f = e.file("a.txt");
    fs::write(&f, "x").unwrap();
    let out = e
        .cmd()
        .args(["run", "--root"])
        .arg(e.root())
        .args(["--yes", "--pin", PIN, "delete"])
        .arg(&f)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("init-pin"), "{}", stderr(&out));
    assert!(f.exists());
    let d = e.decisions();
    assert!(d.last().unwrap().starts_with("refused: "));
    assert!(!d.iter().any(|x| x == "approved"));
}

#[test]
fn wrong_pin_exits_2_and_never_leaks_pin() {
    let e = Env::new();
    let init = e.cmd().args(["init-pin", PIN]).output().unwrap();
    assert_eq!(init.status.code(), Some(0));
    let f = e.file("a.txt");
    fs::write(&f, "x").unwrap();
    let out = e
        .cmd()
        .args(["run", "--root"])
        .arg(e.root())
        .args(["--yes", "--pin", WRONG_PIN, "delete"])
        .arg(&f)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(f.exists());
    assert_eq!(
        e.decisions().last().map(String::as_str),
        Some("refused: bad pin")
    );
    let pin_file = fs::read_to_string(e.home().join("pin")).unwrap();
    let all = format!(
        "{}{}{}{}{}",
        e.audit_text(),
        stdout(&out),
        stderr(&out),
        stdout(&init),
        stderr(&init)
    );
    for secret in [PIN, WRONG_PIN] {
        assert!(!all.contains(secret), "leaked {secret}");
    }
    for word in pin_file.split_whitespace().filter(|w| w.len() >= 32) {
        assert!(!all.contains(word), "leaked pin file material");
    }
}

#[test]
fn path_outside_root_is_refused() {
    let e = Env::new();
    let other = tempfile::tempdir().unwrap();
    let f = other.path().join("victim.txt");
    fs::write(&f, "outside").unwrap();
    let out = e
        .cmd()
        .args(["run", "--root"])
        .arg(e.root())
        .args(["--yes", "write"])
        .arg(&f)
        .arg("pwned")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert_eq!(fs::read_to_string(&f).unwrap(), "outside");
    assert_eq!(
        e.decisions().last().map(String::as_str),
        Some("refused: outside root")
    );
    // `..` escaping the root is outside too.
    let sneaky = e.root().join("..").join("escape.txt");
    let out = e
        .cmd()
        .args(["run", "--root"])
        .arg(e.root())
        .args(["--yes", "write"])
        .arg(&sneaky)
        .arg("pwned")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(!e.root().parent().unwrap().join("escape.txt").exists());
}

#[test]
fn init_pin_refuses_overwrite_without_force() {
    let e = Env::new();
    e.init_pin();
    let before = fs::read(e.home().join("pin")).unwrap();
    e.cmd().args(["init-pin", "another-pin"]).assert().code(2);
    assert_eq!(fs::read(e.home().join("pin")).unwrap(), before);
    e.cmd()
        .args(["init-pin", "--force", "another-pin"])
        .assert()
        .success();
    assert_ne!(fs::read(e.home().join("pin")).unwrap(), before);
    // The new PIN works, the old one does not.
    let f = e.file("a.txt");
    fs::write(&f, "x").unwrap();
    e.cmd()
        .args(["run", "--root"])
        .arg(e.root())
        .args(["--yes", "--pin", PIN, "delete"])
        .arg(&f)
        .assert()
        .code(2);
    e.cmd()
        .args(["run", "--root"])
        .arg(e.root())
        .args(["--yes", "--pin", "another-pin", "delete"])
        .arg(&f)
        .assert()
        .success();
    assert!(!f.exists());
}

#[test]
fn init_pin_rejects_short_pin_and_reads_env() {
    let e = Env::new();
    e.cmd().args(["init-pin", "12345"]).assert().code(2);
    assert!(!e.home().join("pin").exists());
    e.cmd()
        .env("WARDEN_PIN", PIN)
        .arg("init-pin")
        .assert()
        .success();
    assert!(e.home().join("pin").exists());
}

#[cfg(unix)]
#[test]
fn pin_file_is_0600_and_new_home_is_0700() {
    use std::os::unix::fs::PermissionsExt;
    let base = tempfile::tempdir().unwrap();
    let home = base.path().join("fresh-home");
    let mut c = Command::cargo_bin("warden").unwrap();
    c.env_remove("WARDEN_PIN")
        .arg("--home")
        .arg(&home)
        .args(["init-pin", PIN])
        .assert()
        .success();
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&home.join("pin")), 0o600);
    assert_eq!(mode(&home), 0o700);
    assert_eq!(mode(&home.join("audit.jsonl")), 0o600);
}

#[test]
fn undo_with_wrong_root_is_refused() {
    let e = Env::new();
    let f = e.file("a.txt");
    fs::write(&f, "v1").unwrap();
    let out = e
        .cmd()
        .args(["run", "--root"])
        .arg(e.root())
        .args(["--yes", "write"])
        .arg(&f)
        .arg("v2")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let id = stdout(&out)
        .lines()
        .find_map(|l| l.strip_prefix("snapshot "))
        .unwrap()
        .to_owned();
    let other = tempfile::tempdir().unwrap();
    e.cmd()
        .args(["undo", &id, "--root"])
        .arg(other.path())
        .assert()
        .code(2);
    assert_eq!(fs::read_to_string(&f).unwrap(), "v2");
    e.cmd()
        .args(["undo", &id, "--root"])
        .arg(e.root())
        .assert()
        .success();
    assert_eq!(fs::read_to_string(&f).unwrap(), "v1");
}

#[test]
fn relative_path_is_resolved_against_cwd() {
    let e = Env::new();
    let out = e
        .cmd()
        .current_dir(e.root())
        .args(["run", "--root"])
        .arg(e.root())
        .args(["--yes", "write", "rel.txt", "hello"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(fs::read_to_string(e.file("rel.txt")).unwrap(), "hello");
    let text = e.audit_text();
    let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    let summary = first["summary"].as_str().unwrap();
    assert!(summary.starts_with("write /"), "{summary}");
    assert!(summary.ends_with("rel.txt"), "{summary}");
}

#[test]
fn broken_audit_log_makes_run_refuse() {
    let e = Env::new();
    e.cmd()
        .args(["run", "--root"])
        .arg(e.root())
        .arg("format-disk")
        .assert()
        .code(3);
    let text = e
        .audit_text()
        .replace("refused: blocked", "refused: tampered");
    fs::write(e.audit_path(), &text).unwrap();
    let f = e.file("a.txt");
    fs::write(&f, "old").unwrap();
    let out = e
        .cmd()
        .args(["run", "--root"])
        .arg(e.root())
        .args(["--yes", "write"])
        .arg(&f)
        .arg("new")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("audit"), "{}", stderr(&out));
    assert_eq!(fs::read_to_string(&f).unwrap(), "old");
    assert_eq!(e.audit_text(), text, "broken log left untouched");
}

#[test]
fn audit_summary_never_contains_write_content() {
    let e = Env::new();
    let f = e.file("a.txt");
    let content = "TOP-SECRET-CONTENT-4242";
    e.cmd()
        .args(["run", "--root"])
        .arg(e.root())
        .args(["--yes", "write"])
        .arg(&f)
        .arg(content)
        .assert()
        .success();
    assert_eq!(fs::read_to_string(&f).unwrap(), content);
    assert!(!e.audit_text().contains(content));
    let first: serde_json::Value =
        serde_json::from_str(e.audit_text().lines().next().unwrap()).unwrap();
    assert_eq!(
        first["summary"].as_str().unwrap(),
        format!("write {}", f.display())
    );
}

#[test]
fn classify_only_kinds_are_not_executed() {
    let e = Env::new();
    e.init_pin();
    let out = e
        .cmd()
        .args(["run", "--root"])
        .arg(e.root())
        .arg("read")
        .arg(e.file("x"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("Auto"));
    assert!(stdout(&out).contains("not executed (classify-only in this version)"));

    e.cmd()
        .args(["run", "--root"])
        .arg(e.root())
        .args(["--yes", "email", "a@b.c"])
        .assert()
        .code(2);
    let out = e
        .cmd()
        .args(["run", "--root"])
        .arg(e.root())
        .args(["--yes", "--pin", PIN, "email", "a@b.c"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("not executed (classify-only in this version)"));
}

#[test]
fn prune_prints_count() {
    let e = Env::new();
    let out = e.cmd().args(["prune", "--days", "30"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "pruned 0\n");
}
