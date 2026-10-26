//! Tests that need the `test-hooks` feature (fault injection). The feature
//! is enabled for tests through the self dev-dependency in Cargo.toml, so a
//! plain `cargo test --workspace` runs these.

use assert_cmd::Command;
use std::fs;
use std::path::Path;

const PIN: &str = "zq9-secret-771";

fn cmd(home: &Path) -> Command {
    let mut c = Command::cargo_bin("warden").unwrap();
    c.env_remove("WARDEN_PIN")
        .env_remove("WARDEN_CURRENT_PIN")
        .env_remove("WARDEN_TEST_FAIL_AUDIT_APPEND")
        .arg("--home")
        .arg(home);
    c
}

fn stdout(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn stderr(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn audit_failure_after_action_still_prints_snapshot_and_undo_works() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    cmd(home.path()).args(["init-pin", PIN]).assert().success();
    let f = root.path().join("a.txt");
    fs::write(&f, "original").unwrap();
    // Appends in `run write --yes`: 1 = approved, 2 = executed. Fail the 2nd:
    // the action has happened but its final audit record does not land.
    let out = cmd(home.path())
        .env("WARDEN_TEST_FAIL_AUDIT_APPEND", "2")
        .args(["run", "--root"])
        .arg(root.path())
        .args(["--yes", "write"])
        .arg(&f)
        .arg("changed")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(fs::read_to_string(&f).unwrap(), "changed");
    let id = stdout(&out)
        .lines()
        .find_map(|l| l.strip_prefix("snapshot "))
        .expect("snapshot id printed")
        .to_owned();
    assert!(
        stderr(&out).contains("audit append failed after the action"),
        "{}",
        stderr(&out)
    );
    assert!(stderr(&out).contains(&id));
    let out = cmd(home.path())
        .args(["undo", &id, "--root"])
        .arg(root.path())
        .args(["--yes", "--pin", PIN])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(fs::read_to_string(&f).unwrap(), "original");
}

#[test]
fn init_pin_writes_nothing_if_its_first_audit_append_fails() {
    let home = tempfile::tempdir().unwrap();
    let out = cmd(home.path())
        .env("WARDEN_TEST_FAIL_AUDIT_APPEND", "1")
        .args(["init-pin", PIN])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(!home.path().join("pin").exists());
}
