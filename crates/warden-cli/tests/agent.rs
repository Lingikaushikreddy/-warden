//! End-to-end tests for `warden agent`. They need the `test-hooks` feature
//! (the scripted planner, `provider = "mock"`), which the self
//! dev-dependency turns on, so a plain `cargo test --workspace` runs them.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};

use assert_cmd::Command;
use serde_json::{json, Value};

const KEY_VAR: &str = "ANTHROPIC_API_KEY";
const FAKE_KEY: &str = "sk-ant-testkey-Zx9QwErTyUiOp1234567890AbCdEf";

struct Env {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    home: PathBuf,
    root: PathBuf,
}

impl Env {
    /// `<tmp>/home` (0700) and `<tmp>/root`, canonical.
    fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let home = base.join("home");
        let root = base.join("root");
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&root).unwrap();
        Env {
            _tmp: tmp,
            base,
            home,
            root,
        }
    }

    fn config(&self, body: &str) {
        let p = self.home.join("config.toml");
        fs::write(&p, body).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// A mock-provider config for `root` with `script` as the planner.
    fn mock(&self, root: &Path, script: Value) {
        let s = self.base.join("script.json");
        fs::write(&s, serde_json::to_vec(&script).unwrap()).unwrap();
        self.config(&format!(
            "root = \"{}\"\nprovider = \"mock\"\nscript = \"{}\"\n",
            root.display(),
            s.display()
        ));
    }

    fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("warden").unwrap();
        c.env_remove(KEY_VAR)
            .env_remove("WARDEN_PIN")
            .env_remove("WARDEN_TEST_FAIL_AUDIT_APPEND")
            .current_dir(&self.root)
            .arg("--home")
            .arg(&self.home)
            .arg("agent");
        c
    }

    fn audit_text(&self) -> String {
        fs::read_to_string(self.home.join("audit.jsonl")).unwrap_or_default()
    }

    fn entries(&self) -> Vec<Value> {
        self.audit_text()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn decisions(&self) -> Vec<String> {
        self.entries()
            .iter()
            .map(|v| v["decision"].as_str().unwrap().to_owned())
            .collect()
    }
}

fn out(o: &std::process::Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

fn write_script(path: &str, content: &str) -> Value {
    json!([
        {"text": "updating", "calls": [
            {"id": "t1", "name": "write_file", "args": {"path": path, "content": content}}
        ]},
        {"text": "all done"}
    ])
}

#[test]
fn agent_runs_a_scripted_conversation_on_stdio() {
    let e = Env::new();
    fs::write(e.root.join("a.txt"), "hello from a").unwrap();
    e.mock(
        &e.root,
        json!([
            {"text": "reading", "calls": [
                {"id": "t1", "name": "read_file", "args": {"path": "a.txt"}}
            ]},
            {"text": "the file says hello"}
        ]),
    );
    let o = e.cmd().write_stdin("what is in a.txt?\n").output().unwrap();
    let (so, se) = out(&o);
    assert_eq!(o.status.code(), Some(0), "{so}\n{se}");
    assert!(so.contains("done: read \""), "{so}");
    assert!(so.contains("the file says hello"), "{so}");
    assert!(
        se.contains(&format!(
            "warden agent: owner=local root={}",
            e.root.display()
        )),
        "{se}"
    );
    let d = e.decisions();
    assert!(d.contains(&"approved auto".to_string()), "{d:?}");
    assert!(d.contains(&"executed".to_string()), "{d:?}");
    // File content never reaches the audit log.
    assert!(!e.audit_text().contains("hello from a"));
}

/// Spawn the agent with piped stdio, send `first`, wait for the approval
/// prompt, answer with `answer(code)`, close stdin and collect the output.
fn answer_prompt(e: &Env, first: &str, answer: impl Fn(&str) -> String) -> (i32, String) {
    let re = regex::Regex::new(r#"Reply "yes (\d{4})"#).unwrap();
    let mut child = StdCommand::new(assert_cmd::cargo::cargo_bin("warden"))
        .env_remove(KEY_VAR)
        .env_remove("WARDEN_PIN")
        .current_dir(&e.root)
        .arg("--home")
        .arg(&e.home)
        .arg("agent")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(first.as_bytes()).unwrap();
    stdin.flush().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut seen = String::new();
    let code = loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).unwrap();
        assert!(n > 0, "agent exited before prompting: {seen}");
        seen.push_str(&line);
        if let Some(c) = re.captures(&line) {
            break c[1].to_string();
        }
    };
    stdin.write_all(answer(&code).as_bytes()).unwrap();
    drop(stdin);
    let mut rest = String::new();
    std::io::Read::read_to_string(&mut reader, &mut rest).unwrap();
    seen.push_str(&rest);
    let status = child.wait().unwrap();
    (status.code().unwrap_or(-1), seen)
}

#[test]
fn agent_write_needs_the_challenge_reply() {
    let e = Env::new();
    let a = e.root.join("a.txt");
    fs::write(&a, "old").unwrap();
    e.mock(&e.root, write_script("a.txt", "new"));
    let (code, text) = answer_prompt(&e, "update a.txt\n", |c| format!("yes {c}\n"));
    assert_eq!(code, 0, "{text}");
    assert_eq!(fs::read_to_string(&a).unwrap(), "new", "{text}");
    let d = e.decisions();
    assert!(d.contains(&"approved".to_string()), "{d:?}");
    assert!(
        d.iter().any(|x| x.starts_with("executed snapshot=")),
        "{d:?}"
    );
    assert!(text.contains("all done"), "{text}");
}

#[test]
fn agent_write_refused_with_no_changes_nothing() {
    let e = Env::new();
    let a = e.root.join("a.txt");
    fs::write(&a, "old").unwrap();
    e.mock(&e.root, write_script("a.txt", "new"));
    let (code, text) = answer_prompt(&e, "update a.txt\n", |_| "no\n".to_string());
    assert_eq!(code, 0, "{text}");
    assert_eq!(fs::read_to_string(&a).unwrap(), "old");
    let d = e.decisions();
    assert!(d.contains(&"refused: owner declined".to_string()), "{d:?}");
    assert!(!d.iter().any(|x| x == "approved"), "{d:?}");
}

#[test]
fn agent_write_with_a_wrong_code_changes_nothing() {
    let e = Env::new();
    let a = e.root.join("a.txt");
    fs::write(&a, "old").unwrap();
    e.mock(&e.root, write_script("a.txt", "new"));
    let (_, text) = answer_prompt(&e, "update a.txt\n", |c| {
        let wrong = (c.parse::<u32>().unwrap() + 1) % 10_000;
        format!("yes {wrong:04}\n")
    });
    assert_eq!(fs::read_to_string(&a).unwrap(), "old", "{text}");
    assert!(e
        .decisions()
        .contains(&"refused: owner declined".to_string()));
}

#[test]
fn agent_without_env_key_exits_1_naming_only_the_variable() {
    let e = Env::new();
    e.config(&format!("root = \"{}\"\n", e.root.display()));
    let o = e.cmd().write_stdin("hi\n").output().unwrap();
    let (so, se) = out(&o);
    assert_eq!(o.status.code(), Some(1), "{so}\n{se}");
    assert!(se.contains(KEY_VAR), "{se}");
    assert_eq!(se.lines().count(), 1, "one-line message: {se}");
    // Set but empty, under a custom variable name.
    e.config(&format!(
        "root = \"{}\"\napi_key_env = \"WARDEN_TEST_KEY_VAR\"\n",
        e.root.display()
    ));
    let o = e
        .cmd()
        .env("WARDEN_TEST_KEY_VAR", "")
        .env(KEY_VAR, FAKE_KEY)
        .write_stdin("hi\n")
        .output()
        .unwrap();
    let (so, se) = out(&o);
    assert_eq!(o.status.code(), Some(1), "{so}\n{se}");
    assert!(se.contains("WARDEN_TEST_KEY_VAR"), "{se}");
    assert!(!se.contains(FAKE_KEY) && !so.contains(FAKE_KEY));
    // Nothing ran, so no session was logged.
    assert!(e.decisions().is_empty(), "{:?}", e.decisions());
}

/// Every substring of `key` of length 12 or more.
fn key_fragments(key: &str) -> Vec<&str> {
    let mut v = Vec::new();
    for i in 0..key.len() {
        for j in (i + 12)..=key.len() {
            v.push(&key[i..j]);
        }
    }
    v
}

#[test]
fn agent_never_prints_the_api_key() {
    let e = Env::new();
    fs::write(e.root.join("a.txt"), "x").unwrap();
    // Mock provider: the agent runs a whole conversation with the key set.
    e.mock(
        &e.root,
        json!([
            {"text": "reading", "calls": [
                {"id": "t1", "name": "read_file", "args": {"path": "a.txt"}}
            ]},
            {"text": "done"}
        ]),
    );
    let o1 = e
        .cmd()
        .env(KEY_VAR, FAKE_KEY)
        .write_stdin("read a.txt\n")
        .output()
        .unwrap();
    assert_eq!(o1.status.code(), Some(0));
    // Anthropic provider with the key, pointed at a closed local port: the
    // key is read and used, the planner fails, nothing leaks.
    e.config(&format!(
        "root = \"{}\"\nbase_url = \"http://127.0.0.1:9\"\n",
        e.root.display()
    ));
    let o2 = e
        .cmd()
        .env(KEY_VAR, FAKE_KEY)
        .write_stdin("hello\n")
        .output()
        .unwrap();
    let (so2, se2) = out(&o2);
    assert_eq!(o2.status.code(), Some(0), "{so2}\n{se2}");
    assert!(so2.contains("planner unavailable"), "{so2}");
    let mut all = String::new();
    for o in [&o1, &o2] {
        let (so, se) = out(o);
        all.push_str(&so);
        all.push_str(&se);
    }
    all.push_str(&e.audit_text());
    for f in key_fragments(FAKE_KEY) {
        assert!(!all.contains(f), "key fragment {f:?} leaked");
    }
}

#[test]
fn agent_refuses_a_broken_audit_log() {
    let e = Env::new();
    let a = e.root.join("a.txt");
    fs::write(&a, "old").unwrap();
    e.mock(&e.root, write_script("a.txt", "new"));
    fs::write(e.home.join("audit.jsonl"), "{not json\n").unwrap();
    let o = e.cmd().write_stdin("update a.txt\n").output().unwrap();
    let (so, se) = out(&o);
    assert_eq!(o.status.code(), Some(1), "{so}\n{se}");
    assert!(se.contains("audit log"), "{se}");
    assert!(so.is_empty(), "{so}");
    assert_eq!(fs::read_to_string(&a).unwrap(), "old");
    assert_eq!(
        fs::read_to_string(e.home.join("audit.jsonl")).unwrap(),
        "{not json\n"
    );
}

#[test]
fn agent_refuses_root_slash() {
    let e = Env::new();
    e.mock(Path::new("/"), json!([]));
    let o = e.cmd().write_stdin("hi\n").output().unwrap();
    let (so, se) = out(&o);
    assert_eq!(o.status.code(), Some(1), "{so}\n{se}");
    assert!(se.contains("root"), "{se}");
    assert!(e.decisions().is_empty());
}

#[test]
fn agent_refuses_a_missing_root() {
    let e = Env::new();
    e.mock(&e.base.join("nope"), json!([]));
    let o = e.cmd().write_stdin("hi\n").output().unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(out(&o).1.contains("root"));
}

#[test]
fn agent_refuses_home_dir_root_without_flag() {
    let e = Env::new();
    let fake_home = e.base.join("user");
    fs::create_dir(&fake_home).unwrap();
    e.mock(&fake_home, json!([]));
    let o = e
        .cmd()
        .env("HOME", &fake_home)
        .write_stdin("")
        .output()
        .unwrap();
    let (so, se) = out(&o);
    assert_eq!(o.status.code(), Some(1), "{so}\n{se}");
    assert!(se.contains("--allow-home-root"), "{se}");
    // With the flag it starts (and exits 0 at EOF).
    let o = e
        .cmd()
        .env("HOME", &fake_home)
        .arg("--allow-home-root")
        .write_stdin("")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", out(&o).1);
}

/// The CLI always protects the home and the snapshot store, so a root that
/// contains the home passes `Engine::try_new` (no `UnprotectedHome`): the
/// agent starts, and every tool call into the home is refused `Protected`.
#[test]
fn agent_root_containing_the_home_starts_with_the_home_protected() {
    let e = Env::new();
    e.mock(
        &e.base,
        json!([
            {"text": "peeking", "calls": [
                {"id": "t1", "name": "read_file", "args": {"path": "home/audit.jsonl"}},
                {"id": "t2", "name": "list_dir", "args": {"path": "home"}},
                {"id": "t3", "name": "read_file", "args": {"path": "home/snapshots/manifests"}}
            ]},
            {"text": "ok"}
        ]),
    );
    let o = e
        .cmd()
        .current_dir(&e.base)
        .write_stdin("look at home\n")
        .output()
        .unwrap();
    let (so, se) = out(&o);
    assert_eq!(o.status.code(), Some(0), "{so}\n{se}");
    let d = e.decisions();
    assert_eq!(
        d.iter().filter(|x| *x == "failed: Protected").count(),
        3,
        "{d:?}"
    );
    assert!(!d.iter().any(|x| x == "executed"), "{d:?}");
}

#[test]
fn agent_exits_0_when_stdin_closes() {
    let e = Env::new();
    e.mock(&e.root, json!([]));
    let o = e.cmd().write_stdin("").output().unwrap();
    let (so, se) = out(&o);
    assert_eq!(o.status.code(), Some(0), "{so}\n{se}");
}

#[test]
fn agent_logs_session_start_and_end() {
    let e = Env::new();
    e.mock(&e.root, json!([]));
    e.cmd().write_stdin("").assert().success();
    let entries = e.entries();
    let got: Vec<(&str, &str, &str)> = entries
        .iter()
        .map(|v| {
            (
                v["action_id"].as_str().unwrap(),
                v["decision"].as_str().unwrap(),
                v["tier"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        got,
        vec![
            ("session", "agent session started", "Auto"),
            ("session", "agent session ended", "Auto"),
        ]
    );
    // The chain verifies.
    Command::cargo_bin("warden")
        .unwrap()
        .arg("--home")
        .arg(&e.home)
        .args(["audit", "verify"])
        .assert()
        .success();
}

#[test]
fn agent_refuses_a_missing_config_naming_the_path() {
    let e = Env::new();
    let o = e.cmd().write_stdin("").output().unwrap();
    let (so, se) = out(&o);
    assert_eq!(o.status.code(), Some(1), "{so}\n{se}");
    assert!(
        se.contains(&e.home.join("config.toml").display().to_string()),
        "{se}"
    );
}

#[test]
fn agent_refuses_a_group_writable_config() {
    let e = Env::new();
    e.mock(&e.root, json!([]));
    fs::set_permissions(
        e.home.join("config.toml"),
        fs::Permissions::from_mode(0o664),
    )
    .unwrap();
    let o = e.cmd().write_stdin("").output().unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(out(&o).1.contains("writable"));
}

#[test]
fn agent_refuses_a_config_with_a_key_without_echoing_it() {
    let e = Env::new();
    e.config(&format!(
        "root = \"{}\"\napi_key = \"{FAKE_KEY}\"\n",
        e.root.display()
    ));
    let o = e.cmd().write_stdin("").output().unwrap();
    let (so, se) = out(&o);
    assert_eq!(o.status.code(), Some(1));
    assert!(se.contains("environment variable"), "{se}");
    assert!(!se.contains("testkey") && !so.contains("testkey"));
}

#[test]
fn agent_config_flag_overrides_the_default_path() {
    let e = Env::new();
    e.mock(&e.root, json!([]));
    let elsewhere = e.base.join("other.toml");
    fs::rename(e.home.join("config.toml"), &elsewhere).unwrap();
    let o = e
        .cmd()
        .arg("--config")
        .arg(&elsewhere)
        .write_stdin("")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", out(&o).1);
}
