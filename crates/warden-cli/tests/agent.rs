//! End-to-end tests for `warden agent`. They need the `test-hooks` feature
//! (the scripted planner, `provider = "mock"`), which the self
//! dev-dependency turns on, so a plain `cargo test --workspace` runs them.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use assert_cmd::Command;
use serde_json::{json, Value};

const KEY_VAR: &str = "ANTHROPIC_API_KEY";
const FAKE_KEY: &str = "sk-ant-testkey-Zx9QwErTyUiOp1234567890AbCdEf";
/// Every agent run in these tests must finish within this, or the test
/// fails instead of hanging.
const RUN_TIMEOUT: Duration = Duration::from_secs(20);

struct Env {
    _tmp: tempfile::TempDir,
    /// A fake `$HOME` for every spawned agent, in its own tempdir so it is
    /// never under `base` (the tests must not depend on the ambient HOME,
    /// which may be unset or missing, e.g. `/homeless-shelter` under Nix).
    _user_tmp: tempfile::TempDir,
    user_home: PathBuf,
    base: PathBuf,
    home: PathBuf,
    root: PathBuf,
}

impl Env {
    /// `<tmp>/home` (0700) and `<tmp>/root`, canonical.
    fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let user_tmp = tempfile::tempdir().unwrap();
        let user_home = fs::canonicalize(user_tmp.path()).unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let home = base.join("home");
        let root = base.join("root");
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&root).unwrap();
        Env {
            _tmp: tmp,
            _user_tmp: user_tmp,
            user_home,
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
            .env("HOME", &self.user_home)
            .current_dir(&self.root)
            .timeout(RUN_TIMEOUT)
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
/// Output is read on a thread with [`RUN_TIMEOUT`]: if the agent never
/// prompts or never exits, the child is killed and the test fails.
fn answer_prompt(e: &Env, first: &str, answer: impl Fn(&str) -> String) -> (i32, String) {
    answer_prompt_with(e, &[], first, answer)
}

/// [`answer_prompt`] with `extra` arguments after `agent`.
fn answer_prompt_with(
    e: &Env,
    extra: &[&std::ffi::OsStr],
    first: &str,
    answer: impl Fn(&str) -> String,
) -> (i32, String) {
    let re = regex::Regex::new(r#"Reply "yes (\d{4})"#).unwrap();
    let mut child = StdCommand::new(assert_cmd::cargo::cargo_bin("warden"))
        .env_remove(KEY_VAR)
        .env("HOME", &e.user_home)
        .env_remove("WARDEN_PIN")
        .current_dir(&e.root)
        .arg("--home")
        .arg(&e.home)
        .arg("agent")
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(first.as_bytes()).unwrap();
    stdin.flush().unwrap();
    let (tx, rx) = mpsc::channel::<String>();
    let stdout = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(n) if n > 0 => {
                    if tx.send(line).is_err() {
                        return;
                    }
                }
                _ => return,
            }
        }
    });
    let deadline = Instant::now() + RUN_TIMEOUT;
    let mut seen = String::new();
    let fail = |child: &mut std::process::Child, seen: &str, why: &str| -> ! {
        let _ = child.kill();
        let _ = child.wait();
        panic!("{why}: {seen}");
    };
    let code = loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(line) => {
                seen.push_str(&line);
                if let Some(c) = re.captures(&line) {
                    break c[1].to_string();
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => fail(&mut child, &seen, "agent never prompted"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                fail(&mut child, &seen, "agent exited before prompting")
            }
        }
    };
    stdin.write_all(answer(&code).as_bytes()).unwrap();
    drop(stdin);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(line) => seen.push_str(&line),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                fail(&mut child, &seen, "agent did not exit after stdin closed")
            }
        }
    }
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        if Instant::now() >= deadline {
            fail(&mut child, &seen, "agent did not exit");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
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
        .env("HOME", &e.user_home)
        .arg("--home")
        .arg(&e.home)
        .args(["audit", "verify"])
        .assert()
        .success();
}

#[test]
fn agent_warns_when_the_clock_is_behind_the_mark() {
    let e = Env::new();
    e.mock(&e.root, json!([]));
    let now_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let mark = e.home.join("clock-mark");
    fs::write(&mark, (now_ms + 3_600_000).to_be_bytes()).unwrap();
    fs::set_permissions(&mark, fs::Permissions::from_mode(0o600)).unwrap();
    let o = e.cmd().write_stdin("").output().unwrap();
    let (so, se) = out(&o);
    assert_eq!(o.status.code(), Some(0), "{so}\n{se}");
    let warning = se
        .lines()
        .find(|l| l.starts_with("warning: the system clock is "))
        .unwrap_or_else(|| panic!("no clock warning: {se}"));
    let secs: u64 = warning
        .strip_prefix("warning: the system clock is ")
        .and_then(|r| {
            r.strip_suffix(" s behind the last time Warden ran; approvals use the later time")
        })
        .unwrap_or_else(|| panic!("{warning}"))
        .parse()
        .unwrap();
    assert!((3_500..=3_600).contains(&secs), "{warning}");
    let entries = e.entries();
    assert!(
        entries.iter().any(|v| v["action_id"] == "session"
            && v["decision"] == "clock behind high-water mark"),
        "{}",
        e.audit_text()
    );
    // The mark was not lowered.
    assert_eq!(
        u64::from_be_bytes(fs::read(&mark).unwrap().try_into().unwrap()),
        now_ms + 3_600_000
    );
}

#[test]
fn agent_does_not_warn_about_the_clock_on_a_fresh_home() {
    let e = Env::new();
    e.mock(&e.root, json!([]));
    let o = e.cmd().write_stdin("").output().unwrap();
    let (so, se) = out(&o);
    assert_eq!(o.status.code(), Some(0), "{so}\n{se}");
    assert!(!se.contains("system clock"), "{se}");
    assert!(!e.audit_text().contains("high-water"));
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

// ------------------------------------------------- review round 1

/// `<base>/a/b/user` as a fake $HOME (created).
fn fake_home(e: &Env) -> PathBuf {
    let h = e.base.join("a").join("b").join("user");
    fs::create_dir_all(&h).unwrap();
    h
}

fn run_with_home(e: &Env, home_env: Option<&Path>, root: &Path, flag: bool) -> (i32, String) {
    e.mock(root, json!([]));
    let mut c = e.cmd();
    match home_env {
        Some(h) => c.env("HOME", h),
        None => c.env_remove("HOME"),
    };
    if flag {
        c.arg("--allow-home-root");
    }
    let o = c.write_stdin("").output().unwrap();
    (o.status.code().unwrap_or(-1), out(&o).1)
}

#[test]
fn agent_refuses_home_and_its_ancestors_as_root() {
    let e = Env::new();
    let h = fake_home(&e);
    let parent = h.parent().unwrap().to_path_buf();
    let grandparent = parent.parent().unwrap().to_path_buf();
    for root in [&h, &parent, &grandparent] {
        let before = e.decisions().len();
        let (code, se) = run_with_home(&e, Some(&h), root, false);
        assert_eq!(code, 1, "{}: {se}", root.display());
        assert!(se.contains("--allow-home-root"), "{se}");
        assert_eq!(e.decisions().len(), before, "nothing logged when refused");
        let (code, se) = run_with_home(&e, Some(&h), root, true);
        assert_eq!(code, 0, "{}: {se}", root.display());
    }
    // A sibling of the home is fine.
    let sibling = parent.join("other");
    fs::create_dir(&sibling).unwrap();
    let (code, se) = run_with_home(&e, Some(&h), &sibling, false);
    assert_eq!(code, 0, "{se}");
}

#[test]
fn agent_catches_home_spelled_through_a_symlink() {
    let e = Env::new();
    let h = fake_home(&e);
    let link = e.base.join("homelink");
    std::os::unix::fs::symlink(&h, &link).unwrap();
    let (code, se) = run_with_home(&e, Some(&link), h.parent().unwrap(), false);
    assert_eq!(code, 1, "{se}");
    assert!(se.contains("--allow-home-root"), "{se}");
}

#[test]
fn agent_refuses_to_start_without_home_env() {
    let e = Env::new();
    let (code, se) = run_with_home(&e, None, &e.root.clone(), false);
    assert_eq!(code, 1, "{se}");
    assert!(
        se.contains("HOME is not set or does not exist; pass --allow-home-root to continue"),
        "{se}"
    );
    let (code, se) = run_with_home(&e, None, &e.root.clone(), true);
    assert_eq!(code, 0, "{se}");
    // A HOME that does not exist cannot be checked either.
    let missing = e.base.join("no-such-home");
    let (code, se) = run_with_home(&e, Some(&missing), &e.root.clone(), false);
    assert_eq!(code, 1, "{se}");
    assert!(se.contains("does not exist"), "{se}");
}

#[test]
fn agent_refuses_a_group_writable_data_dir() {
    let e = Env::new();
    e.mock(&e.root, json!([]));
    fs::set_permissions(&e.home, fs::Permissions::from_mode(0o775)).unwrap();
    let o = e.cmd().write_stdin("").output().unwrap();
    let (so, se) = out(&o);
    assert_eq!(o.status.code(), Some(1), "{so}\n{se}");
    assert!(se.contains("writable by group or others"), "{se}");
    assert!(!e.home.join("audit.jsonl").exists());
}

#[test]
fn agent_refuses_a_symlinked_data_dir() {
    let e = Env::new();
    e.mock(&e.root, json!([]));
    let link = e.base.join("homelink");
    std::os::unix::fs::symlink(&e.home, &link).unwrap();
    let o = Command::cargo_bin("warden")
        .unwrap()
        .env_remove(KEY_VAR)
        .env("HOME", &e.user_home)
        .current_dir(&e.root)
        .timeout(RUN_TIMEOUT)
        .arg("--home")
        .arg(&link)
        .arg("agent")
        .write_stdin("")
        .output()
        .unwrap();
    let (so, se) = out(&o);
    assert_eq!(o.status.code(), Some(1), "{so}\n{se}");
    assert!(se.contains("symlink"), "{se}");
    assert!(!e.home.join("audit.jsonl").exists());
}

#[test]
fn agent_refuses_an_owner_other_than_local() {
    let e = Env::new();
    let s = e.base.join("script.json");
    fs::write(&s, "[]").unwrap();
    e.config(&format!(
        "root = \"{}\"\nowner = \"alice\"\nprovider = \"mock\"\nscript = \"{}\"\n",
        e.root.display(),
        s.display()
    ));
    let o = e.cmd().write_stdin("hi\n").output().unwrap();
    let (so, se) = out(&o);
    assert_eq!(o.status.code(), Some(1), "{so}\n{se}");
    assert!(
        se.contains("the stdio channel only supports owner = \"local\""),
        "{se}"
    );
    assert!(e.decisions().is_empty());
}

#[test]
fn agent_missing_key_creates_nothing_but_the_home() {
    let e = Env::new();
    e.config(&format!("root = \"{}\"\n", e.root.display()));
    let o = e.cmd().write_stdin("hi\n").output().unwrap();
    assert_eq!(o.status.code(), Some(1));
    let mut names: Vec<String> = fs::read_dir(&e.home)
        .unwrap()
        .map(|d| d.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, vec!["config.toml"]);
}

#[test]
fn agent_does_not_name_an_odd_key_variable() {
    let e = Env::new();
    let hex64 = "deadbeef".repeat(8);
    let base62 = "Qx7pLm2ZrT9vBn4KcW8sYh3DfJ6gAe1Uo5RiNt0EyMq";
    for name in [hex64.as_str(), base62] {
        e.config(&format!(
            "root = \"{}\"\napi_key_env = \"{name}\"\n",
            e.root.display()
        ));
        let o = e.cmd().env_remove(name).write_stdin("").output().unwrap();
        let (so, se) = out(&o);
        assert_eq!(o.status.code(), Some(1), "{so}\n{se}");
        assert!(!se.contains(name) && !so.contains(name), "{se}");
    }
    // A conventional name is named.
    e.config(&format!(
        "root = \"{}\"\napi_key_env = \"MY_TEAM_KEY\"\n",
        e.root.display()
    ));
    let o = e
        .cmd()
        .env_remove("MY_TEAM_KEY")
        .write_stdin("")
        .output()
        .unwrap();
    let se = out(&o).1;
    assert!(se.contains("MY_TEAM_KEY"), "{se}");
}

// ------------------------------------------------- review round 2

#[test]
fn agent_does_not_name_a_key_variable_that_carries_data() {
    let e = Env::new();
    for name in [
        "CARD_4111111111111111",
        "K_123456789012345678901234567890",
        "GHP_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "SK_LIVE_51ABCDEFGHIJKLMNOPQRSTUV",
        "A_4111_1111_1111_1111",
    ] {
        e.config(&format!(
            "root = \"{}\"\napi_key_env = \"{name}\"\n",
            e.root.display()
        ));
        let o = e.cmd().env_remove(name).write_stdin("").output().unwrap();
        let (so, se) = out(&o);
        assert_eq!(o.status.code(), Some(1), "{name}: {so}\n{se}");
        assert!(!se.contains(name) && !so.contains(name), "{name}: {se}");
    }
    // The default is always named.
    e.config(&format!("root = \"{}\"\n", e.root.display()));
    let o = e.cmd().write_stdin("").output().unwrap();
    assert!(out(&o).1.contains(KEY_VAR));
}

#[test]
fn relative_paths_resolve_against_the_root_not_the_process_cwd() {
    let e = Env::new();
    fs::write(e.root.join("notes.txt"), "inside the root").unwrap();
    // Same name next to the root, where the process cwd will be.
    fs::write(e.base.join("notes.txt"), "outside the root").unwrap();
    e.mock(
        &e.root,
        json!([
            {"text": "looking", "calls": [
                {"id": "t1", "name": "read_file", "args": {"path": "notes.txt"}},
                {"id": "t2", "name": "list_dir", "args": {"path": "."}},
                {"id": "t3", "name": "read_file", "args": {"path": "../notes.txt"}}
            ]},
            {"text": "done looking"}
        ]),
    );
    let o = e
        .cmd()
        .current_dir(&e.base)
        .write_stdin("read notes\n")
        .output()
        .unwrap();
    let (so, se) = out(&o);
    assert_eq!(o.status.code(), Some(0), "{so}\n{se}");
    let root = e.root.display().to_string();
    assert!(
        so.contains(&format!("done: read \"{root}/notes.txt\"")),
        "{so}"
    );
    assert!(so.contains(&format!("done: list \"{root}\"")), "{so}");
    // `..` still leaves the root and is refused before any prompt.
    let outside = e.base.join("notes.txt").display().to_string();
    assert!(so.contains(&format!("refused: read \"{outside}\"")), "{so}");
    let d = e.decisions();
    assert!(d.contains(&"refused: outside root".to_string()), "{d:?}");
    assert_eq!(
        d.iter().filter(|x| x.as_str() == "executed").count(),
        2,
        "{d:?}"
    );
}

// ------------------------------------------------- final fix wave

/// A `--config` inside the root is protected: an approved write_file to it
/// is refused by the executor, and the config is unchanged. Reads of it are
/// refused too.
#[test]
fn agent_config_inside_the_root_cannot_be_rewritten() {
    let e = Env::new();
    e.mock(&e.root, json!([]));
    let original = fs::read_to_string(e.home.join("config.toml")).unwrap();
    let cfg = e.root.join("warden.toml");
    fs::rename(e.home.join("config.toml"), &cfg).unwrap();
    let script = json!([
        {"text": "loosening my policy", "calls": [
            {"id": "t1", "name": "write_file",
             "args": {"path": "warden.toml", "content": "root = \"/\"\n"}},
            {"id": "t2", "name": "read_file", "args": {"path": "warden.toml"}}
        ]},
        {"text": "all done"}
    ]);
    fs::write(
        e.base.join("script.json"),
        serde_json::to_vec(&script).unwrap(),
    )
    .unwrap();
    let (code, text) = answer_prompt_with(
        &e,
        &["--config".as_ref(), cfg.as_os_str()],
        "rewrite your config\n",
        |c| format!("yes {c}\n"),
    );
    assert_eq!(code, 0, "{text}");
    assert_eq!(fs::read_to_string(&cfg).unwrap(), original, "{text}");
    let d = e.decisions();
    assert_eq!(
        d.iter().filter(|x| *x == "failed: Protected").count(),
        2,
        "{d:?}"
    );
    assert!(!d.iter().any(|x| x.starts_with("executed")), "{d:?}");
    assert!(text.contains("all done"), "{text}");
}
