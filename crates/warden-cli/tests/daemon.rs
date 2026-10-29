//! End-to-end tests for `warden daemon`. Telegram is a loopback wiremock
//! server (`[telegram] api_base`) running on a tokio runtime owned by the
//! test; the planner is the `test-hooks` scripted one (`provider = "mock"`).
//! The daemon is a real child process, stopped with `kill -TERM`.

use std::collections::VecDeque;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as StdCommand, Stdio};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const KEY_VAR: &str = "ANTHROPIC_API_KEY";
const TOKEN_VAR: &str = "WARDEN_TELEGRAM_TOKEN";
const TOKEN: &str = "123456789:AAH-secret_half_0123456789abcdefDONOTLEAK";
const TOKEN_SECRET: &str = "AAH-secret_half_0123456789abcdefDONOTLEAK";
const OWNER: i64 = 42;
const STRANGER: i64 = 666;
/// Every wait in these tests ends within this, or the test fails.
const TIMEOUT: Duration = Duration::from_secs(20);

fn now_s() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

// ------------------------------------------------------------ fake Telegram

/// Records of what the daemon sent to the fake Bot API.
#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<Value>>>);

impl Log {
    fn all(&self) -> Vec<Value> {
        self.0.lock().unwrap().clone()
    }
    fn clear(&self) {
        self.0.lock().unwrap().clear();
    }
}

/// `getUpdates`: queued responses first, then an empty batch after 100 ms
/// (an idle long poll). Every request body is recorded.
#[derive(Clone, Default)]
struct Updates {
    queue: Arc<Mutex<VecDeque<ResponseTemplate>>>,
    polls: Log,
}

impl Respond for Updates {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        if let Ok(v) = serde_json::from_slice::<Value>(&req.body) {
            self.polls.0.lock().unwrap().push(v);
        }
        self.queue.lock().unwrap().pop_front().unwrap_or_else(|| {
            ResponseTemplate::new(200)
                .set_body_json(json!({"ok": true, "result": []}))
                .set_delay(Duration::from_millis(100))
        })
    }
}

/// `sendMessage` / `deleteMessage`: record the body, answer ok.
#[derive(Clone)]
struct Recorder {
    log: Log,
    next_id: Arc<AtomicI64>,
}

impl Respond for Recorder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        if let Ok(v) = serde_json::from_slice::<Value>(&req.body) {
            self.log.0.lock().unwrap().push(v);
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        ResponseTemplate::new(200).set_body_json(json!({"ok": true, "result": {"message_id": id}}))
    }
}

struct Tg {
    _rt: tokio::runtime::Runtime,
    server: MockServer,
    updates: Updates,
    sent: Log,
    deleted: Log,
}

fn bot_path(m: &str) -> String {
    format!("/bot{TOKEN}/{m}")
}

impl Tg {
    fn start() -> Tg {
        Tg::start_with_get_me(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {"id": 987654321, "is_bot": true, "first_name": "W", "username": "warden_test_bot"}
        })))
    }

    fn start_with_get_me(get_me: ResponseTemplate) -> Tg {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let server = rt.block_on(MockServer::start());
        let updates = Updates::default();
        let sent = Log::default();
        let deleted = Log::default();
        let next_id = Arc::new(AtomicI64::new(5000));
        rt.block_on(async {
            Mock::given(method("POST"))
                .and(path(bot_path("getMe")))
                .respond_with(get_me)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(bot_path("getUpdates")))
                .respond_with(updates.clone())
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(bot_path("sendMessage")))
                .respond_with(Recorder {
                    log: sent.clone(),
                    next_id: Arc::clone(&next_id),
                })
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(bot_path("deleteMessage")))
                .respond_with(Recorder {
                    log: deleted.clone(),
                    next_id: Arc::clone(&next_id),
                })
                .mount(&server)
                .await;
        });
        Tg {
            _rt: rt,
            server,
            updates,
            sent,
            deleted,
        }
    }

    fn base(&self) -> String {
        self.server.uri()
    }

    fn push(&self, batch: Vec<Value>) {
        self.push_response(
            ResponseTemplate::new(200).set_body_json(json!({"ok": true, "result": batch})),
        );
    }

    /// Queue a raw `getUpdates` response (an error, say).
    fn push_response(&self, r: ResponseTemplate) {
        self.updates.queue.lock().unwrap().push_back(r);
    }

    /// Texts sent to `chat`.
    fn texts_to(&self, chat: i64) -> Vec<String> {
        self.sent
            .all()
            .iter()
            .filter(|v| v["chat_id"] == chat)
            .map(|v| v["text"].as_str().unwrap_or_default().to_owned())
            .collect()
    }
}

fn private_text(update_id: i64, from: i64, text: &str, date: i64) -> Value {
    json!({"update_id": update_id, "message": {
        "message_id": update_id + 100,
        "from": {"id": from, "is_bot": false, "first_name": "x"},
        "chat": {"id": from, "type": "private"},
        "date": date,
        "text": text,
    }})
}

fn owner_text(update_id: i64, text: &str) -> Value {
    private_text(update_id, OWNER, text, now_s())
}

fn group_text(update_id: i64, from: i64, text: &str) -> Value {
    json!({"update_id": update_id, "message": {
        "message_id": update_id + 100,
        "from": {"id": from, "is_bot": false, "first_name": "x"},
        "chat": {"id": -1001234, "type": "group", "title": "g"},
        "date": now_s(),
        "text": text,
    }})
}

// ------------------------------------------------------------- environment

struct Env {
    _tmp: tempfile::TempDir,
    _user_tmp: tempfile::TempDir,
    user_home: PathBuf,
    base: PathBuf,
    home: PathBuf,
    root: PathBuf,
    config: PathBuf,
}

impl Env {
    /// `<tmp>/home` (0700), `<tmp>/root`, the config at `<tmp>/config.toml`
    /// (outside the data dir, so the data dir holds only Warden's state).
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
        let config = base.join("config.toml");
        Env {
            _tmp: tmp,
            _user_tmp: user_tmp,
            user_home,
            base,
            home,
            root,
            config,
        }
    }

    fn config_text(&self, body: &str) {
        fs::write(&self.config, body).unwrap();
        fs::set_permissions(&self.config, fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// A mock-provider config with a `[telegram]` table pointing at `base`.
    fn mock(&self, api_base: &str, script: Value) {
        let s = self.base.join("script.json");
        fs::write(&s, serde_json::to_vec(&script).unwrap()).unwrap();
        self.config_text(&format!(
            "root = \"{}\"\nprovider = \"mock\"\nscript = \"{}\"\n\n[telegram]\nowner_ids = [{OWNER}]\napi_base = \"{api_base}\"\n",
            self.root.display(),
            s.display()
        ));
    }

    /// `warden --home <home>` with a clean environment and the token set.
    fn warden(&self) -> Command {
        self.warden_at(&self.home)
    }

    /// [`Env::warden`] with another data dir.
    fn warden_at(&self, home: &Path) -> Command {
        let mut c = Command::cargo_bin("warden").unwrap();
        c.env_remove(KEY_VAR)
            .env_remove("WARDEN_PIN")
            .env_remove("WARDEN_TEST_FAIL_AUDIT_APPEND")
            .env(TOKEN_VAR, TOKEN)
            .env("HOME", &self.user_home)
            .current_dir(&self.root)
            .timeout(TIMEOUT)
            .arg("--home")
            .arg(home);
        c
    }

    /// `warden daemon --config <config>`, run to completion.
    fn daemon_cmd(&self) -> Command {
        let mut c = self.warden();
        c.arg("daemon").arg("--config").arg(&self.config);
        c
    }

    fn spawn(&self) -> Daemon {
        let mut child = StdCommand::new(assert_cmd::cargo::cargo_bin("warden"))
            .env_remove(KEY_VAR)
            .env_remove("WARDEN_PIN")
            .env_remove("WARDEN_TEST_FAIL_AUDIT_APPEND")
            .env(TOKEN_VAR, TOKEN)
            .env("HOME", &self.user_home)
            .current_dir(&self.root)
            .arg("--home")
            .arg(&self.home)
            .arg("daemon")
            .arg("--config")
            .arg(&self.config)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = Arc::new(Mutex::new(String::new()));
        let stderr = Arc::new(Mutex::new(String::new()));
        pump(child.stdout.take().unwrap(), Arc::clone(&stdout));
        pump(child.stderr.take().unwrap(), Arc::clone(&stderr));
        Daemon {
            child,
            stdout,
            stderr,
        }
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

fn pump(mut r: impl Read + Send + 'static, into: Arc<Mutex<String>>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => into
                    .lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buf[..n])),
            }
        }
    });
}

struct Daemon {
    child: Child,
    stdout: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
}

impl Daemon {
    fn stderr(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }
    fn stdout(&self) -> String {
        self.stdout.lock().unwrap().clone()
    }

    /// Kill the child and fail with `why` and everything seen so far.
    fn fail(&mut self, why: &str) -> ! {
        let _ = self.child.kill();
        let _ = self.child.wait();
        panic!(
            "{why}\nstderr: {}\nstdout: {}",
            self.stderr(),
            self.stdout()
        );
    }

    /// Wait for `pred`, or fail.
    fn wait_for(&mut self, why: &str, pred: impl Fn() -> bool) {
        let deadline = Instant::now() + TIMEOUT;
        while !pred() {
            if Instant::now() >= deadline {
                self.fail(why);
            }
            if let Some(st) = self.child.try_wait().unwrap() {
                if !pred() {
                    self.fail(&format!("{why} (the daemon exited: {st})"));
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Wait for the startup banner.
    fn ready(&mut self) {
        let err = Arc::clone(&self.stderr);
        self.wait_for("the daemon never printed its banner", move || {
            err.lock()
                .unwrap()
                .contains("warden daemon: telegram @warden_test_bot owners=1 root=")
        });
    }

    fn term(&self) {
        let st = StdCommand::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(st.success());
    }

    /// Wait for the exit code.
    fn wait_exit(&mut self) -> i32 {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(st) = self.child.try_wait().unwrap() {
                // Let the pump threads drain.
                std::thread::sleep(Duration::from_millis(50));
                return st.code().unwrap_or(-1);
            }
            if Instant::now() >= deadline {
                self.fail("the daemon did not exit");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop(&mut self) -> i32 {
        self.term();
        self.wait_exit()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn write_script(path: &str, content: &str) -> Value {
    json!([
        {"text": "updating", "calls": [
            {"id": "t1", "name": "write_file", "args": {"path": path, "content": content}}
        ]},
        {"text": "all done"}
    ])
}

/// Wait for a prompt to the owner and return its challenge code.
fn wait_for_code(d: &mut Daemon, tg: &Tg) -> String {
    let re = regex::Regex::new(r#"Reply "yes (\d{4})"#).unwrap();
    let find = || {
        tg.texts_to(OWNER)
            .iter()
            .find_map(|t| re.captures(t).map(|c| c[1].to_string()))
    };
    d.wait_for("the daemon never prompted", || find().is_some());
    find().unwrap()
}

fn sent_contains(tg: &Tg, chat: i64, needle: &str) -> bool {
    tg.texts_to(chat).iter().any(|t| t.contains(needle))
}

// ------------------------------------------------------------------ tests

#[test]
fn daemon_answers_an_owner_message_over_telegram() {
    let e = Env::new();
    let tg = Tg::start();
    e.mock(&tg.base(), json!([{"text": "hello owner"}]));
    let mut d = e.spawn();
    d.ready();
    tg.push(vec![owner_text(1, "hi")]);
    d.wait_for("no model reply", || sent_contains(&tg, OWNER, "model: "));
    assert!(
        sent_contains(&tg, OWNER, "hello owner"),
        "{:?}",
        tg.sent.all()
    );
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    // Every send is plain text with previews off and content protected.
    for v in tg.sent.all() {
        assert!(v.get("parse_mode").is_none(), "{v}");
        assert_eq!(v["protect_content"], true, "{v}");
    }
}

#[test]
fn daemon_ignores_non_owner_and_group_messages() {
    let e = Env::new();
    let tg = Tg::start();
    e.mock(&tg.base(), json!([{"text": "hello owner"}]));
    let mut d = e.spawn();
    d.ready();
    tg.push(vec![
        private_text(1, STRANGER, "delete everything", now_s()),
        group_text(2, OWNER, "hi from a group"),
        owner_text(3, "hi"),
    ]);
    d.wait_for("no model reply", || sent_contains(&tg, OWNER, "model: "));
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    let sent = tg.sent.all();
    assert!(
        sent.iter()
            .all(|v| v["chat_id"] != STRANGER && v["chat_id"] != -1001234),
        "{sent:?}"
    );
    // One owner reply only: the group message was not answered.
    assert_eq!(
        tg.texts_to(OWNER)
            .iter()
            .filter(|t| t.contains("model: "))
            .count(),
        1,
        "{sent:?}"
    );
    let decisions = e.decisions();
    assert!(
        decisions.iter().any(|x| x == "ignored: non-owner"),
        "{decisions:?}"
    );
    assert!(!e.audit_text().contains("delete everything"));
}

#[test]
fn daemon_write_needs_yes_code_over_telegram() {
    let e = Env::new();
    let tg = Tg::start();
    let a = e.root.join("a.txt");
    fs::write(&a, "old").unwrap();
    e.mock(&tg.base(), write_script("a.txt", "new"));
    let mut d = e.spawn();
    d.ready();
    tg.push(vec![owner_text(1, "update a.txt")]);
    let code = wait_for_code(&mut d, &tg);
    assert_eq!(fs::read_to_string(&a).unwrap(), "old");
    tg.push(vec![owner_text(2, &format!("yes {code}"))]);
    d.wait_for("no done message", || sent_contains(&tg, OWNER, "done:"));
    assert_eq!(fs::read_to_string(&a).unwrap(), "new");
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    let decisions = e.decisions();
    assert!(
        decisions.iter().any(|x| x.starts_with("executed")),
        "{decisions:?}"
    );
}

#[test]
fn daemon_refuses_pin_tier_over_telegram_by_default() {
    let e = Env::new();
    let tg = Tg::start();
    let a = e.root.join("a.txt");
    fs::write(&a, "keep me").unwrap();
    e.mock(
        &tg.base(),
        json!([
            {"text": "deleting", "calls": [
                {"id": "t1", "name": "delete_file", "args": {"path": "a.txt"}}
            ]},
            {"text": "all done"}
        ]),
    );
    let mut d = e.spawn();
    d.ready();
    tg.push(vec![owner_text(1, "delete a.txt")]);
    d.wait_for("the owner was not told", || {
        sent_contains(&tg, OWNER, "does not accept")
    });
    d.wait_for("the message never finished", || {
        sent_contains(&tg, OWNER, "all done")
    });
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    assert!(a.exists());
    assert!(
        !tg.texts_to(OWNER).iter().any(|t| t.contains("Reply \"yes")),
        "{:?}",
        tg.sent.all()
    );
    let decisions = e.decisions();
    assert!(
        decisions
            .iter()
            .any(|x| x == "refused: pin not accepted on this channel"),
        "{decisions:?}"
    );
}

#[test]
fn daemon_restart_does_not_replay_messages() {
    let e = Env::new();
    let tg = Tg::start();
    e.mock(&tg.base(), json!([{"text": "hello owner"}]));
    let mut d = e.spawn();
    d.ready();
    tg.push(vec![owner_text(70, "hi")]);
    d.wait_for("no model reply", || sent_contains(&tg, OWNER, "model: "));
    assert_eq!(d.stop(), 0, "{}", d.stderr());

    tg.updates.polls.clear();
    let mut d = e.spawn();
    d.ready();
    let polls = tg.updates.polls.clone();
    d.wait_for("no poll after restart", || !polls.all().is_empty());
    assert_eq!(polls.all()[0]["offset"], 71, "{:?}", polls.all());
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    assert_eq!(
        tg.texts_to(OWNER)
            .iter()
            .filter(|t| t.contains("model: "))
            .count(),
        1
    );
}

#[test]
fn daemon_drops_messages_older_than_max_age() {
    let e = Env::new();
    let tg = Tg::start();
    // Empty script: a planner call would fail.
    e.mock(&tg.base(), json!([]));
    let mut d = e.spawn();
    d.ready();
    tg.push(vec![private_text(1, OWNER, "hi", now_s() - 3600)]);
    d.wait_for("the owner was not told", || {
        sent_contains(&tg, OWNER, "ignored 1 message")
    });
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    assert!(!sent_contains(&tg, OWNER, "model: "), "{:?}", tg.sent.all());
}

#[test]
fn second_daemon_on_same_home_exits_1() {
    let e = Env::new();
    let tg = Tg::start();
    e.mock(&tg.base(), json!([]));
    let mut d = e.spawn();
    d.ready();
    let o = e.daemon_cmd().output().unwrap();
    let se = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(1), "{se}");
    assert!(
        se.contains(&format!(
            "another warden daemon is using {}",
            e.home.display()
        )),
        "{se}"
    );
    assert_eq!(d.stop(), 0, "{}", d.stderr());
}

#[test]
fn sigterm_exits_0_and_audits_session_end() {
    let e = Env::new();
    let tg = Tg::start();
    e.mock(&tg.base(), json!([]));
    let mut d = e.spawn();
    d.ready();
    assert!(
        d.stderr()
            .contains(&format!("owners=1 root={}", e.root.display())),
        "{}",
        d.stderr()
    );
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    assert!(
        d.stderr().contains("shutting down after the current step"),
        "{}",
        d.stderr()
    );
    let entries = e.entries();
    let first = entries.first().unwrap();
    assert_eq!(first["action_id"], "session");
    assert_eq!(first["summary"], "daemon session");
    assert_eq!(first["decision"], "daemon session started");
    let last = entries.last().unwrap();
    assert_eq!(last["decision"], "daemon session ended");
    e.warden().args(["audit", "verify"]).assert().success();
}

#[test]
fn sigterm_during_prompt_refuses_the_action() {
    let e = Env::new();
    let tg = Tg::start();
    let a = e.root.join("a.txt");
    fs::write(&a, "old").unwrap();
    e.mock(&tg.base(), write_script("a.txt", "new"));
    let mut d = e.spawn();
    d.ready();
    tg.push(vec![owner_text(1, "update a.txt")]);
    let _code = wait_for_code(&mut d, &tg);
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    assert_eq!(fs::read_to_string(&a).unwrap(), "old");
    let decisions = e.decisions();
    assert!(
        decisions.iter().any(|x| x == "refused: shutting down"),
        "{decisions:?}"
    );
    assert_eq!(
        decisions.last().map(String::as_str),
        Some("daemon session ended")
    );
}

#[test]
fn sigterm_flushes_a_pending_pin_deletion_before_exit() {
    let e = Env::new();
    let tg = Tg::start();
    // The first deleteMessage hangs well past the shutdown.
    tg._rt.block_on(
        Mock::given(method("POST"))
            .and(path(bot_path("deleteMessage")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"ok": true, "result": true}))
                    .set_delay(Duration::from_secs(30)),
            )
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&tg.server),
    );
    let a = e.root.join("a.txt");
    fs::write(&a, "old").unwrap();
    e.mock(&tg.base(), write_script("a.txt", "new"));
    let mut d = e.spawn();
    d.ready();
    tg.push(vec![owner_text(1, "update a.txt")]);
    let _code = wait_for_code(&mut d, &tg);
    // A wrong two-token reply: refused, and deleted as it may be `yes <PIN>`.
    tg.push(vec![owner_text(2, "yes 0000")]);
    let delete_in_flight = || {
        tg._rt
            .block_on(tg.server.received_requests())
            .unwrap()
            .iter()
            .any(|r| r.url.path() == bot_path("deleteMessage"))
    };
    d.wait_for("the reply was never deleted", delete_in_flight);
    let t = Instant::now();
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    assert!(t.elapsed() < Duration::from_secs(15), "{:?}", t.elapsed());
    // The hung request was abandoned; the final flush sent it again.
    let deleted = tg.deleted.all();
    assert_eq!(deleted.len(), 1, "{deleted:?}");
    assert_eq!(deleted[0]["chat_id"], OWNER);
    assert_eq!(deleted[0]["message_id"], 102);
    assert_eq!(fs::read_to_string(&a).unwrap(), "old");
}

#[test]
fn insecure_telegram_offset_fails_startup_with_a_recovery_hint() {
    let e = Env::new();
    let tg = Tg::start();
    e.mock(&tg.base(), json!([]));
    let p = e.home.join("telegram-offset");
    fs::write(&p, 7i64.to_be_bytes()).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
    let o = e.daemon_cmd().output().unwrap();
    let se = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(1), "{se}");
    assert!(
        se.contains(
            "make telegram-offset a regular file with mode 0600, or remove it while Warden is stopped (removing telegram-offset may replay messages newer than max_message_age_secs)"
        ),
        "{se}"
    );
}

#[test]
fn daemon_without_telegram_table_exits_1() {
    let e = Env::new();
    let s = e.base.join("script.json");
    fs::write(&s, "[]").unwrap();
    e.config_text(&format!(
        "root = \"{}\"\nprovider = \"mock\"\nscript = \"{}\"\n",
        e.root.display(),
        s.display()
    ));
    let o = e.daemon_cmd().output().unwrap();
    let se = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(1), "{se}");
    assert!(
        se.contains("no channel configured: add a [telegram] table"),
        "{se}"
    );
    assert!(!e.home.join("audit.jsonl").exists());
}

fn home_listing(home: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(home)
        .unwrap()
        .map(|d| d.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn daemon_without_token_env_exits_1_without_side_effects() {
    let e = Env::new();
    e.mock("http://127.0.0.1:9", json!([]));
    let o = e.daemon_cmd().env_remove(TOKEN_VAR).output().unwrap();
    let se = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(1), "{se}");
    assert!(se.contains(TOKEN_VAR), "{se}");
    assert_eq!(home_listing(&e.home), vec!["daemon.lock".to_string()]);

    // A badly shaped token is refused the same way.
    let o = e
        .daemon_cmd()
        .env(TOKEN_VAR, "not-a-token")
        .output()
        .unwrap();
    let se = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(1), "{se}");
    assert!(
        se.contains("the Telegram bot token variable does not hold a valid bot token"),
        "{se}"
    );
    assert!(!se.contains("not-a-token"), "{se}");
    assert_eq!(home_listing(&e.home), vec!["daemon.lock".to_string()]);
}

#[test]
fn token_rejected_by_telegram_exits_1() {
    let e = Env::new();
    let tg = Tg::start_with_get_me(ResponseTemplate::new(401).set_body_json(json!({
        "ok": false, "error_code": 401, "description": "Unauthorized"
    })));
    e.mock(&tg.base(), json!([]));
    let o = e.daemon_cmd().output().unwrap();
    let se = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(1), "{se}");
    assert!(se.contains("Telegram rejected the bot token"), "{se}");
    assert_eq!(home_listing(&e.home), vec!["daemon.lock".to_string()]);
    assert_token_absent(&e, &String::from_utf8_lossy(&o.stdout), &se);
}

#[test]
fn revoked_token_404_on_get_me_exits_1() {
    let e = Env::new();
    let tg = Tg::start_with_get_me(ResponseTemplate::new(404).set_body_json(json!({
        "ok": false, "error_code": 404, "description": "Not Found"
    })));
    e.mock(&tg.base(), json!([]));
    let o = e.daemon_cmd().output().unwrap();
    let se = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(1), "{se}");
    assert!(se.contains("Telegram rejected the bot token"), "{se}");
    assert_eq!(home_listing(&e.home), vec!["daemon.lock".to_string()]);
    assert_token_absent(&e, &String::from_utf8_lossy(&o.stdout), &se);
}

#[test]
fn unreachable_telegram_exits_1_naming_the_kind() {
    let e = Env::new();
    // A loopback port nobody listens on.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    e.mock(&format!("http://127.0.0.1:{port}"), json!([]));
    let o = e.daemon_cmd().output().unwrap();
    let se = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(1), "{se}");
    assert!(se.contains("cannot reach Telegram (connect)"), "{se}");
    assert_eq!(home_listing(&e.home), vec!["daemon.lock".to_string()]);
    assert_token_absent(&e, &String::from_utf8_lossy(&o.stdout), &se);
}

/// Run a daemon whose first `getUpdates` answers `code`; it must exit 1
/// with `fatal` on stderr after auditing the session end.
fn fatal_mid_run(code: u16, fatal: &str) {
    let e = Env::new();
    let tg = Tg::start();
    e.mock(&tg.base(), json!([]));
    tg.push_response(ResponseTemplate::new(code).set_body_json(json!({
        "ok": false, "error_code": code, "description": "x"
    })));
    let mut d = e.spawn();
    d.ready();
    assert_eq!(d.wait_exit(), 1, "{}", d.stderr());
    let se = d.stderr();
    assert!(se.contains(&format!("error: {fatal}")), "{se}");
    assert_eq!(
        e.decisions().last().map(String::as_str),
        Some("daemon session ended"),
        "{}",
        e.audit_text()
    );
    assert_token_absent(&e, &d.stdout(), &se);
}

#[test]
fn telegram_fatal_mid_run_exits_1() {
    fatal_mid_run(
        409,
        "another program is receiving updates for this bot (Telegram 409 conflict)",
    );
    fatal_mid_run(401, "Telegram rejected the bot token");
}

/// Every regular file under `dir`, recursively.
fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for ent in fs::read_dir(dir).unwrap() {
        let p = ent.unwrap().path();
        let m = fs::symlink_metadata(&p).unwrap();
        if m.is_dir() {
            files_under(&p, out);
        } else if m.is_file() {
            out.push(p);
        }
    }
}

#[test]
fn daemon_never_prints_or_audits_the_token() {
    let e = Env::new();
    let tg = Tg::start();
    let a = e.root.join("a.txt");
    fs::write(&a, "old").unwrap();
    e.mock(&tg.base(), write_script("a.txt", "new"));
    let mut d = e.spawn();
    d.ready();
    tg.push(vec![owner_text(1, "update a.txt")]);
    let code = wait_for_code(&mut d, &tg);
    tg.push(vec![owner_text(2, &format!("yes {code}"))]);
    d.wait_for("no done message", || sent_contains(&tg, OWNER, "done:"));
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    let (so, se) = (d.stdout(), d.stderr());
    for needle in [TOKEN, TOKEN_SECRET] {
        assert!(!so.contains(needle), "stdout: {so}");
        assert!(!se.contains(needle), "stderr: {se}");
    }
    let mut files = Vec::new();
    files_under(&e.home, &mut files);
    assert!(!files.is_empty());
    for f in files {
        let bytes = fs::read(&f).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        for needle in [TOKEN, TOKEN_SECRET] {
            assert!(!text.contains(needle), "{} holds the token", f.display());
        }
    }
    // Nothing the user typed reaches stderr either.
    assert!(!se.contains("update a.txt"), "{se}");
}

/// Poll until nobody holds the audit log's lock, then let go of it again.
fn wait_for_audit_unlocked(d: &mut Daemon, e: &Env) {
    let f = fs::File::open(e.home.join("audit.jsonl")).unwrap();
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match f.try_lock() {
            Ok(()) => {
                f.unlock().unwrap();
                return;
            }
            Err(fs::TryLockError::WouldBlock) => {}
            Err(fs::TryLockError::Error(err)) => panic!("cannot lock the audit log: {err}"),
        }
        if Instant::now() >= deadline {
            d.fail("the daemon never released the audit log");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn warden_undo_works_while_the_daemon_is_idle() {
    const PIN: &str = "4815162342";
    let e = Env::new();
    let tg = Tg::start();
    let a = e.root.join("a.txt");
    fs::write(&a, "old").unwrap();
    e.mock(&tg.base(), write_script("a.txt", "new"));
    e.warden().args(["init-pin", PIN]).assert().success();
    let mut d = e.spawn();
    d.ready();
    tg.push(vec![owner_text(1, "update a.txt")]);
    let code = wait_for_code(&mut d, &tg);
    tg.push(vec![owner_text(2, &format!("yes {code}"))]);
    d.wait_for("the message never finished", || {
        sent_contains(&tg, OWNER, "all done")
    });
    assert_eq!(fs::read_to_string(&a).unwrap(), "new");
    let id = e
        .decisions()
        .iter()
        .find_map(|x| x.strip_prefix("executed snapshot=").map(str::to_owned))
        .expect("snapshot id in the audit log");

    wait_for_audit_unlocked(&mut d, &e);
    assert!(
        d.child.try_wait().unwrap().is_none(),
        "the daemon is running"
    );
    let o = e
        .warden()
        .env("WARDEN_PIN", PIN)
        .args(["undo", &id, "--root"])
        .arg(&e.root)
        .arg("--yes")
        .output()
        .unwrap();
    if o.status.code() != Some(0) {
        let why = format!(
            "undo failed: {}\n{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        d.fail(&why);
    }
    assert_eq!(fs::read_to_string(&a).unwrap(), "old");
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    let decisions = e.decisions();
    assert!(
        decisions.iter().any(|x| x.starts_with("restored files=")),
        "{decisions:?}"
    );
    assert_eq!(
        decisions.last().map(String::as_str),
        Some("daemon session ended"),
        "{decisions:?}"
    );
    e.warden().args(["audit", "verify"]).assert().success();
    // The deleteMessage log exists for PIN-shaped replies only; none here.
    assert!(tg.deleted.all().is_empty(), "{:?}", tg.deleted.all());
}

/// Neither the token nor its secret half is in `stdout`, `stderr` or any
/// file under the data dir.
fn assert_token_absent(e: &Env, stdout: &str, stderr: &str) {
    for needle in [TOKEN, TOKEN_SECRET] {
        assert!(!stdout.contains(needle), "stdout: {stdout}");
        assert!(!stderr.contains(needle), "stderr: {stderr}");
    }
    let mut files = Vec::new();
    files_under(&e.home, &mut files);
    for f in files {
        let text = String::from_utf8_lossy(&fs::read(&f).unwrap()).into_owned();
        for needle in [TOKEN, TOKEN_SECRET] {
            assert!(!text.contains(needle), "{} holds the token", f.display());
        }
    }
}

// --------------------------------------------------------- print-service

/// `warden --home <home> daemon print-service <args> --config <config>`.
fn print_service(e: &Env, args: &[&str]) -> std::process::Output {
    let mut c = e.warden();
    c.arg("daemon").arg("print-service").args(args);
    c.arg("--config").arg(&e.config);
    c.output().unwrap()
}

/// The canonical path of the `warden` binary under test.
fn warden_exe() -> String {
    fs::canonicalize(assert_cmd::cargo::cargo_bin("warden"))
        .unwrap()
        .display()
        .to_string()
}

#[test]
fn print_service_launchd_has_absolute_paths_and_placeholders() {
    let e = Env::new();
    e.mock("http://127.0.0.1:9", json!([]));
    let o = print_service(&e, &["--launchd"]);
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    let se = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(0), "{se}");
    for needle in [
        warden_exe(),
        e.home.display().to_string(),
        e.config.display().to_string(),
        format!("{}/daemon.log", e.home.display()),
        "<string>--home</string>".to_string(),
        "<string>daemon</string>".to_string(),
        "<string>--config</string>".to_string(),
        "<string>local.warden.daemon</string>".to_string(),
        "<key>ANTHROPIC_API_KEY</key>".to_string(),
        "<key>WARDEN_TELEGRAM_TOKEN</key>".to_string(),
        "<string>REPLACE_ME</string>".to_string(),
        "<key>SuccessfulExit</key>".to_string(),
        "chmod 600".to_string(),
    ] {
        assert!(out.contains(&needle), "missing {needle}:\n{out}");
    }
    assert!(out.starts_with("<?xml"), "{out}");
    // The token is in the environment (Env::warden) but never printed.
    assert_token_absent(&e, &out, &se);
}

#[test]
fn print_service_systemd_has_execstart_and_environment_file() {
    let e = Env::new();
    e.mock("http://127.0.0.1:9", json!([]));
    let o = print_service(&e, &["--systemd"]);
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    let se = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(0), "{se}");
    let exec = format!(
        "ExecStart=\"{}\" --home \"{}\" daemon --config \"{}\"\n",
        warden_exe(),
        e.home.display(),
        e.config.display()
    );
    for needle in [
        exec.as_str(),
        "EnvironmentFile=%h/.config/warden/daemon.env\n",
        "Restart=on-failure\n",
        "RestartSec=60\n",
        "TimeoutStopSec=60\n",
        "KillSignal=SIGTERM\n",
        "NoNewPrivileges=yes\n",
        "UMask=0077\n",
        "WantedBy=default.target\n",
        "ANTHROPIC_API_KEY=REPLACE_ME",
        "WARDEN_TELEGRAM_TOKEN=REPLACE_ME",
    ] {
        assert!(out.contains(needle), "missing {needle}:\n{out}");
    }
    assert_token_absent(&e, &out, &se);
}

#[test]
fn print_service_requires_exactly_one_format() {
    let e = Env::new();
    e.mock("http://127.0.0.1:9", json!([]));
    for args in [&[][..], &["--launchd", "--systemd"][..]] {
        let o = print_service(&e, args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert!(o.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn print_service_refuses_paths_with_quotes_or_percent() {
    let e = Env::new();
    e.mock("http://127.0.0.1:9", json!([]));
    // A data dir with a quote or a percent sign.
    for bad in ["ho\"me", "ho%me", "ho$me", "ho`me", "ho\nme"] {
        let o = e
            .warden_at(&e.base.join(bad))
            .args(["daemon", "print-service", "--systemd", "--config"])
            .arg(&e.config)
            .output()
            .unwrap();
        let se = String::from_utf8_lossy(&o.stderr).into_owned();
        assert_eq!(o.status.code(), Some(1), "{bad:?}: {se}");
        assert!(se.contains("path not supported in a service file"), "{se}");
        assert!(o.stdout.is_empty(), "{bad:?}");
        assert!(!e.base.join(bad).exists(), "{bad:?}");
    }
    // A config path with a quote.
    let quoted = e.base.join("con'fig.toml");
    fs::copy(&e.config, &quoted).unwrap();
    fs::set_permissions(&quoted, fs::Permissions::from_mode(0o600)).unwrap();
    let o = e
        .warden()
        .args(["daemon", "print-service", "--launchd", "--config"])
        .arg(&quoted)
        .output()
        .unwrap();
    let se = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(1), "{se}");
    assert!(se.contains("path not supported in a service file"), "{se}");
    assert!(o.stdout.is_empty());
}

#[test]
fn print_service_writes_nothing_to_disk() {
    let e = Env::new();
    e.mock("http://127.0.0.1:9", json!([]));
    let before = home_listing(&e.home);
    let base_before = home_listing(&e.base);
    for fmt in ["--launchd", "--systemd"] {
        let o = print_service(&e, &[fmt]);
        assert_eq!(o.status.code(), Some(0), "{fmt}");
    }
    assert_eq!(home_listing(&e.home), before);
    assert_eq!(home_listing(&e.base), base_before);
    // A data dir that does not exist yet is not created.
    let missing = e.base.join("not-yet");
    let o = e
        .warden_at(&missing)
        .args(["daemon", "print-service", "--launchd", "--config"])
        .arg(&e.config)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0));
    assert!(!missing.exists());
}

/// A `[whatsapp]` table body with the default env names.
const WA_TABLE: &str =
    "[whatsapp]\nowner_numbers = [\"+15551234567\"]\nphone_number_id = \"106540352242922\"\n";

/// The three default WhatsApp secret env names, with fake values.
const WA_VARS: [(&str, &str); 3] = [
    (
        "WARDEN_WHATSAPP_TOKEN",
        "EAAGfakeAccessTokenDONOTLEAK0123456789",
    ),
    (
        "WARDEN_WHATSAPP_APP_SECRET",
        "fakeappsecretDONOTLEAK0123456789ab",
    ),
    (
        "WARDEN_WHATSAPP_VERIFY_TOKEN",
        "fakeverifytokenDONOTLEAK987654321",
    ),
];

/// A mock-provider config holding `tables` after the top-level fields.
fn config_with_tables(e: &Env, tables: &str) {
    let s = e.base.join("script.json");
    fs::write(&s, "[]").unwrap();
    e.config_text(&format!(
        "root = \"{}\"\nprovider = \"mock\"\nscript = \"{}\"\n\n{tables}",
        e.root.display(),
        s.display()
    ));
}

/// [`print_service`] with the WhatsApp secrets set to fake values.
fn print_service_wa(e: &Env, fmt: &str) -> (String, String, Option<i32>) {
    let mut c = e.warden();
    for (k, v) in WA_VARS {
        c.env(k, v);
    }
    c.args(["daemon", "print-service", fmt, "--config"])
        .arg(&e.config);
    let o = c.output().unwrap();
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
        o.status.code(),
    )
}

#[test]
fn print_service_lists_whatsapp_env_names() {
    let e = Env::new();
    // [whatsapp] only.
    config_with_tables(&e, WA_TABLE);
    for fmt in ["--launchd", "--systemd"] {
        let (out, se, code) = print_service_wa(&e, fmt);
        assert_eq!(code, Some(0), "{fmt}: {se}");
        for (name, _) in WA_VARS {
            assert!(out.contains(name), "{fmt}: missing {name}:\n{out}");
        }
        assert!(out.contains("REPLACE_ME"), "{fmt}:\n{out}");
        assert!(out.contains(KEY_VAR), "{fmt}:\n{out}");
        assert!(!out.contains(TOKEN_VAR), "{fmt}:\n{out}");
        for (_, value) in WA_VARS {
            assert!(!out.contains(value), "{fmt}: value printed:\n{out}");
            assert!(!se.contains(value), "{fmt}: value in stderr:\n{se}");
        }
        assert_token_absent(&e, &out, &se);
    }
    let (out, _, _) = print_service_wa(&e, "--systemd");
    for (name, _) in WA_VARS {
        assert!(
            out.contains(&format!("#   {name}=REPLACE_ME\n")),
            "missing {name} line:\n{out}"
        );
    }
    // Both tables: all five names, in the documented order.
    config_with_tables(
        &e,
        &format!("[telegram]\nowner_ids = [{OWNER}]\n\n{WA_TABLE}"),
    );
    for fmt in ["--launchd", "--systemd"] {
        let (out, se, code) = print_service_wa(&e, fmt);
        assert_eq!(code, Some(0), "{fmt}: {se}");
        let names = [
            KEY_VAR,
            TOKEN_VAR,
            "WARDEN_WHATSAPP_TOKEN",
            "WARDEN_WHATSAPP_APP_SECRET",
            "WARDEN_WHATSAPP_VERIFY_TOKEN",
        ];
        let at: Vec<usize> = names
            .iter()
            .map(|n| {
                let pat = match fmt {
                    "--launchd" => format!("<key>{n}</key>"),
                    _ => format!("{n}=REPLACE_ME"),
                };
                out.find(&pat)
                    .unwrap_or_else(|| panic!("{fmt}: missing {pat}:\n{out}"))
            })
            .collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "{fmt}: order:\n{out}");
        for (_, value) in WA_VARS {
            assert!(!out.contains(value), "{fmt}: value printed:\n{out}");
            assert!(!se.contains(value), "{fmt}: value in stderr:\n{se}");
        }
        assert_token_absent(&e, &out, &se);
    }
    // Copy changes.
    let (plist, _, _) = print_service_wa(&e, "--launchd");
    assert!(plist.contains("API key and the channel secrets"), "{plist}");
    let (unit, _, _) = print_service_wa(&e, "--systemd");
    assert!(unit.contains("Description=Warden agent daemon\n"), "{unit}");
}

#[test]
fn print_service_without_any_channel_exits_1() {
    let e = Env::new();
    config_with_tables(&e, "");
    for fmt in ["--launchd", "--systemd"] {
        let o = print_service(&e, &[fmt]);
        let se = String::from_utf8_lossy(&o.stderr).into_owned();
        assert_eq!(o.status.code(), Some(1), "{fmt}: {se}");
        assert!(
            se.contains("error: no channel configured: add a [telegram] or [whatsapp] table"),
            "{fmt}: {se}"
        );
        assert!(o.stdout.is_empty(), "{fmt}");
    }
}
