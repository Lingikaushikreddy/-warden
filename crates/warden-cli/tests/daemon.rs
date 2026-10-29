//! End-to-end tests for `warden daemon`. Telegram and the WhatsApp Graph
//! API are loopback wiremock servers (`api_base`) running on tokio runtimes
//! owned by the test; WhatsApp webhooks are signed and posted to the
//! daemon's loopback listener over a raw `TcpStream`. The planner is the
//! `test-hooks` scripted one (`provider = "mock"`). The daemon is a real
//! child process, stopped with `kill -TERM`.

use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as StdCommand, Stdio};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const KEY_VAR: &str = "ANTHROPIC_API_KEY";
const TOKEN_VAR: &str = "WARDEN_TELEGRAM_TOKEN";
const TOKEN: &str = "123456789:AAH-secret_half_0123456789abcdefDONOTLEAK";
const TOKEN_SECRET: &str = "AAH-secret_half_0123456789abcdefDONOTLEAK";
const OWNER: i64 = 42;
const STRANGER: i64 = 666;
/// The WhatsApp owner number and the business phone number id.
const WA_OWNER: &str = "15550000042";
const PNID: &str = "106540352242922";
const WA_TOKEN: &str = "EAAox9yimTcfipZGnzPbDFDyFKm51zfFoWbSrHAE56yUhQqg0eyN1ygQdvpSfF5";
const WA_APP_SECRET: &str = "6421f64ee9bd453abf694b927b709a78";
const WA_VERIFY: &str = "cBqyt1T5AlQzhk7Q2bmXktha";
/// The three default WhatsApp secret env names, with fake values.
const WA_VARS: [(&str, &str); 3] = [
    ("WARDEN_WHATSAPP_TOKEN", WA_TOKEN),
    ("WARDEN_WHATSAPP_APP_SECRET", WA_APP_SECRET),
    ("WARDEN_WHATSAPP_VERIFY_TOKEN", WA_VERIFY),
];
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
            .envs(WA_VARS)
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
            .envs(WA_VARS)
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
fn daemon_without_any_channel_exits_1() {
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
        se.contains("error: no channel configured: add a [telegram] or [whatsapp] table"),
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

/// Every secret value the tests put in the environment.
const SECRETS: [&str; 5] = [TOKEN, TOKEN_SECRET, WA_TOKEN, WA_APP_SECRET, WA_VERIFY];

/// Neither the bot token (nor its secret half) nor any WhatsApp secret is
/// in `stdout`, `stderr` or any file under the data dir.
fn assert_token_absent(e: &Env, stdout: &str, stderr: &str) {
    for needle in SECRETS {
        assert!(!stdout.contains(needle), "stdout: {stdout}");
        assert!(!stderr.contains(needle), "stderr: {stderr}");
    }
    let mut files = Vec::new();
    files_under(&e.home, &mut files);
    for f in files {
        let text = String::from_utf8_lossy(&fs::read(&f).unwrap()).into_owned();
        for needle in SECRETS {
            assert!(!text.contains(needle), "{} holds a secret", f.display());
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

// ------------------------------------------------------------ fake WhatsApp

/// `POST /v26.0/<PNID>/messages`: record the body, answer with
/// `wamid.test<n>`.
#[derive(Clone)]
struct WaRecorder {
    log: Log,
    next_id: Arc<AtomicI64>,
}

impl Respond for WaRecorder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        let to = v["to"].clone();
        self.log.0.lock().unwrap().push(v);
        let n = self.next_id.fetch_add(1, Ordering::SeqCst);
        ResponseTemplate::new(200).set_body_json(json!({
            "messaging_product": "whatsapp",
            "contacts": [{"input": to, "wa_id": to}],
            "messages": [{"id": format!("wamid.test{n}")}],
        }))
    }
}

/// The Graph API on a test-owned runtime.
struct Wa {
    rt: tokio::runtime::Runtime,
    server: MockServer,
    sent: Log,
}

fn graph_path(suffix: &str) -> String {
    format!("/v26.0/{PNID}{suffix}")
}

impl Wa {
    fn start() -> Wa {
        Wa::start_with_phone(ResponseTemplate::new(200).set_body_json(json!({
            "display_phone_number": "+1 555-010-0000",
            "verified_name": "Warden Test",
            "id": PNID,
        })))
    }

    fn start_with_phone(phone: ResponseTemplate) -> Wa {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let server = rt.block_on(MockServer::start());
        let sent = Log::default();
        rt.block_on(async {
            Mock::given(method("GET"))
                .and(path(graph_path("")))
                .respond_with(phone)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(graph_path("/messages")))
                .respond_with(WaRecorder {
                    log: sent.clone(),
                    next_id: Arc::new(AtomicI64::new(1)),
                })
                .mount(&server)
                .await;
        });
        Wa { rt, server, sent }
    }

    fn base(&self) -> String {
        self.server.uri()
    }

    /// Text bodies sent to `number`.
    fn texts_to(&self, number: &str) -> Vec<String> {
        self.sent
            .all()
            .iter()
            .filter(|v| v["to"] == number)
            .map(|v| v["text"]["body"].as_str().unwrap_or_default().to_owned())
            .collect()
    }

    fn sent_contains(&self, needle: &str) -> bool {
        self.texts_to(WA_OWNER).iter().any(|t| t.contains(needle))
    }

    fn count(&self, needle: &str) -> usize {
        self.texts_to(WA_OWNER)
            .iter()
            .filter(|t| t.contains(needle))
            .count()
    }
}

/// A signed-ready webhook body with one text message.
fn wa_text(wamid: &str, from: &str, text: &str, ts: i64) -> Value {
    json!({
        "object": "whatsapp_business_account",
        "entry": [{"id": "1029384756", "changes": [{"field": "messages", "value": {
            "messaging_product": "whatsapp",
            "metadata": {"display_phone_number": "15550100000", "phone_number_id": PNID},
            "contacts": [{"profile": {"name": "x"}, "wa_id": from}],
            "messages": [{
                "from": from,
                "id": wamid,
                "timestamp": ts.to_string(),
                "type": "text",
                "text": {"body": text},
            }],
        }}]}],
    })
}

/// Send one raw HTTP/1.1 request (`Connection: close`) and return the
/// status code and the body.
fn http(addr: SocketAddr, head: &str, body: &[u8]) -> (u16, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(TIMEOUT)).unwrap();
    let mut req = head.as_bytes().to_vec();
    req.extend_from_slice(body);
    s.write_all(&req).unwrap();
    let mut resp = Vec::new();
    let _ = s.read_to_end(&mut resp);
    let resp = String::from_utf8_lossy(&resp).into_owned();
    let code = resp
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status line: {resp:?}"));
    let body = resp
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    (code, body)
}

/// POST `body` to the webhook, signed with `secret` when given.
fn post_webhook(addr: SocketAddr, body: &Value, secret: Option<&str>) -> u16 {
    let (head, raw) = webhook_request(addr, body, secret);
    http(addr, &head, &raw).0
}

/// The head and body of a webhook POST, signed with `secret` when given.
fn webhook_request(addr: SocketAddr, body: &Value, secret: Option<&str>) -> (String, Vec<u8>) {
    let raw = serde_json::to_vec(body).unwrap();
    let mut head = format!(
        "POST /webhook HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        raw.len()
    );
    if let Some(secret) = secret {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(&raw);
        let sig = hex::encode(mac.finalize().into_bytes());
        head.push_str(&format!("X-Hub-Signature-256: sha256={sig}\r\n"));
    }
    head.push_str("\r\n");
    (head, raw)
}

/// Whether a correctly signed owner text is NOT taken: the connection is
/// refused or reset, or the answer is anything but 200.
fn webhook_refused(addr: SocketAddr) -> bool {
    let body = wa_text("wamid.probe", WA_OWNER, "probe", now_s());
    let (head, raw) = webhook_request(addr, &body, Some(WA_APP_SECRET));
    let Ok(mut s) = TcpStream::connect(addr) else {
        return true;
    };
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut req = head.into_bytes();
    req.extend_from_slice(&raw);
    if s.write_all(&req).is_err() {
        return true;
    }
    let mut resp = Vec::new();
    let _ = s.read_to_end(&mut resp);
    String::from_utf8_lossy(&resp).split_whitespace().nth(1) != Some("200")
}

/// The listener refuses a signed webhook while the daemon process is
/// still running, so the kernel closing the socket at exit cannot be what
/// refused it. At most 10 probes, far below the 16-batch queue, so a full
/// queue's 503 cannot pass for a stopped listener either.
fn assert_listener_stops_while_alive(d: &mut Daemon, addr: SocketAddr) {
    for _ in 0..10 {
        let refused = webhook_refused(addr);
        if d.child.try_wait().unwrap().is_some() {
            d.fail("the daemon exited before its listener was seen refusing webhooks");
        }
        if refused {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    d.fail("the webhook listener still takes webhooks after shutdown started");
}

/// Requests the fake Graph API received on `path`.
fn graph_hits(wa: &Wa, suffix: &str) -> usize {
    wa.rt
        .block_on(wa.server.received_requests())
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == graph_path(suffix))
        .count()
}

/// An owner text, signed with the right secret; must be accepted.
fn post_owner(d: &mut Daemon, addr: SocketAddr, wamid: &str, text: &str) {
    let code = post_webhook(
        addr,
        &wa_text(wamid, WA_OWNER, text, now_s()),
        Some(WA_APP_SECRET),
    );
    if code != 200 {
        d.fail(&format!("webhook answered {code}"));
    }
}

/// GET the webhook with `query`.
fn get_webhook(addr: SocketAddr, query: &str) -> (u16, String) {
    let head =
        format!("GET /webhook?{query} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    http(addr, &head, &[])
}

impl Env {
    /// A mock-provider config with a `[whatsapp]` table pointing at
    /// `api_base` and listening on an ephemeral loopback port, plus a
    /// `[telegram]` table pointing at `telegram` if given.
    fn mock_wa(&self, api_base: &str, script: Value, telegram: Option<&str>) {
        self.mock_wa_listen(api_base, script, telegram, "127.0.0.1:0");
    }

    fn mock_wa_listen(&self, api_base: &str, script: Value, telegram: Option<&str>, listen: &str) {
        let s = self.base.join("script.json");
        fs::write(&s, serde_json::to_vec(&script).unwrap()).unwrap();
        let tg = telegram
            .map(|b| format!("[telegram]\nowner_ids = [{OWNER}]\napi_base = \"{b}\"\n\n"))
            .unwrap_or_default();
        self.config_text(&format!(
            "root = \"{}\"\nprovider = \"mock\"\nscript = \"{}\"\n\n{tg}[whatsapp]\nowner_numbers = [\"{WA_OWNER}\"]\nphone_number_id = \"{PNID}\"\nlisten = \"{listen}\"\napi_base = \"{api_base}\"\n",
            self.root.display(),
            s.display()
        ));
    }
}

impl Daemon {
    /// Wait for a banner that names the WhatsApp listener.
    fn ready_wa(&mut self) -> SocketAddr {
        let err = Arc::clone(&self.stderr);
        let re = regex::Regex::new(r"warden daemon: .*listen=\S+ owners=\d+ root=").unwrap();
        self.wait_for("the daemon never printed its banner", move || {
            re.is_match(&err.lock().unwrap())
        });
        listen_addr(self)
    }
}

/// The bound webhook address, from the banner's `listen=`.
fn listen_addr(d: &Daemon) -> SocketAddr {
    let se = d.stderr();
    let re = regex::Regex::new(r"listen=(\S+) ").unwrap();
    let c = re
        .captures(&se)
        .unwrap_or_else(|| panic!("no listen= in {se}"));
    c[1].parse().unwrap()
}

/// Wait for a WhatsApp prompt and return its challenge code.
fn wait_for_wa_code(d: &mut Daemon, wa: &Wa) -> String {
    let re = regex::Regex::new(r#"Reply "yes (\d{4})"#).unwrap();
    let find = || {
        wa.texts_to(WA_OWNER)
            .iter()
            .find_map(|t| re.captures(t).map(|c| c[1].to_string()))
    };
    d.wait_for("the daemon never prompted over WhatsApp", || {
        find().is_some()
    });
    find().unwrap()
}

#[test]
fn whatsapp_daemon_answers_an_owner_text() {
    let e = Env::new();
    let wa = Wa::start();
    e.mock_wa(&wa.base(), json!([{"text": "hello owner"}]), None);
    let mut d = e.spawn();
    let addr = d.ready_wa();
    assert!(
        d.stderr().contains(&format!(
            "warden daemon: whatsapp +1 555-010-0000 listen={addr} owners=1 root={}",
            e.root.display()
        )),
        "{}",
        d.stderr()
    );
    post_owner(&mut d, addr, "wamid.in1", "hi");
    d.wait_for("no model reply", || wa.sent_contains("model: "));
    assert!(wa.sent_contains("hello owner"), "{:?}", wa.sent.all());
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    for v in wa.sent.all() {
        assert_eq!(v["to"], WA_OWNER, "{v}");
        assert_eq!(v["type"], "text", "{v}");
        assert_eq!(v["text"]["preview_url"], false, "{v}");
    }
    // No refusal or window drop: no counters line.
    assert!(!d.stderr().contains("whatsapp: refused"), "{}", d.stderr());
}

#[test]
fn whatsapp_forged_webhooks_are_401_and_never_acted_on() {
    let e = Env::new();
    let wa = Wa::start();
    // Empty script: a planner call would fail.
    e.mock_wa(&wa.base(), json!([]), None);
    let mut d = e.spawn();
    let addr = d.ready_wa();
    let body = wa_text("wamid.forged", WA_OWNER, "delete everything", now_s());
    assert_eq!(post_webhook(addr, &body, None), 401);
    assert_eq!(
        post_webhook(addr, &body, Some("00000000000000000000000000000000")),
        401
    );
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    let posts = wa
        .rt
        .block_on(wa.server.received_requests())
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() == "POST")
        .count();
    assert_eq!(posts, 0, "{:?}", wa.sent.all());
    let decisions = e.decisions();
    assert!(
        !decisions.iter().any(|x| x.starts_with("ignored")),
        "{decisions:?}"
    );
    assert!(!e.audit_text().contains("delete everything"));
    assert!(
        d.stderr().contains(
            "whatsapp: refused 1 unsigned, 1 bad-signature, 0 oversized, 0 slow webhook requests; 0 replies not sent outside the 24 h window"
        ),
        "{}",
        d.stderr()
    );
}

#[test]
fn whatsapp_handshake_needs_the_verify_token() {
    let e = Env::new();
    let wa = Wa::start();
    e.mock_wa(&wa.base(), json!([]), None);
    let mut d = e.spawn();
    let addr = d.ready_wa();
    let (code, body) = get_webhook(
        addr,
        &format!("hub.mode=subscribe&hub.verify_token={WA_VERIFY}&hub.challenge=1158201444"),
    );
    assert_eq!((code, body.as_str()), (200, "1158201444"));
    let (code, body) = get_webhook(
        addr,
        "hub.mode=subscribe&hub.verify_token=wrongwrongwrongwrong&hub.challenge=1158201444",
    );
    assert_eq!(code, 403);
    assert!(!body.contains("1158201444"), "{body}");
    assert_eq!(d.stop(), 0, "{}", d.stderr());
}

#[test]
fn whatsapp_write_needs_yes_code() {
    let e = Env::new();
    let wa = Wa::start();
    let a = e.root.join("a.txt");
    fs::write(&a, "old").unwrap();
    e.mock_wa(&wa.base(), write_script("a.txt", "new"), None);
    let mut d = e.spawn();
    let addr = d.ready_wa();
    post_owner(&mut d, addr, "wamid.in1", "update a.txt");
    let code = wait_for_wa_code(&mut d, &wa);
    assert_eq!(fs::read_to_string(&a).unwrap(), "old");
    post_owner(&mut d, addr, "wamid.in2", &format!("yes {code}"));
    d.wait_for("no done message", || wa.sent_contains("done:"));
    assert_eq!(fs::read_to_string(&a).unwrap(), "new");
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    let decisions = e.decisions();
    assert!(
        decisions.iter().any(|x| x.starts_with("executed")),
        "{decisions:?}"
    );
}

#[test]
fn whatsapp_refuses_pin_tier_without_a_prompt() {
    const PIN: &str = "4815162342";
    let e = Env::new();
    let wa = Wa::start();
    let a = e.root.join("a.txt");
    fs::write(&a, "keep me").unwrap();
    e.mock_wa(
        &wa.base(),
        json!([
            {"text": "deleting", "calls": [
                {"id": "t1", "name": "delete_file", "args": {"path": "a.txt"}}
            ]},
            {"text": "all done"}
        ]),
        None,
    );
    e.warden().args(["init-pin", PIN]).assert().success();
    let mut d = e.spawn();
    let addr = d.ready_wa();
    post_owner(&mut d, addr, "wamid.in1", "delete a.txt");
    d.wait_for("the owner was not told", || {
        wa.sent_contains("does not accept")
    });
    d.wait_for("the message never finished", || {
        wa.sent_contains("all done")
    });
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    assert!(a.exists());
    assert!(
        !wa.texts_to(WA_OWNER)
            .iter()
            .any(|t| t.contains("Reply \"yes")),
        "{:?}",
        wa.sent.all()
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
fn whatsapp_pin_like_message_never_reaches_the_planner() {
    const PIN: &str = "4815162342";
    let e = Env::new();
    let wa = Wa::start();
    // Empty script: a planner call would fail.
    e.mock_wa(&wa.base(), json!([]), None);
    e.warden().args(["init-pin", PIN]).assert().success();
    let mut d = e.spawn();
    let addr = d.ready_wa();
    post_owner(&mut d, addr, "wamid.in1", PIN);
    d.wait_for("the owner was not told", || {
        wa.sent_contains("looks like your PIN")
    });
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    let decisions = e.decisions();
    assert!(
        decisions.iter().any(|x| x == "ignored: pin-like message"),
        "{decisions:?}"
    );
    assert!(!e.audit_text().contains(PIN));
}

#[test]
fn whatsapp_duplicate_delivery_is_acted_on_once() {
    let e = Env::new();
    let wa = Wa::start();
    e.mock_wa(
        &wa.base(),
        json!([{"text": "reply one"}, {"text": "reply two"}, {"text": "reply three"}]),
        None,
    );
    let mut d = e.spawn();
    let addr = d.ready_wa();
    post_owner(&mut d, addr, "wamid.dup", "hi");
    post_owner(&mut d, addr, "wamid.dup", "hi");
    post_owner(&mut d, addr, "wamid.next", "hi again");
    d.wait_for("no second model reply", || wa.count("model: ") >= 2);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    assert_eq!(wa.count("model: "), 2, "{:?}", wa.sent.all());
    assert!(!wa.sent_contains("reply three"), "{:?}", wa.sent.all());
}

#[test]
fn whatsapp_redelivery_after_restart_is_not_replayed() {
    let e = Env::new();
    let wa = Wa::start();
    e.mock_wa(
        &wa.base(),
        json!([{"text": "reply one"}, {"text": "reply two"}]),
        None,
    );
    let mut d = e.spawn();
    let addr = d.ready_wa();
    post_owner(&mut d, addr, "wamid.once", "hi");
    d.wait_for("no model reply", || wa.count("model: ") == 1);
    assert_eq!(d.stop(), 0, "{}", d.stderr());

    // A new process starts its script over: a replay would be "reply one".
    let mut d = e.spawn();
    let addr = d.ready_wa();
    post_owner(&mut d, addr, "wamid.once", "hi");
    post_owner(&mut d, addr, "wamid.fresh", "hi again");
    d.wait_for("no reply to the fresh message", || wa.count("model: ") >= 2);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    assert_eq!(wa.count("model: "), 2, "{:?}", wa.sent.all());
    assert_eq!(wa.count("reply one"), 2, "{:?}", wa.sent.all());
    assert!(!wa.sent_contains("reply two"), "{:?}", wa.sent.all());
}

#[test]
fn whatsapp_drops_messages_older_than_max_age() {
    let e = Env::new();
    let wa = Wa::start();
    // Empty script: a planner call would fail.
    e.mock_wa(&wa.base(), json!([]), None);
    let mut d = e.spawn();
    let addr = d.ready_wa();
    let body = wa_text("wamid.old", WA_OWNER, "hi", now_s() - 3600);
    assert_eq!(post_webhook(addr, &body, Some(WA_APP_SECRET)), 200);
    d.wait_for("the owner was not told", || {
        wa.sent_contains("ignored 1 message")
    });
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    assert!(!wa.sent_contains("model: "), "{:?}", wa.sent.all());
}

#[test]
fn daemon_serves_telegram_and_whatsapp_together() {
    let e = Env::new();
    let tg = Tg::start();
    let wa = Wa::start();
    e.mock_wa(
        &wa.base(),
        json!([{"text": "reply one"}, {"text": "reply two"}]),
        Some(&tg.base()),
    );
    let mut d = e.spawn();
    let addr = d.ready_wa();
    assert!(
        d.stderr().contains(&format!(
            "warden daemon: telegram @warden_test_bot whatsapp +1 555-010-0000 listen={addr} owners=2 root={}",
            e.root.display()
        )),
        "{}",
        d.stderr()
    );
    tg.push(vec![owner_text(1, "hi")]);
    d.wait_for("no Telegram reply", || sent_contains(&tg, OWNER, "model: "));
    post_owner(&mut d, addr, "wamid.in1", "hi");
    d.wait_for("no WhatsApp reply", || wa.sent_contains("model: "));
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    // Each reply went out on its own channel only.
    assert_eq!(
        tg.texts_to(OWNER)
            .iter()
            .filter(|t| t.contains("model: "))
            .count(),
        1
    );
    assert_eq!(wa.count("model: "), 1, "{:?}", wa.sent.all());
    assert!(sent_contains(&tg, OWNER, "reply one"));
    assert!(wa.sent_contains("reply two"));
}

/// A WhatsApp text answered 200 while the engine waits on a Telegram
/// prompt is still in the batch queue at SIGTERM. Meta will not deliver it
/// again, so the owner is told to send it again and the exit line counts it.
#[test]
fn whatsapp_batch_unread_at_stop_gets_a_notice_and_is_counted() {
    let e = Env::new();
    let tg = Tg::start();
    let wa = Wa::start();
    let a = e.root.join("a.txt");
    fs::write(&a, "old").unwrap();
    e.mock_wa(&wa.base(), write_script("a.txt", "new"), Some(&tg.base()));
    let mut d = e.spawn();
    let addr = d.ready_wa();
    tg.push(vec![owner_text(1, "update a.txt")]);
    let _code = wait_for_code(&mut d, &tg);
    post_owner(&mut d, addr, "wamid.unread", "what time is it");
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    assert_eq!(fs::read_to_string(&a).unwrap(), "old");
    assert_eq!(
        wa.texts_to(WA_OWNER),
        vec!["Warden stopped before reading 1 message(s); send them again.".to_string()],
        "{}",
        d.stderr()
    );
    let se = d.stderr();
    assert!(se.contains("; other: 1 unread at stop"), "{se}");
    // Recorded as seen: a redelivery after a restart is not acted on.
    assert!(!e.audit_text().contains("what time is it"));
}

#[test]
fn whatsapp_token_rejected_at_startup_exits_1() {
    let e = Env::new();
    let wa = Wa::start_with_phone(ResponseTemplate::new(401).set_body_json(json!({
        "error": {"message": "Invalid OAuth access token.", "type": "OAuthException", "code": 190, "fbtrace_id": "x"}
    })));
    e.mock_wa(&wa.base(), json!([]), None);
    let o = e.daemon_cmd().output().unwrap();
    let se = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(1), "{se}");
    assert!(
        se.contains("error: WhatsApp rejected the access token"),
        "{se}"
    );
    assert!(!se.contains("Invalid OAuth"), "{se}");
    assert_eq!(home_listing(&e.home), vec!["daemon.lock".to_string()]);
    assert_token_absent(&e, &String::from_utf8_lossy(&o.stdout), &se);

    // The token cannot see the phone number id: Graph code 100, or a 404.
    for resp in [
        ResponseTemplate::new(400)
            .set_body_json(json!({"error": {"code": 100, "error_subcode": 33}})),
        ResponseTemplate::new(404),
    ] {
        let wa = Wa::start_with_phone(resp);
        e.mock_wa(&wa.base(), json!([]), None);
        let o = e.daemon_cmd().output().unwrap();
        let se = String::from_utf8_lossy(&o.stderr).into_owned();
        assert_eq!(o.status.code(), Some(1), "{se}");
        assert!(
            se.contains(&format!(
                "error: the access token cannot see phone_number_id {PNID}"
            )),
            "{se}"
        );
        assert_eq!(home_listing(&e.home), vec!["daemon.lock".to_string()]);
    }

    // Unreachable: the kind is named.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    e.mock_wa(&format!("http://127.0.0.1:{port}"), json!([]), None);
    let o = e.daemon_cmd().output().unwrap();
    let se = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(1), "{se}");
    assert!(
        se.contains("error: cannot reach the WhatsApp Cloud API (connect)"),
        "{se}"
    );
    assert_eq!(home_listing(&e.home), vec!["daemon.lock".to_string()]);
}

#[test]
fn whatsapp_token_rejected_mid_run_exits_1() {
    let e = Env::new();
    let wa = Wa::start();
    wa.rt.block_on(
        Mock::given(method("POST"))
            .and(path(graph_path("/messages")))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "error": {"message": "Error validating access token", "type": "OAuthException", "code": 190}
            })))
            .with_priority(1)
            .mount(&wa.server),
    );
    e.mock_wa(&wa.base(), json!([{"text": "hello owner"}]), None);
    let mut d = e.spawn();
    let addr = d.ready_wa();
    post_owner(&mut d, addr, "wamid.in1", "hi");
    assert_eq!(d.wait_exit(), 1, "{}", d.stderr());
    let se = d.stderr();
    assert!(
        se.contains("error: WhatsApp rejected the access token"),
        "{se}"
    );
    assert!(!se.contains("Error validating"), "{se}");
    assert_eq!(
        e.decisions().last().map(String::as_str),
        Some("daemon session ended"),
        "{}",
        e.audit_text()
    );
    assert_token_absent(&e, &d.stdout(), &se);
}

#[test]
fn whatsapp_missing_or_equal_secrets_exit_1_without_side_effects() {
    let e = Env::new();
    e.mock_wa("http://127.0.0.1:9", json!([]), None);
    for (var, _) in WA_VARS {
        let o = e.daemon_cmd().env_remove(var).output().unwrap();
        let se = String::from_utf8_lossy(&o.stderr).into_owned();
        assert_eq!(o.status.code(), Some(1), "{var}: {se}");
        assert!(se.contains(var), "{var}: {se}");
        assert!(se.contains("is not set or is empty"), "{var}: {se}");
        assert_eq!(home_listing(&e.home), vec!["daemon.lock".to_string()]);
        assert_token_absent(&e, &String::from_utf8_lossy(&o.stdout), &se);
    }
    // Badly shaped values are refused without being shown.
    for (var, what) in [
        ("WARDEN_WHATSAPP_TOKEN", "access token"),
        ("WARDEN_WHATSAPP_APP_SECRET", "app secret"),
        ("WARDEN_WHATSAPP_VERIFY_TOKEN", "verify token"),
    ] {
        let o = e.daemon_cmd().env(var, "bad value!").output().unwrap();
        let se = String::from_utf8_lossy(&o.stderr).into_owned();
        assert_eq!(o.status.code(), Some(1), "{var}: {se}");
        assert!(
            se.contains(&format!(
                "the WhatsApp {what} variable does not hold a valid {}",
                if what == "access token" {
                    "token"
                } else {
                    what
                }
            )),
            "{var}: {se}"
        );
        assert!(!se.contains("bad value!"), "{se}");
        assert_eq!(home_listing(&e.home), vec!["daemon.lock".to_string()]);
    }
    // Two equal secrets, either pair the shapes allow.
    for (var, value) in [
        ("WARDEN_WHATSAPP_VERIFY_TOKEN", WA_APP_SECRET),
        ("WARDEN_WHATSAPP_APP_SECRET", WA_TOKEN),
    ] {
        let o = e.daemon_cmd().env(var, value).output().unwrap();
        let se = String::from_utf8_lossy(&o.stderr).into_owned();
        assert_eq!(o.status.code(), Some(1), "{var}: {se}");
        assert!(
            se.contains(
                "error: the WhatsApp secrets, the bot token and the API key must all be different values"
            ),
            "{var}: {se}"
        );
        assert_eq!(home_listing(&e.home), vec!["daemon.lock".to_string()]);
        assert_token_absent(&e, &String::from_utf8_lossy(&o.stdout), &se);
    }
}

#[test]
fn whatsapp_listen_port_in_use_exits_1() {
    let e = Env::new();
    let wa = Wa::start();
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = held.local_addr().unwrap();
    e.mock_wa_listen(&wa.base(), json!([]), None, &addr.to_string());
    let o = e.daemon_cmd().output().unwrap();
    let se = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(1), "{se}");
    assert!(
        se.contains(&format!("error: {addr} is already in use")),
        "{se}"
    );
    assert_eq!(home_listing(&e.home), vec!["daemon.lock".to_string()]);
    drop(held);
}

#[test]
fn daemon_never_prints_or_audits_whatsapp_secrets() {
    let e = Env::new();
    let wa = Wa::start();
    e.mock_wa(&wa.base(), json!([{"text": "hello owner"}]), None);
    let mut d = e.spawn();
    let addr = d.ready_wa();
    let forged = wa_text("wamid.forged", WA_OWNER, "hi", now_s());
    assert_eq!(post_webhook(addr, &forged, Some(WA_VERIFY)), 401);
    let (code, _) = get_webhook(
        addr,
        &format!("hub.mode=subscribe&hub.verify_token={WA_VERIFY}&hub.challenge=42"),
    );
    assert_eq!(code, 200);
    post_owner(&mut d, addr, "wamid.in1", "hi");
    d.wait_for("no model reply", || wa.sent_contains("model: "));
    assert_eq!(d.stop(), 0, "{}", d.stderr());
    let mut files = Vec::new();
    files_under(&e.home, &mut files);
    assert!(
        files.iter().any(|f| f.ends_with("whatsapp-seen")),
        "{files:?}"
    );
    assert_token_absent(&e, &d.stdout(), &d.stderr());
    // The access token went in the header only.
    for r in wa.rt.block_on(wa.server.received_requests()).unwrap() {
        assert!(!r.url.as_str().contains(WA_TOKEN), "{}", r.url);
        let auth = r.headers.get("authorization").unwrap().to_str().unwrap();
        assert_eq!(auth, format!("Bearer {WA_TOKEN}"));
    }
}

#[test]
fn sigterm_stops_the_whatsapp_listener() {
    let e = Env::new();
    let wa = Wa::start();
    // The first reply hangs: the step is still sending when SIGTERM
    // arrives, and the daemon lives on for up to 5 s finishing it.
    wa.rt.block_on(
        Mock::given(method("POST"))
            .and(path(graph_path("/messages")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"messages": [{"id": "wamid.slow"}]}))
                    .set_delay(Duration::from_secs(30)),
            )
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&wa.server),
    );
    e.mock_wa(&wa.base(), json!([{"text": "hello owner"}]), None);
    let mut d = e.spawn();
    let addr = d.ready_wa();
    post_owner(&mut d, addr, "wamid.in1", "hi");
    d.wait_for("the reply was never sent", || {
        graph_hits(&wa, "/messages") > 0
    });
    d.term();
    let err = Arc::clone(&d.stderr);
    d.wait_for("the daemon never started shutting down", move || {
        err.lock()
            .unwrap()
            .contains("shutting down after the current step")
    });
    assert_listener_stops_while_alive(&mut d, addr);
    assert_eq!(d.wait_exit(), 0, "{}", d.stderr());
    assert_eq!(
        e.decisions().last().map(String::as_str),
        Some("daemon session ended")
    );
}

#[test]
fn whatsapp_fatal_stops_the_listener_while_the_daemon_runs() {
    let e = Env::new();
    let tg = Tg::start();
    let wa = Wa::start();
    // Telegram deletions hang, so the final flush keeps the daemon alive
    // for up to 5 s after shutdown has started.
    tg._rt.block_on(
        Mock::given(method("POST"))
            .and(path(bot_path("deleteMessage")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"ok": true, "result": true}))
                    .set_delay(Duration::from_secs(30)),
            )
            .with_priority(1)
            .mount(&tg.server),
    );
    // Every Graph send is a rejected token: the WhatsApp channel's fatal.
    wa.rt.block_on(
        Mock::given(method("POST"))
            .and(path(graph_path("/messages")))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "error": {"type": "OAuthException", "code": 190}
            })))
            .with_priority(1)
            .mount(&wa.server),
    );
    e.mock_wa(&wa.base(), json!([]), Some(&tg.base()));
    let mut d = e.spawn();
    let addr = d.ready_wa();
    // A stale, PIN-like Telegram message: dropped, and its deletion owed.
    tg.push(vec![private_text(1, OWNER, "4815162342", now_s() - 3600)]);
    let deleting = || {
        tg._rt
            .block_on(tg.server.received_requests())
            .unwrap()
            .iter()
            .any(|r| r.url.path() == bot_path("deleteMessage"))
    };
    d.wait_for("the deletion was never attempted", deleting);
    // A stale WhatsApp text: its notice meets the rejected token.
    let old = wa_text("wamid.old", WA_OWNER, "hi", now_s() - 3600);
    assert_eq!(post_webhook(addr, &old, Some(WA_APP_SECRET)), 200);
    d.wait_for("the notice was never sent", || {
        graph_hits(&wa, "/messages") > 0
    });
    assert_listener_stops_while_alive(&mut d, addr);
    assert_eq!(d.wait_exit(), 1, "{}", d.stderr());
    let se = d.stderr();
    assert!(
        se.contains("error: WhatsApp rejected the access token"),
        "{se}"
    );
    assert_eq!(
        e.decisions().last().map(String::as_str),
        Some("daemon session ended"),
        "{}",
        e.audit_text()
    );
    assert_token_absent(&e, &d.stdout(), &se);
}

/// A config for the real (Anthropic) planner, which no test reaches: every
/// one of them stops at startup.
fn anthropic_config(e: &Env, tables: &str) {
    e.config_text(&format!("root = \"{}\"\n\n{tables}", e.root.display()));
}

#[test]
fn api_key_equal_to_a_whatsapp_secret_exits_1_before_any_network_call() {
    let e = Env::new();
    let wa = Wa::start();
    anthropic_config(
        &e,
        &format!(
            "[whatsapp]\nowner_numbers = [\"{WA_OWNER}\"]\nphone_number_id = \"{PNID}\"\nlisten = \"127.0.0.1:0\"\napi_base = \"{}\"\n",
            wa.base()
        ),
    );
    for (_, value) in WA_VARS {
        let o = e.daemon_cmd().env(KEY_VAR, value).output().unwrap();
        let se = String::from_utf8_lossy(&o.stderr).into_owned();
        assert_eq!(o.status.code(), Some(1), "{se}");
        assert!(
            se.contains(
                "error: the WhatsApp secrets, the bot token and the API key must all be different values"
            ),
            "{se}"
        );
        assert_eq!(home_listing(&e.home), vec!["daemon.lock".to_string()]);
        assert_token_absent(&e, &String::from_utf8_lossy(&o.stdout), &se);
    }
    let hits = wa.rt.block_on(wa.server.received_requests()).unwrap();
    assert!(hits.is_empty(), "{hits:?}");
}

#[test]
fn api_key_equal_to_the_bot_token_exits_1_on_telegram_only() {
    let e = Env::new();
    let tg = Tg::start();
    anthropic_config(
        &e,
        &format!(
            "[telegram]\nowner_ids = [{OWNER}]\napi_base = \"{}\"\n",
            tg.base()
        ),
    );
    let o = e.daemon_cmd().env(KEY_VAR, TOKEN).output().unwrap();
    let se = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(1), "{se}");
    assert!(
        se.contains(
            "error: the WhatsApp secrets, the bot token and the API key must all be different values"
        ),
        "{se}"
    );
    assert_eq!(home_listing(&e.home), vec!["daemon.lock".to_string()]);
    assert_token_absent(&e, &String::from_utf8_lossy(&o.stdout), &se);
    let hits = tg._rt.block_on(tg.server.received_requests()).unwrap();
    assert!(hits.is_empty(), "{hits:?}");
}
