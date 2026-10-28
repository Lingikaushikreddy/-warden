//! Tests for the per-message audit lease: the engine holds the audit log
//! only while it handles a message, so other writers (`warden undo`) can
//! use it while the agent is idle.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use warden_agent::authorize::ApproverStore;
use warden_agent::channel::{ApprovalPrompt, ApprovalReply, Channel, Inbound, SenderId};
use warden_agent::engine::{Engine, EngineConfig};
use warden_agent::exec::Executor;
use warden_agent::lease::LeasedAuditLog;
use warden_agent::planner::{MockPlanner, PlanResponse, PlannerError};
use warden_agent::tools::ToolCall;
use warden_core::{AuditLog, SnapshotStore, Tier, VerifyReport};

const NOW: u64 = 1_700_000_000_000;

/// Records what is sent; answers every prompt with `yes`.
#[derive(Clone, Default)]
struct TestChannel {
    sent: Arc<Mutex<Vec<String>>>,
    prompts: Arc<Mutex<usize>>,
}

impl Channel for TestChannel {
    async fn recv(&mut self) -> Option<Inbound> {
        None
    }

    async fn send(&mut self, _to: &SenderId, text: &str) {
        self.sent.lock().unwrap().push(text.to_string());
    }

    async fn ask_approval(&mut self, _to: &SenderId, _prompt: &ApprovalPrompt) -> ApprovalReply {
        *self.prompts.lock().unwrap() += 1;
        ApprovalReply::Yes
    }
}

struct Env {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    snaps: PathBuf,
    channel: TestChannel,
}

impl Env {
    fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let home = tmp.path().join("home");
        let snaps = tmp.path().join("snaps");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&home).unwrap();
        Env {
            _tmp: tmp,
            root,
            home,
            snaps,
            channel: TestChannel::default(),
        }
    }

    fn log_path(&self) -> PathBuf {
        self.home.join("audit.jsonl")
    }

    fn engine(
        &self,
        script: Vec<Result<PlanResponse, PlannerError>>,
        sink: LeasedAuditLog,
    ) -> Engine<MockPlanner, TestChannel, LeasedAuditLog> {
        let store = ApproverStore::open(&self.home, NOW).unwrap();
        let snapshots = SnapshotStore::open(&self.snaps).unwrap();
        let exec = Executor::new(
            &self.root,
            vec![self.home.clone(), self.snaps.clone()],
            snapshots,
        )
        .unwrap();
        let cfg = EngineConfig::new(owner(), self.root.clone(), self.root.clone());
        Engine::try_new(
            cfg,
            MockPlanner::scripted(script),
            self.channel.clone(),
            sink,
            store,
            exec,
            self.home.clone(),
            std::slice::from_ref(&self.snaps),
        )
        .unwrap()
    }

    fn sent(&self) -> Vec<String> {
        self.channel.sent.lock().unwrap().clone()
    }
}

fn owner() -> SenderId {
    SenderId("owner".into())
}

fn msg(text: &str) -> Inbound {
    Inbound {
        sender: owner(),
        text: text.into(),
    }
}

fn reply(text: Option<&str>, calls: Vec<ToolCall>) -> Result<PlanResponse, PlannerError> {
    Ok(PlanResponse {
        text: text.map(str::to_string),
        calls,
        truncated: false,
    })
}

fn call(id: &str, name: &str, args: Value) -> ToolCall {
    ToolCall {
        id: id.into(),
        name: name.into(),
        args,
    }
}

/// A read of `a.txt` (Auto tier: `approved auto` and `executed`), then a
/// final answer.
fn read_script() -> Vec<Result<PlanResponse, PlannerError>> {
    vec![
        reply(
            None,
            vec![call("t1", "read_file", json!({"path": "a.txt"}))],
        ),
        reply(Some("read it"), vec![]),
    ]
}

fn entries(path: &Path) -> u64 {
    match AuditLog::verify(path).unwrap() {
        VerifyReport::Ok { entries } => entries,
        VerifyReport::Broken {
            first_bad_index,
            reason,
        } => panic!("audit log broken at {first_bad_index}: {reason}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn lease_is_released_after_each_message() {
    let env = Env::new();
    fs::write(env.root.join("a.txt"), "hello").unwrap();
    let mut sink = LeasedAuditLog::new(env.log_path());
    // The startup check takes the lock; the first message releases it even
    // though nothing is audited while handling it.
    sink.open_now().unwrap();
    let mut script = vec![reply(Some("hi"), vec![])];
    script.extend(read_script());
    let mut e = env.engine(script, sink);
    let locked = AuditLog::open(&env.log_path()).unwrap_err();
    assert_eq!(locked.kind(), std::io::ErrorKind::WouldBlock);

    e.handle(msg("hello")).await;
    drop(AuditLog::open(&env.log_path()).expect("released after a chat message"));

    // An owner message that audits.
    e.handle(msg("read a.txt")).await;
    drop(AuditLog::open(&env.log_path()).expect("released after a tool call"));
    assert_eq!(entries(&env.log_path()), 2);

    // A non-owner message (audited, no reply).
    e.handle(Inbound {
        sender: SenderId("mallory".into()),
        text: "delete everything".into(),
    })
    .await;
    drop(AuditLog::open(&env.log_path()).expect("released after a non-owner message"));
    assert_eq!(entries(&env.log_path()), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn append_while_another_writer_holds_the_log_fails_closed() {
    let env = Env::new();
    let a = env.root.join("a.txt");
    fs::write(&a, "old").unwrap();
    let sink = LeasedAuditLog::new(env.log_path()).with_wait(Duration::from_millis(200));
    let mut e = env.engine(
        vec![
            reply(
                None,
                vec![call(
                    "t1",
                    "write_file",
                    json!({"path": "a.txt", "content": "new"}),
                )],
            ),
            reply(Some("ok"), vec![]),
        ],
        sink,
    );
    let mut held = AuditLog::open(&env.log_path()).unwrap();
    held.append("other", "another writer", Tier::Auto, "executed")
        .unwrap();
    let before = fs::read(env.log_path()).unwrap();

    e.handle(msg("update a.txt")).await;

    assert_eq!(fs::read_to_string(&a).unwrap(), "old");
    assert_eq!(*env.channel.prompts.lock().unwrap(), 0, "no prompt");
    let sent = env.sent();
    assert!(
        sent.iter().any(|s| s.contains("(audit unavailable)")),
        "{sent:?}"
    );
    assert_eq!(fs::read(env.log_path()).unwrap(), before);
    drop(held);
    assert_eq!(fs::read(env.log_path()).unwrap(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn appends_by_another_writer_between_messages_keep_the_chain_valid() {
    let env = Env::new();
    fs::write(env.root.join("a.txt"), "hello").unwrap();
    let mut script = read_script();
    script.extend(read_script());
    let mut e = env.engine(script, LeasedAuditLog::new(env.log_path()));

    e.handle(msg("read a.txt")).await;
    {
        let mut other = AuditLog::open(&env.log_path()).unwrap();
        other
            .append("undo-1", "undo 0123", Tier::YesPin, "requested")
            .unwrap();
    }
    e.handle(msg("read a.txt again")).await;

    assert_eq!(entries(&env.log_path()), 5);
    let text = fs::read_to_string(env.log_path()).unwrap();
    let decisions: Vec<String> = text
        .lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            v["decision"].as_str().unwrap().to_owned()
        })
        .collect();
    assert_eq!(
        decisions,
        vec![
            "approved auto",
            "executed",
            "requested",
            "approved auto",
            "executed"
        ]
    );
}
