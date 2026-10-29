//! `TelegramChannel` against a wiremock Bot API. `getUpdates` is served by
//! a script: queued responses first, then `{"ok":true,"result":[]}` after a
//! 100 ms delay (an idle long poll).

use serde_json::{json, Value};
use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use warden_agent::channel::{ApprovalPrompt, ApprovalReply, Channel, SenderId};
use warden_agent::telegram::{
    sender_id, BotToken, OffsetStore, TelegramApi, TelegramChannel, TelegramFatal, TelegramOptions,
};
use warden_core::Tier;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const TOKEN: &str = "123456789:AAH-secret_half_0123456789abcdefDONOTLEAK";
const OWNER: i64 = 42;
const OWNER2: i64 = 43;
const STRANGER: i64 = 666;
const NOW_S: i64 = 1_800_000_000;
const PROMPT_ID: i64 = 1000;

fn method_path(m: &str) -> String {
    format!("/bot{TOKEN}/{m}")
}

/// Scripted `getUpdates`: queued responses, then an empty batch after
/// 100 ms.
#[derive(Clone, Default)]
struct Script(Arc<Mutex<VecDeque<ResponseTemplate>>>);

impl Script {
    fn batch(&self, updates: Vec<Value>) {
        self.push(ResponseTemplate::new(200).set_body_json(json!({"ok": true, "result": updates})));
    }
    fn push(&self, r: ResponseTemplate) {
        self.0.lock().unwrap().push_back(r);
    }
}

impl Respond for Script {
    fn respond(&self, _req: &Request) -> ResponseTemplate {
        self.0.lock().unwrap().pop_front().unwrap_or_else(|| {
            ResponseTemplate::new(200)
                .set_body_json(json!({"ok": true, "result": []}))
                .set_delay(Duration::from_millis(100))
        })
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
    private_text(update_id, OWNER, text, NOW_S)
}

fn opts() -> TelegramOptions {
    TelegramOptions {
        allow_pin_approvals: false,
        max_message_age: Duration::from_secs(120),
        poll_timeout_secs: 1,
        backoff_base: Duration::from_millis(10),
        shutdown_request_timeout: Duration::from_millis(200),
    }
}

struct Harness {
    server: MockServer,
    script: Script,
    home: tempfile::TempDir,
}

impl Harness {
    async fn new() -> Harness {
        let server = MockServer::start().await;
        let script = Script::default();
        Mock::given(method("POST"))
            .and(path(method_path("getUpdates")))
            .respond_with(script.clone())
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(method_path("sendMessage")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"ok": true, "result": {"message_id": PROMPT_ID}})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(method_path("deleteMessage")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"ok": true, "result": true})),
            )
            .mount(&server)
            .await;
        Harness {
            server,
            script,
            home: tempfile::tempdir().unwrap(),
        }
    }

    fn channel_with(&self, owners: Vec<i64>, o: TelegramOptions) -> TelegramChannel {
        channel_on(&self.server.uri(), self.home.path(), owners, o)
    }

    fn channel(&self) -> TelegramChannel {
        self.channel_with(vec![OWNER], opts())
    }

    async fn bodies(&self, m: &str) -> Vec<Value> {
        let want = method_path(m);
        self.server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path() == want)
            .map(|r| serde_json::from_slice(&r.body).unwrap())
            .collect()
    }
}

fn channel_on(base: &str, home: &Path, owners: Vec<i64>, o: TelegramOptions) -> TelegramChannel {
    let api = TelegramApi::new(BotToken::new(TOKEN.to_string()).unwrap(), base).unwrap();
    let (store, start) = OffsetStore::open(home).unwrap();
    TelegramChannel::new(api, owners, store, start, o)
        .with_clock(Box::new(|| (NOW_S as u64) * 1000 + 500))
}

fn owner() -> SenderId {
    sender_id(OWNER)
}

fn prompt(tier: Tier) -> ApprovalPrompt {
    ApprovalPrompt {
        summary: "write_file \"/r/a\" (2 bytes)".into(),
        tier,
        model_note: None,
        challenge: "4821".into(),
    }
}

async fn recv_quiet(ch: &mut TelegramChannel) -> bool {
    tokio::time::timeout(Duration::from_millis(400), ch.recv())
        .await
        .is_err()
}

#[tokio::test]
async fn owner_private_text_becomes_inbound_with_tg_sender() {
    let h = Harness::new().await;
    h.script.batch(vec![owner_text(1, "hello")]);
    let mut ch = h.channel();
    let m = ch.recv().await.unwrap();
    assert_eq!(m.sender, SenderId("tg:42".into()));
    assert_eq!(m.text, "hello");
    assert!(ch.serves(&m.sender));
    assert!(!ch.serves(&SenderId("local".into())));
}

#[tokio::test]
async fn non_owner_text_becomes_non_owner_inbound_with_empty_text() {
    let h = Harness::new().await;
    h.script
        .batch(vec![private_text(1, STRANGER, "yes 1234", NOW_S)]);
    let mut ch = h.channel();
    let m = ch.recv().await.unwrap();
    assert_eq!(m.sender, SenderId("tg:666".into()));
    assert_eq!(m.text, "");
    assert!(h.bodies("sendMessage").await.is_empty());
}

#[tokio::test]
async fn group_message_from_owner_is_not_owner() {
    let h = Harness::new().await;
    h.script.batch(vec![json!({"update_id": 1, "message": {
        "message_id": 5,
        "from": {"id": OWNER, "is_bot": false},
        "chat": {"id": -100, "type": "group"},
        "date": NOW_S,
        "text": "delete everything",
    }})]);
    let mut ch = h.channel();
    let m = ch.recv().await.unwrap();
    assert_eq!(m.sender, SenderId("tg-group:42".into()));
    assert_ne!(m.sender, owner());
    assert_eq!(m.text, "");
}

#[tokio::test]
async fn forwarded_message_from_owner_is_not_owner() {
    let h = Harness::new().await;
    let mut u = owner_text(1, "yes 4821");
    u["message"]["forward_origin"] = json!({"type": "user", "date": NOW_S});
    h.script.batch(vec![u]);
    let mut ch = h.channel();
    let m = ch.recv().await.unwrap();
    assert_eq!(m.sender, SenderId("tg-forward:42".into()));
    assert_eq!(m.text, "");
}

#[tokio::test]
async fn stale_messages_are_dropped_and_owner_is_told_once() {
    let h = Harness::new().await;
    h.script.batch(vec![
        private_text(1, OWNER, "old one", NOW_S - 3600),
        private_text(2, OWNER, "old two", NOW_S - 121),
        owner_text(3, "fresh"),
    ]);
    let mut ch = h.channel();
    for _ in 0..2 {
        let m = ch.recv().await.unwrap();
        assert_eq!(m.sender, SenderId("tg-stale:42".into()));
        assert_eq!(m.text, "");
    }
    let m = ch.recv().await.unwrap();
    assert_eq!((m.sender, m.text.as_str()), (owner(), "fresh"));
    let sent = h.bodies("sendMessage").await;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["chat_id"], OWNER);
    assert_eq!(
        sent[0]["text"],
        "ignored 2 message(s) older than 120 s (Warden was not running or was busy)"
    );
}

#[tokio::test]
async fn offset_is_persisted_before_the_message_is_returned() {
    let h = Harness::new().await;
    h.script
        .batch(vec![owner_text(10, "a"), owner_text(11, "b")]);
    let mut ch = h.channel();
    assert_eq!(ch.recv().await.unwrap().text, "a");
    // Saved past the whole batch before the first item was handed out.
    let (_, saved) = OffsetStore::open(h.home.path()).unwrap();
    assert_eq!(saved, 12);
}

#[tokio::test]
async fn restart_does_not_replay() {
    let h = Harness::new().await;
    h.script.batch(vec![owner_text(10, "once")]);
    {
        let mut ch = h.channel();
        assert_eq!(ch.recv().await.unwrap().text, "once");
    }
    let mut ch = h.channel();
    assert!(recv_quiet(&mut ch).await);
    let polls = h.bodies("getUpdates").await;
    assert_eq!(polls[0]["offset"], 0);
    assert_eq!(polls[1]["offset"], 11);
    assert_eq!(polls[1]["limit"], 20);
    assert_eq!(polls[1]["timeout"], 1);
}

#[tokio::test]
async fn send_goes_only_to_owner_chats() {
    let h = Harness::new().await;
    let mut ch = h.channel();
    ch.send(&owner(), "hi").await;
    for who in [
        "tg:666",
        "tg-group:42",
        "tg-stale:42",
        "local",
        "tg:+42",
        "tg:042",
    ] {
        ch.send(&SenderId(who.into()), "nope").await;
    }
    let sent = h.bodies("sendMessage").await;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["chat_id"], OWNER);
    assert_eq!(sent[0]["text"], "hi");
    assert_eq!(sent[0]["protect_content"], true);
    assert!(sent[0].get("parse_mode").is_none());
}

#[tokio::test]
async fn send_redacts_sanitizes_and_caps_at_4096_utf16() {
    let h = Harness::new().await;
    let mut ch = h.channel();
    ch.send(
        &owner(),
        "key sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 end",
    )
    .await;
    ch.send(&owner(), "red \x1b[31m text").await;
    ch.send(&owner(), &"😀".repeat(3000)).await;
    let sent = h.bodies("sendMessage").await;
    assert_eq!(sent.len(), 3);
    let t0 = sent[0]["text"].as_str().unwrap();
    assert!(t0.contains("[REDACTED:api_key]"), "{t0}");
    assert!(!t0.contains("AbCdEfGh"), "{t0}");
    let t1 = sent[1]["text"].as_str().unwrap();
    assert!(t1.contains("\\u{1b}[31m"), "{t1}");
    assert!(!t1.contains('\x1b'));
    let t2 = sent[2]["text"].as_str().unwrap();
    let units = t2.encode_utf16().count();
    assert!(units <= 4096 && units > 4000, "{units}");
    assert!(t2.ends_with('…'));
}

#[tokio::test]
async fn send_retries_once_after_short_429_only() {
    let server = MockServer::start().await;
    let home = tempfile::tempdir().unwrap();
    let replies = Script::default();
    replies.push(
        ResponseTemplate::new(429).set_body_json(
            json!({"ok": false, "error_code": 429, "parameters": {"retry_after": 1}}),
        ),
    );
    replies.push(
        ResponseTemplate::new(200).set_body_json(json!({"ok": true, "result": {"message_id": 1}})),
    );
    replies.push(
        ResponseTemplate::new(429).set_body_json(
            json!({"ok": false, "error_code": 429, "parameters": {"retry_after": 31}}),
        ),
    );
    Mock::given(method("POST"))
        .and(path(method_path("sendMessage")))
        .respond_with(replies)
        .mount(&server)
        .await;
    let mut ch = channel_on(&server.uri(), home.path(), vec![OWNER], opts());
    ch.send(&owner(), "a").await;
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
    let t = std::time::Instant::now();
    ch.send(&owner(), "b").await;
    assert!(t.elapsed() < Duration::from_secs(5));
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

#[tokio::test]
async fn ask_approval_accepts_yes_code_from_the_sender_chat() {
    let h = Harness::new().await;
    h.script.batch(vec![owner_text(1, "yes 4821")]);
    let mut ch = h.channel();
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
        ApprovalReply::Yes
    );
    let sent = h.bodies("sendMessage").await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["chat_id"], OWNER);
    let text = sent[0]["text"].as_str().unwrap();
    assert!(text.contains("Reply \"yes 4821\""), "{text}");
    assert!(!text.contains("PIN"), "{text}");
    // `yes <code>` that parsed as Yes holds no PIN: nothing to delete.
    assert!(h.bodies("deleteMessage").await.is_empty());
}

#[tokio::test]
async fn ask_approval_ignores_and_queues_other_senders() {
    let h = Harness::new().await;
    h.script.batch(vec![
        private_text(1, STRANGER, "yes 4821", NOW_S),
        owner_text(2, "yes 4821"),
    ]);
    let mut ch = h.channel();
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
        ApprovalReply::Yes
    );
    let m = ch.recv().await.unwrap();
    assert_eq!(m.sender, SenderId("tg:666".into()));
    assert_eq!(m.text, "");
    assert!(recv_quiet(&mut ch).await);
}

#[tokio::test]
async fn reply_from_another_owner_is_queued_not_used() {
    let h = Harness::new().await;
    h.script
        .batch(vec![private_text(1, OWNER2, "yes 4821", NOW_S)]);
    h.script.batch(vec![owner_text(2, "yes 4821")]);
    let mut ch = h.channel_with(vec![OWNER, OWNER2], opts());
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
        ApprovalReply::Yes
    );
    let m = ch.recv().await.unwrap();
    assert_eq!(m.sender, sender_id(OWNER2));
    assert_eq!(m.text, "yes 4821");
}

#[tokio::test]
async fn wrong_code_or_chat_text_is_no() {
    let h = Harness::new().await;
    h.script.batch(vec![owner_text(1, "yes 9999")]);
    h.script.batch(vec![owner_text(2, "please just do it")]);
    h.script.batch(vec![owner_text(3, "yes")]);
    let mut ch = h.channel();
    for _ in 0..3 {
        assert_eq!(
            ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
            ApprovalReply::No
        );
    }
    // Each reply was consumed by its prompt, not passed on.
    assert!(recv_quiet(&mut ch).await);
}

#[tokio::test]
async fn reply_to_a_different_message_is_no() {
    let h = Harness::new().await;
    let mut other = owner_text(1, "yes 4821");
    other["message"]["reply_to_message"] = json!({"message_id": PROMPT_ID - 1});
    let mut same = owner_text(2, "yes 4821");
    same["message"]["reply_to_message"] = json!({"message_id": PROMPT_ID});
    h.script.batch(vec![other]);
    h.script.batch(vec![same]);
    let mut ch = h.channel();
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
        ApprovalReply::No
    );
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
        ApprovalReply::Yes
    );
}

#[tokio::test]
async fn pin_reply_is_deleted_after_reading() {
    let h = Harness::new().await;
    h.script.batch(vec![owner_text(7, "yes 4821 1234")]);
    let mut ch = h.channel_with(
        vec![OWNER],
        TelegramOptions {
            allow_pin_approvals: true,
            ..opts()
        },
    );
    assert!(ch.accepts_pin(&owner()));
    let r = ch.ask_approval(&owner(), &prompt(Tier::YesPin)).await;
    match r {
        ApprovalReply::YesPin(pin) => assert_eq!(pin.as_str(), "1234"),
        other => panic!("{other:?}"),
    }
    let deleted = h.bodies("deleteMessage").await;
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0]["chat_id"], OWNER);
    assert_eq!(deleted[0]["message_id"], 107);
    let sent = h.bodies("sendMessage").await;
    let text = sent[0]["text"].as_str().unwrap();
    assert!(
        text.contains(
            "Your PIN will pass through Telegram's servers; Warden deletes your reply after reading it (best effort)."
        ),
        "{text}"
    );
}

#[tokio::test]
async fn yespin_prompt_refused_when_pin_approvals_disabled() {
    let h = Harness::new().await;
    h.script.batch(vec![owner_text(1, "yes 4821 1234")]);
    let mut ch = h.channel();
    assert!(!ch.accepts_pin(&owner()));
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::YesPin)).await,
        ApprovalReply::No
    );
    assert!(h.bodies("sendMessage").await.is_empty());
    // A non-owner is never prompted either.
    assert_eq!(
        ch.ask_approval(&sender_id(STRANGER), &prompt(Tier::Yes))
            .await,
        ApprovalReply::No
    );
    assert!(h.bodies("sendMessage").await.is_empty());
    assert!(h.bodies("getUpdates").await.is_empty());
}

#[tokio::test]
async fn discard_drops_pending_owner_messages_and_keeps_others() {
    let h = Harness::new().await;
    h.script.batch(vec![
        private_text(1, STRANGER, "s1", NOW_S),
        owner_text(2, "a"),
        owner_text(3, "bb"),
    ]);
    h.script.batch(vec![
        owner_text(4, "ccc"),
        private_text(5, STRANGER, "s2", NOW_S),
    ]);
    let mut ch = h.channel();
    assert_eq!(ch.recv().await.unwrap().sender, sender_id(STRANGER));
    assert_eq!(ch.discard_pending_input(&owner()).await, 6);
    let polls = h.bodies("getUpdates").await;
    assert_eq!(polls.last().unwrap()["timeout"], 0);
    assert_eq!(polls.last().unwrap()["offset"], 4);
    let m = ch.recv().await.unwrap();
    assert_eq!(m.sender, sender_id(STRANGER));
    assert!(recv_quiet(&mut ch).await);
    let (_, saved) = OffsetStore::open(h.home.path()).unwrap();
    assert_eq!(saved, 6);
}

#[tokio::test]
async fn slash_commands_get_help_and_are_not_passed_on() {
    let h = Harness::new().await;
    h.script
        .batch(vec![owner_text(1, "/start"), owner_text(2, "hi")]);
    let mut ch = h.channel();
    let m = ch.recv().await.unwrap();
    assert_eq!(m.text, "hi");
    let sent = h.bodies("sendMessage").await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["chat_id"], OWNER);
    assert!(!sent[0]["text"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn owner_non_text_gets_a_reply_and_is_not_passed_on() {
    let h = Harness::new().await;
    h.script.batch(vec![
        json!({"update_id": 1, "message": {
            "message_id": 9,
            "from": {"id": OWNER, "is_bot": false},
            "chat": {"id": OWNER, "type": "private"},
            "date": NOW_S,
            "photo": [],
        }}),
        owner_text(2, "hi"),
    ]);
    let mut ch = h.channel();
    assert_eq!(ch.recv().await.unwrap().text, "hi");
    let sent = h.bodies("sendMessage").await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["text"], "only text messages are supported");
}

fn api_error(code: u16) -> ResponseTemplate {
    ResponseTemplate::new(code)
        .set_body_json(json!({"ok": false, "error_code": code, "description": "nope"}))
}

#[tokio::test]
async fn unauthorized_token_ends_recv_with_fatal() {
    let h = Harness::new().await;
    h.script.push(api_error(401));
    let mut ch = h.channel();
    assert!(ch.recv().await.is_none());
    assert_eq!(ch.fatal(), Some(TelegramFatal::TokenRejected));
    assert!(ch.recv().await.is_none());
    assert!(!TelegramFatal::TokenRejected.to_string().contains(TOKEN));

    let h = Harness::new().await;
    h.script.push(ResponseTemplate::new(404));
    let mut ch = h.channel();
    assert!(ch.recv().await.is_none());
    assert_eq!(ch.fatal(), Some(TelegramFatal::TokenRejected));
}

#[tokio::test]
async fn conflict_409_ends_recv_with_fatal() {
    let h = Harness::new().await;
    h.script.push(api_error(409));
    let mut ch = h.channel();
    assert!(ch.recv().await.is_none());
    assert_eq!(ch.fatal(), Some(TelegramFatal::Conflict));
}

#[tokio::test]
async fn transient_500_backs_off_and_recovers() {
    let h = Harness::new().await;
    h.script.push(ResponseTemplate::new(500));
    h.script.push(api_error(502));
    h.script
        .push(ResponseTemplate::new(200).set_body_string("not json"));
    h.script.batch(vec![owner_text(1, "after")]);
    let mut ch = h.channel();
    assert_eq!(ch.recv().await.unwrap().text, "after");
    assert_eq!(ch.fatal(), None);
    assert_eq!(h.bodies("getUpdates").await.len(), 4);
}

#[tokio::test]
async fn offset_save_failure_ends_recv_with_fatal() {
    let h = Harness::new().await;
    h.script.batch(vec![owner_text(1, "never acted on")]);
    let mut ch = h.channel();
    // A directory where the file goes makes the atomic replace fail.
    std::fs::create_dir(h.home.path().join("telegram-offset")).unwrap();
    assert!(ch.recv().await.is_none());
    assert_eq!(ch.fatal(), Some(TelegramFatal::OffsetUnwritable));
}

#[tokio::test]
async fn recv_is_cancel_safe() {
    let h = Harness::new().await;
    let batch = json!({"ok": true, "result": [owner_text(1, "exactly once")]});
    // Telegram re-serves an unconfirmed update: the dropped poll's batch is
    // served again to the next poll.
    h.script.push(
        ResponseTemplate::new(200)
            .set_body_json(batch.clone())
            .set_delay(Duration::from_millis(500)),
    );
    h.script
        .push(ResponseTemplate::new(200).set_body_json(batch));
    let mut ch = h.channel();
    assert!(tokio::time::timeout(Duration::from_millis(100), ch.recv())
        .await
        .is_err());
    assert_eq!(ch.recv().await.unwrap().text, "exactly once");
    assert!(recv_quiet(&mut ch).await);
}

#[tokio::test]
async fn cancelled_ask_approval_leaves_no_reply_behind() {
    let h = Harness::new().await;
    h.script.push(
        ResponseTemplate::new(200)
            .set_body_json(json!({"ok": true, "result": [owner_text(1, "yes 4821")]}))
            .set_delay(Duration::from_millis(500)),
    );
    let mut ch = h.channel();
    let r = tokio::time::timeout(
        Duration::from_millis(100),
        ch.ask_approval(&owner(), &prompt(Tier::Yes)),
    )
    .await;
    assert!(r.is_err());
    // The reply was never confirmed, so it comes back as plain text for the
    // engine (which treats approval-shaped text as no approval), never as
    // the answer to a later prompt with a different code.
    h.script.batch(vec![owner_text(1, "yes 4821")]);
    let m = ch.recv().await.unwrap();
    assert_eq!(m.text, "yes 4821");
    assert!(recv_quiet(&mut ch).await);
}

#[tokio::test]
async fn queue_overflow_drops_beyond_64() {
    let h = Harness::new().await;
    let flood: Vec<Value> = (0..70)
        .map(|i| private_text(i + 1, 1000 + i, "spam", NOW_S))
        .collect();
    h.script.batch(flood);
    h.script.batch(vec![owner_text(71, "real")]);
    let mut ch = h.channel();
    for i in 0..64 {
        let m = ch.recv().await.unwrap();
        assert_eq!(m.sender, sender_id(1000 + i));
    }
    assert_eq!(ch.dropped_count(), 6);
    assert_eq!(ch.recv().await.unwrap().text, "real");
}

fn too_large() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_string("x".repeat((1 << 20) + 16))
}

#[tokio::test]
async fn too_large_batch_is_refetched_one_at_a_time() {
    let h = Harness::new().await;
    h.script.push(too_large());
    h.script.batch(vec![owner_text(500, "small")]);
    let (mut store, _) = OffsetStore::open(h.home.path()).unwrap();
    store.save(500).unwrap();
    let mut ch = h.channel();
    assert_eq!(ch.recv().await.unwrap().text, "small");
    let polls = h.bodies("getUpdates").await;
    assert_eq!(polls[0]["limit"], 20);
    assert_eq!(polls[1]["limit"], 1);
    assert_eq!(polls[1]["offset"], 500);
}

#[tokio::test]
async fn single_oversized_update_is_skipped_and_polling_continues() {
    let h = Harness::new().await;
    h.script.push(too_large());
    h.script.push(too_large());
    h.script.batch(vec![owner_text(501, "next")]);
    let (mut store, _) = OffsetStore::open(h.home.path()).unwrap();
    store.save(500).unwrap();
    let mut ch = h.channel();
    let m = ch.recv().await.unwrap();
    assert_eq!(m.sender, SenderId("tg-malformed:0".into()));
    assert_eq!(m.text, "");
    let (_, saved) = OffsetStore::open(h.home.path()).unwrap();
    assert_eq!(saved, 501);
    assert_eq!(ch.recv().await.unwrap().text, "next");
    let polls = h.bodies("getUpdates").await;
    assert_eq!(polls[2]["offset"], 501);
    assert_eq!(polls[2]["limit"], 20);
}

#[tokio::test]
async fn retract_last_deletes_the_last_message_handed_out() {
    let h = Harness::new().await;
    h.script
        .batch(vec![owner_text(1, "first"), owner_text(2, "second")]);
    let mut ch = h.channel();
    assert_eq!(ch.recv().await.unwrap().text, "first");
    ch.retract_last(&owner()).await;
    ch.retract_last(&sender_id(STRANGER)).await;
    let deleted = h.bodies("deleteMessage").await;
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0]["message_id"], 101);
}

#[tokio::test]
async fn updates_below_the_offset_are_ignored() {
    let h = Harness::new().await;
    let (mut store, _) = OffsetStore::open(h.home.path()).unwrap();
    store.save(10).unwrap();
    h.script
        .batch(vec![owner_text(9, "old"), owner_text(10, "new")]);
    h.script.batch(vec![owner_text(3, "replayed")]);
    let mut ch = h.channel();
    assert_eq!(ch.recv().await.unwrap().text, "new");
    assert!(recv_quiet(&mut ch).await);
    assert_eq!(ch.fatal(), None);
}

#[tokio::test]
async fn overflow_evicts_strangers_before_owner_text() {
    let h = Harness::new().await;
    let mut batch: Vec<Value> = (0..64)
        .map(|i| private_text(i + 1, 1000 + i, "spam", NOW_S))
        .collect();
    batch.push(owner_text(65, "real"));
    h.script.batch(batch);
    let mut ch = h.channel();
    let mut strangers = 0;
    // Bounded: a regression that loses the owner text fails, not hangs.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let m = ch.recv().await.unwrap();
            if m.sender == owner() {
                assert_eq!(m.text, "real");
                break;
            }
            strangers += 1;
        }
    })
    .await
    .expect("the owner text never came out of the queue");
    assert_eq!(strangers, 63);
    assert_eq!(ch.dropped_count(), 1);
    assert!(recv_quiet(&mut ch).await);
}

#[tokio::test]
async fn overflow_drop_of_owner_pin_reply_deletes_it() {
    let h = Harness::new().await;
    let mut batch: Vec<Value> = (0..64)
        .map(|i| owner_text(i + 1, &format!("msg {i}")))
        .collect();
    batch.push(owner_text(65, "yes 4821 1234"));
    h.script.batch(batch);
    let mut ch = h.channel();
    assert_eq!(ch.recv().await.unwrap().text, "msg 0");
    assert_eq!(ch.dropped_count(), 1);
    let deleted = h.bodies("deleteMessage").await;
    assert_eq!(deleted.len(), 1, "{deleted:?}");
    assert_eq!(deleted[0]["chat_id"], OWNER);
    assert_eq!(deleted[0]["message_id"], 165);
}

#[tokio::test]
async fn cancelled_flush_still_deletes_pin_reply() {
    let h = Harness::new().await;
    // The first deleteMessage hangs long enough to be cancelled.
    Mock::given(method("POST"))
        .and(path(method_path("deleteMessage")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"ok": true, "result": true}))
                .set_delay(Duration::from_millis(2000)),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&h.server)
        .await;
    h.script.batch(vec![owner_text(7, "yes 4821 1234")]);
    let mut ch = h.channel_with(
        vec![OWNER],
        TelegramOptions {
            allow_pin_approvals: true,
            ..opts()
        },
    );
    let r = tokio::time::timeout(
        Duration::from_millis(500),
        ch.ask_approval(&owner(), &prompt(Tier::YesPin)),
    )
    .await;
    assert!(r.is_err(), "the delete should still be in flight");
    assert_eq!(h.bodies("deleteMessage").await.len(), 1);
    // The next call performs the deletion again.
    assert!(recv_quiet(&mut ch).await);
    let deleted = h.bodies("deleteMessage").await;
    assert_eq!(deleted.len(), 2, "{deleted:?}");
    assert_eq!(deleted[1]["chat_id"], OWNER);
    assert_eq!(deleted[1]["message_id"], 107);
}

#[tokio::test]
async fn cancelled_prompt_old_code_in_new_prompt_is_no() {
    let h = Harness::new().await;
    let mut ch = h.channel();
    let a = ApprovalPrompt {
        challenge: "1111".into(),
        ..prompt(Tier::Yes)
    };
    let r = tokio::time::timeout(Duration::from_millis(50), ch.ask_approval(&owner(), &a)).await;
    assert!(r.is_err());
    let b = ApprovalPrompt {
        challenge: "2222".into(),
        ..prompt(Tier::Yes)
    };
    h.script.batch(vec![owner_text(1, "yes 1111")]);
    assert_eq!(ch.ask_approval(&owner(), &b).await, ApprovalReply::No);
}

fn pin_opts() -> TelegramOptions {
    TelegramOptions {
        allow_pin_approvals: true,
        ..opts()
    }
}

/// The `message_id`s of every `deleteMessage` call, sorted.
async fn deleted_ids(h: &Harness) -> Vec<i64> {
    let mut ids: Vec<i64> = h
        .bodies("deleteMessage")
        .await
        .iter()
        .map(|b| {
            assert_eq!(b["chat_id"], OWNER, "{b:?}");
            b["message_id"].as_i64().unwrap()
        })
        .collect();
    ids.sort_unstable();
    ids
}

#[tokio::test]
async fn short_pin_replies_at_a_yespin_prompt_are_deleted() {
    // None of these approves (no code, or no PIN after it), but each may be
    // the PIN typed on its own or after a forgotten code.
    for reply in ["yes 482193", "482193", "4821 482193"] {
        let h = Harness::new().await;
        h.script.batch(vec![owner_text(7, reply)]);
        let mut ch = h.channel_with(vec![OWNER], pin_opts());
        assert_eq!(
            ch.ask_approval(&owner(), &prompt(Tier::YesPin)).await,
            ApprovalReply::No,
            "{reply}"
        );
        assert_eq!(deleted_ids(&h).await, vec![107], "{reply}");
    }
}

#[tokio::test]
async fn failed_two_token_reply_at_a_yes_prompt_is_deleted() {
    let h = Harness::new().await;
    h.script.batch(vec![owner_text(7, "yes 482193")]);
    h.script.batch(vec![owner_text(8, "no")]);
    let mut ch = h.channel();
    for _ in 0..2 {
        assert_eq!(
            ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
            ApprovalReply::No
        );
    }
    // `yes 482193` may be `yes <PIN>`; a bare `no` holds nothing.
    assert_eq!(deleted_ids(&h).await, vec![107]);
}

#[tokio::test]
async fn stale_pin_shaped_messages_are_deleted_and_plain_text_is_not() {
    let h = Harness::new().await;
    h.script.batch(vec![
        private_text(7, OWNER, "482193", NOW_S - 1000),
        private_text(8, OWNER, "yes 482193", NOW_S - 1000),
        private_text(9, OWNER, "hello", NOW_S - 1000),
    ]);
    let mut ch = h.channel();
    for _ in 0..3 {
        let m = ch.recv().await.unwrap();
        assert_eq!((m.sender.0.as_str(), m.text.as_str()), ("tg-stale:42", ""));
    }
    assert_eq!(deleted_ids(&h).await, vec![107, 108]);
}

#[tokio::test]
async fn discarded_short_pin_replies_are_deleted() {
    let h = Harness::new().await;
    h.script.batch(vec![
        owner_text(1, "first"),
        owner_text(2, "yes 482193"),
        owner_text(3, "482193"),
        owner_text(4, "hello there"),
    ]);
    let mut ch = h.channel();
    assert_eq!(ch.recv().await.unwrap().text, "first");
    assert!(ch.discard_pending_input(&owner()).await > 0);
    assert_eq!(deleted_ids(&h).await, vec![102, 103]);
}

#[tokio::test]
async fn queued_owner_text_is_rechecked_for_age_when_popped() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let h = Harness::new().await;
    h.script.batch(vec![
        owner_text(7, "first"),
        owner_text(8, "delete notes.txt"),
        owner_text(9, "482193"),
    ]);
    let now = Arc::new(AtomicU64::new((NOW_S as u64) * 1000 + 500));
    let clock = Arc::clone(&now);
    let mut ch = channel_on(&h.server.uri(), h.home.path(), vec![OWNER], opts())
        .with_clock(Box::new(move || clock.load(Ordering::SeqCst)));
    assert_eq!(ch.recv().await.unwrap().text, "first");
    // The engine spends an hour on `first` (say, prompts to other owners);
    // the rest of the batch waits in the queue meanwhile.
    now.fetch_add(3_600_000, Ordering::SeqCst);
    for _ in 0..2 {
        let m = ch.recv().await.unwrap();
        assert_eq!(m.sender, SenderId("tg-stale:42".into()));
        assert_eq!(m.text, "");
    }
    assert!(recv_quiet(&mut ch).await);
    assert_eq!(deleted_ids(&h).await, vec![109]);
    let sent = h.bodies("sendMessage").await;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(
        sent[0]["text"],
        "ignored 2 message(s) older than 120 s (Warden was not running or was busy)"
    );
}

#[tokio::test]
async fn failed_prompt_send_is_undelivered_not_declined() {
    let h = Harness::new().await;
    Mock::given(method("POST"))
        .and(path(method_path("sendMessage")))
        .respond_with(api_error(500))
        .with_priority(1)
        .mount(&h.server)
        .await;
    let mut ch = h.channel();
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
        ApprovalReply::Undelivered
    );
    // No reply was waited for.
    assert!(h.bodies("getUpdates").await.is_empty());
}

#[tokio::test]
async fn flush_pending_performs_queued_deletions() {
    let h = Harness::new().await;
    // The first deleteMessage hangs long enough to be cancelled.
    Mock::given(method("POST"))
        .and(path(method_path("deleteMessage")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"ok": true, "result": true}))
                .set_delay(Duration::from_millis(2000)),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&h.server)
        .await;
    h.script.batch(vec![owner_text(7, "yes 4821 1234")]);
    let mut ch = h.channel_with(vec![OWNER], pin_opts());
    let r = tokio::time::timeout(
        Duration::from_millis(500),
        ch.ask_approval(&owner(), &prompt(Tier::YesPin)),
    )
    .await;
    assert!(r.is_err(), "the delete should still be in flight");
    // What the daemon calls once the engine has stopped.
    ch.flush_pending().await;
    assert_eq!(deleted_ids(&h).await, vec![107, 107]);
    // Nothing is left to do.
    ch.flush_pending().await;
    assert_eq!(h.bodies("deleteMessage").await.len(), 2);
}

/// A server whose sendMessage always answers 429 with `retry_after` 30.
async fn rate_limited() -> (MockServer, tempfile::TempDir) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(method_path("sendMessage")))
        .respond_with(ResponseTemplate::new(429).set_body_json(
            json!({"ok": false, "error_code": 429, "parameters": {"retry_after": 30}}),
        ))
        .mount(&server)
        .await;
    (server, tempfile::tempdir().unwrap())
}

#[tokio::test]
async fn after_shutdown_send_skips_the_429_retry() {
    let (server, home) = rate_limited().await;
    let (_tx, rx) = tokio::sync::watch::channel(true);
    let mut ch = channel_on(&server.uri(), home.path(), vec![OWNER], opts()).with_shutdown(rx);
    let t = std::time::Instant::now();
    ch.send(&owner(), "Warden is shutting down").await;
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn shutdown_cuts_a_429_wait_short() {
    let (server, home) = rate_limited().await;
    let (tx, rx) = tokio::sync::watch::channel(false);
    let mut ch = channel_on(&server.uri(), home.path(), vec![OWNER], opts()).with_shutdown(rx);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        tx.send_replace(true);
        // Keep the sender alive: a dropped sender means no shutdown.
        tokio::time::sleep(Duration::from_secs(60)).await;
    });
    let t = std::time::Instant::now();
    ch.send(&owner(), "hi").await;
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn after_shutdown_requests_get_the_short_timeout() {
    let h = Harness::new().await;
    Mock::given(method("POST"))
        .and(path(method_path("sendMessage")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"ok": true, "result": {"message_id": 1}}))
                .set_delay(Duration::from_secs(20)),
        )
        .with_priority(1)
        .mount(&h.server)
        .await;
    let (tx, rx) = tokio::sync::watch::channel(false);
    let mut ch = h.channel().with_shutdown(rx);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        tx.send_replace(true);
        tokio::time::sleep(Duration::from_secs(60)).await;
    });
    // In flight when shutdown starts: it gets the short timeout from then.
    let t = std::time::Instant::now();
    ch.send(&owner(), "slow").await;
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    // Started after shutdown: the short timeout from the start.
    let t = std::time::Instant::now();
    ch.send(&owner(), "slow again").await;
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
}
