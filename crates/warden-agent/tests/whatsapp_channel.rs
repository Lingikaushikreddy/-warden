//! `WhatsAppChannel` against a wiremock Graph API. The test holds the
//! `mpsc::Sender<WebhookBatch>` and feeds parsed batches directly; no
//! listener is involved.

use serde_json::{json, Value};
use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use warden_agent::channel::{ApprovalPrompt, ApprovalReply, Channel, SenderId};
use warden_agent::whatsapp::{
    sender_id, AccessToken, GraphApi, RefuseReason, SeenStore, WaEvent, WebhookBatch,
    WhatsAppChannel, WhatsAppFatal, WhatsAppOptions, WINDOW_MS,
};
use warden_core::Tier;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const TOKEN: &str = "EAAGtestTOKEN0123456789abcdefghijDONOTLEAK";
const PNID: &str = "123456789012345";
const OWNER: &str = "15551234567";
const OWNER2: &str = "15557654321";
const STRANGER: &str = "15550000666";
const NOW_S: i64 = 1_800_000_000;
const NOW_MS: u64 = (NOW_S as u64) * 1000 + 500;
const PROMPT_WAMID: &str = "wamid.PROMPT";
const DELETE_NOTICE: &str = "Warden cannot delete WhatsApp messages; delete that message yourself.";

fn messages_path() -> String {
    format!("/v26.0/{PNID}/messages")
}

fn sent_ok() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "messaging_product": "whatsapp",
        "contacts": [{"input": OWNER, "wa_id": OWNER}],
        "messages": [{"id": PROMPT_WAMID}],
    }))
}

fn graph_error(status: u16, code: i64) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .set_body_json(json!({"error": {"message": "x", "type": "OAuthException", "code": code}}))
}

/// Scripted responses, then `sent_ok`.
#[derive(Clone, Default)]
struct Script(Arc<Mutex<VecDeque<ResponseTemplate>>>);

impl Script {
    fn push(&self, r: ResponseTemplate) {
        self.0.lock().unwrap().push_back(r);
    }
}

impl Respond for Script {
    fn respond(&self, _req: &Request) -> ResponseTemplate {
        self.0.lock().unwrap().pop_front().unwrap_or_else(sent_ok)
    }
}

fn text_at(wamid: &str, from: &str, body: &str, ts: i64) -> WaEvent {
    WaEvent::Text {
        wamid: wamid.into(),
        from: from.into(),
        timestamp_s: ts,
        body: body.into(),
        reply_to: None,
    }
}

fn text(wamid: &str, from: &str, body: &str) -> WaEvent {
    text_at(wamid, from, body, NOW_S)
}

fn reply(wamid: &str, from: &str, body: &str, to: &str) -> WaEvent {
    WaEvent::Text {
        wamid: wamid.into(),
        from: from.into(),
        timestamp_s: NOW_S,
        body: body.into(),
        reply_to: Some(to.into()),
    }
}

fn refused(wamid: &str, from: &str, reason: RefuseReason) -> WaEvent {
    WaEvent::Refused {
        wamid: Some(wamid.into()),
        from: Some(from.into()),
        timestamp_s: Some(NOW_S),
        reason,
    }
}

fn batch(events: Vec<WaEvent>) -> WebhookBatch {
    WebhookBatch { events }
}

fn opts() -> WhatsAppOptions {
    WhatsAppOptions {
        max_message_age: Duration::from_secs(120),
        rate_limit_backoff: Duration::from_millis(10),
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
            .and(path(messages_path()))
            .respond_with(script.clone())
            .mount(&server)
            .await;
        Harness {
            server,
            script,
            home: tempfile::tempdir().unwrap(),
        }
    }

    fn channel_with(
        &self,
        owners: &[&str],
        clock: Box<dyn Fn() -> u64 + Send + Sync>,
    ) -> (mpsc::Sender<WebhookBatch>, WhatsAppChannel) {
        channel_on(&self.server.uri(), self.home.path(), owners, clock)
    }

    fn channel(&self) -> (mpsc::Sender<WebhookBatch>, WhatsAppChannel) {
        self.channel_with(&[OWNER], Box::new(|| NOW_MS))
    }

    /// Bodies of every POST to `/messages`.
    async fn sent(&self) -> Vec<Value> {
        let want = messages_path();
        self.server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path() == want)
            .map(|r| serde_json::from_slice(&r.body).unwrap())
            .collect()
    }

    async fn sent_texts(&self) -> Vec<(String, String)> {
        self.sent()
            .await
            .into_iter()
            .map(|b| {
                (
                    b["to"].as_str().unwrap().to_string(),
                    b["text"]["body"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }
}

fn channel_on(
    base: &str,
    home: &Path,
    owners: &[&str],
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
) -> (mpsc::Sender<WebhookBatch>, WhatsAppChannel) {
    let api = GraphApi::new(AccessToken::new(TOKEN.into()).unwrap(), base, "v26.0", PNID).unwrap();
    let seen = SeenStore::open(home).unwrap();
    let (tx, rx) = mpsc::channel(16);
    let ch = WhatsAppChannel::new(
        api,
        rx,
        owners.iter().map(|s| s.to_string()).collect(),
        seen,
        opts(),
    )
    .with_clock(clock);
    (tx, ch)
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

async fn recv_quiet(ch: &mut WhatsAppChannel) -> bool {
    tokio::time::timeout(Duration::from_millis(300), ch.recv())
        .await
        .is_err()
}

/// The owner writes once (opening the 24 h window) and the engine takes it.
async fn open_window(tx: &mpsc::Sender<WebhookBatch>, ch: &mut WhatsAppChannel) {
    tx.send(batch(vec![text("wamid.open", OWNER, "hello")]))
        .await
        .unwrap();
    assert_eq!(ch.recv().await.unwrap().text, "hello");
}

// ---------------------------------------------------------------- inbound

#[tokio::test]
async fn owner_text_becomes_inbound_with_wa_sender() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    tx.send(batch(vec![text("wamid.1", OWNER, "hello")]))
        .await
        .unwrap();
    let m = ch.recv().await.unwrap();
    assert_eq!(m.sender, SenderId(format!("wa:{OWNER}")));
    assert_eq!(m.sender, owner());
    assert_eq!(m.text, "hello");
}

#[tokio::test]
async fn non_owner_text_is_non_owner_with_empty_text() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    tx.send(batch(vec![text("wamid.1", STRANGER, "yes 4821")]))
        .await
        .unwrap();
    let m = ch.recv().await.unwrap();
    assert_eq!(m.sender, SenderId(format!("wa:{STRANGER}")));
    assert_ne!(m.sender, owner());
    assert_eq!(m.text, "");
    assert!(h.sent().await.is_empty());
}

/// Controller ruling: statuses are counted and dropped; they never reach
/// the engine. Reactions, media and forwards reach it as tagged
/// non-owners.
#[tokio::test]
async fn forwarded_reaction_and_media_reach_engine_as_tagged_non_owners_and_statuses_are_dropped() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    tx.send(batch(vec![
        WaEvent::Status,
        refused("wamid.1", OWNER, RefuseReason::Forwarded),
        WaEvent::Status,
        refused("wamid.2", OWNER, RefuseReason::Reaction),
        refused("wamid.3", STRANGER, RefuseReason::NotText),
        WaEvent::Refused {
            wamid: None,
            from: None,
            timestamp_s: None,
            reason: RefuseReason::Malformed,
        },
        WaEvent::Status,
    ]))
    .await
    .unwrap();
    let want = [
        format!("wa-forward:{OWNER}"),
        format!("wa-reaction:{OWNER}"),
        format!("wa-non-text:{STRANGER}"),
        "wa-malformed:0".to_string(),
    ];
    for w in want {
        let m = ch.recv().await.unwrap();
        assert_eq!(m.sender, SenderId(w));
        assert_eq!(m.text, "");
        assert!(!m.sender.0.starts_with("wa:"));
    }
    assert!(recv_quiet(&mut ch).await);
    assert_eq!(ch.status_count(), 3);
    assert!(h.sent().await.is_empty());
}

#[tokio::test]
async fn owner_non_text_gets_notice_and_is_tagged() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    tx.send(batch(vec![refused(
        "wamid.img",
        OWNER,
        RefuseReason::NotText,
    )]))
    .await
    .unwrap();
    let m = ch.recv().await.unwrap();
    assert_eq!(m.sender, SenderId(format!("wa-non-text:{OWNER}")));
    assert_eq!(m.text, "");
    assert_eq!(
        h.sent_texts().await,
        vec![(OWNER.into(), "only text messages are supported".into())]
    );
}

#[tokio::test]
async fn stale_messages_are_dropped_and_owner_is_told_once() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    tx.send(batch(vec![
        text_at("wamid.1", OWNER, "old one", NOW_S - 3600),
        text_at("wamid.2", OWNER, "old two", NOW_S - 121),
        text("wamid.3", OWNER, "fresh"),
    ]))
    .await
    .unwrap();
    for _ in 0..2 {
        let m = ch.recv().await.unwrap();
        assert_eq!(m.sender, SenderId(format!("wa-stale:{OWNER}")));
        assert_eq!(m.text, "");
    }
    let m = ch.recv().await.unwrap();
    assert_eq!((m.sender, m.text.as_str()), (owner(), "fresh"));
    assert_eq!(
        h.sent_texts().await,
        vec![(
            OWNER.into(),
            "ignored 2 message(s) older than 120 s (Warden was not running or was busy)".into()
        )]
    );
}

#[tokio::test]
async fn queued_message_that_goes_stale_is_not_delivered() {
    let h = Harness::new().await;
    let now = Arc::new(AtomicU64::new(NOW_MS));
    let clock = Arc::clone(&now);
    let (tx, mut ch) = h.channel_with(&[OWNER], Box::new(move || clock.load(Ordering::SeqCst)));
    tx.send(batch(vec![
        text("wamid.1", OWNER, "first"),
        text("wamid.2", OWNER, "delete notes.txt"),
    ]))
    .await
    .unwrap();
    assert_eq!(ch.recv().await.unwrap().text, "first");
    // The engine spends an hour on `first`; the rest waits in the queue.
    now.fetch_add(3_600_000, Ordering::SeqCst);
    let m = ch.recv().await.unwrap();
    assert_eq!(m.sender, SenderId(format!("wa-stale:{OWNER}")));
    assert_eq!(m.text, "");
    assert!(recv_quiet(&mut ch).await);
    assert_eq!(
        h.sent_texts().await,
        vec![(
            OWNER.into(),
            "ignored 1 message(s) older than 120 s (Warden was not running or was busy)".into()
        )]
    );
}

#[tokio::test]
async fn queue_overflow_drops_beyond_64() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    let flood: Vec<WaEvent> = (0..70)
        .map(|i| text(&format!("wamid.s{i}"), &format!("1555000{i:04}"), "spam"))
        .collect();
    tx.send(batch(flood)).await.unwrap();
    tx.send(batch(vec![text("wamid.real", OWNER, "real")]))
        .await
        .unwrap();
    for i in 0..64 {
        let m = ch.recv().await.unwrap();
        assert_eq!(m.sender, sender_id(&format!("1555000{i:04}")));
    }
    assert_eq!(ch.dropped_count(), 6);
    assert_eq!(ch.recv().await.unwrap().text, "real");
}

#[tokio::test]
async fn overflow_evicts_non_owner_items_before_owner_text() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    let mut events: Vec<WaEvent> = (0..64)
        .map(|i| text(&format!("wamid.s{i}"), &format!("1555000{i:04}"), "spam"))
        .collect();
    events.push(text("wamid.real", OWNER, "real"));
    tx.send(batch(events)).await.unwrap();
    let mut got_owner = false;
    for _ in 0..64 {
        let m = ch.recv().await.unwrap();
        got_owner |= m.text == "real";
    }
    assert!(got_owner);
    assert_eq!(ch.dropped_count(), 1);
}

/// The daemon wraps the channel, so it reads the status and drop counts
/// through shared handles taken before wrapping.
#[tokio::test]
async fn status_and_drop_counters_are_shared_handles() {
    let h = Harness::new().await;
    let (tx, ch) = h.channel();
    let statuses = ch.status_counter();
    let dropped = ch.dropped_counter();
    let mut wrapped = Box::new(ch);
    let mut events: Vec<WaEvent> = (0..70)
        .map(|i| text(&format!("wamid.s{i}"), &format!("1555000{i:04}"), "spam"))
        .collect();
    events.push(WaEvent::Status);
    events.push(WaEvent::Status);
    tx.send(batch(events)).await.unwrap();
    wrapped.recv().await.unwrap();
    assert_eq!(statuses.load(Ordering::Relaxed), 2);
    assert_eq!(dropped.load(Ordering::Relaxed), 6);
    assert_eq!(wrapped.status_count(), 2);
    assert_eq!(wrapped.dropped_count(), 6);
}

#[tokio::test]
async fn discard_drops_pending_owner_messages_and_keeps_others() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    tx.send(batch(vec![
        text("wamid.1", OWNER, "first"),
        text("wamid.2", OWNER, "pending"),
        text("wamid.3", STRANGER, "x"),
    ]))
    .await
    .unwrap();
    assert_eq!(ch.recv().await.unwrap().text, "first");
    tx.send(batch(vec![
        text("wamid.4", OWNER, "new"),
        text("wamid.5", OWNER2, "y"),
    ]))
    .await
    .unwrap();
    assert_eq!(ch.discard_pending_input(&owner()).await, 7 + 3);
    assert_eq!(ch.recv().await.unwrap().sender, sender_id(STRANGER));
    assert_eq!(ch.recv().await.unwrap().sender, sender_id(OWNER2));
    assert!(recv_quiet(&mut ch).await);
    // Nothing was pending any more.
    assert_eq!(ch.discard_pending_input(&owner()).await, 0);
    // Not an owner: nothing to discard.
    assert_eq!(ch.discard_pending_input(&sender_id(STRANGER)).await, 0);
}

#[tokio::test]
async fn recv_is_cancel_safe() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    assert!(tokio::time::timeout(Duration::from_millis(100), ch.recv())
        .await
        .is_err());
    tx.send(batch(vec![text("wamid.1", OWNER, "exactly once")]))
        .await
        .unwrap();
    assert_eq!(ch.recv().await.unwrap().text, "exactly once");
    assert!(recv_quiet(&mut ch).await);
}

// ------------------------------------------------- deduplication and fatal

#[tokio::test]
async fn duplicate_wamid_is_delivered_once() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    let b = batch(vec![
        text("wamid.1", OWNER, "once"),
        text("wamid.1", OWNER, "once"),
    ]);
    tx.send(b.clone()).await.unwrap();
    tx.send(b).await.unwrap();
    assert_eq!(ch.recv().await.unwrap().text, "once");
    assert!(recv_quiet(&mut ch).await);
}

#[tokio::test]
async fn seen_is_persisted_before_the_message_is_returned() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    tx.send(batch(vec![
        text("wamid.a", OWNER, "a"),
        text("wamid.b", OWNER, "b"),
    ]))
    .await
    .unwrap();
    assert_eq!(ch.recv().await.unwrap().text, "a");
    // The whole batch was recorded before the first item was handed out.
    let seen = SeenStore::open(h.home.path()).unwrap();
    assert!(seen.contains("wamid.a"));
    assert!(seen.contains("wamid.b"));
}

#[tokio::test]
async fn restart_does_not_redeliver_seen_wamid() {
    let h = Harness::new().await;
    let b = batch(vec![text("wamid.1", OWNER, "once")]);
    {
        let (tx, mut ch) = h.channel();
        tx.send(b.clone()).await.unwrap();
        assert_eq!(ch.recv().await.unwrap().text, "once");
    }
    let (tx, mut ch) = h.channel();
    tx.send(b).await.unwrap();
    assert!(recv_quiet(&mut ch).await);
}

/// Integration finding I1: a stranger flood must not push an owner's
/// message id out of the seen store, or a Meta redelivery inside the age
/// limit would run the owner's command again.
#[tokio::test]
async fn stranger_flood_does_not_evict_owner_wamid_so_redelivery_is_not_replayed() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    let cmd = batch(vec![text("wamid.CMD", OWNER, "delete notes.txt")]);
    tx.send(cmd.clone()).await.unwrap();
    assert_eq!(ch.recv().await.unwrap().text, "delete notes.txt");
    for k in 0..5 {
        let flood = (0..256)
            .map(|i| text(&format!("wamid.s{k}_{i}"), STRANGER, "hi"))
            .collect();
        tx.send(batch(flood)).await.unwrap();
        while !recv_quiet(&mut ch).await {}
    }
    tx.send(cmd).await.unwrap();
    assert!(recv_quiet(&mut ch).await, "owner command replayed");
}

/// Only owner message ids are recorded: strangers' replays cost an audit
/// entry, not seen-store room.
#[tokio::test]
async fn only_owner_wamids_are_recorded() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    tx.send(batch(vec![
        text("wamid.S", STRANGER, "hi"),
        refused("wamid.R", STRANGER, RefuseReason::NotText),
        refused("wamid.ON", OWNER, RefuseReason::NotText),
        text("wamid.O", OWNER, "mine"),
    ]))
    .await
    .unwrap();
    for _ in 0..4 {
        ch.recv().await.unwrap();
    }
    let seen = SeenStore::open(h.home.path()).unwrap();
    assert!(seen.contains("wamid.O"));
    assert!(seen.contains("wamid.ON"));
    assert!(!seen.contains("wamid.S"));
    assert!(!seen.contains("wamid.R"));
}

#[tokio::test]
async fn seen_write_failure_is_fatal_and_nothing_is_delivered() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    // A directory where the seen file goes: the atomic replace fails.
    std::fs::create_dir(h.home.path().join("whatsapp-seen")).unwrap();
    tx.send(batch(vec![text("wamid.1", OWNER, "do it")]))
        .await
        .unwrap();
    assert!(ch.recv().await.is_none());
    assert_eq!(ch.fatal(), Some(WhatsAppFatal::SeenUnwritable));
    assert!(ch.recv().await.is_none());
    assert_eq!(
        WhatsAppFatal::SeenUnwritable.to_string(),
        "cannot save the WhatsApp seen-message list"
    );
}

#[tokio::test]
async fn listener_gone_is_fatal_listener_stopped() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    drop(tx);
    assert!(ch.recv().await.is_none());
    assert_eq!(ch.fatal(), Some(WhatsAppFatal::ListenerStopped));
    assert_eq!(
        WhatsAppFatal::ListenerStopped.to_string(),
        "the WhatsApp webhook listener stopped"
    );
}

#[tokio::test]
async fn listener_gone_during_shutdown_is_not_fatal() {
    let h = Harness::new().await;
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(true);
    let (tx, ch) = h.channel();
    let mut ch = ch.with_shutdown(stop_rx);
    drop(tx);
    assert!(ch.recv().await.is_none());
    assert_eq!(ch.fatal(), None);
    drop(stop_tx);
}

#[tokio::test]
async fn token_rejected_on_send_is_fatal_and_ends_recv() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    open_window(&tx, &mut ch).await;
    h.script.push(graph_error(401, 190));
    ch.send(&owner(), "hi").await;
    assert_eq!(ch.fatal(), Some(WhatsAppFatal::TokenRejected));
    tx.send(batch(vec![text("wamid.2", OWNER, "more")]))
        .await
        .unwrap();
    assert!(ch.recv().await.is_none());
    assert_eq!(
        WhatsAppFatal::TokenRejected.to_string(),
        "WhatsApp rejected the access token"
    );
}

// --------------------------------------------------------------- outbound

#[tokio::test]
async fn send_goes_only_to_owners() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    open_window(&tx, &mut ch).await;
    // A stranger's message opens no window for them, and is no owner.
    tx.send(batch(vec![text("wamid.s", STRANGER, "hi")]))
        .await
        .unwrap();
    ch.recv().await.unwrap();
    ch.send(&owner(), "hi").await;
    for who in [
        format!("wa:{STRANGER}"),
        format!("wa-stale:{OWNER}"),
        format!("wa-forward:{OWNER}"),
        format!("wa:+{OWNER}"),
        format!("wa:0{OWNER}"),
        format!("tg:{OWNER}"),
        "local".to_string(),
    ] {
        ch.send(&SenderId(who), "nope").await;
    }
    let sent = h.sent().await;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(
        sent[0],
        json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": OWNER,
            "type": "text",
            "text": {"preview_url": false, "body": "hi"},
        })
    );
}

#[tokio::test]
async fn send_redacts_sanitizes_and_caps_at_4096() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    open_window(&tx, &mut ch).await;
    ch.send(
        &owner(),
        "key sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 end",
    )
    .await;
    ch.send(&owner(), "red \x1b[31m text").await;
    ch.send(&owner(), &"😀".repeat(3000)).await;
    let sent = h.sent_texts().await;
    assert_eq!(sent.len(), 3);
    let t0 = &sent[0].1;
    assert!(t0.contains("[REDACTED:api_key]"), "{t0}");
    assert!(!t0.contains("AbCdEfGh"), "{t0}");
    let t1 = &sent[1].1;
    assert!(t1.contains("\\u{1b}[31m"), "{t1}");
    assert!(!t1.contains('\x1b'));
    let t2 = &sent[2].1;
    let units = t2.encode_utf16().count();
    assert!(units <= 4096 && units > 4000, "{units}");
    assert!(t2.ends_with('…'));
}

#[tokio::test]
async fn send_outside_24h_window_is_dropped_and_counted() {
    let h = Harness::new().await;
    let now = Arc::new(AtomicU64::new(NOW_MS));
    let clock = Arc::clone(&now);
    let (tx, mut ch) = h.channel_with(&[OWNER], Box::new(move || clock.load(Ordering::SeqCst)));
    let drops = ch.window_drops();
    // No inbound yet: no window.
    ch.send(&owner(), "too early").await;
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert!(h.sent().await.is_empty());

    // Inbound at T = NOW_S (the clock is NOW_S s + 500 ms).
    open_window(&tx, &mut ch).await;
    let t = (NOW_S as u64) * 1000;
    now.store(t + 23 * 3_600_000, Ordering::SeqCst);
    ch.send(&owner(), "at 23 h").await;
    assert_eq!(h.sent().await.len(), 1);
    // T + 24 h - 4 min: within the 5 minute margin, dropped.
    now.store(t + WINDOW_MS - 4 * 60_000, Ordering::SeqCst);
    ch.send(&owner(), "too late").await;
    assert_eq!(h.sent().await.len(), 1);
    assert_eq!(drops.load(Ordering::Relaxed), 2);
    assert_eq!(ch.window_drops().load(Ordering::Relaxed), 2);

    // An inbound timestamp in the future counts as "now", never later.
    let t2 = t + 30 * 3_600_000;
    now.store(t2, Ordering::SeqCst);
    tx.send(batch(vec![text_at(
        "wamid.future",
        OWNER,
        "from the future",
        NOW_S + 40 * 3600,
    )]))
    .await
    .unwrap();
    ch.recv().await.unwrap();
    now.store(t2 + WINDOW_MS - 4 * 60_000, Ordering::SeqCst);
    ch.send(&owner(), "past now + 24 h").await;
    assert_eq!(h.sent().await.len(), 1);
    assert_eq!(drops.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn graph_131047_counts_as_outside_window() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    open_window(&tx, &mut ch).await;
    h.script.push(graph_error(400, 131047));
    ch.send(&owner(), "hi").await;
    assert_eq!(ch.window_drops().load(Ordering::Relaxed), 1);
    assert_eq!(h.sent().await.len(), 1);
    assert_eq!(ch.fatal(), None);
}

#[tokio::test]
async fn rate_limited_send_retries_once() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    open_window(&tx, &mut ch).await;
    h.script.push(graph_error(400, 130429));
    ch.send(&owner(), "a").await;
    assert_eq!(h.sent().await.len(), 2);
    // A second rate limit after the retry is not retried again.
    h.script.push(ResponseTemplate::new(429));
    h.script.push(graph_error(400, 131056));
    ch.send(&owner(), "b").await;
    assert_eq!(h.sent().await.len(), 4);
}

#[tokio::test]
async fn after_shutdown_rate_limited_send_is_not_retried() {
    let h = Harness::new().await;
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let (tx, ch) = h.channel();
    let mut ch = ch.with_shutdown(stop_rx);
    open_window(&tx, &mut ch).await;
    stop_tx.send_replace(true);
    h.script.push(ResponseTemplate::new(429));
    ch.send(&owner(), "a").await;
    assert_eq!(h.sent().await.len(), 1);
}

#[tokio::test]
async fn after_shutdown_requests_get_the_short_timeout() {
    let h = Harness::new().await;
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let (tx, ch) = h.channel();
    let mut ch = ch.with_shutdown(stop_rx);
    open_window(&tx, &mut ch).await;
    h.script.push(sent_ok().set_delay(Duration::from_secs(20)));
    h.script.push(sent_ok().set_delay(Duration::from_secs(20)));
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        stop_tx.send_replace(true);
        tokio::time::sleep(Duration::from_secs(60)).await;
    });
    let t = std::time::Instant::now();
    ch.send(&owner(), "slow").await;
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    let t = std::time::Instant::now();
    ch.send(&owner(), "slow again").await;
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
}

// -------------------------------------------------------------- approvals

#[tokio::test]
async fn ask_approval_outside_window_is_undelivered() {
    let h = Harness::new().await;
    let (_tx, mut ch) = h.channel();
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
        ApprovalReply::Undelivered
    );
    assert!(h.sent().await.is_empty());
    assert_eq!(ch.window_drops().load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn ask_approval_accepts_yes_code_from_the_sender() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    open_window(&tx, &mut ch).await;
    tx.send(batch(vec![text("wamid.r", OWNER, "yes 4821")]))
        .await
        .unwrap();
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
        ApprovalReply::Yes
    );
    let sent = h.sent_texts().await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, OWNER);
    assert!(sent[0].1.contains("Reply \"yes 4821\""), "{}", sent[0].1);
    assert!(recv_quiet(&mut ch).await);
}

#[tokio::test]
async fn ask_approval_ignores_and_queues_other_senders() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    open_window(&tx, &mut ch).await;
    tx.send(batch(vec![text("wamid.s", STRANGER, "yes 4821")]))
        .await
        .unwrap();
    tx.send(batch(vec![text("wamid.r", OWNER, "yes 4821")]))
        .await
        .unwrap();
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
        ApprovalReply::Yes
    );
    let m = ch.recv().await.unwrap();
    assert_eq!(m.sender, sender_id(STRANGER));
    assert_eq!(m.text, "");
}

#[tokio::test]
async fn reply_from_another_owner_is_queued_not_used() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel_with(&[OWNER, OWNER2], Box::new(|| NOW_MS));
    open_window(&tx, &mut ch).await;
    tx.send(batch(vec![
        text("wamid.o2", OWNER2, "yes 4821"),
        text("wamid.o1", OWNER, "no"),
    ]))
    .await
    .unwrap();
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
        ApprovalReply::No
    );
    let m = ch.recv().await.unwrap();
    assert_eq!((m.sender, m.text.as_str()), (sender_id(OWNER2), "yes 4821"));
}

#[tokio::test]
async fn reply_quoting_another_message_is_no() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    open_window(&tx, &mut ch).await;
    tx.send(batch(vec![reply(
        "wamid.r",
        OWNER,
        "yes 4821",
        "wamid.OTHER",
    )]))
    .await
    .unwrap();
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
        ApprovalReply::No
    );
}

#[tokio::test]
async fn reply_quoting_the_prompt_is_accepted() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    open_window(&tx, &mut ch).await;
    tx.send(batch(vec![reply(
        "wamid.r",
        OWNER,
        "yes 4821",
        PROMPT_WAMID,
    )]))
    .await
    .unwrap();
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
        ApprovalReply::Yes
    );
}

#[tokio::test]
async fn non_text_reply_or_wrong_code_is_no() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    open_window(&tx, &mut ch).await;
    tx.send(batch(vec![refused(
        "wamid.r1",
        OWNER,
        RefuseReason::NotText,
    )]))
    .await
    .unwrap();
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
        ApprovalReply::No
    );
    tx.send(batch(vec![text("wamid.r2", OWNER, "yes 1111")]))
        .await
        .unwrap();
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
        ApprovalReply::No
    );
}

#[tokio::test]
async fn failed_prompt_send_is_undelivered() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    open_window(&tx, &mut ch).await;
    h.script.push(ResponseTemplate::new(500));
    tx.send(batch(vec![text("wamid.r", OWNER, "yes 4821")]))
        .await
        .unwrap();
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
        ApprovalReply::Undelivered
    );
    // The reply was not consumed as an answer.
    assert_eq!(ch.recv().await.unwrap().text, "yes 4821");
}

#[tokio::test]
async fn too_long_prompt_is_refused_with_a_notice() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    open_window(&tx, &mut ch).await;
    let mut p = prompt(Tier::Yes);
    p.summary = "a".repeat(5000);
    assert_eq!(ch.ask_approval(&owner(), &p).await, ApprovalReply::No);
    assert_eq!(
        h.sent_texts().await,
        vec![(
            OWNER.into(),
            "request too long to approve safely; refused".into()
        )]
    );
}

#[tokio::test]
async fn cancelled_ask_approval_leaves_no_reply_behind() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    open_window(&tx, &mut ch).await;
    let r = tokio::time::timeout(
        Duration::from_millis(200),
        ch.ask_approval(&owner(), &prompt(Tier::Yes)),
    )
    .await;
    assert!(r.is_err());
    tx.send(batch(vec![text("wamid.r", OWNER, "yes 4821")]))
        .await
        .unwrap();
    let m = ch.recv().await.unwrap();
    assert_eq!(m.text, "yes 4821");
    assert!(recv_quiet(&mut ch).await);
}

#[tokio::test]
async fn yespin_prompt_is_no_without_send() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    open_window(&tx, &mut ch).await;
    tx.send(batch(vec![text("wamid.r", OWNER, "yes 4821 123456")]))
        .await
        .unwrap();
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::YesPin)).await,
        ApprovalReply::No
    );
    assert!(h.sent().await.is_empty());
    // Nothing was read as an answer.
    assert_eq!(ch.recv().await.unwrap().text, "yes 4821 123456");
}

#[tokio::test]
async fn ask_approval_to_non_owner_is_no_without_send() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    open_window(&tx, &mut ch).await;
    for who in [sender_id(STRANGER), SenderId("local".into())] {
        assert_eq!(
            ch.ask_approval(&who, &prompt(Tier::Yes)).await,
            ApprovalReply::No
        );
    }
    assert!(h.sent().await.is_empty());
}

#[tokio::test]
async fn accepts_pin_is_always_false() {
    let h = Harness::new().await;
    let (_tx, ch) = h.channel_with(&[OWNER, OWNER2], Box::new(|| NOW_MS));
    for who in [
        owner(),
        sender_id(OWNER2),
        sender_id(STRANGER),
        SenderId("local".into()),
    ] {
        assert!(!ch.accepts_pin(&who));
    }
}

/// Controller ruling: WhatsApp cannot delete a user's message, so instead
/// of a silent no-op the owner is told to delete it (best effort, inside
/// the 24 h window only).
#[tokio::test]
async fn retract_last_tells_owner_to_delete_it_themselves() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    // Outside the window: nothing is sent.
    ch.retract_last(&owner()).await;
    assert!(h.sent().await.is_empty());
    open_window(&tx, &mut ch).await;
    ch.retract_last(&owner()).await;
    ch.retract_last(&sender_id(STRANGER)).await;
    assert_eq!(
        h.sent_texts().await,
        vec![(OWNER.into(), DELETE_NOTICE.into())]
    );
    // Nothing is deleted: the only requests are sends.
    let reqs = h.server.received_requests().await.unwrap();
    assert!(reqs
        .iter()
        .all(|r| r.method.as_str() == "POST" && r.url.path() == messages_path()));
}

// ---------------------------------------------------------------- routing

#[tokio::test]
async fn serves_only_wa_senders() {
    let h = Harness::new().await;
    let (_tx, ch) = h.channel();
    assert!(ch.serves(&owner()));
    assert!(ch.serves(&sender_id(STRANGER)));
    for who in [
        format!("wa-stale:{OWNER}"),
        format!("tg:{OWNER}"),
        "local".to_string(),
        "wa".to_string(),
    ] {
        assert!(!ch.serves(&SenderId(who.clone())), "{who}");
    }
}

// ------------------------------------------------------- review round 1

/// Meta's clock runs an hour ahead: the age rule uses the timestamp capped
/// at the local clock, so a queued owner text still expires.
#[tokio::test]
async fn future_timestamp_is_capped_for_queue_age() {
    let h = Harness::new().await;
    let now = Arc::new(AtomicU64::new(NOW_MS));
    let clock = Arc::clone(&now);
    let (tx, mut ch) = h.channel_with(&[OWNER], Box::new(move || clock.load(Ordering::SeqCst)));
    tx.send(batch(vec![
        text_at("wamid.f1", OWNER, "first", NOW_S + 3600),
        text_at("wamid.f2", OWNER, "delete notes.txt", NOW_S + 3600),
    ]))
    .await
    .unwrap();
    assert_eq!(ch.recv().await.unwrap().text, "first");
    // 30 minutes in the queue: far past the 120 s age.
    now.fetch_add(1_800_000, Ordering::SeqCst);
    let m = ch.recv().await.unwrap();
    assert_eq!(m.sender, SenderId(format!("wa-stale:{OWNER}")));
    assert_eq!(m.text, "");
    // Also at ingest: a future-stamped text arriving after a long wait
    // since a far-future one is judged by arrival, not by Meta's clock.
    now.fetch_add(3_600_000, Ordering::SeqCst);
    tx.send(batch(vec![text_at(
        "wamid.f3",
        OWNER,
        "later",
        NOW_S + 10 * 3600,
    )]))
    .await
    .unwrap();
    assert_eq!(ch.recv().await.unwrap().text, "later");
}

/// An owner message stamped before the prompt was sent (buffered while the
/// engine built it) is not the reply; it is queued for `recv`, not lost.
#[tokio::test]
async fn message_sent_before_the_prompt_is_queued_not_taken_as_reply() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    open_window(&tx, &mut ch).await;
    tx.send(batch(vec![
        text_at("wamid.b1", OWNER, "delete notes.txt", NOW_S - 10),
        text_at("wamid.b2", OWNER, "also list my files", NOW_S - 6),
    ]))
    .await
    .unwrap();
    tx.send(batch(vec![text("wamid.r", OWNER, "no")]))
        .await
        .unwrap();
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
        ApprovalReply::No
    );
    let m = ch.recv().await.unwrap();
    assert_eq!((m.sender, m.text.as_str()), (owner(), "delete notes.txt"));
    assert_eq!(ch.recv().await.unwrap().text, "also list my files");
    assert!(recv_quiet(&mut ch).await);
}

#[tokio::test]
async fn retract_last_outside_window_is_silent_and_not_counted() {
    let h = Harness::new().await;
    let (_tx, mut ch) = h.channel();
    let drops = ch.window_drops();
    ch.retract_last(&owner()).await;
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert!(h.sent().await.is_empty());
}

#[tokio::test]
async fn fatal_channel_makes_no_requests() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    open_window(&tx, &mut ch).await;
    h.script.push(graph_error(401, 190));
    ch.send(&owner(), "first").await;
    assert_eq!(ch.fatal(), Some(WhatsAppFatal::TokenRejected));
    assert_eq!(h.sent().await.len(), 1);
    ch.send(&owner(), "second").await;
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
        ApprovalReply::Undelivered
    );
    ch.retract_last(&owner()).await;
    assert_eq!(h.sent().await.len(), 1);
    assert_eq!(ch.window_drops().load(Ordering::Relaxed), 0);
}

/// Every batch already waiting is drained, however many there are.
#[tokio::test]
async fn discard_drains_more_than_64_waiting_batches() {
    let h = Harness::new().await;
    let api = GraphApi::new(
        AccessToken::new(TOKEN.into()).unwrap(),
        &h.server.uri(),
        "v26.0",
        PNID,
    )
    .unwrap();
    let (tx, rx) = mpsc::channel(256);
    let mut ch = WhatsAppChannel::new(
        api,
        rx,
        vec![OWNER.to_string()],
        SeenStore::open(h.home.path()).unwrap(),
        opts(),
    )
    .with_clock(Box::new(|| NOW_MS));
    for i in 0..100 {
        tx.send(batch(vec![text(&format!("wamid.d{i}"), OWNER, "x")]))
            .await
            .unwrap();
    }
    assert_eq!(ch.discard_pending_input(&owner()).await, 100);
    assert!(recv_quiet(&mut ch).await);
}

// ------------------------------------------------------- review round 2

/// The local clock runs 30 s ahead of Meta's: `yes <this prompt's code>`
/// still answers, because the code cannot predate the prompt.
#[tokio::test]
async fn matching_code_reply_is_accepted_despite_clock_skew() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel_with(&[OWNER], Box::new(|| NOW_MS + 30_000));
    open_window(&tx, &mut ch).await;
    tx.send(batch(vec![text("wamid.r", OWNER, "yes 4821")]))
        .await
        .unwrap();
    let r = tokio::time::timeout(
        Duration::from_secs(2),
        ch.ask_approval(&owner(), &prompt(Tier::Yes)),
    )
    .await
    .expect("the reply must be taken, not queued");
    assert_eq!(r, ApprovalReply::Yes);
}

/// A pre-prompt `yes` with another code is not the reply: it is queued
/// and later delivered by `recv`.
#[tokio::test]
async fn wrong_code_reply_before_prompt_is_still_queued() {
    let h = Harness::new().await;
    let (tx, mut ch) = h.channel();
    open_window(&tx, &mut ch).await;
    tx.send(batch(vec![
        text_at("wamid.old", OWNER, "yes 1111", NOW_S - 10),
        text("wamid.r", OWNER, "no"),
    ]))
    .await
    .unwrap();
    assert_eq!(
        ch.ask_approval(&owner(), &prompt(Tier::Yes)).await,
        ApprovalReply::No
    );
    let m = ch.recv().await.unwrap();
    assert_eq!((m.sender, m.text.as_str()), (owner(), "yes 1111"));
    assert!(recv_quiet(&mut ch).await);
}

/// Only the batches waiting when the discard starts are drained; a flood
/// that keeps arriving cannot keep it busy, and stays for later.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discard_is_bounded_by_what_was_waiting() {
    const CAP: usize = 32;
    let h = Harness::new().await;
    let api = GraphApi::new(
        AccessToken::new(TOKEN.into()).unwrap(),
        &h.server.uri(),
        "v26.0",
        PNID,
    )
    .unwrap();
    let (tx, rx) = mpsc::channel(CAP);
    let mut ch = WhatsAppChannel::new(
        api,
        rx,
        vec![OWNER.to_string()],
        SeenStore::open(h.home.path()).unwrap(),
        opts(),
    )
    .with_clock(Box::new(|| NOW_MS));
    for i in 0..CAP {
        tx.send(batch(vec![text(&format!("wamid.w{i}"), OWNER, "x")]))
            .await
            .unwrap();
    }
    // A sender that refills every slot the drain frees, without end.
    let flood = tokio::spawn(async move {
        let mut i = 0u64;
        while tx
            .send(batch(vec![text(&format!("wamid.f{i}"), OWNER, "later")]))
            .await
            .is_ok()
        {
            i += 1;
        }
    });
    let dropped = tokio::time::timeout(Duration::from_secs(5), ch.discard_pending_input(&owner()))
        .await
        .expect("the drain must end");
    flood.abort();
    assert_eq!(dropped, CAP);
    // What arrived during the drain is still there.
    assert_eq!(ch.recv().await.unwrap().text, "later");
}
