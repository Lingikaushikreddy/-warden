use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use warden_agent::whatsapp::{
    check_signature, handshake, parse_notification, AppSecret, NotificationError, RefuseReason,
    SignatureCheck, VerifyToken, WaEvent, MAX_EVENTS,
};

const SECRET: &str = "0123456789abcdefABCDEF0123456789";
const TOKEN: &str = "verify-token_0123.~xyz";
const PNID: &str = "106540352242922";
const OWNER: &str = "15551234567";

fn secret() -> AppSecret {
    AppSecret::new(SECRET.into()).unwrap()
}

fn token() -> VerifyToken {
    VerifyToken::new(TOKEN.into()).unwrap()
}

fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

// ---------- signature ----------

#[test]
fn valid_signature_is_valid() {
    let body = br#"{"object":"whatsapp_business_account"}"#;
    let h = sign(SECRET, body);
    assert_eq!(
        check_signature(&secret(), Some(h.as_bytes()), body),
        SignatureCheck::Valid
    );
}

#[test]
fn missing_header_is_missing() {
    assert_eq!(
        check_signature(&secret(), None, b"{}"),
        SignatureCheck::Missing
    );
}

#[test]
fn signature_of_other_body_or_secret_is_invalid() {
    let body = b"{\"a\":1}";
    let other_body = sign(SECRET, b"{\"a\":2}");
    assert_eq!(
        check_signature(&secret(), Some(other_body.as_bytes()), body),
        SignatureCheck::Invalid
    );
    let other_secret = sign("ffffffffffffffffffffffffffffffff", body);
    assert_eq!(
        check_signature(&secret(), Some(other_secret.as_bytes()), body),
        SignatureCheck::Invalid
    );
}

#[test]
fn sha1_prefix_non_hex_and_short_hex_are_invalid() {
    let body = b"{}";
    let good = sign(SECRET, body);
    let hexpart = good.strip_prefix("sha256=").unwrap();
    let cases: Vec<String> = vec![
        format!("sha1={hexpart}"),
        format!("SHA256={hexpart}"),
        format!("sha256={}", &hexpart[..63]),
        format!("sha256={}", &hexpart[..62]),
        format!("sha256={hexpart}0"),
        format!("sha256={hexpart}00"),
        format!("sha256=g{}", &hexpart[1..]),
        format!("sha256= {}", &hexpart[1..]),
        format!(" sha256={hexpart}"),
        format!("sha256={hexpart}\n"),
        hexpart.to_string(),
        String::new(),
        "sha256=".into(),
    ];
    for c in cases {
        assert_eq!(
            check_signature(&secret(), Some(c.as_bytes()), body),
            SignatureCheck::Invalid,
            "{c:?}"
        );
    }
    // Non-UTF-8 header bytes.
    assert_eq!(
        check_signature(&secret(), Some(b"sha256=\xff\xfe"), body),
        SignatureCheck::Invalid
    );
}

#[test]
fn uppercase_hex_is_accepted() {
    let body = b"payload";
    let h = sign(SECRET, body);
    let upper = format!("sha256={}", h["sha256=".len()..].to_ascii_uppercase());
    assert_eq!(
        check_signature(&secret(), Some(upper.as_bytes()), body),
        SignatureCheck::Valid
    );
}

// ---------- handshake ----------

fn q(mode: &str, tok: &str, challenge: &str) -> String {
    format!("hub.mode={mode}&hub.verify_token={tok}&hub.challenge={challenge}")
}

#[test]
fn handshake_returns_digit_challenge() {
    assert_eq!(
        handshake(Some(&q("subscribe", TOKEN, "1158201444")), &token()),
        Some("1158201444".to_string())
    );
    let max = "9".repeat(64);
    assert_eq!(
        handshake(Some(&q("subscribe", TOKEN, &max)), &token()),
        Some(max.clone())
    );
    // Order does not matter; unrelated keys are ignored.
    let reordered = format!("x=1&hub.challenge=7&hub.verify_token={TOKEN}&hub.mode=subscribe");
    assert_eq!(handshake(Some(&reordered), &token()), Some("7".into()));
}

#[test]
fn handshake_refuses_wrong_token_mode_or_challenge() {
    let t = token();
    let cases: Vec<String> = vec![
        q("subscribe", "verify-token_0123.~xyZ", "123"),
        q("subscribe", "verify-token_0123.~xy", "123"),
        q("subscribe", "", "123"),
        q("unsubscribe", TOKEN, "123"),
        q("Subscribe", TOKEN, "123"),
        q("subscribe", TOKEN, "abc"),
        q("subscribe", TOKEN, "12a"),
        q("subscribe", TOKEN, "-1"),
        q("subscribe", TOKEN, "%E0%A5%A7"), // Devanagari digit one
        q("subscribe", TOKEN, &"1".repeat(65)),
        q("subscribe", TOKEN, ""),
        format!("hub.verify_token={TOKEN}&hub.challenge=1"),
        "hub.mode=subscribe&hub.challenge=1".into(),
        format!("hub.mode=subscribe&hub.verify_token={TOKEN}"),
        format!("{}&hub.verify_token={TOKEN}", q("subscribe", TOKEN, "1")),
        format!("{}&hub.verify_token=other", q("subscribe", TOKEN, "1")),
        format!("{}&hub.mode=subscribe", q("subscribe", TOKEN, "1")),
        format!("{}&hub.challenge=1", q("subscribe", TOKEN, "1")),
        String::new(),
    ];
    for c in &cases {
        assert_eq!(handshake(Some(c), &t), None, "{c:?}");
    }
    assert_eq!(handshake(None, &t), None);
}

// ---------- secrets ----------

#[test]
fn secret_shapes_are_validated() {
    assert!(AppSecret::new("a".repeat(16)).is_ok());
    assert!(AppSecret::new("Z9".repeat(64)).is_ok());
    for bad in [
        "a".repeat(15),
        "a".repeat(129),
        format!("{}-", "a".repeat(20)),
        format!("{}\n", "a".repeat(20)),
        format!("{} ", "a".repeat(20)),
        "é".repeat(16),
        String::new(),
    ] {
        assert_eq!(
            AppSecret::new(bad.clone()).unwrap_err(),
            "invalid app secret"
        );
    }

    assert!(VerifyToken::new("a".repeat(16)).is_ok());
    assert!(VerifyToken::new("A-z.0_9~".repeat(16)).is_ok());
    for bad in [
        "a".repeat(15),
        "a".repeat(129),
        format!("{}/", "a".repeat(20)),
        format!("{}&", "a".repeat(20)),
        format!("{}=", "a".repeat(20)),
        format!("{}\n", "a".repeat(20)),
        format!("{} ", "a".repeat(20)),
        "é".repeat(16),
        String::new(),
    ] {
        assert_eq!(
            VerifyToken::new(bad.clone()).unwrap_err(),
            "invalid verify token"
        );
    }
}

#[test]
fn debug_hides_secrets() {
    let s = format!("{:?}", secret());
    assert!(!s.contains(SECRET), "{s}");
    assert!(!s.contains("0123456789"), "{s}");
    let t = format!("{:?}", token());
    assert!(!t.contains(TOKEN), "{t}");
    assert!(!t.contains("verify-token"), "{t}");
}

// ---------- parsing ----------

fn text_msg() -> Value {
    json!({
        "from": OWNER,
        "id": "wamid.HBgLMTU1NTEyMzQ1NjcVAgASGBQzQTk=",
        "timestamp": "1700000000",
        "type": "text",
        "text": {"body": "list the files"},
        "some_future_field": {"x": 1}
    })
}

fn envelope_with(pnid: &str, value_extra: Value) -> Value {
    let mut value = json!({
        "messaging_product": "whatsapp",
        "metadata": {"display_phone_number": "15550000000", "phone_number_id": pnid},
        "contacts": [{"profile": {"name": "K"}, "wa_id": OWNER}]
    });
    for (k, v) in value_extra.as_object().unwrap() {
        value[k] = v.clone();
    }
    json!({
        "object": "whatsapp_business_account",
        "entry": [{"id": "WABA_ID", "changes": [{"field": "messages", "value": value}]}]
    })
}

fn envelope(messages: Vec<Value>) -> Value {
    envelope_with(PNID, json!({ "messages": messages }))
}

fn parse(v: &Value) -> Vec<WaEvent> {
    let n = parse_notification(v.to_string().as_bytes(), PNID).expect("parses");
    assert_eq!(n.foreign, 0);
    n.events
}

fn one(m: Value) -> WaEvent {
    let mut ev = parse(&envelope(vec![m]));
    assert_eq!(ev.len(), 1, "{ev:?}");
    ev.remove(0)
}

fn reason(m: Value) -> RefuseReason {
    match one(m) {
        WaEvent::Refused { reason, .. } => reason,
        e => panic!("expected refusal, got {e:?}"),
    }
}

fn with(mut v: Value, f: impl FnOnce(&mut Value)) -> Value {
    f(&mut v);
    v
}

#[test]
fn text_from_metadata_matching_number_is_text() {
    assert_eq!(
        one(text_msg()),
        WaEvent::Text {
            wamid: "wamid.HBgLMTU1NTEyMzQ1NjcVAgASGBQzQTk=".into(),
            from: OWNER.into(),
            timestamp_s: 1_700_000_000,
            body: "list the files".into(),
            reply_to: None,
        }
    );
    // An integer timestamp is accepted too.
    let m = with(text_msg(), |m| m["timestamp"] = json!(1_700_000_001));
    match one(m) {
        WaEvent::Text { timestamp_s, .. } => assert_eq!(timestamp_s, 1_700_000_001),
        e => panic!("{e:?}"),
    }
}

#[test]
fn reply_context_id_is_reply_to() {
    let m = with(text_msg(), |m| {
        m["context"] = json!({"from": "15550000000", "id": "wamid.PROMPT"})
    });
    match one(m) {
        WaEvent::Text { reply_to, .. } => assert_eq!(reply_to.as_deref(), Some("wamid.PROMPT")),
        e => panic!("{e:?}"),
    }
}

#[test]
fn forwarded_and_frequently_forwarded_are_refused() {
    for k in ["forwarded", "frequently_forwarded"] {
        let m = with(text_msg(), |m| m["context"] = json!({ k: true }));
        match one(m) {
            WaEvent::Refused {
                wamid,
                from,
                timestamp_s,
                reason,
            } => {
                assert_eq!(reason, RefuseReason::Forwarded);
                assert_eq!(from.as_deref(), Some(OWNER));
                assert!(wamid.is_some());
                assert_eq!(timestamp_s, Some(1_700_000_000));
            }
            e => panic!("{e:?}"),
        }
    }
    // `false` is not a forward.
    let m = with(text_msg(), |m| {
        m["context"] = json!({"forwarded": false, "frequently_forwarded": false})
    });
    assert!(matches!(one(m), WaEvent::Text { .. }));
    assert_eq!(RefuseReason::Forwarded.tag(), "forward");
}

#[test]
fn image_audio_document_sticker_location_contacts_interactive_button_are_not_text() {
    for ty in [
        "image",
        "audio",
        "video",
        "document",
        "sticker",
        "location",
        "contacts",
        "interactive",
        "button",
        "order",
        "something_new",
    ] {
        let m = with(text_msg(), |m| {
            m["type"] = json!(ty);
            m.as_object_mut().unwrap().remove("text");
            m[ty] = json!({"id": "MEDIA", "caption": "list the files"});
        });
        assert_eq!(reason(m), RefuseReason::NotText, "{ty}");
    }
    // `type: text` without a string body, and a missing `type`.
    let m = with(text_msg(), |m| m["text"] = json!({"body": 5}));
    assert_eq!(reason(m), RefuseReason::NotText);
    let m = with(text_msg(), |m| {
        m.as_object_mut().unwrap().remove("type");
    });
    assert_eq!(reason(m), RefuseReason::NotText);
    assert_eq!(RefuseReason::NotText.tag(), "non-text");
}

#[test]
fn reaction_system_unsupported_are_tagged() {
    for (ty, want, tag) in [
        ("reaction", RefuseReason::Reaction, "reaction"),
        ("system", RefuseReason::System, "system"),
        ("unsupported", RefuseReason::Unsupported, "unsupported"),
    ] {
        let m = with(text_msg(), |m| {
            m["type"] = json!(ty);
            m.as_object_mut().unwrap().remove("text");
        });
        assert_eq!(reason(m), want, "{ty}");
        assert_eq!(want.tag(), tag);
    }
    assert_eq!(RefuseReason::Malformed.tag(), "malformed");
}

#[test]
fn message_with_errors_is_unsupported() {
    let m = with(text_msg(), |m| {
        m["errors"] = json!([{"code": 131051, "title": "Message type unknown"}])
    });
    assert_eq!(reason(m), RefuseReason::Unsupported);
}

#[test]
fn statuses_become_status_events() {
    let v = envelope_with(
        PNID,
        json!({"statuses": [
            {"id": "wamid.A", "status": "sent", "timestamp": "1700000000", "recipient_id": OWNER},
            {"id": "wamid.B", "status": "delivered", "timestamp": "1700000001", "recipient_id": OWNER},
            {"id": "wamid.C", "status": "read", "timestamp": "1700000002", "recipient_id": OWNER},
            {"id": "wamid.D", "status": "failed", "timestamp": "1700000003", "recipient_id": OWNER,
             "errors": [{"code": 131047}]},
            "not even an object"
        ]}),
    );
    let ev = parse(&v);
    assert_eq!(ev, vec![WaEvent::Status; 5]);
    // Mixed: statuses and a message in the same change.
    let v = envelope_with(
        PNID,
        json!({"statuses": [{"id": "wamid.A", "status": "read"}], "messages": [text_msg()]}),
    );
    let ev = parse(&v);
    assert_eq!(ev.len(), 2);
    assert_eq!(ev.iter().filter(|e| **e == WaEvent::Status).count(), 1);
    assert_eq!(
        ev.iter()
            .filter(|e| matches!(e, WaEvent::Text { .. }))
            .count(),
        1
    );
}

#[test]
fn foreign_phone_number_id_is_ignored() {
    let v = envelope_with(
        "999999999999999",
        json!({"messages": [text_msg()], "statuses": [{"id": "wamid.A", "status": "read"}]}),
    );
    let n = parse_notification(v.to_string().as_bytes(), PNID).unwrap();
    assert_eq!(n.foreign, 1);
    assert!(n.events.is_empty(), "{:?}", n.events);
    // Missing metadata is foreign too: never trusted as ours.
    let mut v = envelope(vec![text_msg()]);
    v["entry"][0]["changes"][0]["value"]
        .as_object_mut()
        .unwrap()
        .remove("metadata");
    let n = parse_notification(v.to_string().as_bytes(), PNID).unwrap();
    assert_eq!(n.foreign, 1);
    assert!(n.events.is_empty());
    // A non-`messages` field is skipped and not counted.
    let mut v = envelope(vec![text_msg()]);
    v["entry"][0]["changes"][0]["field"] = json!("account_update");
    let n = parse_notification(v.to_string().as_bytes(), PNID).unwrap();
    assert_eq!(n.foreign, 0);
    assert!(n.events.is_empty());
}

#[test]
fn missing_id_from_or_timestamp_is_malformed() {
    for k in ["id", "from", "timestamp"] {
        let m = with(text_msg(), |m| {
            m.as_object_mut().unwrap().remove(k);
        });
        match one(m) {
            WaEvent::Refused {
                wamid,
                from,
                timestamp_s,
                reason,
            } => {
                assert_eq!(reason, RefuseReason::Malformed, "{k}");
                assert_eq!(wamid.is_some(), k != "id", "{k}");
                assert_eq!(from.is_some(), k != "from", "{k}");
                assert_eq!(timestamp_s.is_some(), k != "timestamp", "{k}");
            }
            e => panic!("{k}: {e:?}"),
        }
    }
    // Invalid shapes are malformed too, and malformed wins over forwarding.
    for (k, bad) in [
        ("id", json!("")),
        ("id", json!("wamid with space")),
        ("id", json!("x".repeat(257))),
        ("id", json!("wamid.\u{7f}")),
        ("id", json!(5)),
        ("timestamp", json!("17e8")),
        ("timestamp", json!("")),
        ("timestamp", json!(-5)),
        ("timestamp", json!(1.5)),
        ("timestamp", json!("99999999999999999999999")),
    ] {
        let m = with(text_msg(), |m| {
            m[k] = bad.clone();
            m["context"] = json!({"forwarded": true});
        });
        assert_eq!(reason(m), RefuseReason::Malformed, "{k}={bad}");
    }
    // A message that is not an object.
    let ev = parse(&envelope(vec![json!("nope")]));
    assert_eq!(
        ev,
        vec![WaEvent::Refused {
            wamid: None,
            from: None,
            timestamp_s: None,
            reason: RefuseReason::Malformed
        }]
    );
}

#[test]
fn non_digit_from_is_malformed() {
    for bad in [
        json!("+15551234567"),
        json!("1555 123"),
        json!(""),
        json!("1".repeat(21)),
        json!(15551234567_i64),
        json!("１２３"),
    ] {
        let m = with(text_msg(), |m| m["from"] = bad.clone());
        match one(m) {
            WaEvent::Refused { from, reason, .. } => {
                assert_eq!(reason, RefuseReason::Malformed, "{bad}");
                assert_eq!(from, None);
            }
            e => panic!("{bad}: {e:?}"),
        }
    }
    let m = with(text_msg(), |m| m["from"] = json!("1".repeat(20)));
    assert!(matches!(one(m), WaEvent::Text { .. }));
}

#[test]
fn wrong_object_is_not_whatsapp() {
    for v in [
        json!({"object": "page", "entry": []}),
        json!({"object": "instagram", "entry": []}),
        json!({"entry": []}),
        json!([]),
        json!("whatsapp_business_account"),
    ] {
        assert_eq!(
            parse_notification(v.to_string().as_bytes(), PNID).unwrap_err(),
            NotificationError::NotWhatsApp,
            "{v}"
        );
    }
}

#[test]
fn garbage_is_not_json() {
    for b in [&b""[..], b"not json", b"{\"object\":", b"\xff\xfe{}"] {
        assert_eq!(
            parse_notification(b, PNID).unwrap_err(),
            NotificationError::NotJson
        );
    }
}

#[test]
fn events_are_capped_at_256() {
    let msgs: Vec<Value> = (0..300)
        .map(|i| with(text_msg(), |m| m["id"] = json!(format!("wamid.{i}"))))
        .collect();
    let mut v = envelope(msgs);
    // A second entry adds more on top; still capped.
    let extra = v["entry"][0].clone();
    v["entry"].as_array_mut().unwrap().push(extra);
    let ev = parse(&v);
    assert_eq!(ev.len(), 256);
    match &ev[0] {
        WaEvent::Text { wamid, .. } => assert_eq!(wamid, "wamid.0"),
        e => panic!("{e:?}"),
    }
}

// ---------- the event cap ----------

fn msg_from(id: &str, from: &str) -> Value {
    json!({"from": from, "id": id, "timestamp": "1700000000", "type": "text", "text": {"body": "x"}})
}

fn change(pnid: &str, messages: Vec<Value>, statuses: usize) -> Value {
    let statuses: Vec<Value> = (0..statuses)
        .map(|i| json!({"id": format!("wamid.out{i}"), "status": "delivered", "timestamp": "1", "recipient_id": OWNER}))
        .collect();
    json!({"field": "messages", "value": {
        "messaging_product": "whatsapp",
        "metadata": {"display_phone_number": "15550000000", "phone_number_id": pnid},
        "messages": messages,
        "statuses": statuses
    }})
}

fn changes(changes: Vec<Value>) -> Vec<u8> {
    json!({"object": "whatsapp_business_account", "entry": [{"id": "W", "changes": changes}]})
        .to_string()
        .into_bytes()
}

/// Integration finding I4: statuses in an earlier change must not crowd
/// out a later change's owner text; messages from every change come first.
#[test]
fn messages_from_all_changes_come_before_any_status() {
    let body = changes(vec![
        change(PNID, vec![], MAX_EVENTS),
        change(PNID, vec![msg_from("wamid.O", OWNER)], 0),
    ]);
    let n = parse_notification(&body, PNID).unwrap();
    assert_eq!(n.events.len(), MAX_EVENTS);
    assert!(
        matches!(&n.events[0], WaEvent::Text { from, .. } if from == OWNER),
        "{:?}",
        n.events[0]
    );
    assert!(n.events[1..].iter().all(|e| matches!(e, WaEvent::Status)));
    assert_eq!(n.truncated, 1);
    assert_eq!(n.foreign, 0);
}

/// Events past the cap are counted, and foreign changes past the cap are
/// still counted as foreign.
#[test]
fn events_past_the_cap_are_counted_as_truncated() {
    let flood: Vec<Value> = (0..MAX_EVENTS)
        .map(|i| msg_from(&format!("wamid.s{i}"), "15550000666"))
        .collect();
    let body = changes(vec![
        change(PNID, flood, 3),
        change(PNID, vec![msg_from("wamid.O", OWNER)], 0),
        change("999", vec![msg_from("wamid.F", OWNER)], 0),
    ]);
    let n = parse_notification(&body, PNID).unwrap();
    assert_eq!(n.events.len(), MAX_EVENTS);
    assert!(n.events.iter().all(|e| matches!(e, WaEvent::Text { .. })));
    // The owner's text in the second change and the 3 statuses.
    assert_eq!(n.truncated, 4);
    assert_eq!(n.foreign, 1);

    // Under the cap nothing is truncated.
    let small = changes(vec![change(PNID, vec![msg_from("wamid.O", OWNER)], 2)]);
    assert_eq!(parse_notification(&small, PNID).unwrap().truncated, 0);
}
