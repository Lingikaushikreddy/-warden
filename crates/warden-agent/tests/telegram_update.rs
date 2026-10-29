use serde_json::{json, Value};
use warden_agent::telegram::{classify_update, RefuseReason, Update, UpdateKind};

const OWNER: i64 = 1111;

fn private_msg() -> Value {
    json!({
        "update_id": 10,
        "message": {
            "message_id": 5,
            "date": 1_700_000_000,
            "from": {"id": OWNER, "is_bot": false, "first_name": "K"},
            "chat": {"id": OWNER, "type": "private"},
            "text": "list the files",
            "some_future_field": {"x": 1}
        }
    })
}

fn with(mut v: Value, f: impl FnOnce(&mut Value)) -> Value {
    f(&mut v["message"]);
    v
}

fn refused(v: &Value) -> RefuseReason {
    match classify_update(v).expect("has update_id").kind {
        UpdateKind::Refused { reason, .. } => reason,
        k => panic!("expected refusal, got {k:?}"),
    }
}

#[test]
fn private_text_from_owner_is_text() {
    let u = classify_update(&private_msg()).unwrap();
    assert_eq!(
        u,
        Update {
            update_id: 10,
            kind: UpdateKind::Text {
                chat_id: OWNER,
                from_id: OWNER,
                message_id: 5,
                date_s: 1_700_000_000,
                text: "list the files".into(),
                reply_to: None,
            }
        }
    );
}

#[test]
fn chat_id_differs_from_from_id_is_not_private() {
    let v = with(private_msg(), |m| m["chat"]["id"] = json!(2222));
    assert_eq!(refused(&v), RefuseReason::NotPrivate);
    assert_eq!(RefuseReason::NotPrivate.tag(), "group");
}

#[test]
fn group_chat_is_not_private() {
    for ty in ["group", "supergroup", "channel"] {
        let v = with(private_msg(), |m| m["chat"]["type"] = json!(ty));
        assert_eq!(refused(&v), RefuseReason::NotPrivate, "{ty}");
    }
    let v = with(private_msg(), |m| {
        m["chat"] = json!({"id": -100, "type": "group"})
    });
    match classify_update(&v).unwrap().kind {
        UpdateKind::Refused {
            from_id,
            message_id,
            chat_id,
            reason,
        } => {
            assert_eq!(reason, RefuseReason::NotPrivate);
            assert_eq!(from_id, Some(OWNER));
            assert_eq!(message_id, Some(5));
            assert_eq!(chat_id, Some(-100));
        }
        k => panic!("{k:?}"),
    }
}

#[test]
fn edited_message_is_refused() {
    let msg = private_msg()["message"].clone();
    let v = json!({"update_id": 11, "edited_message": msg});
    assert_eq!(refused(&v), RefuseReason::Edited);
    assert_eq!(RefuseReason::Edited.tag(), "edited");
    // Checked first, even when a message is present too.
    let v = json!({"update_id": 11, "edited_message": msg, "message": msg});
    assert_eq!(refused(&v), RefuseReason::Edited);
}

#[test]
fn forward_origin_is_refused() {
    let v = with(private_msg(), |m| {
        m["forward_origin"] = json!({"type": "user", "date": 1, "sender_user": {"id": 9}})
    });
    assert_eq!(refused(&v), RefuseReason::Forwarded);
    assert_eq!(RefuseReason::Forwarded.tag(), "forward");
}

#[test]
fn legacy_forward_from_is_refused() {
    for (k, val) in [
        ("forward_from", json!({"id": 9, "is_bot": false})),
        ("forward_from_chat", json!({"id": -9, "type": "channel"})),
        ("forward_date", json!(1)),
        ("forward_sender_name", json!("someone")),
        ("is_automatic_forward", json!(true)),
    ] {
        let v = with(private_msg(), |m| m[k] = val);
        assert_eq!(refused(&v), RefuseReason::Forwarded, "{k}");
    }
}

#[test]
fn external_reply_is_refused() {
    let v = with(private_msg(), |m| {
        m["external_reply"] = json!({"origin": {"type": "hidden_user", "date": 1}})
    });
    assert_eq!(refused(&v), RefuseReason::Forwarded);
}

#[test]
fn bot_sender_is_refused() {
    let v = with(private_msg(), |m| m["from"]["is_bot"] = json!(true));
    assert_eq!(refused(&v), RefuseReason::FromBot);
    assert_eq!(RefuseReason::FromBot.tag(), "bot");
}

#[test]
fn via_bot_is_refused() {
    let v = with(private_msg(), |m| {
        m["via_bot"] = json!({"id": 3, "is_bot": true, "username": "x_bot"})
    });
    assert_eq!(refused(&v), RefuseReason::ViaBot);
    assert_eq!(RefuseReason::ViaBot.tag(), "via-bot");
}

#[test]
fn sender_chat_is_refused() {
    let v = with(private_msg(), |m| {
        m["sender_chat"] = json!({"id": -5, "type": "channel"})
    });
    assert_eq!(refused(&v), RefuseReason::SenderChat);
    assert_eq!(RefuseReason::SenderChat.tag(), "sender-chat");
    // No `from` at all (channel posts, anonymous admins).
    let v = with(private_msg(), |m| {
        m.as_object_mut().unwrap().remove("from");
    });
    assert_eq!(refused(&v), RefuseReason::SenderChat);
}

#[test]
fn photo_with_caption_is_not_text() {
    let v = with(private_msg(), |m| {
        let o = m.as_object_mut().unwrap();
        o.remove("text");
        o.insert("photo".into(), json!([{"file_id": "f"}]));
        o.insert("caption".into(), json!("list the files"));
    });
    assert_eq!(refused(&v), RefuseReason::NotText);
    assert_eq!(RefuseReason::NotText.tag(), "non-text");
}

#[test]
fn missing_update_id_is_none() {
    let mut v = private_msg();
    v.as_object_mut().unwrap().remove("update_id");
    assert!(classify_update(&v).is_none());
    v["update_id"] = json!("10");
    assert!(classify_update(&v).is_none());
    assert!(classify_update(&json!([1])).is_none());
    // An update_id with no message is Other, not None.
    let v = json!({"update_id": 3, "callback_query": {"id": "q"}});
    assert_eq!(refused(&v), RefuseReason::Other);
    assert_eq!(RefuseReason::Other.tag(), "other");
    assert_eq!(RefuseReason::Malformed.tag(), "malformed");
}

#[test]
fn reply_to_is_extracted() {
    let v = with(private_msg(), |m| {
        m["reply_to_message"] = json!({"message_id": 4, "text": "approve? code 123"})
    });
    match classify_update(&v).unwrap().kind {
        UpdateKind::Text { reply_to, .. } => assert_eq!(reply_to, Some(4)),
        k => panic!("{k:?}"),
    }
}
