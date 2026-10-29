//! The update filter: which raw `getUpdates` entries may reach the engine
//! as owner text.
//!
//! Only a new text message in a private chat whose id equals the sender's
//! id, sent by a person (not a bot, not via a bot, not on behalf of a chat)
//! and not forwarded or quoting another chat, becomes [`UpdateKind::Text`].
//! Everything else is [`UpdateKind::Refused`] with a reason; the caller
//! hands those to the engine as a non-owner sender with empty text. Whether
//! the sender is an owner is decided later, against `owner_ids`.

use serde_json::{Map, Value};

/// One classified update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    pub update_id: i64,
    pub kind: UpdateKind,
}

/// What an update is, once filtered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateKind {
    /// A private text message from a person.
    Text {
        chat_id: i64,
        from_id: i64,
        message_id: i64,
        /// Telegram's `date` (Unix seconds).
        date_s: i64,
        text: String,
        /// `reply_to_message.message_id`, if any.
        reply_to: Option<i64>,
    },
    /// Anything else; the ids are whatever could be read.
    Refused {
        from_id: Option<i64>,
        message_id: Option<i64>,
        chat_id: Option<i64>,
        reason: RefuseReason,
    },
}

/// Why an update was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefuseReason {
    NotPrivate,
    Forwarded,
    FromBot,
    ViaBot,
    SenderChat,
    Edited,
    NotText,
    Other,
    Malformed,
}

impl RefuseReason {
    /// A short fixed tag for audit records.
    pub fn tag(self) -> &'static str {
        match self {
            RefuseReason::NotPrivate => "group",
            RefuseReason::Forwarded => "forward",
            RefuseReason::FromBot => "bot",
            RefuseReason::ViaBot => "via-bot",
            RefuseReason::SenderChat => "sender-chat",
            RefuseReason::Edited => "edited",
            RefuseReason::NotText => "non-text",
            RefuseReason::Other => "other",
            RefuseReason::Malformed => "malformed",
        }
    }
}

/// Fields whose presence marks a forward or a quote from another chat.
const FORWARD_FIELDS: [&str; 7] = [
    "forward_origin",
    "forward_from",
    "forward_from_chat",
    "forward_date",
    "forward_sender_name",
    "is_automatic_forward",
    "external_reply",
];

/// Present and not `null`.
fn has(m: &Map<String, Value>, k: &str) -> bool {
    m.get(k).is_some_and(|v| !v.is_null())
}

fn int_at(m: &Map<String, Value>, obj: &str, k: &str) -> Option<i64> {
    m.get(obj).and_then(|o| o.get(k)).and_then(Value::as_i64)
}

/// Classify one raw update. `None` only when there is no integer
/// `update_id` (the offset cannot advance past it). Rules, in order:
/// `edited_message` → `Edited`; no `message` → `Other`; `from` missing →
/// `SenderChat`; `from.is_bot` → `FromBot`; `sender_chat` → `SenderChat`;
/// `via_bot` → `ViaBot`; any forward field or `external_reply` →
/// `Forwarded`; `chat.type != "private"` or `chat.id != from.id` →
/// `NotPrivate`; no string `text` → `NotText`; otherwise `Text`. A field
/// of the wrong type where an id is needed is `Malformed`. Unknown fields
/// are ignored.
pub fn classify_update(v: &Value) -> Option<Update> {
    let update_id = v.get("update_id")?.as_i64()?;
    Some(Update {
        update_id,
        kind: classify_kind(v),
    })
}

fn classify_kind(v: &Value) -> UpdateKind {
    let refuse_in = |m: Option<&Map<String, Value>>, reason| UpdateKind::Refused {
        from_id: m.and_then(|m| int_at(m, "from", "id")),
        message_id: m.and_then(|m| m.get("message_id")).and_then(Value::as_i64),
        chat_id: m.and_then(|m| int_at(m, "chat", "id")),
        reason,
    };
    if v.get("edited_message").is_some_and(|e| !e.is_null()) {
        return refuse_in(
            v.get("edited_message").and_then(Value::as_object),
            RefuseReason::Edited,
        );
    }
    let m = match v.get("message") {
        None | Some(Value::Null) => return refuse_in(None, RefuseReason::Other),
        Some(Value::Object(m)) => m,
        Some(_) => return refuse_in(None, RefuseReason::Malformed),
    };
    let refuse = |reason| refuse_in(Some(m), reason);

    let from = match m.get("from") {
        None | Some(Value::Null) => return refuse(RefuseReason::SenderChat),
        Some(Value::Object(f)) => f,
        Some(_) => return refuse(RefuseReason::Malformed),
    };
    match from.get("is_bot").and_then(Value::as_bool) {
        Some(false) => {}
        Some(true) => return refuse(RefuseReason::FromBot),
        None => return refuse(RefuseReason::Malformed),
    }
    if has(m, "sender_chat") {
        return refuse(RefuseReason::SenderChat);
    }
    if has(m, "via_bot") {
        return refuse(RefuseReason::ViaBot);
    }
    if FORWARD_FIELDS.iter().any(|k| has(m, k)) {
        return refuse(RefuseReason::Forwarded);
    }
    let (Some(from_id), Some(chat_id)) = (
        from.get("id").and_then(Value::as_i64),
        int_at(m, "chat", "id"),
    ) else {
        return refuse(RefuseReason::Malformed);
    };
    let chat_type = m
        .get("chat")
        .and_then(|c| c.get("type"))
        .and_then(Value::as_str);
    if chat_type != Some("private") || chat_id != from_id {
        return refuse(RefuseReason::NotPrivate);
    }
    let Some(text) = m.get("text").and_then(Value::as_str) else {
        return refuse(RefuseReason::NotText);
    };
    let (Some(message_id), Some(date_s)) = (
        m.get("message_id").and_then(Value::as_i64),
        m.get("date").and_then(Value::as_i64),
    ) else {
        return refuse(RefuseReason::Malformed);
    };
    UpdateKind::Text {
        chat_id,
        from_id,
        message_id,
        date_s,
        text: text.to_string(),
        reply_to: int_at(m, "reply_to_message", "message_id"),
    }
}
