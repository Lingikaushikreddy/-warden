//! Webhook verification and payload parsing.
//!
//! Anyone on the internet can reach the webhook through the owner's tunnel,
//! so every check here fails closed:
//! - [`check_signature`] verifies `X-Hub-Signature-256` (HMAC-SHA256 with
//!   the app secret over the raw body) in constant time. The listener calls
//!   it before any byte of the body is parsed.
//! - [`handshake`] answers Meta's subscription check only for
//!   `hub.mode=subscribe`, the right verify token (compared in constant
//!   time over SHA-256 digests, so the length is not leaked either) and a
//!   challenge of 1-64 ASCII digits. Nothing else from the request is
//!   echoed.
//! - [`parse_notification`] turns a signed body into [`WaEvent`]s. Only a
//!   well-formed, non-forwarded `type: "text"` message becomes
//!   [`WaEvent::Text`]; whether its sender is an owner is decided later.
//!   Delivery statuses become [`WaEvent::Status`], which the channel counts
//!   and never passes to the engine. Everything else is
//!   [`WaEvent::Refused`] with a reason.

use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// The Meta app secret: the HMAC key for `X-Hub-Signature-256`.
pub struct AppSecret(Zeroizing<Vec<u8>>);

impl fmt::Debug for AppSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppSecret(<redacted>)")
    }
}

impl AppSecret {
    /// Accept only 16-128 ASCII alphanumerics; anything else is
    /// `"invalid app secret"`. The input is zeroized either way.
    pub fn new(s: String) -> Result<AppSecret, &'static str> {
        let s = Zeroizing::new(s);
        if (16..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric()) {
            Ok(AppSecret(Zeroizing::new(s.as_bytes().to_vec())))
        } else {
            Err("invalid app secret")
        }
    }
}

/// The webhook verify token the owner chose in the Meta app dashboard.
pub struct VerifyToken(Zeroizing<String>);

impl fmt::Debug for VerifyToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifyToken(<redacted>)")
    }
}

impl VerifyToken {
    /// Accept only 16-128 characters of `[A-Za-z0-9._~-]`; anything else is
    /// `"invalid verify token"`. The input is zeroized either way.
    pub fn new(s: String) -> Result<VerifyToken, &'static str> {
        let s = Zeroizing::new(s);
        let ok = (16..=128).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'));
        if ok {
            Ok(VerifyToken(s))
        } else {
            Err("invalid verify token")
        }
    }

    /// Constant-time match over the SHA-256 of both values.
    fn matches(&self, candidate: &str) -> bool {
        let a = Sha256::digest(self.0.as_bytes());
        let b = Sha256::digest(candidate.as_bytes());
        a.as_slice().ct_eq(b.as_slice()).into()
    }
}

/// The outcome of [`check_signature`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureCheck {
    Valid,
    /// No `X-Hub-Signature-256` header.
    Missing,
    /// A header of the wrong shape, or a signature that does not match.
    Invalid,
}

const SIG_PREFIX: &[u8] = b"sha256=";

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// `sha256=` followed by exactly 64 hex digits (either case), decoded.
fn decode_header(h: &[u8]) -> Option<[u8; 32]> {
    let hex = h.strip_prefix(SIG_PREFIX)?;
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (o, pair) in out.iter_mut().zip(hex.chunks_exact(2)) {
        *o = (hex_val(pair[0])? << 4) | hex_val(pair[1])?;
    }
    Some(out)
}

/// Check `X-Hub-Signature-256` (`header`, the raw value) against the raw
/// `body`. The comparison is `Mac::verify_slice`, in constant time.
pub fn check_signature(secret: &AppSecret, header: Option<&[u8]>, body: &[u8]) -> SignatureCheck {
    let Some(header) = header else {
        return SignatureCheck::Missing;
    };
    let Some(sig) = decode_header(header) else {
        return SignatureCheck::Invalid;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&secret.0) else {
        return SignatureCheck::Invalid;
    };
    mac.update(body);
    match mac.verify_slice(&sig) {
        Ok(()) => SignatureCheck::Valid,
        Err(_) => SignatureCheck::Invalid,
    }
}

/// Meta's GET subscription check. `query` is the raw query string (no
/// `?`). Returns the challenge to send back with 200 only when `hub.mode`
/// is `subscribe`, `hub.verify_token` matches `token` and `hub.challenge`
/// is 1-64 ASCII digits, each key present exactly once. `None` means 403.
pub fn handshake(query: Option<&str>, token: &VerifyToken) -> Option<String> {
    let url = reqwest::Url::parse(&format!("http://h/?{}", query?)).ok()?;
    let (mut mode, mut tok, mut challenge) = (None, None::<Zeroizing<String>>, None);
    for (k, v) in url.query_pairs() {
        let slot_taken = match k.as_ref() {
            "hub.mode" => mode.replace(v.into_owned()).is_some(),
            "hub.verify_token" => tok.replace(Zeroizing::new(v.into_owned())).is_some(),
            "hub.challenge" => challenge.replace(v.into_owned()).is_some(),
            _ => false,
        };
        if slot_taken {
            return None;
        }
    }
    let (mode, tok, challenge) = (mode?, tok?, challenge?);
    let token_ok = token.matches(&tok);
    let challenge_ok =
        (1..=64).contains(&challenge.len()) && challenge.bytes().all(|b| b.is_ascii_digit());
    (token_ok && mode == "subscribe" && challenge_ok).then_some(challenge)
}

/// Why a message was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefuseReason {
    /// Media, location, contacts, interactive, button, or any other type.
    NotText,
    /// `context.forwarded` or `context.frequently_forwarded`.
    Forwarded,
    Reaction,
    System,
    /// `type: "unsupported"`, or a message carrying `errors`.
    Unsupported,
    /// A missing or invalid `id`, `from` or `timestamp`.
    Malformed,
}

impl RefuseReason {
    /// A short fixed tag for audit records.
    pub fn tag(self) -> &'static str {
        match self {
            RefuseReason::NotText => "non-text",
            RefuseReason::Forwarded => "forward",
            RefuseReason::Reaction => "reaction",
            RefuseReason::System => "system",
            RefuseReason::Unsupported => "unsupported",
            RefuseReason::Malformed => "malformed",
        }
    }
}

/// One parsed webhook item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaEvent {
    /// A well-formed, non-forwarded text message.
    Text {
        wamid: String,
        /// The sender's number, digits only.
        from: String,
        /// WhatsApp's `timestamp` (Unix seconds).
        timestamp_s: i64,
        body: String,
        /// `context.id`, if any: the message this one replies to.
        reply_to: Option<String>,
    },
    /// Any other message; the fields are whatever was valid.
    Refused {
        wamid: Option<String>,
        from: Option<String>,
        timestamp_s: Option<i64>,
        reason: RefuseReason,
    },
    /// A delivery status (sent, delivered, read, failed) for a message
    /// Warden sent. Counted by the channel; never passed to the engine.
    Status,
}

/// A parsed, signed notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    /// At most [`MAX_EVENTS`]: the messages of every change in payload
    /// order, then the statuses of every change, so statuses never crowd
    /// out a message.
    pub events: Vec<WaEvent>,
    /// Changes skipped because their `metadata.phone_number_id` was not
    /// the configured one (or was missing). Counted past the cap too.
    pub foreign: usize,
    /// Events (messages or statuses) dropped because the cap was reached.
    pub truncated: usize,
}

/// Why a signed body could not be used at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationError {
    NotJson,
    /// `object` is not `"whatsapp_business_account"`.
    NotWhatsApp,
}

/// What the listener sends to the channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookBatch {
    pub events: Vec<WaEvent>,
}

/// Events kept per notification.
pub const MAX_EVENTS: usize = 256;

fn arr<'a>(v: &'a Value, k: &str) -> &'a [Value] {
    v.get(k)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// Parse a signed webhook body. Only changes with `field == "messages"`
/// whose `value.metadata.phone_number_id` equals `phone_number_id` are
/// read; other phone number ids are counted in `foreign`. Events past
/// [`MAX_EVENTS`] are counted in `truncated` (messages are kept before
/// statuses). Unknown fields are ignored.
pub fn parse_notification(
    body: &[u8],
    phone_number_id: &str,
) -> Result<Notification, NotificationError> {
    let v: Value = serde_json::from_slice(body).map_err(|_| NotificationError::NotJson)?;
    if v.get("object").and_then(Value::as_str) != Some("whatsapp_business_account") {
        return Err(NotificationError::NotWhatsApp);
    }
    let mut n = Notification {
        events: Vec::new(),
        foreign: 0,
        truncated: 0,
    };
    let mut ours: Vec<&Value> = Vec::new();
    for entry in arr(&v, "entry") {
        for change in arr(entry, "changes") {
            if change.get("field").and_then(Value::as_str) != Some("messages") {
                continue;
            }
            let Some(value) = change.get("value") else {
                continue;
            };
            let pnid = value
                .get("metadata")
                .and_then(|m| m.get("phone_number_id"))
                .and_then(Value::as_str);
            if pnid != Some(phone_number_id) {
                n.foreign += 1;
                continue;
            }
            ours.push(value);
        }
    }
    // Messages from every change first, then statuses: a status can never
    // push a message past the cap.
    let messages = ours
        .iter()
        .flat_map(|value| arr(value, "messages"))
        .map(classify_message);
    let statuses = ours
        .iter()
        .flat_map(|value| arr(value, "statuses"))
        .map(|_| WaEvent::Status);
    for ev in messages.chain(statuses) {
        if n.events.len() == MAX_EVENTS {
            n.truncated += 1;
        } else {
            n.events.push(ev);
        }
    }
    Ok(n)
}

/// 1-256 printable ASCII, no whitespace.
fn valid_wamid(v: &Value) -> Option<String> {
    let s = v.as_str()?;
    ((1..=256).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_graphic())).then(|| s.into())
}

/// 1-20 ASCII digits.
fn valid_from(v: &Value) -> Option<String> {
    let s = v.as_str()?;
    ((1..=20).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.into())
}

/// A non-negative decimal string or integer that fits an `i64`.
fn valid_timestamp(v: &Value) -> Option<i64> {
    match v {
        Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            s.parse().ok()
        }
        Value::Number(n) => n.as_i64().filter(|t| *t >= 0),
        _ => None,
    }
}

/// Present and anything but `false` or `null`: a forward flag of an
/// unexpected type is treated as set.
fn flag_set(ctx: Option<&Value>, k: &str) -> bool {
    ctx.and_then(|c| c.get(k))
        .is_some_and(|f| !matches!(f, Value::Bool(false) | Value::Null))
}

fn classify_message(m: &Value) -> WaEvent {
    let Some(m) = m.as_object() else {
        return WaEvent::Refused {
            wamid: None,
            from: None,
            timestamp_s: None,
            reason: RefuseReason::Malformed,
        };
    };
    let get = |k: &str| m.get(k).unwrap_or(&Value::Null);
    let wamid = valid_wamid(get("id"));
    let from = valid_from(get("from"));
    let timestamp_s = valid_timestamp(get("timestamp"));
    let (Some(wamid), Some(from), Some(timestamp_s)) = (wamid.clone(), from.clone(), timestamp_s)
    else {
        return WaEvent::Refused {
            wamid,
            from,
            timestamp_s,
            reason: RefuseReason::Malformed,
        };
    };
    let refuse = |reason| WaEvent::Refused {
        wamid: Some(wamid.clone()),
        from: Some(from.clone()),
        timestamp_s: Some(timestamp_s),
        reason,
    };
    let ctx = m.get("context");
    if flag_set(ctx, "forwarded") || flag_set(ctx, "frequently_forwarded") {
        return refuse(RefuseReason::Forwarded);
    }
    if has(m, "errors") {
        return refuse(RefuseReason::Unsupported);
    }
    match m.get("type").and_then(Value::as_str) {
        Some("text") => match m
            .get("text")
            .and_then(|t| t.get("body"))
            .and_then(Value::as_str)
        {
            Some(body) => WaEvent::Text {
                body: body.to_string(),
                reply_to: ctx
                    .and_then(|c| c.get("id"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                wamid,
                from,
                timestamp_s,
            },
            None => refuse(RefuseReason::NotText),
        },
        Some("reaction") => refuse(RefuseReason::Reaction),
        Some("system") => refuse(RefuseReason::System),
        Some("unsupported") => refuse(RefuseReason::Unsupported),
        _ => refuse(RefuseReason::NotText),
    }
}

/// Present and not `null`.
fn has(m: &Map<String, Value>, k: &str) -> bool {
    m.get(k).is_some_and(|v| !v.is_null())
}
