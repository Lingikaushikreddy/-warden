//! Telegram Bot API client (long polling, POST JSON, no retries).
//!
//! The bot token sits in the URL path (`{base}/bot{token}/{method}`), so it
//! is kept out of everything that could be shown: [`BotToken`] has no
//! `Display` and a redacted `Debug`, the request URL is built per request in
//! a zeroizing buffer, and every [`TelegramError`] is fixed text. reqwest
//! errors are reduced to a kind word (`timeout`, `connect`, `other`) and are
//! never formatted. Server text (`description`) is never kept.
//!
//! Responses are read in chunks with a 1 MiB cap (Content-Length is not
//! consulted). Redirects are not followed, so a 3xx is [`TelegramError::Status`].

use crate::http;
use reqwest::header::CONTENT_TYPE;
use serde_json::{json, Value};
use std::fmt;
use std::time::Duration;
use zeroize::Zeroizing;

/// Largest response body read, in bytes.
pub const MAX_RESPONSE_BYTES: usize = 1 << 20;
/// Seconds added to the long-poll timeout to get the `getUpdates` HTTP timeout.
pub const POLL_GRACE_SECS: u64 = 15;

/// Whole-request timeout for every method except `getUpdates`.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// A Telegram client error. Every variant is fixed text: none holds text
/// from reqwest, the URL or the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelegramError {
    /// Bad configuration (token shape, base URL, client setup).
    Config(&'static str),
    /// Transport failure: `"timeout"`, `"connect"` or `"other"`.
    Transport(&'static str),
    /// A non-2xx status without a Telegram error body (3xx included).
    Status(u16),
    /// Telegram's `{"ok":false,"error_code":n,...}`, with
    /// `parameters.retry_after` when present.
    Api { code: u16, retry_after: Option<u64> },
    /// A response that is not the expected shape.
    Malformed(&'static str),
    /// The response body exceeded [`MAX_RESPONSE_BYTES`].
    TooLarge,
}

impl fmt::Display for TelegramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TelegramError::Config(m) => write!(f, "telegram config error: {m}"),
            TelegramError::Transport(k) => write!(f, "telegram transport error: {k}"),
            TelegramError::Status(c) => write!(f, "telegram http status {c}"),
            TelegramError::Api {
                code,
                retry_after: Some(s),
            } => write!(f, "telegram api error {code} (retry after {s} s)"),
            TelegramError::Api {
                code,
                retry_after: None,
            } => write!(f, "telegram api error {code}"),
            TelegramError::Malformed(m) => write!(f, "malformed telegram response: {m}"),
            TelegramError::TooLarge => write!(f, "telegram response too large"),
        }
    }
}

impl std::error::Error for TelegramError {}

/// A bot token, shape-checked and zeroized on drop. No `Display`; `Debug`
/// prints `BotToken(<redacted>)`.
pub struct BotToken(Zeroizing<String>);

impl fmt::Debug for BotToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BotToken(<redacted>)")
    }
}

/// `^[0-9]{5,16}:[A-Za-z0-9_-]{30,64}$`, with no trailing-newline leeway.
fn valid_token(s: &str) -> bool {
    let Some((id, secret)) = s.split_once(':') else {
        return false;
    };
    (5..=16).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_digit())
        && (30..=64).contains(&secret.len())
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

impl BotToken {
    /// Accept only `^[0-9]{5,16}:[A-Za-z0-9_-]{30,64}$`; anything else is
    /// `Config("invalid bot token")`. The input is zeroized either way.
    pub fn new(s: String) -> Result<BotToken, TelegramError> {
        let s = Zeroizing::new(s);
        if valid_token(&s) {
            Ok(BotToken(s))
        } else {
            Err(TelegramError::Config("invalid bot token"))
        }
    }
}

/// What `getMe` reports about the bot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotInfo {
    pub id: i64,
    pub username: Option<String>,
}

/// A Telegram Bot API client. `Debug` shows the base URL only.
pub struct TelegramApi {
    client: reqwest::Client,
    token: BotToken,
    base: String,
    timeout: Duration,
}

impl fmt::Debug for TelegramApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelegramApi")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

/// A reqwest error reduced to a kind word. The error itself is dropped
/// unformatted: its `Display` would include the URL, and so the token.
fn transport(e: reqwest::Error) -> TelegramError {
    TelegramError::Transport(if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect"
    } else {
        "other"
    })
}

/// Telegram's error body, if `body` is one.
fn api_error(body: &[u8]) -> Option<TelegramError> {
    let v: Value = serde_json::from_slice(body).ok()?;
    if v.get("ok").and_then(Value::as_bool) != Some(false) {
        return None;
    }
    let code = u16::try_from(v.get("error_code")?.as_u64()?).ok()?;
    let retry_after = v
        .get("parameters")
        .and_then(|p| p.get("retry_after"))
        .and_then(Value::as_u64);
    Some(TelegramError::Api { code, retry_after })
}

impl TelegramApi {
    /// Build a client. `api_base` must be `https://`, or `http://` to
    /// `127.0.0.1`, `localhost` or `[::1]`, with no credentials, query or
    /// fragment; a trailing slash is ignored. Errors are
    /// [`TelegramError::Config`].
    pub fn new(token: BotToken, api_base: &str) -> Result<TelegramApi, TelegramError> {
        let url = http::check_base_url(api_base).map_err(TelegramError::Config)?;
        let base = url.as_str().trim_end_matches('/').to_string();
        let client =
            http::client().map_err(|_| TelegramError::Config("could not build HTTP client"))?;
        Ok(TelegramApi {
            client,
            token,
            base,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Whole-request timeout for every method except `getUpdates` (whose
    /// timeout is the long-poll timeout plus 15 s). Default 30 s.
    pub fn with_timeout(mut self, timeout: Duration) -> TelegramApi {
        self.timeout = timeout;
        self
    }

    /// POST `body` to `method` and return the `result` of an `ok` response.
    async fn call(
        &self,
        method: &str,
        body: &Value,
        timeout: Duration,
    ) -> Result<Value, TelegramError> {
        // Backstop over reqwest's own timeout, which also covers the body.
        match tokio::time::timeout(timeout, self.send(method, body, timeout)).await {
            Ok(r) => r,
            Err(_) => Err(TelegramError::Transport("timeout")),
        }
    }

    async fn send(
        &self,
        method: &str,
        body: &Value,
        timeout: Duration,
    ) -> Result<Value, TelegramError> {
        let body = serde_json::to_vec(body)
            .map_err(|_| TelegramError::Malformed("could not encode request"))?;
        let mut url = Zeroizing::new(String::with_capacity(
            self.base.len() + self.token.0.len() + method.len() + 5,
        ));
        url.push_str(&self.base);
        url.push_str("/bot");
        url.push_str(&self.token.0);
        url.push('/');
        url.push_str(method);
        let mut resp = self
            .client
            .post(url.as_str())
            .header(CONTENT_TYPE, "application/json")
            .timeout(timeout)
            .body(body)
            .send()
            .await
            .map_err(transport)?;
        drop(url);
        let status = resp.status();

        // Zeroized, best effort: an update batch may hold a PIN typed by the
        // owner. Only this raw buffer is; the parsed `Value` and the strings
        // taken from it are ordinary heap copies.
        let mut buf = Zeroizing::new(Vec::new());
        while let Some(chunk) = resp.chunk().await.map_err(transport)? {
            if buf.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(if status.is_success() {
                    TelegramError::TooLarge
                } else {
                    TelegramError::Status(status.as_u16())
                });
            }
            buf.extend_from_slice(&chunk);
        }
        if let Some(e) = api_error(&buf) {
            return Err(e);
        }
        if !status.is_success() {
            return Err(TelegramError::Status(status.as_u16()));
        }
        let mut v: Value = serde_json::from_slice(&buf)
            .map_err(|_| TelegramError::Malformed("response is not valid JSON"))?;
        if v.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(TelegramError::Malformed("response is not ok"));
        }
        v.get_mut("result")
            .map(Value::take)
            .ok_or(TelegramError::Malformed("missing result"))
    }

    /// `getMe`. A user account (`is_bot` not `true`) is `Malformed("not a bot")`.
    pub async fn get_me(&self) -> Result<BotInfo, TelegramError> {
        let r = self.call("getMe", &json!({}), self.timeout).await?;
        if r.get("is_bot").and_then(Value::as_bool) != Some(true) {
            return Err(TelegramError::Malformed("not a bot"));
        }
        let id = r
            .get("id")
            .and_then(Value::as_i64)
            .ok_or(TelegramError::Malformed("missing bot id"))?;
        let username = r
            .get("username")
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok(BotInfo { id, username })
    }

    /// `getUpdates` (long poll), message updates only. The HTTP timeout is
    /// `timeout_secs + 15` s. The updates are returned raw, for
    /// [`classify_update`](super::update::classify_update).
    pub async fn get_updates(
        &self,
        offset: i64,
        timeout_secs: u32,
        limit: u8,
    ) -> Result<Vec<Value>, TelegramError> {
        let body = json!({
            "offset": offset,
            "timeout": timeout_secs,
            "limit": limit,
            "allowed_updates": ["message"],
        });
        let timeout = Duration::from_secs(u64::from(timeout_secs) + POLL_GRACE_SECS);
        match self.call("getUpdates", &body, timeout).await? {
            Value::Array(a) => Ok(a),
            _ => Err(TelegramError::Malformed("updates are not an array")),
        }
    }

    /// `sendMessage` as plain text (no `parse_mode`), link previews off and
    /// `protect_content` on. Returns the new `message_id`. The caller must
    /// already have redacted and display-sanitized `text`.
    pub async fn send_message(&self, chat_id: i64, text: &str) -> Result<i64, TelegramError> {
        let body = json!({
            "chat_id": chat_id,
            "text": text,
            "link_preview_options": {"is_disabled": true},
            "protect_content": true,
        });
        let r = self.call("sendMessage", &body, self.timeout).await?;
        r.get("message_id")
            .and_then(Value::as_i64)
            .ok_or(TelegramError::Malformed("missing message_id"))
    }

    /// `deleteMessage`.
    pub async fn delete_message(&self, chat_id: i64, message_id: i64) -> Result<(), TelegramError> {
        let body = json!({"chat_id": chat_id, "message_id": message_id});
        self.call("deleteMessage", &body, self.timeout)
            .await
            .map(drop)
    }
}
