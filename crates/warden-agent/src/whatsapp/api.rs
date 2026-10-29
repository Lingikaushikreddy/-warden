//! WhatsApp Cloud API (Graph API) client: the phone number lookup and
//! free-form text sends. No retries here; the channel decides.
//!
//! The access token travels only in an `Authorization: Bearer` header,
//! built per request in a zeroizing buffer and marked sensitive; it is
//! never put in a URL. [`AccessToken`] has no `Display` and a redacted
//! `Debug`, and every [`WhatsAppError`] is fixed text. reqwest errors are
//! reduced to a kind word (`timeout`, `connect`, `other`) and are never
//! formatted. Of a Graph error only the HTTP status, `code` and
//! `error_subcode` are kept: `message`, `error_user_msg` and `fbtrace_id`
//! are dropped.
//!
//! Responses are read in chunks with a 64 KiB cap (Content-Length is not
//! consulted). Redirects are not followed, so a 3xx is
//! [`WhatsAppError::Status`].

use crate::http;
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde_json::{json, Value};
use std::fmt;
use std::time::Duration;
use zeroize::Zeroizing;

/// Largest response body read, in bytes.
pub const MAX_RESPONSE_BYTES: usize = 64 << 10;

/// Default whole-request timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Longest accepted `phone_number_id`, in digits.
const MAX_PHONE_NUMBER_ID_LEN: usize = 32;

/// A WhatsApp client error. Every variant is fixed text: none holds text
/// from reqwest, the URL or the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhatsAppError {
    /// Bad configuration (token shape, base URL, version, id, client setup).
    Config(&'static str),
    /// Transport failure: `"timeout"`, `"connect"` or `"other"`.
    Transport(&'static str),
    /// A non-2xx status without a Graph error body (3xx included).
    Status(u16),
    /// A Graph `{"error":{"code":n,"error_subcode":m,...}}` body.
    Graph {
        status: u16,
        code: i64,
        subcode: Option<i64>,
    },
    /// A response that is not the expected shape.
    Malformed(&'static str),
    /// The response body exceeded [`MAX_RESPONSE_BYTES`].
    TooLarge,
}

impl fmt::Display for WhatsAppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WhatsAppError::Config(m) => write!(f, "whatsapp config error: {m}"),
            WhatsAppError::Transport(k) => write!(f, "whatsapp transport error: {k}"),
            WhatsAppError::Status(c) => write!(f, "whatsapp http status {c}"),
            WhatsAppError::Graph {
                status,
                code,
                subcode: Some(s),
            } => write!(
                f,
                "whatsapp graph error {code} (subcode {s}, http status {status})"
            ),
            WhatsAppError::Graph {
                status,
                code,
                subcode: None,
            } => write!(f, "whatsapp graph error {code} (http status {status})"),
            WhatsAppError::Malformed(m) => write!(f, "malformed whatsapp response: {m}"),
            WhatsAppError::TooLarge => write!(f, "whatsapp response too large"),
        }
    }
}

impl std::error::Error for WhatsAppError {}

/// What kind of failure an error is, for the channel's handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// HTTP 401 or Graph code 190: the token is rejected (fatal).
    AuthRejected,
    /// HTTP 429 or Graph code 4, 80007, 130429, 131048 or 131056.
    RateLimited,
    /// Graph code 131047: outside the 24-hour customer-service window.
    OutsideWindow,
    /// Anything else.
    Other,
}

impl WhatsAppError {
    /// Classify this error. Auth is checked first, then rate limits, then
    /// the 24-hour window.
    pub fn class(&self) -> ErrorClass {
        let (status, code) = match self {
            WhatsAppError::Status(s) => (Some(*s), None),
            WhatsAppError::Graph { status, code, .. } => (Some(*status), Some(*code)),
            _ => (None, None),
        };
        if status == Some(401) || code == Some(190) {
            ErrorClass::AuthRejected
        } else if status == Some(429) || matches!(code, Some(4 | 80007 | 130429 | 131048 | 131056))
        {
            ErrorClass::RateLimited
        } else if code == Some(131047) {
            ErrorClass::OutsideWindow
        } else {
            ErrorClass::Other
        }
    }
}

/// A Graph API access token, shape-checked and zeroized on drop. No
/// `Display`; `Debug` prints `AccessToken(<redacted>)`.
pub struct AccessToken(Zeroizing<String>);

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessToken(<redacted>)")
    }
}

/// `^[A-Za-z0-9._-]{32,2048}$`, with no trailing-newline leeway.
fn valid_token(s: &str) -> bool {
    (32..=2048).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl AccessToken {
    /// Accept only 32-2048 chars of `[A-Za-z0-9._-]`; anything else is
    /// `Config("invalid access token")`. The input is zeroized either way.
    pub fn new(s: String) -> Result<AccessToken, WhatsAppError> {
        let s = Zeroizing::new(s);
        if valid_token(&s) {
            Ok(AccessToken(s))
        } else {
            Err(WhatsAppError::Config("invalid access token"))
        }
    }

    /// `Bearer <token>` as a sensitive header value. The intermediate
    /// buffer is zeroized; the `HeaderValue`'s own copy is not (reqwest
    /// owns it until the request is sent).
    fn bearer(&self) -> Result<HeaderValue, WhatsAppError> {
        let mut buf = Zeroizing::new(Vec::with_capacity(7 + self.0.len()));
        buf.extend_from_slice(b"Bearer ");
        buf.extend_from_slice(self.0.as_bytes());
        let mut v = HeaderValue::from_bytes(&buf)
            .map_err(|_| WhatsAppError::Config("invalid access token"))?;
        v.set_sensitive(true);
        Ok(v)
    }
}

/// `^v[0-9]{1,3}\.[0-9]{1,3}$`.
fn valid_version(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('v') else {
        return false;
    };
    let Some((major, minor)) = rest.split_once('.') else {
        return false;
    };
    [major, minor]
        .iter()
        .all(|p| (1..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
}

/// 1-32 ASCII digits.
fn valid_phone_number_id(s: &str) -> bool {
    (1..=MAX_PHONE_NUMBER_ID_LEN).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

/// What the Graph API reports about the business phone number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhoneInfo {
    pub display_phone_number: String,
    pub verified_name: Option<String>,
}

/// A Graph API client for one business phone number. `Debug` shows the
/// base URL, the Graph version and the phone number id only.
pub struct GraphApi {
    client: reqwest::Client,
    token: AccessToken,
    base: String,
    version: String,
    phone_number_id: String,
    timeout: Duration,
}

impl fmt::Debug for GraphApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GraphApi")
            .field("base", &self.base)
            .field("version", &self.version)
            .field("phone_number_id", &self.phone_number_id)
            .finish_non_exhaustive()
    }
}

/// A reqwest error reduced to a kind word. The error itself is dropped
/// unformatted.
fn transport(e: reqwest::Error) -> WhatsAppError {
    WhatsAppError::Transport(if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect"
    } else {
        "other"
    })
}

/// The Graph error in `body`, if it is one. Only `code` and
/// `error_subcode` are read.
fn graph_error(status: u16, body: &[u8]) -> Option<WhatsAppError> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let e = v.get("error")?;
    let code = e.get("code")?.as_i64()?;
    let subcode = e.get("error_subcode").and_then(Value::as_i64);
    Some(WhatsAppError::Graph {
        status,
        code,
        subcode,
    })
}

impl GraphApi {
    /// Build a client. `api_base` must be `https://`, or `http://` to
    /// `127.0.0.1`, `localhost` or `[::1]`, with no credentials, query or
    /// fragment; a trailing slash is ignored. `graph_version` must look
    /// like `v26.0` and `phone_number_id` must be 1-32 digits, since both
    /// go into the URL path. Errors are [`WhatsAppError::Config`].
    pub fn new(
        token: AccessToken,
        api_base: &str,
        graph_version: &str,
        phone_number_id: &str,
    ) -> Result<GraphApi, WhatsAppError> {
        let url = http::check_base_url(api_base).map_err(WhatsAppError::Config)?;
        if !valid_version(graph_version) {
            return Err(WhatsAppError::Config("invalid graph version"));
        }
        if !valid_phone_number_id(phone_number_id) {
            return Err(WhatsAppError::Config("invalid phone number id"));
        }
        let base = url.as_str().trim_end_matches('/').to_string();
        let client =
            http::client().map_err(|_| WhatsAppError::Config("could not build HTTP client"))?;
        Ok(GraphApi {
            client,
            token,
            base,
            version: graph_version.to_string(),
            phone_number_id: phone_number_id.to_string(),
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Whole-request timeout. Default 30 s.
    pub fn with_timeout(mut self, timeout: Duration) -> GraphApi {
        self.timeout = timeout;
        self
    }

    /// `{base}/{version}/{phone_number_id}` followed by `suffix`.
    fn url(&self, suffix: &str) -> String {
        format!(
            "{}/{}/{}{suffix}",
            self.base, self.version, self.phone_number_id
        )
    }

    /// Send `req` with the bearer header and return the parsed JSON body of
    /// a 2xx response.
    async fn call(&self, req: reqwest::RequestBuilder) -> Result<Value, WhatsAppError> {
        // Backstop over reqwest's own timeout, which also covers the body.
        match tokio::time::timeout(self.timeout, self.send(req)).await {
            Ok(r) => r,
            Err(_) => Err(WhatsAppError::Transport("timeout")),
        }
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<Value, WhatsAppError> {
        let mut resp = req
            .header(AUTHORIZATION, self.token.bearer()?)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(transport)?;
        let status = resp.status();

        let mut buf = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(transport)? {
            if buf.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(if status.is_success() {
                    WhatsAppError::TooLarge
                } else {
                    WhatsAppError::Status(status.as_u16())
                });
            }
            buf.extend_from_slice(&chunk);
        }
        if let Some(e) = graph_error(status.as_u16(), &buf) {
            return Err(e);
        }
        if !status.is_success() {
            return Err(WhatsAppError::Status(status.as_u16()));
        }
        serde_json::from_slice(&buf)
            .map_err(|_| WhatsAppError::Malformed("response is not valid JSON"))
    }

    /// `GET {base}/{version}/{id}?fields=display_phone_number,verified_name`.
    pub async fn phone_number(&self) -> Result<PhoneInfo, WhatsAppError> {
        let req = self
            .client
            .get(self.url("?fields=display_phone_number,verified_name"));
        let v = self.call(req).await?;
        let display_phone_number = v
            .get("display_phone_number")
            .and_then(Value::as_str)
            .ok_or(WhatsAppError::Malformed("missing display_phone_number"))?
            .to_string();
        let verified_name = v
            .get("verified_name")
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok(PhoneInfo {
            display_phone_number,
            verified_name,
        })
    }

    /// Send `body` as a free-form text message to `to` (digits), link
    /// previews off. Returns `messages[0].id` (the wamid). The caller must
    /// already have redacted, sanitized and capped `body`.
    pub async fn send_text(&self, to: &str, body: &str) -> Result<String, WhatsAppError> {
        let payload = json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": to,
            "type": "text",
            "text": {"preview_url": false, "body": body},
        });
        let payload = serde_json::to_vec(&payload)
            .map_err(|_| WhatsAppError::Malformed("could not encode request"))?;
        let req = self
            .client
            .post(self.url("/messages"))
            .header(CONTENT_TYPE, "application/json")
            .body(payload);
        let v = self.call(req).await?;
        v.get("messages")
            .and_then(|m| m.get(0))
            .and_then(|m| m.get("id"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or(WhatsAppError::Malformed("missing message id"))
    }
}
