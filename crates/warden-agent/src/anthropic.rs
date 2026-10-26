//! Anthropic Messages API planner.
//!
//! One POST per [`Planner::plan`] call, no retries. The API key is supplied by
//! the caller, stored only as a sensitive header value, and never appears in
//! `Debug`, errors or logs. The response is untrusted: it is read with a
//! 1 MiB cap (Content-Length is not consulted), non-2xx statuses are reported
//! without reading the body, and tool-use ids and names are restricted to
//! `[A-Za-z0-9_-]{1,64}` because they are echoed back into later requests.

use crate::planner::{Block, PlanRequest, PlanResponse, Planner, PlannerError, Role, Turn};
use crate::tools::ToolCall;
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use reqwest::redirect::Policy;
use reqwest::Url;
use serde_json::{json, Map, Value};
use std::fmt;
use std::time::Duration;
use zeroize::Zeroize;

/// Default model id.
pub const DEFAULT_MODEL: &str = "claude-sonnet-5-5";
/// Default API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
/// `anthropic-version` header value.
pub const API_VERSION: &str = "2023-06-01";
/// `max_tokens` sent with every request.
pub const MAX_TOKENS: u32 = 1024;
/// Largest response body read, in bytes.
pub const MAX_RESPONSE_BYTES: usize = 1 << 20;
/// Longest text kept from one response, in bytes (longer text is truncated).
pub const MAX_TEXT_BYTES: usize = 64 * 1024;
/// Most tool calls accepted in one response.
pub const MAX_TOOL_CALLS: usize = 64;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const USER_AGENT_VALUE: &str = concat!("warden-agent/", env!("CARGO_PKG_VERSION"));

/// A [`Planner`] backed by the Anthropic Messages API.
pub struct AnthropicPlanner {
    client: reqwest::Client,
    key: HeaderValue,
    model: String,
    base_url: String,
    endpoint: Url,
    timeout: Duration,
}

impl fmt::Debug for AnthropicPlanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnthropicPlanner")
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            .field("timeout", &self.timeout)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

fn config_err(m: &str) -> PlannerError {
    PlannerError::Malformed(m.to_string())
}

fn check_base_url(base_url: &str) -> Result<Url, PlannerError> {
    let url = Url::parse(base_url).map_err(|_| config_err("invalid base url"))?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => {
            return Err(config_err(
                "base url must be https (http only for loopback)",
            ))
        }
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(config_err("base url has no host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(config_err("base url must not contain credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(config_err("base url must not have a query or fragment"));
    }
    Ok(url)
}

impl AnthropicPlanner {
    /// Build a planner. `api_key` and `model` must be non-empty; `base_url`
    /// must be `https://`, or `http://` to `127.0.0.1`, `localhost` or
    /// `[::1]`. A trailing slash is ignored.
    pub fn new(
        api_key: String,
        model: String,
        base_url: String,
    ) -> Result<AnthropicPlanner, PlannerError> {
        if api_key.is_empty() {
            return Err(config_err("empty api key"));
        }
        if model.trim().is_empty() {
            return Err(config_err("empty model"));
        }
        let url = check_base_url(&base_url)?;
        let base = url.as_str().trim_end_matches('/').to_string();
        let endpoint = Url::parse(&format!("{base}/v1/messages"))
            .map_err(|_| config_err("invalid base url"))?;
        let mut key = HeaderValue::from_str(&api_key)
            .map_err(|_| config_err("api key is not a valid header value"))?;
        key.set_sensitive(true);
        let mut api_key = api_key;
        api_key.zeroize();

        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .use_rustls_tls()
            .connect_timeout(CONNECT_TIMEOUT)
            .user_agent(USER_AGENT_VALUE)
            .build()
            .map_err(|_| PlannerError::Transport("could not build HTTP client".into()))?;
        Ok(AnthropicPlanner {
            client,
            key,
            model,
            base_url: base,
            endpoint,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Whole-request timeout (connect, send and reading the body). Default
    /// 60 s.
    pub fn with_timeout(mut self, timeout: Duration) -> AnthropicPlanner {
        self.timeout = timeout;
        self
    }

    fn body(&self, req: &PlanRequest) -> Value {
        let tools: Vec<Value> = req
            .tools
            .iter()
            .map(
                |t| json!({"name": t.name, "description": t.description, "input_schema": t.schema}),
            )
            .collect();
        json!({
            "model": self.model,
            "max_tokens": MAX_TOKENS,
            "system": req.system.as_str(),
            "messages": messages(&req.turns),
            "tools": tools,
        })
    }

    async fn send(&self, req: &PlanRequest) -> Result<PlanResponse, PlannerError> {
        let body = serde_json::to_vec(&self.body(req))
            .map_err(|_| PlannerError::Transport("could not encode request".into()))?;
        let mut resp = self
            .client
            .post(self.endpoint.clone())
            .header("x-api-key", self.key.clone())
            .header("anthropic-version", API_VERSION)
            .header(CONTENT_TYPE, "application/json")
            .timeout(self.timeout)
            .body(body)
            .send()
            .await
            .map_err(transport)?;
        let status = resp.status();
        if !status.is_success() {
            // The body is never read: it may echo request content.
            return Err(PlannerError::Status(status.as_u16()));
        }
        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(transport)? {
            if buf.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(PlannerError::TooLarge);
            }
            buf.extend_from_slice(&chunk);
        }
        parse_response(&buf)
    }
}

impl Planner for AnthropicPlanner {
    fn plan(
        &self,
        req: &PlanRequest,
    ) -> impl std::future::Future<Output = Result<PlanResponse, PlannerError>> + Send {
        let timeout = self.timeout;
        let fut = self.send(req);
        async move {
            // reqwest's own timeout covers the body too; this is a backstop.
            match tokio::time::timeout(timeout, fut).await {
                Ok(r) => r,
                Err(_) => Err(PlannerError::Transport("request timed out".into())),
            }
        }
    }
}

/// A transport error described without its URL or any header value.
fn transport(e: reqwest::Error) -> PlannerError {
    let kind = if e.is_timeout() {
        "request timed out"
    } else if e.is_connect() {
        "connection failed"
    } else if e.is_body() || e.is_decode() {
        "error reading response body"
    } else if e.is_request() {
        "error sending request"
    } else {
        "transport error"
    };
    // `without_url` drops the URL; reqwest's Display does not print headers.
    // The source chain (hyper/io errors) is left out on purpose.
    PlannerError::Transport(format!("{kind}: {}", e.without_url()))
}

fn role_str(r: Role) -> &'static str {
    match r {
        Role::User => "user",
        Role::Assistant => "assistant",
    }
}

fn block_json(b: &Block) -> Value {
    match b {
        Block::Text(t) => json!({"type": "text", "text": t.as_str()}),
        Block::ToolUse { id, name, args } => {
            json!({"type": "tool_use", "id": id, "name": name, "input": args.as_value()})
        }
        Block::ToolResult {
            id,
            content,
            is_error,
        } => json!({
            "type": "tool_result",
            "tool_use_id": id,
            "content": content.as_str(),
            "is_error": is_error,
        }),
    }
}

/// API messages, with consecutive turns of the same role merged so roles
/// alternate as the API requires.
fn messages(turns: &[Turn]) -> Vec<Value> {
    let mut out: Vec<(Role, Vec<Value>)> = Vec::new();
    for t in turns {
        let blocks = t.blocks.iter().map(block_json);
        match out.last_mut() {
            Some((role, content)) if *role == t.role => content.extend(blocks),
            _ => out.push((t.role, blocks.collect())),
        }
    }
    out.into_iter()
        .map(|(role, content)| json!({"role": role_str(role), "content": content}))
        .collect()
}

fn clean_ident(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn str_field<'a>(o: &'a Map<String, Value>, k: &str) -> Result<&'a str, PlannerError> {
    o.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| PlannerError::Malformed("bad content block".into()))
}

fn push_truncated(text: &mut String, add: &str) {
    let room = MAX_TEXT_BYTES.saturating_sub(text.len());
    if add.len() <= room {
        text.push_str(add);
        return;
    }
    let mut end = room;
    while !add.is_char_boundary(end) {
        end -= 1;
    }
    text.push_str(&add[..end]);
}

/// Parse a 2xx response body. Error messages are fixed text: the body is
/// never quoted.
fn parse_response(body: &[u8]) -> Result<PlanResponse, PlannerError> {
    let v: Value = serde_json::from_slice(body)
        .map_err(|_| PlannerError::Malformed("response is not valid JSON".into()))?;
    let content = v
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| PlannerError::Malformed("missing content array".into()))?;
    let mut text = String::new();
    let mut saw_text = false;
    let mut calls = Vec::new();
    for block in content {
        let o = block
            .as_object()
            .ok_or_else(|| PlannerError::Malformed("bad content block".into()))?;
        match str_field(o, "type")? {
            "text" => {
                push_truncated(&mut text, str_field(o, "text")?);
                saw_text = true;
            }
            "tool_use" => {
                let id = str_field(o, "id")?;
                let name = str_field(o, "name")?;
                let input = o
                    .get("input")
                    .ok_or_else(|| PlannerError::Malformed("bad content block".into()))?;
                if !clean_ident(id) || !clean_ident(name) {
                    return Err(PlannerError::Malformed("bad tool id".into()));
                }
                if calls.len() == MAX_TOOL_CALLS {
                    return Err(PlannerError::Malformed("too many tool calls".into()));
                }
                calls.push(ToolCall {
                    id: id.to_string(),
                    name: name.to_string(),
                    args: input.clone(),
                });
            }
            _ => {} // thinking, server tools, ...: ignored
        }
    }
    let text = (saw_text && !text.is_empty()).then_some(text);
    Ok(PlanResponse { text, calls })
}
