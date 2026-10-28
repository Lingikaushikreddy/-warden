//! Anthropic Messages API planner.
//!
//! One POST per [`Planner::plan`] call, no retries. The API key is supplied by
//! the caller, stored only as a sensitive header value, and never appears in
//! `Debug`, errors or logs. The response is untrusted: it is read with a
//! 1 MiB cap (Content-Length is not consulted), non-2xx statuses are reported
//! without reading the body, and tool-use ids and names are restricted to
//! `[A-Za-z0-9_-]{1,64}` because they are echoed back into later requests.

use crate::planner::{Block, PlanRequest, PlanResponse, Planner, PlannerError, Role, ToolId, Turn};
use crate::redact::redact;
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
/// `max_tokens` sent with every request. A response cut at this limit
/// (`stop_reason: "max_tokens"`) that contains a tool call is refused, so
/// `write_file` content longer than the output budget (roughly 16 KB of
/// text) cannot be produced in one call.
pub const MAX_TOKENS: u32 = 4096;
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

fn config_err(m: &'static str) -> PlannerError {
    PlannerError::Config(m)
}

/// `^[A-Za-z0-9._:-]{1,100}$`, and nothing the redactor would touch (a
/// secret-shaped model string is refused rather than sent).
fn valid_model(m: &str) -> bool {
    (1..=100).contains(&m.len())
        && m.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
        && redact(m).1.count == 0
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
    /// Build a planner. `api_key` must be non-empty; `model` must match
    /// `[A-Za-z0-9._:-]{1,100}` and not look like a secret; `base_url` must be
    /// `https://`, or `http://` to `127.0.0.1`, `localhost` or `[::1]`. A
    /// trailing slash is ignored. Errors are [`PlannerError::Config`].
    ///
    /// Proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`,
    /// `ALL_PROXY`) are ignored: the client always connects directly.
    /// Corporate-proxy support would be a later, explicit opt-in.
    pub fn new(
        api_key: String,
        model: String,
        base_url: String,
    ) -> Result<AnthropicPlanner, PlannerError> {
        if api_key.is_empty() {
            return Err(config_err("empty api key"));
        }
        if model.is_empty() {
            return Err(config_err("empty model"));
        }
        if !valid_model(&model) {
            return Err(config_err("invalid model id"));
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
            .no_proxy()
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
                |t| json!({"name": t.name(), "description": t.description(), "input_schema": t.schema()}),
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
            json!({"type": "tool_use", "id": id.as_str(), "name": name.as_str(), "input": args.as_value()})
        }
        Block::ToolResult {
            id,
            content,
            is_error,
        } => json!({
            "type": "tool_result",
            "tool_use_id": id.as_str(),
            "content": content.as_str(),
            "is_error": is_error,
        }),
    }
}

/// API messages. Turns with no blocks are dropped; consecutive turns of the
/// same role are merged so roles alternate as the API requires; within a
/// user message, `tool_result` blocks are moved (stably) before everything
/// else, as the API requires. Pairing each `tool_use` with a `tool_result`
/// is the engine's job, not checked here.
fn messages(turns: &[Turn]) -> Vec<Value> {
    let mut out: Vec<(Role, Vec<&Block>)> = Vec::new();
    for t in turns.iter().filter(|t| !t.blocks.is_empty()) {
        match out.last_mut() {
            Some((role, blocks)) if *role == t.role => blocks.extend(&t.blocks),
            _ => out.push((t.role, t.blocks.iter().collect())),
        }
    }
    out.into_iter()
        .map(|(role, mut blocks)| {
            if role == Role::User {
                blocks.sort_by_key(|b| !matches!(b, Block::ToolResult { .. }));
            }
            let content: Vec<Value> = blocks.into_iter().map(block_json).collect();
            json!({"role": role_str(role), "content": content})
        })
        .collect()
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
///
/// `stop_reason: "max_tokens"` means the output was cut at [`MAX_TOKENS`]:
/// with any `tool_use` block the whole response is
/// `Malformed("response truncated")` (a cut-off call could carry partial
/// write content the owner would approve by path and size only); text only
/// is returned with `truncated` set. Other or unknown stop reasons, and a
/// missing one, are ignored.
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
                // Validated as ToolIds: they are echoed back into history.
                let id = ToolId::new(id)?;
                let name = ToolId::new(name)?;
                if calls.len() == MAX_TOOL_CALLS {
                    return Err(PlannerError::Malformed("too many tool calls".into()));
                }
                calls.push(ToolCall {
                    id: id.as_str().to_string(),
                    name: name.as_str().to_string(),
                    args: input.clone(),
                });
            }
            _ => {} // thinking, server tools, ...: ignored
        }
    }
    let stop = v.get("stop_reason").and_then(Value::as_str);
    let truncated = stop == Some("max_tokens");
    if truncated && !calls.is_empty() {
        return Err(PlannerError::Malformed("response truncated".into()));
    }
    // Tool calls are trusted to be complete only under a stop reason known
    // to mean the turn ended normally. Anything else (null, a context-window
    // stop, a reason added later) may mean a cut-off call: fail closed.
    if !calls.is_empty() && !matches!(stop, Some("tool_use" | "end_turn" | "stop_sequence")) {
        return Err(PlannerError::Malformed("unexpected stop reason".into()));
    }
    let text = (saw_text && !text.is_empty()).then_some(text);
    Ok(PlanResponse {
        text,
        calls,
        truncated,
    })
}
