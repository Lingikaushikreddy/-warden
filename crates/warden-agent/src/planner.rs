//! The planner boundary: the only place the agent talks to a model.
//!
//! Everything sent to a planner is typed so that it has gone through the
//! redactor or a strict validator: text and tool results are [`Redacted`];
//! tool-call arguments echoed back into history are [`RedactedJson`], which
//! only [`Block::tool_use`] can build (it runs [`redact_json`]); tool-use ids
//! and names are [`ToolId`]s, which only [`ToolId::new`] can build (it allows
//! `[A-Za-z0-9_-]{1,64}` and nothing else); tool specs come only from
//! `tools::tool_specs`. Everything a planner returns ([`PlanResponse`]) is
//! UNTRUSTED model output: tool calls must still go through
//! `tools::parse_call`, `classify` and approval.
//!
//! Pairing every `tool_use` with exactly one `tool_result` in the next user
//! turn is the engine's job; providers only merge and order what they get.
//!
//! A raw `serde_json::Value` cannot be placed in a tool-use block:
//!
//! ```compile_fail
//! use warden_agent::planner::{Block, ToolId};
//! let id = ToolId::new("t1").unwrap();
//! let _ = Block::ToolUse {
//!     id: id.clone(),
//!     name: id,
//!     args: serde_json::json!({"password": "hunter2"}),
//! };
//! ```
//!
//! nor wrapped by hand:
//!
//! ```compile_fail
//! let _ = warden_agent::planner::RedactedJson(serde_json::json!({}));
//! ```
//!
//! A raw `String` cannot be a tool-use id or name:
//!
//! ```compile_fail
//! use warden_agent::planner::{Block, ToolId};
//! let id = ToolId::new("t1").unwrap();
//! let Block::ToolUse { name, args, .. } = Block::tool_use(&id, &id, &serde_json::json!({}))
//! else { unreachable!() };
//! let _ = Block::ToolUse { id: String::from("AKIAIOSFODNN7EXAMPLE"), name, args };
//! ```
//!
//! nor a tool-result id:
//!
//! ```compile_fail
//! use warden_agent::planner::Block;
//! let _ = Block::ToolResult {
//!     id: String::from("AKIAIOSFODNN7EXAMPLE"),
//!     content: warden_agent::redact::redact("x").0,
//!     is_error: false,
//! };
//! ```
//!
//! and a `ToolId` cannot be wrapped by hand:
//!
//! ```compile_fail
//! let _ = warden_agent::planner::ToolId(String::from("a b"));
//! ```
//!
//! The constructors are the way in (same shapes as above, so the failures
//! are about the types, not the surrounding code):
//!
//! ```
//! use warden_agent::planner::{Block, ToolId};
//! let id = ToolId::new("t1").unwrap();
//! let b = Block::tool_use(&id, &id, &serde_json::json!({"password": "hunter2"}));
//! let Block::ToolUse { name, args, .. } = b else { unreachable!() };
//! assert_ne!(args.as_value()["password"], "hunter2");
//! let _ = Block::ToolUse { id: id.clone(), name, args };
//! let _ = Block::ToolResult {
//!     id,
//!     content: warden_agent::redact::redact("x").0,
//!     is_error: false,
//! };
//! assert!(ToolId::new("a b").is_err());
//! ```

use crate::redact::{redact_json, Redacted};
use crate::tools::{ToolCall, ToolSpec};
use serde::Serialize;
use serde_json::Value;
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::sync::Mutex;

/// Who said a turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Assistant,
}

/// JSON that has passed through [`redact_json`]. Built only by
/// [`Block::tool_use`]; serializes as the JSON value itself.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RedactedJson(Value);

impl RedactedJson {
    fn redact(value: &Value) -> RedactedJson {
        RedactedJson(redact_json(value).0)
    }

    pub fn as_value(&self) -> &Value {
        &self.0
    }
}

/// Is `s` 1-64 chars of `[A-Za-z0-9_-]`?
pub(crate) fn clean_ident(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A tool-use id or tool name: 1-64 chars of `[A-Za-z0-9_-]`. Validated,
/// not redacted: only [`ToolId::new`] builds one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ToolId(String);

impl ToolId {
    /// `Malformed("bad tool id")` unless `s` matches `^[A-Za-z0-9_-]{1,64}$`.
    pub fn new(s: &str) -> Result<ToolId, PlannerError> {
        if clean_ident(s) {
            Ok(ToolId(s.to_string()))
        } else {
            Err(PlannerError::Malformed("bad tool id".into()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One piece of a turn.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Block {
    Text(Redacted),
    /// A tool call the assistant made, echoed back into history. `args`
    /// has been through `redact_json`; build it with [`Block::tool_use`].
    ToolUse {
        id: ToolId,
        name: ToolId,
        args: RedactedJson,
    },
    ToolResult {
        id: ToolId,
        content: Redacted,
        is_error: bool,
    },
}

impl Block {
    /// A tool-use block whose arguments are redacted with `redact_json`.
    pub fn tool_use(id: &ToolId, name: &ToolId, args: &Value) -> Block {
        Block::ToolUse {
            id: id.clone(),
            name: name.clone(),
            args: RedactedJson::redact(args),
        }
    }

    /// A tool-result block for the call `id`.
    pub fn tool_result(id: &ToolId, content: Redacted, is_error: bool) -> Block {
        Block::ToolResult {
            id: id.clone(),
            content,
            is_error,
        }
    }
}

/// One turn of the conversation.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Turn {
    pub role: Role,
    pub blocks: Vec<Block>,
}

/// Everything a planner is given.
#[derive(Debug, Clone, Serialize)]
pub struct PlanRequest {
    pub system: Redacted,
    pub turns: Vec<Turn>,
    pub tools: Vec<ToolSpec>,
}

/// What a planner answered. Untrusted.
#[derive(Debug, Clone)]
pub struct PlanResponse {
    pub text: Option<String>,
    pub calls: Vec<ToolCall>,
    /// The model stopped at its output limit. A provider must never return
    /// tool calls with this set (a cut-off call could carry partial write
    /// content); the engine refuses such a response as malformed and marks
    /// a truncated text reply `[reply truncated]` for the owner.
    pub truncated: bool,
}

/// Why a plan call failed. Messages never contain response bodies, request
/// URLs or header values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannerError {
    Transport(String),
    Status(u16),
    Malformed(String),
    TooLarge,
    /// The planner could not be built (bad key, model or base URL).
    Config(&'static str),
}

impl fmt::Display for PlannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlannerError::Transport(m) => write!(f, "planner transport error: {m}"),
            PlannerError::Status(c) => write!(f, "planner returned HTTP status {c}"),
            PlannerError::Malformed(m) => write!(f, "malformed planner response: {m}"),
            PlannerError::TooLarge => write!(f, "planner response too large"),
            PlannerError::Config(m) => write!(f, "invalid planner configuration: {m}"),
        }
    }
}

impl std::error::Error for PlannerError {}

/// A model that proposes the next step.
pub trait Planner {
    fn plan(
        &self,
        req: &PlanRequest,
    ) -> impl Future<Output = Result<PlanResponse, PlannerError>> + Send;
}

/// A planner that replays a fixed script and records what it was sent.
pub struct MockPlanner {
    script: Mutex<VecDeque<Result<PlanResponse, PlannerError>>>,
    seen: Mutex<Vec<String>>,
}

impl fmt::Debug for MockPlanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockPlanner").finish_non_exhaustive()
    }
}

impl MockPlanner {
    pub fn scripted(script: Vec<Result<PlanResponse, PlannerError>>) -> MockPlanner {
        MockPlanner {
            script: Mutex::new(script.into()),
            seen: Mutex::new(Vec::new()),
        }
    }

    /// Every request seen so far, serialized with `serde_json` at call time.
    ///
    /// This is the internal serialized form of [`PlanRequest`] (serde's
    /// default enum tagging, e.g. `{"Text": "..."}`, and `ToolSpec` fields),
    /// NOT the Anthropic wire body: merging of same-role turns, block
    /// ordering and the `messages`/`input_schema` layout happen only in
    /// `AnthropicPlanner`. Assert on what is present or redacted here, not on
    /// the provider's format.
    pub fn requests(&self) -> Vec<String> {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Load a script: a JSON array of `{"text": "...", "calls": [{"id",
    /// "name", "args"}], "truncated": false}` entries (all fields optional), or `{"error": "transport" | "too_large" |
    /// "malformed"}` / `{"error": "status", "code": 500}`.
    #[cfg(feature = "test-hooks")]
    pub fn from_script_file(path: impl AsRef<std::path::Path>) -> std::io::Result<MockPlanner> {
        #[derive(serde::Deserialize)]
        #[serde(untagged, deny_unknown_fields)]
        enum Entry {
            Error {
                error: String,
                #[serde(default)]
                code: Option<u16>,
            },
            Reply {
                #[serde(default)]
                text: Option<String>,
                #[serde(default)]
                calls: Vec<ToolCall>,
                #[serde(default)]
                truncated: bool,
            },
        }
        let invalid = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());
        let bytes = std::fs::read(path)?;
        let entries: Vec<Entry> =
            serde_json::from_slice(&bytes).map_err(|_| invalid("invalid planner script"))?;
        let mut script = Vec::with_capacity(entries.len());
        for e in entries {
            script.push(match e {
                Entry::Reply {
                    text,
                    calls,
                    truncated,
                } => Ok(PlanResponse {
                    text,
                    calls,
                    truncated,
                }),
                Entry::Error { error, code } => Err(match (error.as_str(), code) {
                    ("transport", None) => {
                        PlannerError::Transport("scripted transport error".into())
                    }
                    ("too_large", None) => PlannerError::TooLarge,
                    ("malformed", None) => PlannerError::Malformed("scripted malformed".into()),
                    ("status", Some(c)) => PlannerError::Status(c),
                    _ => return Err(invalid("unknown scripted error")),
                }),
            });
        }
        Ok(MockPlanner::scripted(script))
    }
}

impl Planner for MockPlanner {
    fn plan(
        &self,
        req: &PlanRequest,
    ) -> impl Future<Output = Result<PlanResponse, PlannerError>> + Send {
        let recorded = serde_json::to_string(req)
            .unwrap_or_else(|_| "<request did not serialize>".to_string());
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(recorded);
        let next = self
            .script
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front();
        async move { next.unwrap_or_else(|| Err(PlannerError::Malformed("script exhausted".into()))) }
    }
}
