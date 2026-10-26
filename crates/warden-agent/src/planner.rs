//! The planner boundary: the only place the agent talks to a model.
//!
//! Everything sent to a planner is typed so that it has gone through the
//! redactor: text and tool results are [`Redacted`], and tool-call arguments
//! echoed back into history are [`RedactedJson`], which only
//! [`Block::tool_use`] can build (it runs [`redact_json`]). Everything a
//! planner returns ([`PlanResponse`]) is UNTRUSTED model output: tool calls
//! must still go through `tools::parse_call`, `classify` and approval.
//!
//! A raw `serde_json::Value` cannot be placed in a tool-use block:
//!
//! ```compile_fail
//! use warden_agent::planner::Block;
//! let _ = Block::ToolUse {
//!     id: "t1".into(),
//!     name: "write_file".into(),
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
//! The constructor is the way in:
//!
//! ```
//! use warden_agent::planner::Block;
//! let b = Block::tool_use("t1", "write_file", &serde_json::json!({"password": "hunter2"}));
//! let Block::ToolUse { args, .. } = b else { unreachable!() };
//! assert_ne!(args.as_value()["password"], "hunter2");
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

/// One piece of a turn.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Block {
    Text(Redacted),
    /// A tool call the assistant made, echoed back into history. `args`
    /// has been through `redact_json`; build it with [`Block::tool_use`].
    ToolUse {
        id: String,
        name: String,
        args: RedactedJson,
    },
    ToolResult {
        id: String,
        content: Redacted,
        is_error: bool,
    },
}

impl Block {
    /// A tool-use block whose arguments are redacted with `redact_json`.
    pub fn tool_use(id: impl Into<String>, name: impl Into<String>, args: &Value) -> Block {
        Block::ToolUse {
            id: id.into(),
            name: name.into(),
            args: RedactedJson::redact(args),
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
}

/// Why a plan call failed. Messages never contain response bodies, request
/// URLs or header values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannerError {
    Transport(String),
    Status(u16),
    Malformed(String),
    TooLarge,
}

impl fmt::Display for PlannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlannerError::Transport(m) => write!(f, "planner transport error: {m}"),
            PlannerError::Status(c) => write!(f, "planner returned HTTP status {c}"),
            PlannerError::Malformed(m) => write!(f, "malformed planner response: {m}"),
            PlannerError::TooLarge => write!(f, "planner response too large"),
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
    pub fn requests(&self) -> Vec<String> {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Load a script: a JSON array of `{"text": "...", "calls": [{"id",
    /// "name", "args"}]}` entries, or `{"error": "transport" | "too_large" |
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
            },
        }
        let invalid = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());
        let bytes = std::fs::read(path)?;
        let entries: Vec<Entry> =
            serde_json::from_slice(&bytes).map_err(|_| invalid("invalid planner script"))?;
        let mut script = Vec::with_capacity(entries.len());
        for e in entries {
            script.push(match e {
                Entry::Reply { text, calls } => Ok(PlanResponse { text, calls }),
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
