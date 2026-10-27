//! Tool calls from the model: strict parsing and mapping to [`Action`].
//!
//! The model is untrusted. Arguments are validated here, and the [`Action`]
//! (and its summary) is built only from validated fields, so the tier that
//! `classify` computes can never depend on model prose.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt;
use std::path::{Path, PathBuf};
use warden_core::{normalize, Action, Capability};

/// Largest `write_file` content, in bytes.
pub const MAX_WRITE_BYTES: u64 = 1_048_576;
/// Largest `read_file` `max_bytes` (larger requests are clamped).
pub const MAX_READ_BYTES: u64 = 1_048_576;
/// `read_file` `max_bytes` when the model does not give one.
pub const DEFAULT_READ_BYTES: u64 = 65_536;
/// Longest accepted path argument, in bytes.
const MAX_PATH_BYTES: usize = 4096;

/// A tool call as received from the model.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub args: Value,
}

/// A tool the model may be offered. Built only by [`tool_specs`], so
/// nothing outside this module can put arbitrary text into a planner
/// request through a spec:
///
/// ```compile_fail
/// let _ = warden_agent::tools::ToolSpec {
///     name: "x",
///     description: "AKIAIOSFODNN7EXAMPLE",
///     schema: serde_json::json!({}),
/// };
/// ```
///
/// ```compile_fail
/// let mut s = warden_agent::tools::tool_specs().remove(0);
/// s.schema = serde_json::json!({"secret": "x"});
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct ToolSpec {
    name: &'static str,
    description: &'static str,
    schema: Value,
}

impl ToolSpec {
    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn description(&self) -> &'static str {
        self.description
    }

    /// JSON schema of the arguments (an object schema).
    pub fn schema(&self) -> &Value {
        &self.schema
    }
}

/// A validated tool invocation with an absolute, lexically normalized path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tool {
    ListDir { path: PathBuf },
    ReadFile { path: PathBuf, max_bytes: u64 },
    WriteFile { path: PathBuf, content: String },
    DeleteFile { path: PathBuf },
}

impl Tool {
    pub fn name(&self) -> &'static str {
        match self {
            Tool::ListDir { .. } => "list_dir",
            Tool::ReadFile { .. } => "read_file",
            Tool::WriteFile { .. } => "write_file",
            Tool::DeleteFile { .. } => "delete_file",
        }
    }
}

/// Why a tool call was refused. Messages never echo argument values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolError {
    UnknownTool(String),
    BadArgs(String),
    TooLarge,
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Debug-escaped so a model-chosen name cannot inject log lines.
            ToolError::UnknownTool(n) => write!(f, "unknown tool: {n:?}"),
            ToolError::BadArgs(m) => write!(f, "bad arguments: {m}"),
            ToolError::TooLarge => write!(f, "content too large"),
        }
    }
}

impl std::error::Error for ToolError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathArgs {
    path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadArgs {
    path: String,
    max_bytes: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteArgs {
    path: String,
    content: String,
}

fn bad(tool: &str) -> ToolError {
    // Fixed text: serde's own messages can quote the offending value.
    ToolError::BadArgs(format!("invalid arguments for {tool}"))
}

fn parse_args<T: serde::de::DeserializeOwned>(call: &ToolCall) -> Result<T, ToolError> {
    if !call.args.is_object() {
        return Err(ToolError::BadArgs(format!(
            "arguments for {} must be an object",
            call.name
        )));
    }
    serde_json::from_value(call.args.clone()).map_err(|_| bad(&call.name))
}

/// Characters that could make a displayed path misleading: controls,
/// Unicode format, bidi and invisible characters, and blank-looking fillers
/// (Hangul fillers U+115F, U+1160, U+3164, U+FFA0 and the braille blank
/// U+2800).
///
/// This is deliberately strict: legitimate file names that contain ZWNJ or
/// ZWJ (U+200C, U+200D; used in some scripts and in emoji sequences), LRM or
/// RLM (U+200E, U+200F) or a soft hyphen (U+00AD) are rejected on purpose,
/// because the same characters can make two different paths look identical
/// in an approval prompt.
pub(crate) fn is_forbidden_path_char(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{00AD}' | '\u{061C}' | '\u{0085}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}' | '\u{2029}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}'
            | '\u{2800}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0000}'..='\u{E007F}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{E0100}'..='\u{E01EF}'
            | '\u{034F}'
            | '\u{180B}'..='\u{180E}'
            | '\u{17B4}' | '\u{17B5}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{FFFC}')
}

fn resolve(tool: &str, raw: &str, cwd: &Path) -> Result<PathBuf, ToolError> {
    if raw.is_empty() || raw.len() > MAX_PATH_BYTES || raw.chars().any(is_forbidden_path_char) {
        return Err(ToolError::BadArgs(format!("invalid path for {tool}")));
    }
    normalize(&cwd.join(raw))
        .ok_or_else(|| ToolError::BadArgs(format!("path for {tool} is not resolvable")))
}

/// Parse and validate a model tool call. Relative paths resolve against
/// `cwd`, then are normalized lexically (symlinks are not resolved).
pub fn parse_call(call: &ToolCall, cwd: &Path) -> Result<Tool, ToolError> {
    match call.name.as_str() {
        "list_dir" => {
            let a: PathArgs = parse_args(call)?;
            Ok(Tool::ListDir {
                path: resolve("list_dir", &a.path, cwd)?,
            })
        }
        "read_file" => {
            // An explicit JSON null deserializes to None: same as absent.
            let a: ReadArgs = parse_args(call)?;
            let max_bytes = match a.max_bytes {
                None => DEFAULT_READ_BYTES,
                Some(0) => return Err(bad("read_file")),
                Some(n) => n.min(MAX_READ_BYTES),
            };
            Ok(Tool::ReadFile {
                path: resolve("read_file", &a.path, cwd)?,
                max_bytes,
            })
        }
        "write_file" => {
            let a: WriteArgs = parse_args(call)?;
            if a.content.len() as u64 > MAX_WRITE_BYTES {
                return Err(ToolError::TooLarge);
            }
            Ok(Tool::WriteFile {
                path: resolve("write_file", &a.path, cwd)?,
                content: a.content,
            })
        }
        "delete_file" => {
            let a: PathArgs = parse_args(call)?;
            Ok(Tool::DeleteFile {
                path: resolve("delete_file", &a.path, cwd)?,
            })
        }
        other => Err(ToolError::UnknownTool(other.chars().take(64).collect())),
    }
}

/// Map a validated tool to the [`Action`] that `classify` tiers. The summary
/// uses only validated fields: never model prose or file content.
pub fn to_action(tool: &Tool, action_id: &str) -> Action {
    // Quoted with Debug escaping, so `"` and `\` cannot close the quote and
    // the path cannot fake the trailing size group.
    let q = |p: &Path| format!("{:?}", p.to_string_lossy());
    let (summary, cap) = match tool {
        Tool::ListDir { path } => (
            format!("list {}", q(path)),
            Capability::ReadPath(path.clone()),
        ),
        Tool::ReadFile { path, max_bytes } => (
            format!("read {} (max {max_bytes} bytes)", q(path)),
            Capability::ReadPath(path.clone()),
        ),
        Tool::WriteFile { path, content } => (
            format!("write {} ({} bytes)", q(path), content.len()),
            Capability::WritePath(path.clone()),
        ),
        Tool::DeleteFile { path } => (
            format!("delete {}", q(path)),
            Capability::DeletePath(path.clone()),
        ),
    };
    Action {
        id: action_id.to_string(),
        summary,
        capabilities: vec![cap],
    }
}

fn spec(
    name: &'static str,
    description: &'static str,
    properties: Value,
    required: &[&str],
) -> ToolSpec {
    ToolSpec {
        name,
        description,
        schema: json!({
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": false,
        }),
    }
}

/// The four tools offered to the model.
pub fn tool_specs() -> Vec<ToolSpec> {
    let path = json!({"type": "string", "description": "Absolute path, or relative to the working directory."});
    vec![
        spec(
            "list_dir",
            "List the entries of a directory.",
            json!({"path": path}),
            &["path"],
        ),
        spec(
            "read_file",
            "Read a file, up to max_bytes bytes.",
            json!({
                "path": path,
                "max_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_READ_BYTES}
            }),
            &["path"],
        ),
        spec(
            "write_file",
            "Write text content to a file, replacing it.",
            json!({"path": path, "content": {"type": "string"}}),
            &["path", "content"],
        ),
        spec(
            "delete_file",
            "Delete a file.",
            json!({"path": path}),
            &["path"],
        ),
    ]
}
