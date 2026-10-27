//! Owner-facing channel: how the owner talks to the agent and approves
//! actions.
//!
//! Everything a channel prints is shown to a human and may contain text from
//! an untrusted model or from file names, so it goes through
//! [`sanitize_for_display`], which makes dangerous characters visible instead
//! of deleting them.

use std::fmt;
use std::future::Future;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use warden_core::Tier;

use crate::tools::is_forbidden_path_char;

/// Maximum characters of display output per call (marker included).
const MAX_DISPLAY_CHARS: usize = 4096;
/// Hard cap on one input line, in bytes (newline excluded).
const MAX_LINE_BYTES: usize = 65_536;

/// Identity of the party that sent a message, as vouched for by the channel.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct SenderId(pub String);

/// One inbound message.
#[derive(Clone, Debug)]
pub struct Inbound {
    pub sender: SenderId,
    pub text: String,
}

/// The owner's answer to an approval prompt.
#[derive(Clone, PartialEq, Eq)]
pub enum ApprovalReply {
    Yes,
    No,
    /// "yes" together with a PIN. The engine ignores the PIN for `Tier::Yes`.
    YesPin(String),
}

impl fmt::Debug for ApprovalReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApprovalReply::Yes => f.write_str("Yes"),
            ApprovalReply::No => f.write_str("No"),
            ApprovalReply::YesPin(_) => f.write_str("YesPin(<redacted>)"),
        }
    }
}

/// What the owner is asked to approve.
#[derive(Clone, Debug)]
pub struct ApprovalPrompt {
    /// Built by `to_action` (already quoted/escaped); still sanitized on display.
    pub summary: String,
    pub tier: Tier,
    /// Model prose, shown under an "unverified" label.
    pub model_note: Option<String>,
}

/// A two-way conversation with the owner.
pub trait Channel {
    /// Next message, or `None` when the channel is closed.
    fn recv(&mut self) -> impl Future<Output = Option<Inbound>> + Send;

    /// Show text to the owner. The engine has already redacted secrets; the
    /// channel still sanitizes for display.
    fn send(&mut self, text: &str) -> impl Future<Output = ()> + Send;

    /// Ask the owner to approve an action.
    ///
    /// Contract: this must only return a reply that came from the OWNER. The
    /// engine does not re-check who answered. Implementations must return
    /// `ApprovalReply::No` on any doubt (closed channel, unparseable reply,
    /// reply from anyone else).
    fn ask_approval(
        &mut self,
        prompt: &ApprovalPrompt,
    ) -> impl Future<Output = ApprovalReply> + Send;
}

/// Make text safe to show to a human. Control, C1, DEL, `\r`, format, bidi
/// and invisible characters become a visible `\u{hex}` escape (never silently
/// dropped, so injected terminal escapes cannot hide). `\n` and `\t` are kept.
/// The result is capped at 4096 characters, ending with `…` when truncated.
pub fn sanitize_for_display(s: &str) -> String {
    let mut out = String::new();
    let mut count = 0usize;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        let escape =
            c == '\r' || (c != '\n' && c != '\t' && (is_forbidden_path_char(c) || c == '\u{7f}'));
        let piece: String = if escape {
            format!("\\u{{{:x}}}", c as u32)
        } else {
            c.to_string()
        };
        let n = piece.chars().count();
        // Leave room for the marker unless this is the last piece and fits.
        let fits = if chars.peek().is_none() {
            count + n <= MAX_DISPLAY_CHARS
        } else {
            count + n < MAX_DISPLAY_CHARS
        };
        if !fits {
            out.push('…');
            return out;
        }
        out.push_str(&piece);
        count += n;
    }
    out
}

/// Sanitize and prefix every line after the first with `  | ` so multi-line
/// text cannot start a line that looks like part of the prompt.
fn block(s: &str) -> String {
    sanitize_for_display(s).replace('\n', "\n  | ")
}

enum Line {
    Text(Vec<u8>),
    TooLong,
    Eof,
}

/// A channel over any async reader and writer (line oriented, local only).
pub struct StdioChannel<R, W> {
    reader: R,
    writer: W,
}

impl<R, W> StdioChannel<R, W>
where
    R: AsyncBufRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }

    /// Read one line with a bounded buffer. An over-long line is consumed up
    /// to its newline without being stored.
    async fn read_line(&mut self) -> Line {
        let mut line: Vec<u8> = Vec::new();
        let mut overflow = false;
        loop {
            let (used, done) = {
                let chunk = match self.reader.fill_buf().await {
                    Ok(c) => c,
                    Err(_) => &[],
                };
                if chunk.is_empty() {
                    if overflow {
                        return Line::TooLong;
                    }
                    if line.is_empty() {
                        return Line::Eof;
                    }
                    return Line::Text(line);
                }
                let (data, used, done) = match chunk.iter().position(|&b| b == b'\n') {
                    Some(p) => (&chunk[..p], p + 1, true),
                    None => (chunk, chunk.len(), false),
                };
                if !overflow {
                    if line.len() + data.len() > MAX_LINE_BYTES {
                        overflow = true;
                        line = Vec::new();
                    } else {
                        line.extend_from_slice(data);
                    }
                }
                (used, done)
            };
            self.reader.consume(used);
            if done {
                return if overflow {
                    Line::TooLong
                } else {
                    Line::Text(line)
                };
            }
        }
    }

    async fn write(&mut self, text: &str) {
        // A broken output is not recoverable here; approvals fail closed
        // because no reply can follow.
        let _ = self.writer.write_all(text.as_bytes()).await;
        let _ = self.writer.flush().await;
    }
}

impl<R, W> Channel for StdioChannel<R, W>
where
    R: AsyncBufRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    async fn recv(&mut self) -> Option<Inbound> {
        loop {
            match self.read_line().await {
                Line::Eof => return None,
                Line::TooLong => self.write("line too long, ignored\n").await,
                Line::Text(mut bytes) => {
                    if bytes.last() == Some(&b'\r') {
                        bytes.pop();
                    }
                    if bytes.is_empty() {
                        continue;
                    }
                    return Some(Inbound {
                        sender: SenderId("local".into()),
                        text: String::from_utf8_lossy(&bytes).into_owned(),
                    });
                }
            }
        }
    }

    async fn send(&mut self, text: &str) {
        let mut s = sanitize_for_display(text);
        s.push('\n');
        self.write(&s).await;
    }

    async fn ask_approval(&mut self, prompt: &ApprovalPrompt) -> ApprovalReply {
        let mut s = format!(
            "Approval needed ({:?}):\n  {}\n",
            prompt.tier,
            block(&prompt.summary)
        );
        if let Some(note) = &prompt.model_note {
            s.push_str(&format!("  model says (unverified): {}\n", block(note)));
        }
        if prompt.tier == Tier::YesPin {
            s.push_str("Reply \"yes\", \"no\", or \"yes <PIN>\":\n");
        } else {
            s.push_str("Reply \"yes\", \"no\":\n");
        }
        self.write(&s).await;

        let Line::Text(bytes) = self.read_line().await else {
            return ApprovalReply::No;
        };
        let text = String::from_utf8_lossy(&bytes);
        let text = text.trim();
        let mut parts = text.splitn(2, char::is_whitespace);
        let first = parts.next().unwrap_or("");
        let rest = parts.next().map(str::trim).unwrap_or("");
        if first.eq_ignore_ascii_case("yes") {
            if rest.is_empty() {
                ApprovalReply::Yes
            } else {
                ApprovalReply::YesPin(rest.to_string())
            }
        } else {
            ApprovalReply::No
        }
    }
}
