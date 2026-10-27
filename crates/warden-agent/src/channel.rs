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
/// Longest accepted PIN, in characters.
const MAX_PIN_CHARS: usize = 128;

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
    /// Reply rules (stdio): for tiers other than `YesPin`, only the exact
    /// reply `yes` (case-insensitive, trimmed) is `Yes`; `yes <anything>` is
    /// `No`. For `YesPin`, `yes <pin>` (1-128 chars) is `YesPin(pin)` and a
    /// bare `yes` is `No`. A prompt whose summary or note would be truncated
    /// is refused without asking.
    ///
    /// Freshness: stdin is one stream, so an approval is only as fresh as the
    /// stream. Input queued before the prompt can answer it. An interactive
    /// terminal front end should discard pending input before prompting, and
    /// the engine must keep chat text and approvals as separate states. The
    /// PIN is returned as a plain `String` (not zeroized); the engine must
    /// compare it in constant time.
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

/// Blank-looking spaces escaped for display only. They are legal in paths
/// but can make two different strings look identical in a prompt.
fn is_blank_looking(c: char) -> bool {
    matches!(
        c,
        '\u{00A0}' | '\u{2000}'..='\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}'
    )
}

/// Sanitize and report whether the 4096-character cap truncated the text.
fn sanitize_capped(s: &str) -> (String, bool) {
    let mut out = String::new();
    let mut count = 0usize;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        let escape = c == '\r'
            || is_blank_looking(c)
            || (c != '\n' && c != '\t' && (is_forbidden_path_char(c) || c == '\u{7f}'));
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
            return (out, true);
        }
        out.push_str(&piece);
        count += n;
    }
    (out, false)
}

/// Make text safe to show to a human. Control, C1, DEL, `\r`, format, bidi,
/// invisible and blank-looking space characters become a visible `\u{hex}`
/// escape (never silently dropped, so injected terminal escapes cannot hide).
/// `\n`, `\t` and plain space are kept. The result is capped at 4096
/// characters, ending with `…` when truncated.
///
/// Limits: a literal backslash is not escaped, so literal text `\u{1b}` is
/// indistinguishable from an escaped ESC (noise only, it hides nothing).
/// Visual confusables (e.g. Cyrillic lookalikes) and tab alignment tricks are
/// not solvable by character filtering.
pub fn sanitize_for_display(s: &str) -> String {
    sanitize_capped(s).0
}

/// Sanitize and prefix every line after the first with `  | ` so multi-line
/// text cannot start a line that looks like part of the prompt.
/// Returns `None` when the text was truncated.
fn block(s: &str) -> Option<String> {
    let (t, truncated) = sanitize_capped(s);
    (!truncated).then(|| t.replace('\n', "\n  | "))
}

fn finish(mut bytes: Vec<u8>, terminated: bool) -> Line {
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    if bytes.len() > MAX_LINE_BYTES {
        return Line::TooLong;
    }
    Line::Text { bytes, terminated }
}

enum Line {
    /// `terminated` is false when EOF ended the line.
    Text {
        bytes: Vec<u8>,
        terminated: bool,
    },
    TooLong,
    Eof,
}

/// A channel over any async reader and writer (line oriented, local only).
///
/// Line reading is cancel-safe: the part of a line read so far lives in the
/// struct, not in the future, so a read cancelled by a timeout (for example
/// an `ask_approval` the engine gave up on) loses nothing and the rest of
/// the line is not mistaken for a new line.
pub struct StdioChannel<R, W> {
    reader: R,
    writer: W,
    /// Bytes of the current line read so far.
    partial: Vec<u8>,
    /// The current line is over the cap and is being discarded.
    overflow: bool,
}

impl<R, W> StdioChannel<R, W>
where
    R: AsyncBufRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            partial: Vec::new(),
            overflow: false,
        }
    }

    /// Read one line with a bounded buffer. The cap applies to the content
    /// excluding the trailing `\r\n`/`\n`. An over-long line is consumed up
    /// to its newline without being stored.
    ///
    /// Cancel-safe: the only await is `fill_buf` (which consumes nothing);
    /// bytes are moved into `self.partial` and consumed with no await in
    /// between, so dropping this future keeps the line intact.
    async fn read_line(&mut self) -> Line {
        // One extra byte is allowed while reading so a trailing `\r` fits.
        let limit = MAX_LINE_BYTES + 1;
        loop {
            let (used, done) = {
                let chunk = match self.reader.fill_buf().await {
                    Ok(c) => c,
                    Err(_) => &[],
                };
                if chunk.is_empty() {
                    let overflow = std::mem::take(&mut self.overflow);
                    let line = std::mem::take(&mut self.partial);
                    if overflow {
                        return Line::TooLong;
                    }
                    if line.is_empty() {
                        return Line::Eof;
                    }
                    return finish(line, false);
                }
                let (data, used, done) = match chunk.iter().position(|&b| b == b'\n') {
                    Some(p) => (&chunk[..p], p + 1, true),
                    None => (chunk, chunk.len(), false),
                };
                if !self.overflow {
                    if self.partial.len() + data.len() > limit {
                        self.overflow = true;
                        self.partial = Vec::new();
                    } else {
                        self.partial.extend_from_slice(data);
                    }
                }
                (used, done)
            };
            self.reader.consume(used);
            if done {
                let overflow = std::mem::take(&mut self.overflow);
                let line = std::mem::take(&mut self.partial);
                return if overflow {
                    Line::TooLong
                } else {
                    finish(line, true)
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
                Line::Text { bytes, .. } => {
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
        let summary = block(&prompt.summary);
        let note = prompt.model_note.as_deref().map(block);
        let (Some(summary), true) = (summary, note.as_ref().is_none_or(|n| n.is_some())) else {
            self.write("request too long to approve safely; refused\n")
                .await;
            return ApprovalReply::No;
        };
        let needs_pin = prompt.tier == Tier::YesPin;
        let mut s = format!("Approval needed ({:?}):\n  {}\n", prompt.tier, summary);
        if let Some(Some(note)) = note {
            s.push_str(&format!("  model says (unverified): {note}\n"));
        }
        if needs_pin {
            s.push_str("Reply \"yes <PIN>\" or \"no\":\n");
        } else {
            s.push_str("Reply \"yes\" or \"no\":\n");
        }
        self.write(&s).await;

        let bytes = match self.read_line().await {
            Line::Text {
                bytes,
                terminated: true,
            } => bytes,
            Line::TooLong => {
                self.write("reply too long, treated as no\n").await;
                return ApprovalReply::No;
            }
            // EOF mid-line or no line at all: fail closed.
            _ => return ApprovalReply::No,
        };
        let text = String::from_utf8_lossy(&bytes).into_owned();
        drop(bytes);
        let text = text.trim();
        if !needs_pin {
            return if text.eq_ignore_ascii_case("yes") {
                ApprovalReply::Yes
            } else {
                ApprovalReply::No
            };
        }
        let mut parts = text.splitn(2, char::is_whitespace);
        let first = parts.next().unwrap_or("");
        let rest = parts.next().map(str::trim).unwrap_or("");
        let n = rest.chars().count();
        if first.eq_ignore_ascii_case("yes") && (1..=MAX_PIN_CHARS).contains(&n) {
            ApprovalReply::YesPin(rest.to_string())
        } else {
            ApprovalReply::No
        }
    }
}
