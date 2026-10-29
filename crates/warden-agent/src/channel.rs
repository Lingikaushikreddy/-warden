//! Owner-facing channel: how the owner talks to the agent and approves
//! actions.
//!
//! Everything a channel prints is shown to a human and may contain text from
//! an untrusted model or from file names, so it goes through
//! [`sanitize_for_display`], which makes dangerous characters visible instead
//! of deleting them.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::Poll;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use warden_core::Tier;
use zeroize::Zeroizing;

use crate::tools::is_forbidden_path_char;

/// Maximum characters of display output per call (marker included).
const MAX_DISPLAY_CHARS: usize = 4096;
/// Hard cap on one input line, in bytes (newline excluded).
const MAX_LINE_BYTES: usize = 65_536;
/// Longest accepted PIN, in characters.
const MAX_PIN_CHARS: usize = 128;
/// Most bytes `discard_pending_input` drops in one call.
const MAX_DISCARD_BYTES: usize = 1 << 20;

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
    /// "yes" together with a PIN, held in zeroizing memory. The engine
    /// ignores the PIN for `Tier::Yes`.
    YesPin(Zeroizing<String>),
    /// No reply at all: the channel closed (EOF) before a complete reply
    /// line. Treated as a refusal, audited distinctly.
    Closed,
    /// The prompt could not be shown (a remote channel's send failed), so
    /// nobody was asked. Treated as a refusal, audited distinctly.
    Undelivered,
}

impl fmt::Debug for ApprovalReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApprovalReply::Yes => f.write_str("Yes"),
            ApprovalReply::No => f.write_str("No"),
            ApprovalReply::YesPin(_) => f.write_str("YesPin(<redacted>)"),
            ApprovalReply::Closed => f.write_str("Closed"),
            ApprovalReply::Undelivered => f.write_str("Undelivered"),
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
    /// A fresh code chosen by the engine for THIS prompt and shown in it.
    /// Only a reply containing it approves, so input typed before the
    /// prompt was displayed (stale, typed ahead, in transit) never can.
    /// 1-16 ASCII alphanumerics; anything else makes the prompt refuse.
    pub challenge: String,
}

/// A two-way conversation with the owners.
///
/// Every outbound call names its recipient (`to`): the engine sends
/// everything it says while handling a message to that message's sender. A
/// local channel with a single sender (such as [`StdioChannel`]) may ignore
/// `to`; a remote channel must deliver to `to` and nobody else.
pub trait Channel {
    /// Next message, or `None` when the channel is closed.
    ///
    /// Must be cancel-safe: a caller may drop this future (for example in a
    /// `select!` with a shutdown signal) and call `recv` again without
    /// losing or splitting a message.
    fn recv(&mut self) -> impl Future<Output = Option<Inbound>> + Send;

    /// Show text to `to`. The engine has already redacted secrets; the
    /// channel still sanitizes for display.
    fn send(&mut self, to: &SenderId, text: &str) -> impl Future<Output = ()> + Send;

    /// Ask `to` to approve an action.
    ///
    /// Reply rules (stdio): the prompt shows `prompt.challenge`. For tiers
    /// other than `YesPin`, only `yes <code>` (`yes` case-insensitive,
    /// trimmed, exactly one token after it, equal to the code) is `Yes`. For
    /// `YesPin`, `yes <code> <pin>` (pin 1-128 chars) is `YesPin(pin)`.
    /// Everything else is `No`; EOF before a complete reply is `Closed`; a
    /// prompt that could not be shown at all is `Undelivered`. A
    /// prompt whose summary or note would be truncated, or whose challenge
    /// is not 1-16 ASCII alphanumerics, is refused without asking.
    ///
    /// Freshness: stdin is one stream, so an approval is only as fresh as the
    /// stream. Input queued before the prompt can answer it. An interactive
    /// terminal front end should discard pending input before prompting, and
    /// the engine must keep chat text and approvals as separate states. The
    /// PIN is returned in a `Zeroizing<String>`; the engine must compare it
    /// in constant time.
    ///
    /// Contract: this must only return a reply that came from `to` (one of
    /// the owners, the sender of the message being handled). The engine does
    /// not re-check who answered, and with several owners a reply from any
    /// other owner must not count either. Implementations must return
    /// `ApprovalReply::No` on any doubt (closed channel, unparseable reply,
    /// reply from anyone else).
    fn ask_approval(
        &mut self,
        to: &SenderId,
        prompt: &ApprovalPrompt,
    ) -> impl Future<Output = ApprovalReply> + Send;

    /// Drop any input from `to` that is already waiting, so that it cannot
    /// answer the next prompt, and return how many bytes were dropped (0 if
    /// none). The engine calls this right before every
    /// [`Channel::ask_approval`] and tells the owner when something was
    /// dropped. Must not block. Default: nothing to drop.
    fn discard_pending_input(&mut self, to: &SenderId) -> impl Future<Output = usize> + Send {
        let _ = to;
        async { 0 }
    }

    /// Whether a PIN may be typed over this channel by `to`. When `false`,
    /// the engine refuses every `YesPin` action asked for by `to` without a
    /// prompt. Default: `true` (a local channel).
    fn accepts_pin(&self, to: &SenderId) -> bool {
        let _ = to;
        true
    }

    /// Best-effort removal of the most recent message received from `to`
    /// (the engine calls it after dropping a message that may hold the PIN).
    /// Default: nothing to remove.
    fn retract_last(&mut self, to: &SenderId) -> impl Future<Output = ()> + Send {
        let _ = to;
        async {}
    }

    /// Best-effort completion of work the channel still owes, such as
    /// deleting messages that may hold the PIN. Called once when the
    /// engine has stopped; the caller bounds how long it may take.
    /// Default: nothing pending.
    fn flush_pending(&mut self) -> impl Future<Output = ()> + Send {
        async {}
    }

    /// Whether this channel can reach `who` (used by [`Pair`] to route
    /// outbound calls). Default: `true`.
    fn serves(&self, who: &SenderId) -> bool {
        let _ = who;
        true
    }
}

/// Two channels as one (`warden daemon --console`: the terminal and
/// Telegram). Inbound messages come from either side; every outbound call
/// goes to `a` if `a` serves the recipient, else to `b` if `b` does, else
/// nowhere: `send` and `retract_last` do nothing, `ask_approval` is `No`,
/// `discard_pending_input` is 0 and `accepts_pin` is `false`.
///
/// `recv` races both sides, keeps reading the other side after one has
/// closed, is `None` once both have, and alternates which side is polled
/// first so a busy side cannot starve the other. It is cancel-safe when both
/// sides' `recv` are.
pub struct Pair<A, B> {
    a: A,
    b: B,
    a_closed: bool,
    b_closed: bool,
    /// Poll `a` first on the next `recv`.
    a_first: bool,
}

impl<A, B> Pair<A, B> {
    pub fn new(a: A, b: B) -> Self {
        Self {
            a,
            b,
            a_closed: false,
            b_closed: false,
            a_first: true,
        }
    }
}

/// Which side of a [`Pair`] a `recv` result came from.
enum Side {
    A(Option<Inbound>),
    B(Option<Inbound>),
}

impl<A: Channel + Send, B: Channel + Send> Channel for Pair<A, B> {
    async fn recv(&mut self) -> Option<Inbound> {
        loop {
            if self.a_closed && self.b_closed {
                return None;
            }
            let a_first = self.a_first;
            self.a_first = !a_first;
            let (a_open, b_open) = (!self.a_closed, !self.b_closed);
            // Each branch is a whole `recv` of one side; the loser is
            // dropped, which loses nothing because each side's `recv` is
            // cancel-safe. State changes only after a branch completes.
            let side = if a_first {
                tokio::select! {
                    biased;
                    m = self.a.recv(), if a_open => Side::A(m),
                    m = self.b.recv(), if b_open => Side::B(m),
                }
            } else {
                tokio::select! {
                    biased;
                    m = self.b.recv(), if b_open => Side::B(m),
                    m = self.a.recv(), if a_open => Side::A(m),
                }
            };
            match side {
                Side::A(None) => self.a_closed = true,
                Side::B(None) => self.b_closed = true,
                Side::A(m) | Side::B(m) => return m,
            }
        }
    }

    async fn send(&mut self, to: &SenderId, text: &str) {
        if self.a.serves(to) {
            self.a.send(to, text).await;
        } else if self.b.serves(to) {
            self.b.send(to, text).await;
        }
    }

    async fn ask_approval(&mut self, to: &SenderId, prompt: &ApprovalPrompt) -> ApprovalReply {
        if self.a.serves(to) {
            self.a.ask_approval(to, prompt).await
        } else if self.b.serves(to) {
            self.b.ask_approval(to, prompt).await
        } else {
            ApprovalReply::No
        }
    }

    async fn discard_pending_input(&mut self, to: &SenderId) -> usize {
        if self.a.serves(to) {
            self.a.discard_pending_input(to).await
        } else if self.b.serves(to) {
            self.b.discard_pending_input(to).await
        } else {
            0
        }
    }

    fn accepts_pin(&self, to: &SenderId) -> bool {
        if self.a.serves(to) {
            self.a.accepts_pin(to)
        } else if self.b.serves(to) {
            self.b.accepts_pin(to)
        } else {
            false
        }
    }

    async fn retract_last(&mut self, to: &SenderId) {
        if self.a.serves(to) {
            self.a.retract_last(to).await;
        } else if self.b.serves(to) {
            self.b.retract_last(to).await;
        }
    }

    /// Both sides, `a` first.
    async fn flush_pending(&mut self) {
        self.a.flush_pending().await;
        self.b.flush_pending().await;
    }

    fn serves(&self, who: &SenderId) -> bool {
        self.a.serves(who) || self.b.serves(who)
    }
}

/// An optional channel (the daemon's channels that may not be configured).
///
/// `Some` delegates every call, including the defaulted ones. `None` is a
/// closed channel that serves nobody, so it fails closed: `recv` is `None`,
/// `send`, `retract_last` and `flush_pending` do nothing, `ask_approval` is
/// `No`, `discard_pending_input` is 0, and `accepts_pin` and `serves` are
/// `false`. Inside a [`Pair`], a `None` side therefore closes at once and
/// every call goes to the other side.
impl<C: Channel + Send> Channel for Option<C> {
    async fn recv(&mut self) -> Option<Inbound> {
        match self {
            Some(c) => c.recv().await,
            None => None,
        }
    }

    async fn send(&mut self, to: &SenderId, text: &str) {
        if let Some(c) = self {
            c.send(to, text).await;
        }
    }

    async fn ask_approval(&mut self, to: &SenderId, prompt: &ApprovalPrompt) -> ApprovalReply {
        match self {
            Some(c) => c.ask_approval(to, prompt).await,
            None => ApprovalReply::No,
        }
    }

    async fn discard_pending_input(&mut self, to: &SenderId) -> usize {
        match self {
            Some(c) => c.discard_pending_input(to).await,
            None => 0,
        }
    }

    fn accepts_pin(&self, to: &SenderId) -> bool {
        self.as_ref().is_some_and(|c| c.accepts_pin(to))
    }

    async fn retract_last(&mut self, to: &SenderId) {
        if let Some(c) = self {
            c.retract_last(to).await;
        }
    }

    async fn flush_pending(&mut self) {
        if let Some(c) = self {
            c.flush_pending().await;
        }
    }

    fn serves(&self, who: &SenderId) -> bool {
        self.as_ref().is_some_and(|c| c.serves(who))
    }
}

/// A challenge code the channel will show: 1-16 ASCII alphanumerics.
fn valid_challenge(c: &str) -> bool {
    (1..=16).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Parse a reply line against the prompt's challenge `code`.
///
/// - not a PIN tier: exactly `yes <code>` (`yes` in any case, any
///   whitespace) is `Yes`;
/// - PIN tier: `yes <code> <PIN>` (the PIN is everything after the code,
///   trimmed, 1-128 chars) is `YesPin(PIN)`;
/// - anything else (bare `yes`, a wrong or previous code, `yes <PIN>`
///   without the code) is `No`.
pub(crate) fn parse_reply(text: &str, needs_pin: bool, code: &str) -> ApprovalReply {
    let t = text.trim();
    let Some((first, rest)) = t.split_once(char::is_whitespace) else {
        return ApprovalReply::No;
    };
    if !first.eq_ignore_ascii_case("yes") {
        return ApprovalReply::No;
    }
    let rest = rest.trim_start();
    let (token, after) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
    // The code is not secret (it is on screen); exact match is enough.
    if token != code {
        return ApprovalReply::No;
    }
    let after = after.trim();
    if !needs_pin {
        return if after.is_empty() {
            ApprovalReply::Yes
        } else {
            ApprovalReply::No
        };
    }
    if (1..=MAX_PIN_CHARS).contains(&after.chars().count()) {
        ApprovalReply::YesPin(Zeroizing::new(after.to_string()))
    } else {
        ApprovalReply::No
    }
}

/// Blank-looking spaces escaped for display only. They are legal in paths
/// but can make two different strings look identical in a prompt.
fn is_blank_looking(c: char) -> bool {
    matches!(
        c,
        '\u{00A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}'
    )
}

/// Is `c` shown as a `\u{hex}` escape?
fn is_escaped(c: char) -> bool {
    c == '\r'
        || is_blank_looking(c)
        || (c != '\n' && c != '\t' && (is_forbidden_path_char(c) || c == '\u{7f}'))
}

/// How many characters `c` takes once sanitized for display.
fn display_len(c: char) -> usize {
    if is_escaped(c) {
        // `\u{` + hex digits + `}`
        let digits = format!("{:x}", c as u32).len();
        4 + digits
    } else {
        1
    }
}

/// The longest prefix of `s` whose display form ([`sanitize_for_display`],
/// before any cap) is at most `max` characters.
pub(crate) fn display_prefix(s: &str, max: usize) -> &str {
    let mut used = 0usize;
    for (i, c) in s.char_indices() {
        used += display_len(c);
        if used > max {
            return &s[..i];
        }
    }
    s
}

/// Sanitize and report whether the 4096-character cap truncated the text.
fn sanitize_capped(s: &str) -> (String, bool) {
    let mut out = String::new();
    let mut count = 0usize;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        let piece: String = if is_escaped(c) {
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

/// Cut `s` to at most `max_units` UTF-16 code units (at least 1), ending
/// with `…` when cut. Remote chat services count message length in UTF-16
/// units, which are never fewer than characters.
pub(crate) fn cap_utf16(s: String, max_units: usize) -> String {
    if s.encode_utf16().count() <= max_units {
        return s;
    }
    let mut out = String::new();
    let mut units = 0usize;
    for c in s.chars() {
        // Leave one unit for the marker.
        if units + c.len_utf16() > max_units.saturating_sub(1) {
            break;
        }
        units += c.len_utf16();
        out.push(c);
    }
    out.push('…');
    out
}

/// Sanitize and prefix every line after the first with `  | ` so multi-line
/// text cannot start a line that looks like part of the prompt.
/// Returns `None` when the text was truncated.
fn block(s: &str) -> Option<String> {
    let (t, truncated) = sanitize_capped(s);
    (!truncated).then(|| t.replace('\n', "\n  | "))
}

/// The prompt text, or the refusal shown instead of it.
fn render(prompt: &ApprovalPrompt) -> Result<String, &'static str> {
    let summary = block(&prompt.summary);
    let note = prompt.model_note.as_deref().map(block);
    let (Some(summary), true) = (summary, note.as_ref().is_none_or(|n| n.is_some())) else {
        return Err("request too long to approve safely; refused");
    };
    if !valid_challenge(&prompt.challenge) {
        return Err("approval prompt has no valid code; refused");
    }
    let code = prompt.challenge.as_str();
    let mut s = format!("Approval needed ({:?}):\n  {}\n", prompt.tier, summary);
    if let Some(Some(note)) = note {
        s.push_str(&format!("  model says (unverified): {note}\n"));
    }
    if prompt.tier == Tier::YesPin {
        s.push_str(&format!("Reply \"yes {code} <PIN>\" or \"no\":\n"));
    } else {
        s.push_str(&format!("Reply \"yes {code}\" or \"no\":\n"));
    }
    Ok(s)
}

/// The approval prompt as [`StdioChannel`] prints it (sanitized, multi-line
/// text indented with `  | `). `None` when the summary or note would be
/// truncated or the challenge is invalid: such a prompt must be refused
/// without asking.
pub(crate) fn render_prompt(prompt: &ApprovalPrompt) -> Option<String> {
    render(prompt).ok()
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
    /// The rest of the current line belongs to input that
    /// `discard_pending_input` dropped part of; skip it up to its newline.
    skip_line: bool,
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
            skip_line: false,
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
            let (used, done, skipped) = {
                let chunk = match self.reader.fill_buf().await {
                    Ok(c) => c,
                    Err(_) => &[],
                };
                if chunk.is_empty() {
                    self.skip_line = false;
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
                if self.skip_line {
                    (used, done, true)
                } else {
                    if !self.overflow {
                        if self.partial.len() + data.len() > limit {
                            self.overflow = true;
                            self.partial = Vec::new();
                        } else {
                            self.partial.extend_from_slice(data);
                        }
                    }
                    (used, done, false)
                }
            };
            self.reader.consume(used);
            if skipped {
                if done {
                    self.skip_line = false;
                }
                continue;
            }
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

    async fn send(&mut self, _to: &SenderId, text: &str) {
        let mut s = sanitize_for_display(text);
        s.push('\n');
        self.write(&s).await;
    }

    /// Drops the partial line and whatever the reader has ready right now
    /// (polled once per chunk, never waiting), up to 1 MiB. If the dropped
    /// input ended mid-line, the rest of that line is skipped when it
    /// arrives, so `ye` (dropped) + `s\n` (later) is not read as `s`.
    ///
    /// Limits: an `AsyncBufRead` only shows what has reached this process.
    /// Bytes still in a pipe, terminal line buffer or network path when this
    /// runs arrive later and are read as the reply; and an owner who
    /// answers a fresh prompt by completing a dropped half line must type
    /// the reply again.
    async fn discard_pending_input(&mut self, _to: &SenderId) -> usize {
        let mut mid_line = !self.partial.is_empty() || self.overflow || self.skip_line;
        let mut dropped = self.partial.len() + usize::from(self.overflow);
        self.partial.clear();
        self.overflow = false;
        let mut budget = MAX_DISCARD_BYTES;
        loop {
            let ready = std::future::poll_fn(|cx| {
                Poll::Ready(match Pin::new(&mut self.reader).poll_fill_buf(cx) {
                    Poll::Ready(Ok(b)) => Some((b.len(), b.last().copied())),
                    Poll::Ready(Err(_)) | Poll::Pending => None,
                })
            })
            .await;
            match ready {
                Some((n, last)) if n > 0 => {
                    self.reader.consume(n);
                    dropped = dropped.saturating_add(n);
                    mid_line = last != Some(b'\n');
                    budget = budget.saturating_sub(n);
                    if budget == 0 {
                        break;
                    }
                }
                _ => break,
            }
        }
        self.skip_line = mid_line;
        dropped
    }

    /// The only sender is `local`.
    fn serves(&self, who: &SenderId) -> bool {
        who.0 == "local"
    }

    /// `to` is ignored: the only sender is `local`.
    async fn ask_approval(&mut self, _to: &SenderId, prompt: &ApprovalPrompt) -> ApprovalReply {
        let Some(s) = render_prompt(prompt) else {
            let refusal = render(prompt).err().unwrap_or("refused");
            self.write(&format!("{refusal}\n")).await;
            return ApprovalReply::No;
        };
        self.write(&s).await;
        let needs_pin = prompt.tier == Tier::YesPin;
        let code = prompt.challenge.as_str();

        let bytes = match self.read_line().await {
            Line::Text {
                bytes,
                terminated: true,
            } => bytes,
            Line::TooLong => {
                self.write("reply too long, treated as no\n").await;
                return ApprovalReply::No;
            }
            // EOF mid-line or no line at all: no reply, fail closed.
            Line::Text {
                terminated: false, ..
            }
            | Line::Eof => return ApprovalReply::Closed,
        };
        let text = String::from_utf8_lossy(&bytes).into_owned();
        drop(bytes);
        parse_reply(&text, needs_pin, code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `render_prompt` is exactly what `StdioChannel` prints for a prompt
    /// (and nothing else is printed before the reply is read).
    #[tokio::test]
    async fn render_prompt_matches_stdio_output() {
        let prompts = [
            (Tier::Yes, "write_file \"/r/a\" (2 bytes)", None, "4821"),
            (
                Tier::YesPin,
                "delete_file \"/r/a\nfake line\"",
                Some("trust me\n\u{1b}[2J"),
                "0042",
            ),
            (Tier::Yes, "x\u{202e}y", Some(""), "Ab9"),
        ];
        for (tier, summary, note, code) in prompts {
            let p = ApprovalPrompt {
                summary: summary.into(),
                tier,
                model_note: note.map(Into::into),
                challenge: code.into(),
            };
            let mut out = Vec::new();
            {
                let mut c = StdioChannel::new(&b"no\n"[..], &mut out);
                let to = SenderId("local".into());
                assert_eq!(c.ask_approval(&to, &p).await, ApprovalReply::No);
            }
            let rendered = render_prompt(&p).expect("renders");
            assert_eq!(String::from_utf8(out).unwrap(), rendered, "{summary:?}");
        }
        // Refused prompts render nothing.
        let bad_code = ApprovalPrompt {
            summary: "x".into(),
            tier: Tier::Yes,
            model_note: None,
            challenge: "12-4".into(),
        };
        assert_eq!(render_prompt(&bad_code), None);
        let long = ApprovalPrompt {
            summary: "a".repeat(5000),
            challenge: "1".into(),
            ..bad_code
        };
        assert_eq!(render_prompt(&long), None);
    }
}
