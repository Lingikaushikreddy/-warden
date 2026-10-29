//! [`TelegramChannel`]: the [`Channel`] trait over the Bot API (long polling).
//!
//! Only owners (allowlisted numeric user ids) in their own private chat are
//! owners here: every other update reaches the engine as a non-owner sender
//! (`tg:<id>` for a stranger, `tg-<tag>:<id>` for a refused or stale update)
//! with empty text, so the engine audits it and nothing else happens.
//!
//! Delivery is at most once: the offset past a batch is saved before any
//! update in it is acted on. Every await sits before that save (a poll) or
//! after the batch has been moved into the channel's own state, so `recv`,
//! `ask_approval` and `discard_pending_input` may be dropped at any await
//! without losing or replaying an update.
//!
//! Everything sent goes out as plain text with link previews off; `send`
//! redacts and display-sanitizes. Errors are fixed text; the token never
//! appears in them.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use warden_core::Tier;
use zeroize::Zeroizing;

use super::api::{TelegramApi, TelegramError};
use super::offset::OffsetStore;
use super::update::{classify_update, RefuseReason, UpdateKind};
use crate::channel::{
    parse_reply, render_prompt, sanitize_for_display, ApprovalPrompt, ApprovalReply, Channel,
    Inbound, SenderId,
};
use crate::engine::is_approval_shaped;
use crate::redact::redact;

/// `getUpdates` batch size.
const POLL_LIMIT: u8 = 20;
/// Most items waiting for `recv`; extra items are dropped and counted.
const MAX_QUEUE: usize = 64;
/// Most notices waiting to be sent; extra notices are dropped.
const MAX_NOTICES: usize = 64;
/// Telegram's message length limit, in UTF-16 code units.
const MAX_TEXT_UTF16: usize = 4096;
/// Longest backoff between failed polls.
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Longest `retry_after` honored by `send`.
const MAX_RETRY_AFTER_SECS: u64 = 30;
/// A reply with this many tokens may hold a PIN and is deleted.
const DELETE_MIN_TOKENS: usize = 3;

const PIN_WARNING: &str = "Your PIN will pass through Telegram's servers; Warden deletes your reply after reading it (best effort).";
const NOT_TEXT: &str = "only text messages are supported";
const HELP: &str = "Warden takes plain text requests; commands are not supported. Approve an action by replying with the line its prompt shows.";
const PROMPT_TOO_LONG: &str = "request too long to approve safely; refused";

/// Channel settings.
#[derive(Debug, Clone)]
pub struct TelegramOptions {
    /// Allow `YesPin` approvals (the PIN is typed into Telegram).
    pub allow_pin_approvals: bool,
    /// Owner messages older than this (by Telegram's `date`) are not acted on.
    pub max_message_age: Duration,
    /// Long-poll timeout for `getUpdates` (default 30).
    pub poll_timeout_secs: u32,
    /// First delay after a failed poll; doubles up to 60 s (default 1 s).
    pub backoff_base: Duration,
}

impl Default for TelegramOptions {
    fn default() -> Self {
        TelegramOptions {
            allow_pin_approvals: false,
            max_message_age: Duration::from_secs(120),
            poll_timeout_secs: 30,
            backoff_base: Duration::from_secs(1),
        }
    }
}

/// A condition that ends the channel: `recv` returns `None` from then on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelegramFatal {
    /// Telegram answered 401 or 404: the bot token is not valid.
    TokenRejected,
    /// Telegram answered 409: something else is polling this bot.
    Conflict,
    /// The update offset could not be saved.
    OffsetUnwritable,
}

impl fmt::Display for TelegramFatal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TelegramFatal::TokenRejected => "Telegram rejected the bot token",
            TelegramFatal::Conflict => {
                "another program is receiving updates for this bot (Telegram 409 conflict)"
            }
            TelegramFatal::OffsetUnwritable => "cannot save the Telegram update offset",
        })
    }
}

/// The sender id of a Telegram owner (or stranger): `tg:<id>`.
pub fn sender_id(user_id: i64) -> SenderId {
    SenderId(format!("tg:{user_id}"))
}

/// A sender that is never an owner: `tg-<tag>:<id>`.
fn tagged(tag: &str, id: Option<i64>) -> SenderId {
    SenderId(format!("tg-{tag}:{}", id.unwrap_or(0)))
}

/// One item waiting for `recv`.
struct Item {
    inbound: Inbound,
    /// For owner text: the chat and message it came from.
    origin: Option<(i64, i64)>,
}

/// One update after filtering, owner check and age check.
enum Event {
    /// Fresh text from an owner in their private chat.
    OwnerText {
        chat: i64,
        message_id: i64,
        reply_to: Option<i64>,
        text: Zeroizing<String>,
    },
    /// A fresh non-text message from an owner in their private chat.
    OwnerNotText { chat: i64 },
    /// Anything else, passed on as is (non-owner sender, empty text).
    Pass(Inbound),
}

/// What one `getUpdates` round produced.
enum Fetched {
    Updates(Vec<Value>),
    /// A single update over the size cap: skipped.
    Skipped,
}

enum PollError {
    Fatal,
    Transient,
}

/// The Telegram channel. See the module docs.
pub struct TelegramChannel {
    api: TelegramApi,
    owners: Vec<i64>,
    store: OffsetStore,
    offset: i64,
    opts: TelegramOptions,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
    queue: VecDeque<Item>,
    dropped: u64,
    /// Warden's own texts to send, `(chat, text)`.
    notices: VecDeque<(i64, String)>,
    /// Messages to delete, `(chat, message_id)`, best effort.
    deletes: Vec<(i64, i64)>,
    /// Per owner chat: the last message handed to the engine.
    last_delivered: HashMap<i64, i64>,
    fatal: Option<TelegramFatal>,
    backoff: Duration,
    /// Oversized single updates skipped in a row.
    skips_in_a_row: u32,
}

impl fmt::Debug for TelegramChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelegramChannel")
            .field("api", &self.api)
            .field("owners", &self.owners.len())
            .field("offset", &self.offset)
            .finish_non_exhaustive()
    }
}

fn system_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Cut `s` to at most 4096 UTF-16 code units, ending with `…` when cut.
fn cap_utf16(s: String) -> String {
    if s.encode_utf16().count() <= MAX_TEXT_UTF16 {
        return s;
    }
    let mut out = String::new();
    let mut units = 0usize;
    for c in s.chars() {
        // Leave one unit for the marker.
        if units + c.len_utf16() > MAX_TEXT_UTF16 - 1 {
            break;
        }
        units += c.len_utf16();
        out.push(c);
    }
    out.push('…');
    out
}

impl TelegramChannel {
    /// A channel polling from `start_offset` (as read by [`OffsetStore::open`])
    /// for the given owner user ids.
    pub fn new(
        api: TelegramApi,
        owners: Vec<i64>,
        offset: OffsetStore,
        start_offset: i64,
        opts: TelegramOptions,
    ) -> TelegramChannel {
        let backoff = opts.backoff_base;
        TelegramChannel {
            api,
            owners,
            store: offset,
            offset: start_offset,
            opts,
            clock: Box::new(system_clock_ms),
            queue: VecDeque::new(),
            dropped: 0,
            notices: VecDeque::new(),
            deletes: Vec::new(),
            last_delivered: HashMap::new(),
            fatal: None,
            backoff,
            skips_in_a_row: 0,
        }
    }

    /// Replace the clock (Unix ms) used for message age.
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> u64 + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// Why the channel stopped, if it did.
    pub fn fatal(&self) -> Option<TelegramFatal> {
        self.fatal
    }

    /// Items dropped because the queue was full.
    pub fn dropped_count(&self) -> u64 {
        self.dropped
    }

    /// The owner chat `to` names, if `to` is exactly `tg:<owner id>`.
    fn owner_chat(&self, to: &SenderId) -> Option<i64> {
        self.owners.iter().copied().find(|&id| sender_id(id) == *to)
    }

    fn is_owner(&self, id: i64) -> bool {
        self.owners.contains(&id)
    }

    /// Queue an item for `recv`. When the queue is full, items without
    /// content (non-owner, refused, stale: the engine only audits them) go
    /// first: an owner item evicts the newest of them, and is itself
    /// dropped only when none is left. A dropped owner message that may
    /// hold a PIN is deleted (best effort). Every drop is counted.
    fn enqueue(&mut self, item: Item) {
        if self.queue.len() < MAX_QUEUE {
            self.queue.push_back(item);
            return;
        }
        self.dropped = self.dropped.saturating_add(1);
        let Some((chat, id)) = item.origin else {
            return;
        };
        match self.queue.iter().rposition(|i| i.origin.is_none()) {
            Some(pos) => {
                self.queue.remove(pos);
                self.queue.push_back(item);
            }
            None => {
                let _ = self.drop_text(chat, id, &item.inbound.text);
            }
        }
    }

    fn notify(&mut self, chat: i64, text: impl Into<String>) {
        if self.notices.len() < MAX_NOTICES {
            self.notices.push_back((chat, text.into()));
        }
    }

    /// Queue an event for `recv`, applying the owner-side rules: commands
    /// get the help line, non-text gets a reply; neither is passed on.
    fn enqueue_event(&mut self, ev: Event) {
        match ev {
            Event::OwnerText {
                chat,
                message_id,
                text,
                ..
            } => {
                if text.starts_with('/') {
                    self.notify(chat, HELP);
                    return;
                }
                self.enqueue(Item {
                    inbound: Inbound {
                        sender: sender_id(chat),
                        text: text.as_str().to_owned(),
                    },
                    origin: Some((chat, message_id)),
                });
            }
            Event::OwnerNotText { chat } => self.notify(chat, NOT_TEXT),
            Event::Pass(inbound) => self.enqueue(Item {
                inbound,
                origin: None,
            }),
        }
    }

    /// Send with one retry after a 429 whose `retry_after` is at most 30 s.
    async fn deliver(&self, chat: i64, text: &str) -> Option<i64> {
        match self.api.send_message(chat, text).await {
            Ok(id) => Some(id),
            Err(TelegramError::Api {
                code: 429,
                retry_after: Some(s),
            }) if s <= MAX_RETRY_AFTER_SECS => {
                tokio::time::sleep(Duration::from_secs(s)).await;
                self.api.send_message(chat, text).await.ok()
            }
            Err(_) => None,
        }
    }

    /// Send queued notices and perform queued deletions, best effort. A
    /// notice is removed before its request, so a cancelled flush skips it
    /// rather than repeating it. A deletion (idempotent, and possibly of a
    /// PIN) is removed only once its request has finished, so a cancelled
    /// flush performs it on the next call.
    async fn flush(&mut self) {
        while let Some((chat, text)) = self.notices.pop_front() {
            let _ = self.deliver(chat, &text).await;
        }
        while let Some(&(chat, id)) = self.deletes.last() {
            let _ = self.api.delete_message(chat, id).await;
            self.deletes.pop();
        }
    }

    fn fail(&mut self, f: TelegramFatal) -> PollError {
        self.fatal = Some(f);
        PollError::Fatal
    }

    fn grow_backoff(&mut self) {
        self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
    }

    fn classify_error(&mut self, e: &TelegramError) -> PollError {
        match e {
            TelegramError::Api { code, .. } | TelegramError::Status(code) => match code {
                401 | 404 => self.fail(TelegramFatal::TokenRejected),
                409 => self.fail(TelegramFatal::Conflict),
                _ => PollError::Transient,
            },
            _ => PollError::Transient,
        }
    }

    /// One `getUpdates` round. A batch over the size cap is fetched again
    /// with `limit` 1; a single update still over the cap is skipped by
    /// advancing the offset by one.
    ///
    /// Limit: the skip assumes the oversized update's id is the saved
    /// offset (Telegram numbers updates sequentially). When it is not (a
    /// fresh offset of 0, or ids renumbered after a week of silence), the
    /// skip repeats with backoff.
    async fn fetch(&mut self, timeout: u32) -> Result<Fetched, PollError> {
        if self.skips_in_a_row > 1 {
            tokio::time::sleep(self.backoff).await;
            self.grow_backoff();
        }
        let first = self.api.get_updates(self.offset, timeout, POLL_LIMIT).await;
        let res = match first {
            Err(TelegramError::TooLarge) => self.api.get_updates(self.offset, 0, 1).await,
            other => other,
        };
        match res {
            Ok(v) => Ok(Fetched::Updates(v)),
            Err(TelegramError::TooLarge) => {
                let next = self.offset.saturating_add(1);
                if self.store.save(next).is_err() {
                    return Err(self.fail(TelegramFatal::OffsetUnwritable));
                }
                self.offset = next;
                self.skips_in_a_row = self.skips_in_a_row.saturating_add(1);
                Ok(Fetched::Skipped)
            }
            Err(e) => Err(self.classify_error(&e)),
        }
    }

    /// Poll once and turn the batch into events. The offset past the batch
    /// is saved before anything else; nothing after the network await can
    /// be cancelled, because the rest is synchronous.
    async fn poll(&mut self, timeout: u32) -> Result<Vec<Event>, PollError> {
        if self.fatal.is_some() {
            return Err(PollError::Fatal);
        }
        let raw = match self.fetch(timeout).await? {
            Fetched::Skipped => {
                return Ok(vec![Event::Pass(Inbound {
                    sender: tagged(RefuseReason::Malformed.tag(), None),
                    text: String::new(),
                })])
            }
            Fetched::Updates(raw) => raw,
        };
        let updates: Vec<_> = raw
            .iter()
            .filter_map(classify_update)
            .filter(|u| u.update_id >= self.offset)
            .collect();
        let got_any = !raw.is_empty();
        drop(raw);
        let Some(max) = updates.iter().map(|u| u.update_id).max() else {
            // A non-empty batch the offset cannot move past would be served
            // again at once: back off instead of spinning.
            return if got_any {
                Err(PollError::Transient)
            } else {
                Ok(Vec::new())
            };
        };
        let next = max.saturating_add(1);
        if self.store.save(next).is_err() {
            return Err(self.fail(TelegramFatal::OffsetUnwritable));
        }
        self.offset = next;
        self.backoff = self.opts.backoff_base;
        self.skips_in_a_row = 0;

        let now = i128::from((self.clock)());
        let max_age = i128::try_from(self.opts.max_message_age.as_millis()).unwrap_or(i128::MAX);
        let mut stale: Vec<(i64, usize)> = Vec::new();
        let mut events = Vec::with_capacity(updates.len());
        for u in updates {
            match u.kind {
                UpdateKind::Text {
                    chat_id,
                    from_id,
                    message_id,
                    date_s,
                    text,
                    reply_to,
                } => {
                    let text = Zeroizing::new(text);
                    if !self.is_owner(from_id) {
                        events.push(Event::Pass(Inbound {
                            sender: sender_id(from_id),
                            text: String::new(),
                        }));
                    } else if i128::from(date_s) * 1000 + max_age < now {
                        // Never acted on. One that may hold a PIN is deleted.
                        if is_approval_shaped(&text)
                            && text.split_whitespace().count() >= DELETE_MIN_TOKENS
                        {
                            self.deletes.push((chat_id, message_id));
                        }
                        match stale.iter_mut().find(|(c, _)| *c == chat_id) {
                            Some((_, n)) => *n += 1,
                            None => stale.push((chat_id, 1)),
                        }
                        events.push(Event::Pass(Inbound {
                            sender: tagged("stale", Some(from_id)),
                            text: String::new(),
                        }));
                    } else {
                        events.push(Event::OwnerText {
                            chat: chat_id,
                            message_id,
                            reply_to,
                            text,
                        });
                    }
                }
                UpdateKind::Refused {
                    from_id,
                    chat_id,
                    reason: RefuseReason::NotText,
                    ..
                } if from_id.is_some_and(|f| self.is_owner(f)) && chat_id == from_id => {
                    events.push(Event::OwnerNotText {
                        chat: chat_id.unwrap_or_default(),
                    });
                }
                UpdateKind::Refused {
                    from_id, reason, ..
                } => events.push(Event::Pass(Inbound {
                    sender: tagged(reason.tag(), from_id),
                    text: String::new(),
                })),
            }
        }
        for (chat, n) in stale {
            let secs = self.opts.max_message_age.as_secs();
            let text = format!(
                "ignored {n} message(s) older than {secs} s (sent while Warden was not running)"
            );
            self.notify(chat, text);
        }
        Ok(events)
    }
}

impl Channel for TelegramChannel {
    /// Queued items first, then a long poll. `None` once [`Self::fatal`] is
    /// set. Cancel-safe: a dropped poll confirmed nothing and is fetched
    /// again; a finished poll is moved into the queue with no await.
    async fn recv(&mut self) -> Option<Inbound> {
        loop {
            if self.fatal.is_some() {
                return None;
            }
            self.flush().await;
            if let Some(item) = self.queue.pop_front() {
                if let Some((chat, id)) = item.origin {
                    self.last_delivered.insert(chat, id);
                }
                return Some(item.inbound);
            }
            match self.poll(self.opts.poll_timeout_secs).await {
                Ok(events) => {
                    for ev in events {
                        self.enqueue_event(ev);
                    }
                }
                Err(PollError::Fatal) => return None,
                Err(PollError::Transient) => {
                    tokio::time::sleep(self.backoff).await;
                    self.grow_backoff();
                }
            }
        }
    }

    /// Only to an owner (`tg:<owner id>`); anything else is dropped.
    /// Redacted, display-sanitized and cut to 4096 UTF-16 code units. Best
    /// effort: one retry after a 429 of at most 30 s, otherwise dropped.
    async fn send(&mut self, to: &SenderId, text: &str) {
        let Some(chat) = self.owner_chat(to) else {
            return;
        };
        let text = cap_utf16(sanitize_for_display(redact(text).0.as_str()));
        let _ = self.deliver(chat, &text).await;
    }

    /// The reply is the next text from `to`'s own chat polled after the
    /// prompt was sent; updates from anyone else are queued for `recv`.
    /// Cancel-safe: a reply is taken out of a batch and judged with no
    /// await in between, so a dropped call never leaves it behind to answer
    /// a later prompt.
    async fn ask_approval(&mut self, to: &SenderId, prompt: &ApprovalPrompt) -> ApprovalReply {
        let Some(chat) = self.owner_chat(to) else {
            return ApprovalReply::No;
        };
        let needs_pin = prompt.tier == Tier::YesPin;
        if needs_pin && !self.opts.allow_pin_approvals {
            return ApprovalReply::No;
        }
        let shown = ApprovalPrompt {
            summary: redact(&prompt.summary).0.into_string(),
            tier: prompt.tier,
            model_note: prompt
                .model_note
                .as_deref()
                .map(|n| redact(n).0.into_string()),
            challenge: prompt.challenge.clone(),
        };
        let text = render_prompt(&shown).map(|mut t| {
            if needs_pin {
                t.push_str(PIN_WARNING);
                t.push('\n');
            }
            t
        });
        // Never cut a prompt: a cut could hide part of the request.
        let Some(text) = text.filter(|t| t.encode_utf16().count() <= MAX_TEXT_UTF16) else {
            let _ = self.deliver(chat, PROMPT_TOO_LONG).await;
            return ApprovalReply::No;
        };
        let Some(prompt_id) = self.deliver(chat, &text).await else {
            return ApprovalReply::No;
        };

        loop {
            self.flush().await;
            let events = match self.poll(self.opts.poll_timeout_secs).await {
                Ok(events) => events,
                Err(PollError::Fatal) => return ApprovalReply::Closed,
                Err(PollError::Transient) => {
                    tokio::time::sleep(self.backoff).await;
                    self.grow_backoff();
                    continue;
                }
            };
            // `Some(None)`: a non-text reply.
            let mut reply = None;
            for ev in events {
                match ev {
                    Event::OwnerText {
                        chat: c,
                        message_id,
                        reply_to,
                        text,
                    } if c == chat && reply.is_none() => {
                        reply = Some(Some((message_id, reply_to, text)));
                    }
                    Event::OwnerNotText { chat: c } if c == chat && reply.is_none() => {
                        reply = Some(None);
                    }
                    other => self.enqueue_event(other),
                }
            }
            let Some(reply) = reply else {
                continue;
            };
            let Some((message_id, reply_to, text)) = reply else {
                return ApprovalReply::No;
            };
            let answer = if reply_to.is_some_and(|r| r != prompt_id) {
                ApprovalReply::No
            } else {
                parse_reply(&text, needs_pin, &prompt.challenge)
            };
            let may_hold_pin = text.split_whitespace().count() >= DELETE_MIN_TOKENS;
            drop(text);
            if may_hold_pin {
                self.deletes.push((chat, message_id));
                self.flush().await;
            }
            return answer;
        }
    }

    /// Drops `to`'s queued messages, polls once with timeout 0 (saving the
    /// offset as `recv` does), drops `to`'s new messages and queues the
    /// rest. Dropped messages that may hold a PIN are deleted (best effort).
    async fn discard_pending_input(&mut self, to: &SenderId) -> usize {
        let Some(chat) = self.owner_chat(to) else {
            return 0;
        };
        let mut dropped = 0usize;
        let queued = std::mem::take(&mut self.queue);
        for item in queued {
            match item.origin {
                Some((c, id)) if c == chat => {
                    dropped = dropped.saturating_add(self.drop_text(c, id, &item.inbound.text));
                }
                _ => self.queue.push_back(item),
            }
        }
        if let Ok(events) = self.poll(0).await {
            for ev in events {
                match ev {
                    Event::OwnerText {
                        chat: c,
                        message_id,
                        text,
                        ..
                    } if c == chat => {
                        dropped = dropped.saturating_add(self.drop_text(c, message_id, &text));
                    }
                    Event::OwnerNotText { chat: c } if c == chat => {
                        dropped = dropped.saturating_add(1);
                    }
                    other => self.enqueue_event(other),
                }
            }
        }
        self.flush().await;
        dropped
    }

    fn accepts_pin(&self, _to: &SenderId) -> bool {
        self.opts.allow_pin_approvals
    }

    /// Deletes the last message from `to` that `recv` handed out (the one
    /// the engine is handling), best effort.
    async fn retract_last(&mut self, to: &SenderId) {
        let Some(chat) = self.owner_chat(to) else {
            return;
        };
        if let Some(id) = self.last_delivered.remove(&chat) {
            let _ = self.api.delete_message(chat, id).await;
        }
    }

    fn serves(&self, who: &SenderId) -> bool {
        who.0.starts_with("tg:")
    }
}

impl TelegramChannel {
    /// Account for one dropped owner message; schedule its deletion when
    /// it may hold a PIN. Returns its size in bytes (at least 1).
    fn drop_text(&mut self, chat: i64, message_id: i64, text: &str) -> usize {
        if is_approval_shaped(text) && text.split_whitespace().count() >= DELETE_MIN_TOKENS {
            self.deletes.push((chat, message_id));
        }
        text.len().max(1)
    }
}
