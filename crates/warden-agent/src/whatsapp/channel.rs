//! [`WhatsAppChannel`]: the [`Channel`] trait over the WhatsApp Cloud API.
//!
//! Inbound messages arrive as [`WebhookBatch`]es from the webhook listener
//! over an `mpsc` channel; outbound text goes to the Graph API. Any
//! WhatsApp user can message the business number, so every inbound path
//! fails closed: only a fresh, non-forwarded `text` from an owner number is
//! an owner message (`wa:<digits>`). Everything else reaches the engine as a
//! non-owner sender (`wa:<number>` for a stranger's text, `wa-<tag>:<number
//! or 0>` for a refused or stale message) with empty text, so the engine
//! audits it and nothing else happens. Delivery statuses are counted and
//! dropped; they never reach the engine.
//!
//! Delivery is at most once: a batch's new owner message ids are written
//! to the [`SeenStore`] before any of its messages is queued, and a failed
//! write is fatal. Ingesting a batch is synchronous, and the only awaits are the
//! receiver (cancel-safe) and sends, so `recv`, `ask_approval` and
//! `discard_pending_input` may be dropped at any await without losing or
//! replaying a message.
//!
//! Meta rejects free-form messages outside the 24-hour customer-service
//! window, so a send is made only while `now + 5 min < last inbound + 24 h`
//! for that owner; anything else is dropped and counted
//! ([`WhatsAppChannel::window_drops`]). The last-inbound map is not
//! persisted: after a restart Warden cannot message an owner until that
//! owner writes.
//!
//! No PIN is ever taken over WhatsApp ([`Channel::accepts_pin`] is always
//! `false`): the Cloud API cannot delete a user's message, so a PIN typed
//! into WhatsApp would stay in the chat and at Meta.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, watch};
use warden_core::Tier;
use zeroize::Zeroizing;

use super::api::{ErrorClass, GraphApi, WhatsAppError};
use super::seen::SeenStore;
use super::webhook::{RefuseReason, WaEvent, WebhookBatch};
use crate::channel::{
    cap_utf16, parse_reply, render_prompt, sanitize_for_display, ApprovalPrompt, ApprovalReply,
    Channel, Inbound, SenderId,
};
use crate::engine::may_hold_pin;
use crate::redact::redact;

/// The customer-service window: 24 hours after the owner's last message.
pub const WINDOW_MS: u64 = 86_400_000;
/// A send is allowed only while at least this much of the window is left.
const WINDOW_MARGIN_MS: u64 = 300_000;
/// Most items waiting for `recv`; extra items are dropped and counted.
const MAX_QUEUE: usize = 64;
/// Most notices waiting to be sent; extra notices are dropped.
const MAX_NOTICES: usize = 64;
/// WhatsApp's text body limit (4096 characters), counted in UTF-16 units,
/// which are never fewer than characters.
const MAX_TEXT_UTF16: usize = 4096;
/// A reply that does not carry the prompt's code may be stamped up to this
/// long before the prompt was sent (whole-second timestamps, clock skew).
const REPLY_SLACK_MS: u64 = 5_000;

const NOT_TEXT: &str = "only text messages are supported";
const PROMPT_TOO_LONG: &str = "request too long to approve safely; refused";
const CANNOT_DELETE: &str = "Warden cannot delete WhatsApp messages; delete that message yourself.";

/// Channel settings.
#[derive(Debug, Clone)]
pub struct WhatsAppOptions {
    /// Owner messages older than this (by WhatsApp's `timestamp`) are not
    /// acted on (default 120 s).
    pub max_message_age: Duration,
    /// Wait before the one retry of a rate-limited send (default 2 s).
    pub rate_limit_backoff: Duration,
    /// Once shutdown has started ([`WhatsAppChannel::with_shutdown`]): the
    /// longest any one request may still take (default 5 s).
    pub shutdown_request_timeout: Duration,
}

impl Default for WhatsAppOptions {
    fn default() -> Self {
        WhatsAppOptions {
            max_message_age: Duration::from_secs(120),
            rate_limit_backoff: Duration::from_secs(2),
            shutdown_request_timeout: Duration::from_secs(5),
        }
    }
}

/// A condition that ends the channel: `recv` returns `None` from then on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhatsAppFatal {
    /// HTTP 401 or Graph code 190: the access token is not valid.
    TokenRejected,
    /// The seen-message list could not be saved.
    SeenUnwritable,
    /// The webhook listener's sender went away while not shutting down.
    ListenerStopped,
}

impl fmt::Display for WhatsAppFatal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            WhatsAppFatal::TokenRejected => "WhatsApp rejected the access token",
            WhatsAppFatal::SeenUnwritable => "cannot save the WhatsApp seen-message list",
            WhatsAppFatal::ListenerStopped => "the WhatsApp webhook listener stopped",
        })
    }
}

/// The sender id of a WhatsApp number (owner or stranger): `wa:<number>`.
pub fn sender_id(number: &str) -> SenderId {
    SenderId(format!("wa:{number}"))
}

/// A sender that is never an owner: `wa-<tag>:<number or 0>`.
fn tagged(tag: &str, from: Option<&str>) -> SenderId {
    SenderId(format!("wa-{tag}:{}", from.unwrap_or("0")))
}

/// The non-owner item a stale owner message becomes.
fn stale_inbound(from: &str) -> Inbound {
    Inbound {
        sender: tagged("stale", Some(from)),
        text: String::new(),
    }
}

/// Where an owner text came from.
#[derive(Clone)]
struct Origin {
    from: String,
    /// WhatsApp's `timestamp` in ms, capped at the local clock on arrival.
    at_ms: u64,
}

/// One item waiting for `recv`.
struct Item {
    inbound: Inbound,
    /// For owner text: where it came from. `None` marks an item with no
    /// content (the engine only audits it), evicted first on overflow.
    origin: Option<Origin>,
}

/// One message after deduplication, owner check and age check.
enum Event {
    /// Fresh text from an owner.
    OwnerText {
        from: String,
        /// Capped arrival time (see [`capped_ms`]).
        at_ms: u64,
        reply_to: Option<String>,
        text: Zeroizing<String>,
    },
    /// A non-text message from an owner: tagged, and the owner is told.
    OwnerNotText {
        from: String,
        at_ms: u64,
        inbound: Inbound,
    },
    /// Anything else, passed on as is (non-owner sender, empty text).
    Pass(Inbound),
}

/// The WhatsApp channel. See the module docs.
pub struct WhatsAppChannel {
    api: GraphApi,
    inbound: mpsc::Receiver<WebhookBatch>,
    /// Owner numbers, digits only.
    owners: Vec<String>,
    seen: SeenStore,
    opts: WhatsAppOptions,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
    queue: VecDeque<Item>,
    dropped: Arc<AtomicU64>,
    /// Warden's own texts to send, `(owner number, text)`.
    notices: VecDeque<(String, String)>,
    /// Per owner number: the latest inbound time (Unix ms, capped at the
    /// local clock when it arrived).
    last_inbound: HashMap<String, u64>,
    window_drops: Arc<AtomicU64>,
    statuses: Arc<AtomicU64>,
    /// Owner texts never handed to the engine because Warden stopped first.
    unread_at_stop: Arc<AtomicU64>,
    /// Owners whose consumed text may hold the PIN in the batch being
    /// handled; each gets one [`CANNOT_DELETE`] notice when it is done.
    delete_due: Vec<String>,
    fatal: Option<WhatsAppFatal>,
    /// Shutdown signal ([`Self::with_shutdown`]).
    shutdown: Option<watch::Receiver<bool>>,
}

impl fmt::Debug for WhatsAppChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WhatsAppChannel")
            .field("api", &self.api)
            .field("owners", &self.owners.len())
            .finish_non_exhaustive()
    }
}

fn system_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The notice for `n` owner messages Warden stopped before reading.
fn unread_notice(n: usize) -> String {
    format!("Warden stopped before reading {n} message(s); send them again.")
}

/// The notice for `n` owner messages dropped as older than `secs`.
fn stale_notice(n: usize, secs: u64) -> String {
    format!("ignored {n} message(s) older than {secs} s (Warden was not running or was busy)")
}

/// Add one to `from`'s count.
fn count_per_owner(counts: &mut Vec<(String, usize)>, from: &str) {
    match counts.iter_mut().find(|(f, _)| f == from) {
        Some((_, n)) => *n += 1,
        None => counts.push((from.to_string(), 1)),
    }
}

/// Resolves once `shutdown` is `true`; never without a signal, or once its
/// sender is gone (which the engine reads as "never shut down" too).
async fn shutdown_started(shutdown: Option<watch::Receiver<bool>>) {
    if let Some(mut rx) = shutdown {
        if rx.wait_for(|&v| v).await.is_ok() {
            return;
        }
    }
    std::future::pending().await
}

/// WhatsApp's `timestamp` (seconds) as Unix ms, never later than `now`:
/// a sender clock running ahead must not keep a message fresh, nor extend
/// the 24-hour window.
fn capped_ms(timestamp_s: i64, now: u64) -> u64 {
    u64::try_from(timestamp_s)
        .unwrap_or(0)
        .saturating_mul(1000)
        .min(now)
}

/// The wamid of an event, if it has one.
fn wamid_of(ev: &WaEvent) -> Option<&str> {
    match ev {
        WaEvent::Text { wamid, .. } => Some(wamid),
        WaEvent::Refused { wamid, .. } => wamid.as_deref(),
        WaEvent::Status => None,
    }
}

/// The sender and timestamp of an event, if it has a sender.
fn origin_of(ev: &WaEvent) -> Option<(&str, Option<i64>)> {
    match ev {
        WaEvent::Text {
            from, timestamp_s, ..
        } => Some((from.as_str(), Some(*timestamp_s))),
        WaEvent::Refused {
            from, timestamp_s, ..
        } => Some((from.as_deref()?, *timestamp_s)),
        WaEvent::Status => None,
    }
}

impl WhatsAppChannel {
    /// A channel reading batches from `inbound` (the webhook listener) for
    /// the given owner numbers (digits only).
    pub fn new(
        api: GraphApi,
        inbound: mpsc::Receiver<WebhookBatch>,
        owners: Vec<String>,
        seen: SeenStore,
        opts: WhatsAppOptions,
    ) -> WhatsAppChannel {
        WhatsAppChannel {
            api,
            inbound,
            owners,
            seen,
            opts,
            clock: Box::new(system_clock_ms),
            queue: VecDeque::new(),
            dropped: Arc::new(AtomicU64::new(0)),
            notices: VecDeque::new(),
            last_inbound: HashMap::new(),
            window_drops: Arc::new(AtomicU64::new(0)),
            statuses: Arc::new(AtomicU64::new(0)),
            unread_at_stop: Arc::new(AtomicU64::new(0)),
            delete_due: Vec::new(),
            fatal: None,
            shutdown: None,
        }
    }

    /// Replace the clock (Unix ms) used for message age and the window.
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> u64 + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// Observe `shutdown` (the engine's signal): once it is `true`, sends
    /// skip the rate-limit retry (a wait in progress ends at once), every
    /// request gets at most `shutdown_request_timeout`, and the listener
    /// going away is not fatal.
    pub fn with_shutdown(mut self, shutdown: watch::Receiver<bool>) -> Self {
        self.shutdown = Some(shutdown);
        self
    }

    /// Why the channel stopped, if it did.
    pub fn fatal(&self) -> Option<WhatsAppFatal> {
        self.fatal
    }

    /// Items dropped because the queue was full.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// [`Self::dropped_count`] as a handle shared with the channel, so it
    /// can be read after the channel is wrapped.
    pub fn dropped_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.dropped)
    }

    /// Sends dropped because the owner's 24-hour window was closed (or
    /// Meta said so with code 131047). A handle shared with the channel,
    /// so it can be read after the channel is wrapped.
    pub fn window_drops(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.window_drops)
    }

    /// Delivery statuses received (counted and dropped).
    pub fn status_count(&self) -> u64 {
        self.statuses.load(Ordering::Relaxed)
    }

    /// [`Self::status_count`] as a handle shared with the channel, so it
    /// can be read after the channel is wrapped.
    pub fn status_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.statuses)
    }

    /// Owner texts that were taken from Meta (answered 200) but never
    /// handed to the engine because Warden stopped first (see
    /// [`Channel::drain_at_stop`]). A handle shared with the channel, so it
    /// can be read after the channel is wrapped.
    pub fn unread_at_stop_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.unread_at_stop)
    }

    fn shutting_down(&self) -> bool {
        self.shutdown.as_ref().is_some_and(|rx| *rx.borrow())
    }

    /// Run one request. Once shutdown has been asked for (before or while
    /// it runs), it gets at most `shutdown_request_timeout` more.
    async fn bounded<T>(
        &self,
        req: impl Future<Output = Result<T, WhatsAppError>>,
    ) -> Result<T, WhatsAppError> {
        let mut req = std::pin::pin!(req);
        if !self.shutting_down() {
            tokio::select! {
                r = &mut req => return r,
                () = shutdown_started(self.shutdown.clone()) => {}
            }
        }
        tokio::time::timeout(self.opts.shutdown_request_timeout, req)
            .await
            .unwrap_or(Err(WhatsAppError::Transport("timeout")))
    }

    /// The owner number `to` names, if `to` is exactly `wa:<owner number>`.
    fn owner_number(&self, to: &SenderId) -> Option<String> {
        self.owners.iter().find(|n| sender_id(n) == *to).cloned()
    }

    fn is_owner(&self, number: &str) -> bool {
        self.owners.iter().any(|n| n == number)
    }

    /// Is `number`'s customer-service window open, with the margin to spare?
    fn in_window(&self, number: &str) -> bool {
        let Some(&last) = self.last_inbound.get(number) else {
            return false;
        };
        let now = (self.clock)();
        now.saturating_add(WINDOW_MARGIN_MS) < last.saturating_add(WINDOW_MS)
    }

    fn count_window_drop(&self) {
        self.window_drops.fetch_add(1, Ordering::Relaxed);
    }

    /// Is a message that arrived at `at_ms` (capped, see [`capped_ms`])
    /// too old to act on?
    fn is_stale(&self, at_ms: u64) -> bool {
        let max_age = u64::try_from(self.opts.max_message_age.as_millis()).unwrap_or(u64::MAX);
        at_ms.saturating_add(max_age) < (self.clock)()
    }

    fn notify(&mut self, to: &str, text: impl Into<String>) {
        if self.notices.len() < MAX_NOTICES {
            self.notices.push_back((to.to_string(), text.into()));
        }
    }

    fn notify_stale(&mut self, stale: Vec<(String, usize)>) {
        let secs = self.opts.max_message_age.as_secs();
        for (from, n) in stale {
            self.notify(&from, stale_notice(n, secs));
        }
    }

    /// Note owner text the channel consumed itself (never handed to the
    /// engine): if it may hold the PIN, the owner is told to delete it once
    /// the current batch is handled ([`Self::queue_delete_notices`]).
    fn consumed(&mut self, from: &str, text: &str) {
        if may_hold_pin(text) {
            self.delete_due_for(from);
        }
    }

    /// Note `from` for one [`CANNOT_DELETE`] notice this batch.
    fn delete_due_for(&mut self, from: &str) {
        if !self.delete_due.iter().any(|f| f == from) {
            self.delete_due.push(from.to_string());
        }
    }

    /// One [`CANNOT_DELETE`] notice per owner noted by [`Self::consumed`],
    /// inside the window only (outside it is skipped silently, as in
    /// `retract_last`).
    fn queue_delete_notices(&mut self) {
        for from in std::mem::take(&mut self.delete_due) {
            if self.in_window(&from) {
                self.notify(&from, CANNOT_DELETE);
            }
        }
    }

    /// Queue an item for `recv`. When the queue is full, items without
    /// content (non-owner, refused, stale: the engine only audits them) go
    /// first: an owner item evicts the newest of them, and is itself
    /// dropped only when none is left. Every drop is counted.
    fn enqueue(&mut self, item: Item) {
        if self.queue.len() < MAX_QUEUE {
            self.queue.push_back(item);
            return;
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
        if item.origin.is_none() {
            return;
        }
        if let Some(pos) = self.queue.iter().rposition(|i| i.origin.is_none()) {
            self.queue.remove(pos);
            self.queue.push_back(item);
        }
    }

    /// Queue an event for `recv`; an owner's non-text also gets a notice.
    fn enqueue_event(&mut self, ev: Event) {
        match ev {
            Event::OwnerText {
                from, at_ms, text, ..
            } => self.enqueue(Item {
                inbound: Inbound {
                    sender: sender_id(&from),
                    text: text.as_str().to_owned(),
                },
                origin: Some(Origin { from, at_ms }),
            }),
            Event::OwnerNotText { from, inbound, .. } => {
                self.notify(&from, NOT_TEXT);
                self.enqueue(Item {
                    inbound,
                    origin: None,
                });
            }
            Event::Pass(inbound) => self.enqueue(Item {
                inbound,
                origin: None,
            }),
        }
    }

    /// Turn a batch into events. Synchronous, so it cannot be cancelled
    /// half way:
    /// 1. drop events whose wamid was seen before or earlier in the batch,
    ///    and count and drop statuses;
    /// 2. record the remaining owner wamids; on failure the channel is
    ///    fatal and the batch is dropped;
    /// 3. note the inbound time of every owner message;
    /// 4. sort the messages into owner text, stale, owner non-text and
    ///    pass-through; owners with stale messages get one notice, and
    ///    stale text that may hold the PIN is noted ([`Self::consumed`]).
    fn ingest(&mut self, batch: WebhookBatch) -> Vec<Event> {
        let mut in_batch: HashSet<String> = HashSet::new();
        let mut fresh = Vec::with_capacity(batch.events.len());
        for ev in batch.events {
            if matches!(ev, WaEvent::Status) {
                self.statuses.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if let Some(w) = wamid_of(&ev) {
                if self.seen.contains(w) || !in_batch.insert(w.to_string()) {
                    continue;
                }
            }
            fresh.push(ev);
        }
        let now = (self.clock)();
        // Only owner ids are recorded (see [`SeenStore`]), each with its
        // capped time so eviction can keep it while a redelivery could
        // still be fresh.
        let ids: Vec<(&str, u64)> = fresh
            .iter()
            .filter_map(|ev| {
                let (from, ts) = origin_of(ev)?;
                if !self.is_owner(from) {
                    return None;
                }
                let at = ts.map_or(now, |t| capped_ms(t, now));
                Some((wamid_of(ev)?, at))
            })
            .collect();
        let keep_ms = u64::try_from(self.opts.max_message_age.as_millis()).unwrap_or(u64::MAX);
        if !ids.is_empty() && self.seen.record(&ids, now, keep_ms).is_err() {
            self.fatal = Some(WhatsAppFatal::SeenUnwritable);
            return Vec::new();
        }

        for ev in &fresh {
            let Some((from, Some(ts))) = origin_of(ev) else {
                continue;
            };
            if !self.is_owner(from) {
                continue;
            }
            let at = capped_ms(ts, now);
            let slot = self.last_inbound.entry(from.to_string()).or_insert(0);
            *slot = (*slot).max(at);
        }

        let mut stale: Vec<(String, usize)> = Vec::new();
        let mut events = Vec::with_capacity(fresh.len());
        for ev in fresh {
            match ev {
                WaEvent::Text {
                    from,
                    timestamp_s,
                    body,
                    reply_to,
                    ..
                } => {
                    let body = Zeroizing::new(body);
                    let at_ms = capped_ms(timestamp_s, now);
                    if !self.is_owner(&from) {
                        events.push(Event::Pass(Inbound {
                            sender: sender_id(&from),
                            text: String::new(),
                        }));
                    } else if self.is_stale(at_ms) {
                        self.consumed(&from, &body);
                        count_per_owner(&mut stale, &from);
                        events.push(Event::Pass(stale_inbound(&from)));
                    } else {
                        events.push(Event::OwnerText {
                            from,
                            at_ms,
                            reply_to,
                            text: body,
                        });
                    }
                }
                WaEvent::Refused {
                    from,
                    reason,
                    timestamp_s,
                    ..
                } => {
                    let inbound = Inbound {
                        sender: tagged(reason.tag(), from.as_deref()),
                        text: String::new(),
                    };
                    match from {
                        Some(from) if reason == RefuseReason::NotText && self.is_owner(&from) => {
                            // No timestamp: treat it as arriving now.
                            let at_ms = timestamp_s.map_or(now, |t| capped_ms(t, now));
                            events.push(Event::OwnerNotText {
                                from,
                                at_ms,
                                inbound,
                            });
                        }
                        _ => events.push(Event::Pass(inbound)),
                    }
                }
                WaEvent::Status => {}
            }
        }
        self.notify_stale(stale);
        events
    }

    /// Re-apply the age rule to queued owner texts (they may have waited
    /// while the engine was busy): each stale one becomes a `wa-stale` item
    /// with empty text in place, and its owner gets one notice.
    /// Synchronous, so it cannot be cancelled half way. Returns whether
    /// anything expired.
    fn expire_queued(&mut self) -> bool {
        let mut stale: Vec<(String, usize)> = Vec::new();
        let mut queue = std::mem::take(&mut self.queue);
        for item in &mut queue {
            let Some(o) = &item.origin else { continue };
            if !self.is_stale(o.at_ms) {
                continue;
            }
            let from = o.from.clone();
            self.consumed(&from, &item.inbound.text);
            count_per_owner(&mut stale, &from);
            *item = Item {
                inbound: stale_inbound(&from),
                origin: None,
            };
        }
        self.queue = queue;
        let expired = !stale.is_empty();
        self.notify_stale(stale);
        self.queue_delete_notices();
        expired
    }

    /// Note a failed send: a rejected token is fatal, a closed window is
    /// counted, anything else is dropped.
    fn note_error(&mut self, e: &WhatsAppError) {
        match e.class() {
            ErrorClass::AuthRejected => self.fatal = Some(WhatsAppFatal::TokenRejected),
            ErrorClass::OutsideWindow => self.count_window_drop(),
            ErrorClass::RateLimited | ErrorClass::Other => {}
        }
    }

    /// Send already-prepared text to owner `number`. Only inside the
    /// window (otherwise counted as a window drop). One retry after
    /// `rate_limit_backoff` when rate limited, unless shutdown has started.
    /// Returns the sent message's wamid.
    async fn deliver(&mut self, number: &str, text: &str) -> Option<String> {
        if !self.in_window(number) {
            self.count_window_drop();
            return None;
        }
        let first = self.bounded(self.api.send_text(number, text)).await;
        let err = match first {
            Ok(id) => return Some(id),
            Err(e) => e,
        };
        if err.class() != ErrorClass::RateLimited || self.shutting_down() {
            self.note_error(&err);
            return None;
        }
        tokio::select! {
            () = tokio::time::sleep(self.opts.rate_limit_backoff) => {}
            () = shutdown_started(self.shutdown.clone()) => return None,
        }
        match self.bounded(self.api.send_text(number, text)).await {
            Ok(id) => Some(id),
            Err(e) => {
                self.note_error(&e);
                None
            }
        }
    }

    /// Send queued notices, best effort. A notice is removed only after
    /// its request has finished, so a flush cancelled mid-send (for
    /// example by [`crate::channel::Pair`] when the other channel delivers
    /// first) sends it again next time; a notice may then arrive twice.
    async fn flush(&mut self) {
        while let Some((to, text)) = self.notices.front().cloned() {
            if self.fatal.is_none() {
                let _ = self.deliver(&to, &text).await;
            }
            self.notices.pop_front();
        }
    }

    /// At stop: take every batch still waiting from the listener (each was
    /// answered 200, so Meta will not deliver it again) and ingest it, so
    /// its ids are recorded as seen as usual. Every owner text that will
    /// not be handled, queued before or found now, is counted
    /// ([`Self::unread_at_stop_counter`]), and each owner with any gets one
    /// notice (inside the window only). Synchronous.
    fn drain_unread(&mut self) {
        let mut unread: Vec<(String, usize)> = Vec::new();
        for item in std::mem::take(&mut self.queue) {
            if let Some(o) = item.origin {
                count_per_owner(&mut unread, &o.from);
            }
        }
        // The listener has stopped, so this ends. A failed seen write makes
        // `ingest` fatal and return nothing; the later batches are tried
        // all the same, and every notice is then skipped.
        while let Ok(batch) = self.inbound.try_recv() {
            for ev in self.ingest(batch) {
                match ev {
                    Event::OwnerText { from, .. } => count_per_owner(&mut unread, &from),
                    Event::OwnerNotText { from, .. } => self.notify(&from, NOT_TEXT),
                    // Nothing reads the queue any more.
                    Event::Pass(_) => {}
                }
            }
        }
        self.queue_delete_notices();
        for (from, n) in unread {
            self.unread_at_stop
                .fetch_add(u64::try_from(n).unwrap_or(u64::MAX), Ordering::Relaxed);
            if self.in_window(&from) {
                self.notify(&from, unread_notice(n));
            }
        }
    }

    /// The next batch from the listener. `None` means the listener's
    /// sender is gone: fatal unless shutdown has started. Cancel-safe.
    async fn next_batch(&mut self) -> Option<WebhookBatch> {
        let b = self.inbound.recv().await;
        if b.is_none() && !self.shutting_down() && self.fatal.is_none() {
            self.fatal = Some(WhatsAppFatal::ListenerStopped);
        }
        b
    }
}

impl Channel for WhatsAppChannel {
    /// Queued items first, then the next batch from the listener. `None`
    /// once [`Self::fatal`] is set or the listener is gone. Cancel-safe: a
    /// received batch is ingested and queued with no await.
    async fn recv(&mut self) -> Option<Inbound> {
        loop {
            if self.fatal.is_some() {
                return None;
            }
            self.flush().await;
            // A notice may have found the token rejected.
            if self.fatal.is_some() {
                return None;
            }
            // Age is checked again here, with no await before the pop: an
            // owner text that waited too long in the queue is never acted
            // on. What expiry queued is flushed first.
            if self.expire_queued() {
                continue;
            }
            if let Some(item) = self.queue.pop_front() {
                return Some(item.inbound);
            }
            let batch = self.next_batch().await?;
            for ev in self.ingest(batch) {
                self.enqueue_event(ev);
            }
            self.queue_delete_notices();
        }
    }

    /// Only to an owner (`wa:<owner number>`) inside the window; anything
    /// else is dropped. Redacted, display-sanitized and cut to 4096 UTF-16
    /// code units.
    async fn send(&mut self, to: &SenderId, text: &str) {
        if self.fatal.is_some() {
            return;
        }
        let Some(number) = self.owner_number(to) else {
            return;
        };
        let text = cap_utf16(
            sanitize_for_display(redact(text).0.as_str()),
            MAX_TEXT_UTF16,
        );
        let _ = self.deliver(&number, &text).await;
    }

    /// The reply is the next fresh text from `to` that is `yes <code>` for
    /// this prompt, or is stamped no earlier than the prompt was sent (less
    /// 5 s); messages from anyone else are queued for `recv`. A
    /// reply quoting a message other than the prompt is `No`, as is a
    /// non-text reply. Cancel-safe: a reply is taken out of a batch and
    /// judged with no await in between.
    async fn ask_approval(&mut self, to: &SenderId, prompt: &ApprovalPrompt) -> ApprovalReply {
        let Some(number) = self.owner_number(to) else {
            return ApprovalReply::No;
        };
        if prompt.tier == Tier::YesPin {
            return ApprovalReply::No;
        }
        if self.fatal.is_some() {
            return ApprovalReply::Undelivered;
        }
        if !self.in_window(&number) {
            self.count_window_drop();
            return ApprovalReply::Undelivered;
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
        // Never cut a prompt: a cut could hide part of the request.
        let Some(text) =
            render_prompt(&shown).filter(|t| t.encode_utf16().count() <= MAX_TEXT_UTF16)
        else {
            let _ = self.deliver(&number, PROMPT_TOO_LONG).await;
            return ApprovalReply::No;
        };
        // A text that is `yes <this prompt's code>` answers whatever its
        // timestamp: the code is fresh per prompt, so it cannot predate it,
        // and local/Meta clock skew must not lock the owner out. Any other
        // candidate must be stamped at or after this; earlier ones were
        // typed before the prompt existed and are queued for `recv`.
        let not_before = (self.clock)().saturating_sub(REPLY_SLACK_MS);
        let Some(prompt_id) = self.deliver(&number, &text).await else {
            return ApprovalReply::Undelivered;
        };

        loop {
            if self.fatal.is_some() {
                return ApprovalReply::Closed;
            }
            self.flush().await;
            let Some(batch) = self.next_batch().await else {
                return ApprovalReply::Closed;
            };
            // `Some(None)`: a non-text reply.
            let mut reply: Option<Option<(Option<String>, Zeroizing<String>)>> = None;
            for ev in self.ingest(batch) {
                match ev {
                    Event::OwnerText {
                        from,
                        at_ms,
                        reply_to,
                        text,
                    } if from == number
                        && reply.is_none()
                        && (at_ms >= not_before
                            || parse_reply(&text, false, &prompt.challenge)
                                == ApprovalReply::Yes) =>
                    {
                        reply = Some(Some((reply_to, text)));
                    }
                    Event::OwnerNotText { from, at_ms, .. }
                        if from == number && at_ms >= not_before && reply.is_none() =>
                    {
                        reply = Some(None);
                    }
                    other => self.enqueue_event(other),
                }
            }
            let Some(reply) = reply else {
                self.queue_delete_notices();
                continue;
            };
            let answer = match reply {
                None => ApprovalReply::No,
                Some((reply_to, text)) => {
                    let answer = if reply_to.is_some_and(|r| r != prompt_id) {
                        ApprovalReply::No
                    } else {
                        parse_reply(&text, false, &prompt.challenge)
                    };
                    // The reply is consumed here; anything but a Yes may
                    // carry the PIN (`yes <code> <PIN>`), except a bare
                    // `no`, which cannot.
                    if answer != ApprovalReply::Yes && !text.trim().eq_ignore_ascii_case("no") {
                        self.delete_due_for(&number);
                    }
                    answer
                }
            };
            self.queue_delete_notices();
            return answer;
        }
    }

    /// Drops `to`'s queued messages, takes the batches already waiting on
    /// entry (never waiting for more), drops `to`'s new messages and
    /// queues the rest. Returns the bytes dropped (at least 1 per message).
    async fn discard_pending_input(&mut self, to: &SenderId) -> usize {
        let Some(number) = self.owner_number(to) else {
            return 0;
        };
        let mut dropped = 0usize;
        let queued = std::mem::take(&mut self.queue);
        for item in queued {
            match &item.origin {
                Some(o) if o.from == number => {
                    dropped = dropped.saturating_add(item.inbound.text.len().max(1));
                    self.consumed(&number, &item.inbound.text);
                }
                _ => self.queue.push_back(item),
            }
        }
        // Only what was waiting on entry: batches that keep arriving during
        // the drain stay for later. A closed receiver is left for `recv`.
        for _ in 0..self.inbound.len() {
            if self.fatal.is_some() {
                break;
            }
            let Ok(batch) = self.inbound.try_recv() else {
                break;
            };
            for ev in self.ingest(batch) {
                match ev {
                    Event::OwnerText { from, text, .. } if from == number => {
                        dropped = dropped.saturating_add(text.len().max(1));
                        self.consumed(&number, &text);
                    }
                    Event::OwnerNotText { from, .. } if from == number => {
                        dropped = dropped.saturating_add(1);
                    }
                    other => self.enqueue_event(other),
                }
            }
            self.queue_delete_notices();
        }
        self.queue_delete_notices();
        self.flush().await;
        dropped
    }

    /// Never: a PIN typed into WhatsApp cannot be deleted from the chat or
    /// from Meta.
    fn accepts_pin(&self, _to: &SenderId) -> bool {
        false
    }

    /// The Cloud API cannot delete a user's message, so the owner is told
    /// to delete it themselves (best effort, inside the window only).
    async fn retract_last(&mut self, to: &SenderId) {
        let Some(number) = self.owner_number(to) else {
            return;
        };
        // Outside the window the notice is skipped silently (not counted).
        if self.fatal.is_some() || !self.in_window(&number) {
            return;
        }
        let _ = self.deliver(&number, CANNOT_DELETE).await;
    }

    /// Called once the engine has stopped, after
    /// [`Channel::drain_at_stop`]. First the drain runs again (it finds
    /// nothing when `drain_at_stop` already ran, so nothing is counted
    /// twice). Then the notices still queued (stale, not-text,
    /// delete-it-yourself, unread) are sent, best effort, inside the window
    /// only, and within `shutdown_request_timeout` in all; whatever is left
    /// then is dropped.
    async fn flush_pending(&mut self) {
        self.drain_unread();
        let limit = self.opts.shutdown_request_timeout;
        let _ = tokio::time::timeout(limit, self.flush()).await;
        self.notices.clear();
    }

    /// The batches still waiting from the listener are ingested (their ids
    /// recorded as seen) and every owner text that will not be handled is
    /// counted; each such owner gets one notice, queued for
    /// [`Channel::flush_pending`]. A seen-list write failure here is fatal
    /// ([`WhatsAppFatal::SeenUnwritable`]) and no notice is sent.
    fn drain_at_stop(&mut self) {
        self.drain_unread();
    }

    fn serves(&self, who: &SenderId) -> bool {
        who.0.starts_with("wa:")
    }
}
