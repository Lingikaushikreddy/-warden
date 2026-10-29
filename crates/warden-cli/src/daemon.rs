//! `warden daemon`: the agent engine on Telegram and/or WhatsApp,
//! unattended, in the foreground.
//!
//! Startup fails closed, exit 1, in this order:
//!
//! 1. the data dir ([`startup::check_home`]);
//! 2. `<home>/daemon.lock` (0600, `try_lock`, held for the process's
//!    lifetime): a second daemon on the same home is refused;
//! 3. the config, which must have a `[telegram]` or a `[whatsapp]` table
//!    (or both); with `--console`, `owner` must be `local`;
//! 4. the root ([`startup::resolve_root`]);
//! 5. the planner key;
//! 6. with `[telegram]`: the bot token from the variable named by
//!    `bot_token_env`;
//! 7. with `[whatsapp]`: the access token, app secret and verify token from
//!    the variables it names, each shape-checked; then, with any mix of
//!    channels, every secret held (those three, the bot token, the API key)
//!    must be a different value, since the verify token travels in a URL
//!    query that tunnel logs may record. Variables are named in errors only under the
//!    [`startup::showable_env_name`] rule; values never are;
//! 8. with `[telegram]`: `getMe` against the configured Bot API base;
//! 9. with `[whatsapp]`: the Graph API phone number lookup, which checks
//!    the access token and that it can see `phone_number_id`;
//! 10. with `[whatsapp]`: the loopback webhook listener is bound (not yet
//!     serving);
//! 11. [`startup::open_parts`] with owners `tg:<id>`, `wa:<number>` (and
//!     `local` with `--console`), then the Telegram update offset store and
//!     the WhatsApp seen-message store;
//! 12. `Engine::try_new`, with shutdown wired to the signal handler.
//!
//! Steps 1-10 leave no files except the data dir and `daemon.lock`.
//!
//! Then: audit `daemon session started`, start serving webhooks (their
//! batches go to the WhatsApp channel through a queue of
//! [`WEBHOOK_QUEUE`] batches), print a banner to stderr and run until the
//! channels close or a signal arrives. The channel is
//! `Pair(Pair(telegram, whatsapp), console)`, each side optional. The first
//! SIGINT or SIGTERM asks the engine to stop after the current step (a
//! running tool always finishes; a pending prompt is refused); later
//! signals only say so again. A fatal channel condition (a token rejected,
//! a Telegram 409 conflict, the offset or seen list unwritable, the
//! listener gone) also stops the engine, even with `--console`. Once
//! shutdown has started, every Telegram and Graph request gets at most 5 s
//! and no rate-limit retry, so the last messages fit a service manager's
//! 60 s stop timeout. Afterwards: the webhook listener stops (its socket
//! closes at once; it gets at most 5 s in all); one best-effort flush of
//! the deletions still owed (replies that may hold the PIN), bounded to
//! 10 s; messages still queued are dropped (delivery is at most once); then
//! audit `daemon session ended` (best effort), print one line of WhatsApp
//! counters if any request was refused or any reply was not sent outside
//! the 24-hour window, and exit 1 if a channel failed fatally, else 0.
//!
//! The approver store lock is held for the daemon's lifetime; the audit log
//! only while a message is handled, so `warden undo` works while it idles.
//! stderr never carries message text, tokens, secrets or keys, nothing is
//! printed per request, and no logger is installed (reqwest could log the
//! token-bearing URL).
//!
//! `warden daemon print-service` ([`cmd_print_service`]) prints a launchd
//! plist or a systemd user unit for the daemon. It reads the config only for
//! the secret environment variable names, writes nothing, and puts
//! `REPLACE_ME` where the secrets go.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, watch, Notify};
use warden_agent::channel::{
    sanitize_for_display, ApprovalPrompt, ApprovalReply, Channel, Inbound, Pair, SenderId,
    StdioChannel,
};
use warden_agent::config::{
    Config, Provider, TelegramConfig, WhatsAppConfig, DEFAULT_GRAPH_API_BASE,
    DEFAULT_TELEGRAM_API_BASE,
};
use warden_agent::engine::Engine;
use warden_agent::planner::Planner;
use warden_agent::telegram::{
    self, BotToken, OffsetStore, TelegramApi, TelegramChannel, TelegramError, TelegramFatal,
    TelegramOptions, OFFSET_FILE,
};
use warden_agent::whatsapp::{
    self, AccessToken, AppSecret, ErrorClass, GraphApi, ListenerConfig, SeenStore, StatsSnapshot,
    VerifyToken, WebhookListener, WebhookStats, WhatsAppChannel, WhatsAppError, WhatsAppFatal,
    WhatsAppOptions, SEEN_FILE,
};

use crate::startup::{
    self, err, open_parts, session_entry, shown, Parts, Prepared, SharedAudit, DAEMON_SESSION,
    STDIO_OWNER,
};
use crate::{EXIT_ERROR, EXIT_OK};

/// The single-instance lock file under the data dir.
const LOCK_FILE: &str = "daemon.lock";
/// The launchd job label.
const LAUNCHD_LABEL: &str = "local.warden.daemon";
/// Where a service file's secret values go.
const PLACEHOLDER: &str = "REPLACE_ME";
/// Longest the final flush of pending deletions may take after the engine
/// has stopped.
const FINAL_FLUSH: Duration = Duration::from_secs(10);
/// Webhook batches waiting between the listener and the WhatsApp channel;
/// a full queue answers 503 so Meta retries later.
const WEBHOOK_QUEUE: usize = 16;
/// Longest the webhook listener may take to stop once shutdown is set.
const LISTENER_STOP: Duration = Duration::from_secs(5);
/// Message for secrets that are not all different.
const SECRETS_NOT_DISTINCT: &str =
    "the WhatsApp secrets, the bot token and the API key must all be different values";

pub fn cmd_daemon(
    home: &Path,
    config: Option<PathBuf>,
    console: bool,
    allow_home_root: bool,
) -> u8 {
    match start(home, config, console, allow_home_root) {
        Ok(code) | Err(code) => code,
    }
}

fn start(
    home: &Path,
    config: Option<PathBuf>,
    console: bool,
    allow_home_root: bool,
) -> Result<u8, u8> {
    // 1. Data dir.
    startup::check_home(home)?;
    // 2. Single instance; the lock lives until this function returns.
    let _lock = lock_home(home)?;
    // 3. Config.
    let (cfg, config_path) = startup::load_config(home, config)?;
    if cfg.telegram.is_none() && cfg.whatsapp.is_none() {
        err!("error: no channel configured: add a [telegram] or [whatsapp] table");
        return Err(EXIT_ERROR);
    }
    if console && cfg.owner != STDIO_OWNER {
        err!("error: --console only supports owner = \"local\"; remove `owner` from the config");
        return Err(EXIT_ERROR);
    }
    // 4. Root.
    let root = startup::resolve_root(&cfg.root, allow_home_root)?;
    let prepared = Prepared {
        cfg,
        config_path,
        root,
    };
    // 5. Planner (no files touched), then 6-12. The key is kept only for
    // step 7's comparison.
    match &prepared.cfg.provider {
        Provider::Anthropic => {
            let key = startup::api_key(&prepared.cfg)?;
            let planner = startup::planner_with_key(&prepared.cfg, key.clone())?;
            serve(planner, Some(key), home, &prepared, console)
        }
        #[cfg(feature = "test-hooks")]
        Provider::Mock { script } => {
            let planner = startup::mock_planner(script)?;
            serve(planner, None, home, &prepared, console)
        }
    }
}

/// Open `<home>/daemon.lock` (0600, no symlinks) and take its lock without
/// waiting.
fn lock_home(home: &Path) -> Result<File, u8> {
    let path = home.join(LOCK_FILE);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|e| {
            err!("error: cannot open the daemon lock {}: {e}", shown(&path));
            EXIT_ERROR
        })?;
    let private = file
        .metadata()
        .is_ok_and(|m| m.is_file() && m.mode() & 0o077 == 0);
    if !private {
        err!(
            "error: the daemon lock {} is not a private regular file; remove it",
            shown(&path)
        );
        return Err(EXIT_ERROR);
    }
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => {
            err!("error: another warden daemon is using {}", shown(home));
            Err(EXIT_ERROR)
        }
        Err(std::fs::TryLockError::Error(e)) => {
            err!("error: cannot lock the daemon lock {}: {e}", shown(&path));
            Err(EXIT_ERROR)
        }
    }
}

/// Step 6: the bot token, and its raw value for step 7's comparison. A
/// missing or empty variable is named only when
/// [`startup::showable_env_name`] allows it; a value is never shown.
fn bot_token(tg: &TelegramConfig) -> Result<(BotToken, String), u8> {
    let raw = match std::env::var(&tg.bot_token_env) {
        Ok(t) if !t.is_empty() => t,
        _ => {
            if startup::showable_env_name(&tg.bot_token_env) {
                err!(
                    "error: environment variable {} is not set or is empty; put your Telegram bot token in it",
                    tg.bot_token_env
                );
            } else {
                err!("error: the configured bot token environment variable is not set or is empty");
            }
            return Err(EXIT_ERROR);
        }
    };
    match BotToken::new(raw.clone()) {
        Ok(t) => Ok((t, raw)),
        Err(_) => {
            err!("error: the Telegram bot token variable does not hold a valid bot token");
            Err(EXIT_ERROR)
        }
    }
}

/// One WhatsApp secret variable's raw value. A missing or empty variable is
/// named only when [`startup::showable_env_name`] allows it.
fn whatsapp_var(name: &str, what: &str) -> Result<String, u8> {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => {
            if startup::showable_env_name(name) {
                err!(
                    "error: environment variable {name} is not set or is empty; put your WhatsApp {what} in it"
                );
            } else {
                err!("error: the configured WhatsApp {what} environment variable is not set or is empty");
            }
            Err(EXIT_ERROR)
        }
    }
}

/// The three WhatsApp secrets, shape-checked.
struct WhatsAppSecrets {
    token: AccessToken,
    app_secret: AppSecret,
    verify_token: VerifyToken,
}

/// Step 7, first half: the three variables, present and well shaped, with
/// their raw values for the comparison.
fn whatsapp_secrets(wa: &WhatsAppConfig) -> Result<(WhatsAppSecrets, [String; 3]), u8> {
    let raw = [
        whatsapp_var(&wa.access_token_env, "access token")?,
        whatsapp_var(&wa.app_secret_env, "app secret")?,
        whatsapp_var(&wa.verify_token_env, "verify token")?,
    ];
    let bad = |what: &str| {
        err!("error: the WhatsApp {what} variable does not hold a valid {what}");
        EXIT_ERROR
    };
    let token = AccessToken::new(raw[0].clone()).map_err(|_| {
        err!("error: the WhatsApp access token variable does not hold a valid token");
        EXIT_ERROR
    })?;
    let app_secret = AppSecret::new(raw[1].clone()).map_err(|_| bad("app secret"))?;
    let verify_token = VerifyToken::new(raw[2].clone()).map_err(|_| bad("verify token"))?;
    Ok((
        WhatsAppSecrets {
            token,
            app_secret,
            verify_token,
        },
        raw,
    ))
}

/// No two of `values` are equal.
fn all_different(values: &[&str]) -> bool {
    values
        .iter()
        .enumerate()
        .all(|(i, a)| values[i + 1..].iter().all(|b| a != b))
}

/// A fixed word for a failed `getMe`. Never formats anything from reqwest
/// or the server.
fn reach_kind(e: &TelegramError) -> String {
    match e {
        TelegramError::Transport(k) => (*k).to_string(),
        TelegramError::Status(c) | TelegramError::Api { code: c, .. } => format!("status {c}"),
        TelegramError::Malformed(m) => format!("malformed response: {m}"),
        TelegramError::TooLarge => "response too large".to_string(),
        TelegramError::Config(m) => (*m).to_string(),
    }
}

/// A fixed word for a failed phone number lookup. [`WhatsAppError`] holds
/// no server text; only numbers and fixed words are formatted.
fn graph_kind(e: &WhatsAppError) -> String {
    match e {
        WhatsAppError::Transport(k) => (*k).to_string(),
        WhatsAppError::Status(c) => format!("status {c}"),
        WhatsAppError::Graph { status, code, .. } => format!("status {status}, code {code}"),
        WhatsAppError::Malformed(m) => format!("malformed response: {m}"),
        WhatsAppError::TooLarge => "response too large".to_string(),
        WhatsAppError::Config(m) => (*m).to_string(),
    }
}

/// Step 9's message for a failed phone number lookup.
fn phone_lookup_error(e: &WhatsAppError, phone_number_id: &str) -> String {
    if e.class() == ErrorClass::AuthRejected {
        return "WhatsApp rejected the access token".to_string();
    }
    match e {
        WhatsAppError::Graph { code: 100, .. } | WhatsAppError::Status(404) => {
            format!("the access token cannot see phone_number_id {phone_number_id}")
        }
        other => format!(
            "cannot reach the WhatsApp Cloud API ({})",
            graph_kind(other)
        ),
    }
}

/// Longest server-supplied text shown in the banner, in characters.
const BANNER_FIELD_MAX: usize = 64;

/// Server-supplied text (Meta's `display_phone_number`) for the one-line
/// banner: display-sanitized, with the newlines and tabs that
/// [`sanitize_for_display`] keeps escaped too, so it cannot start a forged
/// stderr line, and capped at [`BANNER_FIELD_MAX`] characters.
fn banner_field(s: &str) -> String {
    let clean = sanitize_for_display(s)
        .replace('\n', "\\u{a}")
        .replace('\t', "\\u{9}");
    if clean.chars().count() <= BANNER_FIELD_MAX {
        return clean;
    }
    let mut cut: String = clean.chars().take(BANNER_FIELD_MAX - 1).collect();
    cut.push('…');
    cut
}

/// The webhook listener's serving future, spawned once the session starts.
type ListenerTask = Pin<Box<dyn Future<Output = ()> + Send>>;

/// The WhatsApp counters reported at exit.
struct Counters {
    stats: Arc<WebhookStats>,
    window_drops: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
    unread_at_stop: Arc<AtomicU64>,
}

/// The channel's counts at exit.
#[derive(Debug, Clone, Copy, Default)]
struct ChannelCounts {
    window_drops: u64,
    /// Items dropped because the channel's queue was full.
    dropped: u64,
    /// Owner texts taken from Meta but never read because Warden stopped.
    unread_at_stop: u64,
}

/// The exit line for these counts, if any listener counter, the window
/// counter, the channel's drop counter or its unread-at-stop counter is
/// non-zero. The first part is
/// fixed; the other non-zero refusal and drop counts follow it. Delivery
/// statuses are normal traffic and are not reported.
fn counters_line(s: &StatsSnapshot, c: ChannelCounts) -> Option<String> {
    let ChannelCounts {
        window_drops,
        dropped,
        unread_at_stop,
    } = c;
    if s.is_zero() && window_drops == 0 && dropped == 0 && unread_at_stop == 0 {
        return None;
    }
    let mut line = format!(
        "whatsapp: refused {} unsigned, {} bad-signature, {} oversized, {} slow webhook requests; {window_drops} replies not sent outside the 24 h window",
        s.unsigned, s.bad_signature, s.too_large, s.timed_out
    );
    let others: Vec<String> = [
        (s.malformed, "malformed"),
        (s.bad_request, "bad-request"),
        (s.foreign, "foreign"),
        (s.truncated, "truncated"),
        (s.queue_full, "queue-full"),
        (s.busy, "busy"),
        (s.handshake_refused, "handshake-refused"),
        (dropped, "queue-dropped"),
        (unread_at_stop, "unread at stop"),
    ]
    .iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, what)| format!("{n} {what}"))
    .collect();
    if !others.is_empty() {
        line.push_str("; other: ");
        line.push_str(&others.join(", "));
    }
    Some(line)
}

/// Steps 6-11, then run.
fn serve<P: Planner>(
    planner: P,
    api_key: Option<String>,
    home: &Path,
    prepared: &Prepared,
    console: bool,
) -> Result<u8, u8> {
    let cfg = &prepared.cfg;
    // 6. Bot token.
    let bot = cfg.telegram.as_ref().map(bot_token).transpose()?;
    // 7. WhatsApp secrets, then every secret held (with any mix of
    // channels, so the bot token and the API key too) must differ.
    let wa_secrets = cfg.whatsapp.as_ref().map(whatsapp_secrets).transpose()?;
    let mut values: Vec<&str> = Vec::new();
    if let Some((_, raw)) = &wa_secrets {
        values.extend(raw.iter().map(String::as_str));
    }
    values.extend(bot.as_ref().map(|(_, r)| r.as_str()));
    values.extend(api_key.as_deref());
    if !all_different(&values) {
        err!("error: {SECRETS_NOT_DISTINCT}");
        return Err(EXIT_ERROR);
    }
    drop(api_key);
    let bot = bot.map(|(t, _)| t);
    let wa_secrets = wa_secrets.map(|(s, _)| s);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            err!("error: cannot start the async runtime: {e}");
            EXIT_ERROR
        })?;
    // 8. Telegram reachable and the token accepted.
    let tg_api = match (&cfg.telegram, bot) {
        (Some(tg), Some(token)) => {
            let base = tg.api_base.as_deref().unwrap_or(DEFAULT_TELEGRAM_API_BASE);
            let api = TelegramApi::new(token, base).map_err(|e| {
                err!("error: cannot set up the Telegram client: {e}");
                EXIT_ERROR
            })?;
            let me = rt.block_on(api.get_me()).map_err(|e| {
                match e {
                    TelegramError::Api {
                        code: 401 | 404, ..
                    }
                    | TelegramError::Status(401 | 404) => {
                        err!("error: Telegram rejected the bot token")
                    }
                    other => err!("error: cannot reach Telegram ({})", reach_kind(&other)),
                }
                EXIT_ERROR
            })?;
            Some((tg, api, me.username.unwrap_or_default()))
        }
        _ => None,
    };
    // 9-10. WhatsApp: the token sees the number, and the listener is bound.
    let wa_api = match (&cfg.whatsapp, wa_secrets) {
        (Some(wa), Some(secrets)) => {
            let base = wa.api_base.as_deref().unwrap_or(DEFAULT_GRAPH_API_BASE);
            let api = GraphApi::new(secrets.token, base, &wa.graph_version, &wa.phone_number_id)
                .map_err(|e| {
                    err!("error: cannot set up the WhatsApp client: {e}");
                    EXIT_ERROR
                })?;
            let phone = rt.block_on(api.phone_number()).map_err(|e| {
                err!("error: {}", phone_lookup_error(&e, &wa.phone_number_id));
                EXIT_ERROR
            })?;
            let listener = rt.block_on(WebhookListener::bind(wa.listen)).map_err(|e| {
                if e.kind() == std::io::ErrorKind::AddrInUse {
                    err!("error: {} is already in use", wa.listen);
                } else {
                    err!("error: cannot listen on {} ({})", wa.listen, e.kind());
                }
                EXIT_ERROR
            })?;
            let addr: SocketAddr = listener.local_addr().map_err(|e| {
                err!("error: cannot listen on {} ({})", wa.listen, e.kind());
                EXIT_ERROR
            })?;
            let lcfg = ListenerConfig::new(
                secrets.app_secret,
                secrets.verify_token,
                wa.phone_number_id.clone(),
            );
            Some((wa, api, phone.display_phone_number, listener, lcfg, addr))
        }
        _ => None,
    };

    // 11. State.
    let mut owners: Vec<SenderId> = Vec::new();
    if let Some(tg) = &cfg.telegram {
        owners.extend(tg.owner_ids.iter().map(|&id| telegram::sender_id(id)));
    }
    if let Some(wa) = &cfg.whatsapp {
        owners.extend(wa.owner_numbers.iter().map(|n| whatsapp::sender_id(n)));
    }
    let remote_owners = owners.len();
    if console {
        owners.push(SenderId(STDIO_OWNER.to_string()));
    }
    let parts = open_parts(home, prepared, owners)?;
    let offsets = if tg_api.is_some() {
        Some(OffsetStore::open(home).map_err(|e| {
            err!(
                "error: cannot open the Telegram update offset in {}: {e}; make {OFFSET_FILE} a regular file with mode 0600, or remove it while Warden is stopped (removing {OFFSET_FILE} may replay messages newer than max_message_age_secs)",
                shown(home)
            );
            EXIT_ERROR
        })?)
    } else {
        None
    };
    let seen = if wa_api.is_some() {
        Some(SeenStore::open(home).map_err(|e| {
            err!(
                "error: cannot open the WhatsApp seen-message list in {}: {e}; make {SEEN_FILE} a regular file with mode 0600, or remove it while Warden is stopped (removing it may act on a redelivered message newer than max_message_age_secs)",
                shown(home)
            );
            EXIT_ERROR
        })?)
    } else {
        None
    };

    let slot = FatalSlot::default();
    // The sender lives for the whole run: a dropped sender would mean
    // "never shut down" to the engine, the channels and the listener.
    let (tx, rx) = watch::channel(false);
    let mut banner = String::from("warden daemon:");
    let telegram = match (tg_api, offsets) {
        (Some((tg, api, username)), Some((offsets, start_offset))) => {
            banner.push_str(&format!(" telegram @{}", sanitize_for_display(&username)));
            let opts = TelegramOptions {
                allow_pin_approvals: tg.allow_pin_approvals,
                max_message_age: Duration::from_secs(tg.max_message_age_secs),
                ..TelegramOptions::default()
            };
            Some(Watched {
                inner: TelegramChannel::new(api, tg.owner_ids.clone(), offsets, start_offset, opts)
                    .with_shutdown(rx.clone()),
                slot: slot.clone(),
            })
        }
        _ => None,
    };
    let (whatsapp, wa_run) = match (wa_api, seen) {
        (Some((wa, api, display, listener, lcfg, addr)), Some(seen)) => {
            banner.push_str(&format!(
                " whatsapp {} listen={addr}",
                banner_field(&display)
            ));
            let (batch_tx, batch_rx) = mpsc::channel(WEBHOOK_QUEUE);
            let opts = WhatsAppOptions {
                max_message_age: Duration::from_secs(wa.max_message_age_secs),
                ..WhatsAppOptions::default()
            };
            let channel = WhatsAppChannel::new(api, batch_rx, wa.owner_numbers.clone(), seen, opts)
                .with_shutdown(rx.clone());
            let stats = Arc::new(WebhookStats::default());
            let counters = Counters {
                stats: Arc::clone(&stats),
                window_drops: channel.window_drops(),
                dropped: channel.dropped_counter(),
                unread_at_stop: channel.unread_at_stop_counter(),
            };
            let task: ListenerTask = Box::pin(listener.serve(lcfg, batch_tx, stats, rx.clone()));
            (
                Some(Watched {
                    inner: channel,
                    slot: slot.clone(),
                }),
                Some((task, counters)),
            )
        }
        _ => (None, None),
    };
    banner.push_str(&format!(
        " owners={remote_owners} root={}",
        shown(&prepared.root)
    ));
    let code = rt.block_on(async {
        let stdio = console.then(|| {
            StdioChannel::new(
                tokio::io::BufReader::new(tokio::io::stdin()),
                tokio::io::stdout(),
            )
        });
        let channel = Pair::new(Pair::new(telegram, whatsapp), stdio);
        run(planner, parts, channel, &slot, (tx, rx), &banner, wa_run).await
    });
    // Every engine task has been awaited. Do not wait on a stdin reader
    // thread (`--console`) that might still be blocked.
    rt.shutdown_timeout(Duration::from_secs(1));
    Ok(code)
}

/// Step 12 and the session: run until the channels close, a signal asks
/// for shutdown or a channel fails fatally. `shutdown` is the signal the
/// engine, the channels and the webhook listener observe; `whatsapp` is the
/// listener to start once the session has begun, and its counters. A fatal
/// channel error sets `shutdown` at once, which also closes the webhook
/// listener, so Meta stops being answered 200 for new batches. Batches
/// already answered 200 but still queued are drained when the engine has
/// stopped, before the timed final flush: their ids are recorded as seen,
/// and each owner with texts in them is told to send them again (counted as
/// unread at stop). The listener alone holds
/// the batch queue's sender (moved into its serving future), so its end is
/// what the WhatsApp channel sees as the queue closing.
async fn run<P: Planner, C: Channel>(
    planner: P,
    parts: Parts,
    channel: C,
    slot: &FatalSlot,
    shutdown: (watch::Sender<bool>, watch::Receiver<bool>),
    banner: &str,
    whatsapp: Option<(ListenerTask, Counters)>,
) -> u8 {
    let Parts {
        cfg,
        audit,
        approvals,
        executor,
        home,
        snapshots,
        config,
    } = parts;
    let (tx, rx) = shutdown;
    let engine = Engine::try_new(
        cfg,
        planner,
        channel,
        SharedAudit(Arc::clone(&audit)),
        approvals,
        executor,
        home,
        &[snapshots, config],
    );
    let mut engine = match engine {
        Ok(e) => e.with_shutdown(rx),
        Err(e) => {
            err!("error: {}", sanitize_for_display(&e.to_string()));
            return EXIT_ERROR;
        }
    };
    let signals =
        signal(SignalKind::interrupt()).and_then(|i| Ok((i, signal(SignalKind::terminate())?)));
    let (mut sigint, mut sigterm) = match signals {
        Ok(s) => s,
        Err(e) => {
            err!("error: cannot install the signal handlers: {e}");
            return EXIT_ERROR;
        }
    };
    if let Err(e) = session_entry(&audit, DAEMON_SESSION, "daemon session started") {
        err!("error: cannot append to audit log: {e}");
        return EXIT_ERROR;
    }
    let (listener, counters) = match whatsapp {
        Some((task, counters)) => (Some(tokio::spawn(task)), Some(counters)),
        None => (None, None),
    };
    err!("{banner}");

    {
        // `run` is polled to completion, never cancelled: shutdown goes
        // through the watch, so a running step finishes and is audited.
        let run = engine.run();
        tokio::pin!(run);
        let mut signalled = false;
        let on_signal = |signalled: &mut bool| {
            if *signalled {
                err!("still shutting down");
            } else {
                *signalled = true;
                tx.send_replace(true);
                err!("shutting down after the current step");
            }
        };
        loop {
            tokio::select! {
                () = &mut run => break,
                Some(()) = sigint.recv() => on_signal(&mut signalled),
                Some(()) = sigterm.recv() => on_signal(&mut signalled),
                () = slot.notify.notified() => {
                    // A fatal channel error: stop, and treat any later
                    // signal as a repeat.
                    signalled = true;
                    tx.send_replace(true);
                }
            }
        }
    }
    // Requests from here on get the short shutdown timeout, and the
    // listener closes its socket.
    tx.send_replace(true);
    if let Some(mut h) = listener {
        if tokio::time::timeout(LISTENER_STOP, &mut h).await.is_err() {
            h.abort();
        }
    }
    // Messages still queued are not acted on (delivery is at most once).
    // First, unbounded by time but synchronous, the WhatsApp batches
    // answered 200 and still queued are ingested (ids recorded as seen),
    // counted, and their owners' notices queued, so the timed flush below
    // cannot skip them. A seen-list failure here is a fatal (exit 1).
    engine.channel_mut().drain_at_stop();
    // Then deletions still owed (replies that may hold the PIN) and
    // notices, best effort and bounded; the channels flush side by side.
    let _ = tokio::time::timeout(FINAL_FLUSH, engine.channel_mut().flush_pending()).await;

    if let Err(e) = session_entry(&audit, DAEMON_SESSION, "daemon session ended") {
        err!("warning: could not record the session end in the audit log: {e}");
    }
    if let Some(c) = counters {
        let line = counters_line(
            &c.stats.snapshot(),
            ChannelCounts {
                window_drops: c.window_drops.load(Ordering::Relaxed),
                dropped: c.dropped.load(Ordering::Relaxed),
                unread_at_stop: c.unread_at_stop.load(Ordering::Relaxed),
            },
        );
        if let Some(line) = line {
            err!("{line}");
        }
    }
    match slot.get() {
        Some(f) => {
            err!("error: {f}");
            EXIT_ERROR
        }
        None => EXIT_OK,
    }
}

/// A condition that ends one of the daemon's channels, and the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelFatal {
    Telegram(TelegramFatal),
    WhatsApp(WhatsAppFatal),
}

impl fmt::Display for ChannelFatal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChannelFatal::Telegram(t) => t.fmt(f),
            ChannelFatal::WhatsApp(w) => w.fmt(f),
        }
    }
}

/// A channel that can fail fatally, as [`Watched`] observes it.
trait FatalSource {
    /// Why the channel stopped, if it did.
    fn fatal(&self) -> Option<ChannelFatal>;
}

impl FatalSource for TelegramChannel {
    fn fatal(&self) -> Option<ChannelFatal> {
        TelegramChannel::fatal(self).map(ChannelFatal::Telegram)
    }
}

impl FatalSource for WhatsAppChannel {
    fn fatal(&self) -> Option<ChannelFatal> {
        WhatsAppChannel::fatal(self).map(ChannelFatal::WhatsApp)
    }
}

/// Where a channel reports a fatal condition, even when it sits inside a
/// [`Pair`] (which has no accessor for its sides). The first one wins.
#[derive(Clone, Default)]
struct FatalSlot {
    fatal: Arc<Mutex<Option<ChannelFatal>>>,
    notify: Arc<Notify>,
}

impl FatalSlot {
    fn get(&self) -> Option<ChannelFatal> {
        self.fatal.lock().ok().and_then(|g| *g)
    }
}

/// A channel that copies its [`FatalSource::fatal`] into a [`FatalSlot`]
/// after every call, and wakes the run loop the first time. Every method
/// delegates; `recv` stays cancel-safe because the copy runs only after the
/// inner call has finished.
struct Watched<C> {
    inner: C,
    slot: FatalSlot,
}

impl<C: FatalSource> Watched<C> {
    fn note(&self) {
        let Some(f) = self.inner.fatal() else {
            return;
        };
        if let Ok(mut g) = self.slot.fatal.lock() {
            if g.is_none() {
                *g = Some(f);
                self.slot.notify.notify_one();
            }
        }
    }
}

impl<C: Channel + FatalSource + Send> Channel for Watched<C> {
    async fn recv(&mut self) -> Option<Inbound> {
        let m = self.inner.recv().await;
        self.note();
        m
    }

    async fn send(&mut self, to: &SenderId, text: &str) {
        self.inner.send(to, text).await;
        self.note();
    }

    async fn ask_approval(&mut self, to: &SenderId, prompt: &ApprovalPrompt) -> ApprovalReply {
        let r = self.inner.ask_approval(to, prompt).await;
        self.note();
        r
    }

    async fn discard_pending_input(&mut self, to: &SenderId) -> usize {
        let n = self.inner.discard_pending_input(to).await;
        self.note();
        n
    }

    fn accepts_pin(&self, to: &SenderId) -> bool {
        self.inner.accepts_pin(to)
    }

    async fn retract_last(&mut self, to: &SenderId) {
        self.inner.retract_last(to).await;
        self.note();
    }

    async fn flush_pending(&mut self) {
        self.inner.flush_pending().await;
        self.note();
    }

    fn drain_at_stop(&mut self) {
        self.inner.drain_at_stop();
        self.note();
    }

    fn serves(&self, who: &SenderId) -> bool {
        self.inner.serves(who)
    }
}

/// Which service manager [`cmd_print_service`] writes for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceFormat {
    /// A launchd agent plist (macOS).
    Launchd,
    /// A systemd user unit (Linux).
    Systemd,
}

/// `warden daemon print-service`: print a service file that runs `warden
/// --home <home> daemon [--config <path>]` with absolute paths (the
/// canonical binary, the absolute data dir, the canonical config).
///
/// The config is loaded only to read the secret env names: `api_key_env`,
/// `[telegram] bot_token_env` and the three `[whatsapp]` `*_env` names
/// (those of the tables present). Their values are never read, and the file
/// holds `REPLACE_ME` in their place. Nothing is written or created, not even the
/// data dir. A path containing a control character or any of
/// `" \ % $ ' & < >` or a backtick is refused (exit 1), so plain quoting is
/// enough in both formats: no XML entity, systemd specifier, variable or
/// shell expansion can appear.
pub fn cmd_print_service(home: &Path, config: Option<PathBuf>, format: ServiceFormat) -> u8 {
    match service_file(home, config, format) {
        Ok(text) => {
            let _ = std::io::stdout().write_all(text.as_bytes());
            EXIT_OK
        }
        Err(code) => code,
    }
}

fn service_file(home: &Path, config: Option<PathBuf>, format: ServiceFormat) -> Result<String, u8> {
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|e| {
            err!("error: cannot find the warden binary: {e}");
            EXIT_ERROR
        })?;
    let exe = service_path("the warden binary", &exe)?;
    let home_s = service_path("the data dir", home)?;
    let explicit = config.is_some();
    let (cfg, config_path) = startup::load_config(home, config)?;
    if cfg.telegram.is_none() && cfg.whatsapp.is_none() {
        err!("error: no channel configured: add a [telegram] or [whatsapp] table");
        return Err(EXIT_ERROR);
    }
    let config_s = if explicit {
        Some(service_path("the config", &config_path)?)
    } else {
        None
    };
    let env = service_env_names(&cfg);
    Ok(match format {
        ServiceFormat::Launchd => launchd_plist(&exe, &home_s, config_s.as_deref(), &env),
        ServiceFormat::Systemd => systemd_unit(&exe, &home_s, config_s.as_deref(), &env),
    })
}

/// The secret env names a service file needs, in order: `api_key_env`, then
/// `[telegram] bot_token_env`, then the `[whatsapp]` access token, app
/// secret and verify token names, each table only if present.
fn service_env_names(cfg: &Config) -> Vec<&str> {
    let mut env = vec![cfg.api_key_env.as_str()];
    if let Some(tg) = &cfg.telegram {
        env.push(tg.bot_token_env.as_str());
    }
    if let Some(wa) = &cfg.whatsapp {
        env.extend([
            wa.access_token_env.as_str(),
            wa.app_secret_env.as_str(),
            wa.verify_token_env.as_str(),
        ]);
    }
    env
}

/// `p` as UTF-8 if it can go into a service file between plain quotes.
fn service_path(what: &str, p: &Path) -> Result<String, u8> {
    const REFUSED: &[char] = &['"', '\\', '%', '$', '\'', '&', '<', '>', '`'];
    match p.to_str() {
        Some(s) if !s.chars().any(|c| c.is_control() || REFUSED.contains(&c)) => Ok(s.to_string()),
        _ => {
            err!(
                "error: path not supported in a service file: {what} {}; use a path without quotes, backslashes, %, $, &, <, >, backticks or control characters",
                shown(p)
            );
            Err(EXIT_ERROR)
        }
    }
}

/// The launchd agent plist. Paths and names were checked by
/// [`service_path`] and the config loader, so none needs XML escaping.
fn launchd_plist(exe: &str, home: &str, config: Option<&str>, env: &[&str]) -> String {
    let mut args = vec![exe, "--home", home, "daemon"];
    if let Some(c) = config {
        args.extend(["--config", c]);
    }
    let args: String = args
        .iter()
        .map(|a| format!("        <string>{a}</string>\n"))
        .collect();
    let vars: String = env
        .iter()
        .map(|n| format!("        <key>{n}</key>\n        <string>{PLACEHOLDER}</string>\n"))
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!--
  Warden daemon, launchd agent.

  This file will hold secrets: replace each {PLACEHOLDER} below with the
  API key and the channel secrets, then make it readable only by you:
    chmod 600 ~/Library/LaunchAgents/{LAUNCHD_LABEL}.plist
  Load it with:
    launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/{LAUNCHD_LABEL}.plist
  launchd restarts the daemon only after a failed exit, at most once a minute.
-->
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
{args}    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>60</integer>
    <key>ExitTimeOut</key>
    <integer>60</integer>
    <key>StandardErrorPath</key>
    <string>{home}/daemon.log</string>
    <key>EnvironmentVariables</key>
    <dict>
{vars}    </dict>
</dict>
</plist>
"#
    )
}

/// The systemd user unit. Paths were checked by [`service_path`], so plain
/// double quotes are enough.
fn systemd_unit(exe: &str, home: &str, config: Option<&str>, env: &[&str]) -> String {
    let config = config
        .map(|c| format!(" --config \"{c}\""))
        .unwrap_or_default();
    let lines: String = env
        .iter()
        .map(|n| format!("#   {n}={PLACEHOLDER}\n"))
        .collect();
    format!(
        r#"# Warden daemon, systemd user unit.
#
# Save as ~/.config/systemd/user/warden.service. The secrets go in a
# separate file readable only by you:
#   mkdir -p ~/.config/warden
#   install -m 600 /dev/null ~/.config/warden/daemon.env
# then put these lines in it, with the real values:
{lines}# Start it with:
#   systemctl --user daemon-reload
#   systemctl --user enable --now warden.service
# systemd restarts the daemon only after a failed exit, after 60 s.

[Unit]
Description=Warden agent daemon

[Service]
Type=simple
ExecStart="{exe}" --home "{home}" daemon{config}
EnvironmentFile=%h/.config/warden/daemon.env
Restart=on-failure
RestartSec=60
TimeoutStopSec=60
KillSignal=SIGTERM
NoNewPrivileges=yes
UMask=0077

[Install]
WantedBy=default.target
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use warden_agent::whatsapp::{WaEvent, WebhookBatch};

    #[test]
    fn channel_fatal_display_is_the_inner_text() {
        for t in [
            TelegramFatal::TokenRejected,
            TelegramFatal::Conflict,
            TelegramFatal::OffsetUnwritable,
        ] {
            assert_eq!(ChannelFatal::Telegram(t).to_string(), t.to_string());
        }
        for w in [
            WhatsAppFatal::TokenRejected,
            WhatsAppFatal::SeenUnwritable,
            WhatsAppFatal::ListenerStopped,
        ] {
            assert_eq!(ChannelFatal::WhatsApp(w).to_string(), w.to_string());
        }
    }

    #[test]
    fn counters_line_only_when_something_was_refused_or_dropped() {
        let zero = StatsSnapshot::default();
        let counts = |window_drops, dropped| ChannelCounts {
            window_drops,
            dropped,
            unread_at_stop: 0,
        };
        assert_eq!(counters_line(&zero, counts(0, 0)), None);
        // The unread-at-stop count alone makes the line print.
        assert_eq!(
            counters_line(
                &zero,
                ChannelCounts {
                    unread_at_stop: 3,
                    ..counts(0, 1)
                }
            )
            .unwrap(),
            "whatsapp: refused 0 unsigned, 0 bad-signature, 0 oversized, 0 slow webhook requests; 0 replies not sent outside the 24 h window; other: 1 queue-dropped, 3 unread at stop"
        );
        assert_eq!(
            counters_line(
                &zero,
                ChannelCounts {
                    unread_at_stop: 2,
                    ..counts(0, 0)
                }
            )
            .unwrap(),
            "whatsapp: refused 0 unsigned, 0 bad-signature, 0 oversized, 0 slow webhook requests; 0 replies not sent outside the 24 h window; other: 2 unread at stop"
        );
        assert_eq!(
            counters_line(&zero, counts(0, 1)).unwrap(),
            "whatsapp: refused 0 unsigned, 0 bad-signature, 0 oversized, 0 slow webhook requests; 0 replies not sent outside the 24 h window; other: 1 queue-dropped"
        );
        assert_eq!(
            counters_line(&zero, counts(2, 0)).unwrap(),
            "whatsapp: refused 0 unsigned, 0 bad-signature, 0 oversized, 0 slow webhook requests; 2 replies not sent outside the 24 h window"
        );
        let s = StatsSnapshot {
            unsigned: 1,
            bad_signature: 2,
            too_large: 3,
            timed_out: 4,
            busy: 5,
            truncated: 7,
            ..StatsSnapshot::default()
        };
        assert_eq!(
            counters_line(&s, counts(0, 0)).unwrap(),
            "whatsapp: refused 1 unsigned, 2 bad-signature, 3 oversized, 4 slow webhook requests; 0 replies not sent outside the 24 h window; other: 7 truncated, 5 busy"
        );
    }

    #[test]
    fn banner_field_is_one_capped_line() {
        assert_eq!(banner_field("+1 555-010-0000"), "+1 555-010-0000");
        let forged = banner_field("+1\nerror: forged\tline\u{1b}[2J");
        assert!(!forged.contains('\n') && !forged.contains('\t'), "{forged}");
        assert!(!forged.contains('\u{1b}'), "{forged}");
        assert!(forged.contains("\\u{a}"), "{forged}");
        let long = banner_field(&"9".repeat(500));
        assert_eq!(long.chars().count(), BANNER_FIELD_MAX);
        assert!(long.ends_with('…'));
    }

    /// A WhatsApp channel whose seen list cannot be written (a directory
    /// sits where the file goes), with one owner text already waiting.
    async fn unwritable_whatsapp(home: &Path) -> (mpsc::Sender<WebhookBatch>, WhatsAppChannel) {
        let api = GraphApi::new(
            AccessToken::new("EAAGtestTOKEN0123456789abcdefghijDONOTLEAK".into()).unwrap(),
            "http://127.0.0.1:9",
            "v26.0",
            "123456789012345",
        )
        .unwrap();
        let seen = SeenStore::open(home).unwrap();
        std::fs::create_dir(home.join(SEEN_FILE)).unwrap();
        let (tx, rx) = mpsc::channel(4);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        tx.send(WebhookBatch {
            events: vec![WaEvent::Text {
                wamid: "wamid.late".into(),
                from: "15551234567".into(),
                timestamp_s: i64::try_from(now).unwrap(),
                body: "late".into(),
                reply_to: None,
            }],
        })
        .await
        .unwrap();
        let ch = WhatsAppChannel::new(
            api,
            rx,
            vec!["15551234567".into()],
            seen,
            WhatsAppOptions::default(),
        );
        (tx, ch)
    }

    /// Follow-up F1: a seen-list write failure during the stop-time drain
    /// reaches the fatal slot, so the daemon prints it and exits 1.
    #[tokio::test]
    async fn watched_drain_at_stop_records_a_late_fatal() {
        let home = tempfile::tempdir().unwrap();
        let (_tx, ch) = unwritable_whatsapp(home.path()).await;
        let slot = FatalSlot::default();
        let mut w = Pair::new(
            None::<StdioChannel<tokio::io::Empty, tokio::io::Sink>>,
            Some(Watched {
                inner: ch,
                slot: slot.clone(),
            }),
        );
        w.drain_at_stop();
        assert_eq!(
            slot.get(),
            Some(ChannelFatal::WhatsApp(WhatsAppFatal::SeenUnwritable))
        );
        assert_eq!(
            slot.get().unwrap().to_string(),
            "cannot save the WhatsApp seen-message list"
        );
    }

    /// Follow-up F1: `flush_pending` records a late fatal too (its own
    /// drain finds the same failure when `drain_at_stop` did not run).
    #[tokio::test]
    async fn watched_flush_pending_records_a_late_fatal() {
        let home = tempfile::tempdir().unwrap();
        let (_tx, ch) = unwritable_whatsapp(home.path()).await;
        let slot = FatalSlot::default();
        let mut w = Watched {
            inner: ch,
            slot: slot.clone(),
        };
        w.flush_pending().await;
        assert_eq!(
            slot.get(),
            Some(ChannelFatal::WhatsApp(WhatsAppFatal::SeenUnwritable))
        );
    }

    #[test]
    fn secrets_must_all_differ() {
        assert!(all_different(&[]));
        assert!(all_different(&["a", "b", "c"]));
        assert!(!all_different(&["a", "b", "a"]));
        assert!(!all_different(&["a", "b", "c", "b"]));
    }
}
