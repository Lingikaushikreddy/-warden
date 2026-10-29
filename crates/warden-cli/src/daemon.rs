//! `warden daemon`: the agent engine on Telegram, unattended, in the
//! foreground.
//!
//! Startup fails closed, exit 1, in this order:
//!
//! 1. the data dir ([`startup::check_home`]);
//! 2. `<home>/daemon.lock` (0600, `try_lock`, held for the process's
//!    lifetime): a second daemon on the same home is refused;
//! 3. the config, which must have a `[telegram]` table; with `--console`,
//!    `owner` must be `local`;
//! 4. the root ([`startup::resolve_root`]);
//! 5. the planner key;
//! 6. the bot token from the variable named by `bot_token_env` (named in
//!    errors only under the [`startup::showable_env_name`] rule);
//! 7. `getMe` against the configured Bot API base;
//! 8. [`startup::open_parts`] with owners `tg:<id>` (and `local` with
//!    `--console`), then the update offset store;
//! 9. `Engine::try_new`, with shutdown wired to the signal handler.
//!
//! Steps 1-7 leave no files except the data dir and `daemon.lock`.
//!
//! Then: audit `daemon session started`, print a banner to stderr and run
//! until the channel closes or a signal arrives. The first SIGINT or
//! SIGTERM asks the engine to stop after the current step (a running tool
//! always finishes; a pending prompt is refused); later signals only say so
//! again. A fatal Telegram condition (token rejected, 409 conflict, offset
//! unwritable) also stops the engine, even with `--console`. Afterwards
//! audit `daemon session ended` (best effort) and exit 1 if Telegram failed
//! fatally, else 0.
//!
//! The approver store lock is held for the daemon's lifetime; the audit log
//! only while a message is handled, so `warden undo` works while it idles.
//! stderr never carries message text, tokens or keys, and no logger is
//! installed (reqwest could log the token-bearing URL).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{watch, Notify};
use warden_agent::channel::{
    sanitize_for_display, ApprovalPrompt, ApprovalReply, Channel, Inbound, Pair, SenderId,
    StdioChannel,
};
use warden_agent::config::{Provider, TelegramConfig, DEFAULT_TELEGRAM_API_BASE};
use warden_agent::engine::Engine;
use warden_agent::planner::Planner;
use warden_agent::telegram::{
    sender_id, BotToken, OffsetStore, TelegramApi, TelegramChannel, TelegramError, TelegramFatal,
    TelegramOptions,
};

use crate::startup::{
    self, err, open_parts, session_entry, shown, Parts, Prepared, SharedAudit, DAEMON_SESSION,
    STDIO_OWNER,
};
use crate::{EXIT_ERROR, EXIT_OK};

/// The single-instance lock file under the data dir.
const LOCK_FILE: &str = "daemon.lock";

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
    let Some(tg) = cfg.telegram.clone() else {
        err!("error: no channel configured: add a [telegram] table");
        return Err(EXIT_ERROR);
    };
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
    // 5. Planner (no files touched), then 6-9.
    match &prepared.cfg.provider {
        Provider::Anthropic => {
            let planner = startup::anthropic_planner(&prepared.cfg)?;
            serve(planner, home, &prepared, &tg, console)
        }
        #[cfg(feature = "test-hooks")]
        Provider::Mock { script } => {
            let planner = startup::mock_planner(script)?;
            serve(planner, home, &prepared, &tg, console)
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

/// Step 6: the bot token. A missing or empty variable is named only when
/// [`startup::showable_env_name`] allows it; a value is never shown.
fn bot_token(tg: &TelegramConfig) -> Result<BotToken, u8> {
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
    BotToken::new(raw).map_err(|_| {
        err!("error: the Telegram bot token variable does not hold a valid bot token");
        EXIT_ERROR
    })
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

/// Steps 6-9, then run.
fn serve<P: Planner>(
    planner: P,
    home: &Path,
    prepared: &Prepared,
    tg: &TelegramConfig,
    console: bool,
) -> Result<u8, u8> {
    // 6. Bot token.
    let token = bot_token(tg)?;
    // 7. Telegram reachable and the token accepted.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            err!("error: cannot start the async runtime: {e}");
            EXIT_ERROR
        })?;
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
            | TelegramError::Status(401 | 404) => err!("error: Telegram rejected the bot token"),
            other => err!("error: cannot reach Telegram ({})", reach_kind(&other)),
        }
        EXIT_ERROR
    })?;
    // 8. State.
    let mut owners: Vec<SenderId> = tg.owner_ids.iter().map(|&id| sender_id(id)).collect();
    if console {
        owners.push(SenderId(STDIO_OWNER.to_string()));
    }
    let parts = open_parts(home, prepared, owners)?;
    let (offsets, start_offset) = OffsetStore::open(home).map_err(|e| {
        err!(
            "error: cannot open the Telegram update offset in {}: {e}",
            shown(home)
        );
        EXIT_ERROR
    })?;
    let opts = TelegramOptions {
        allow_pin_approvals: tg.allow_pin_approvals,
        max_message_age: Duration::from_secs(tg.max_message_age_secs),
        ..TelegramOptions::default()
    };
    let slot = FatalSlot::default();
    let telegram = Watched {
        inner: TelegramChannel::new(api, tg.owner_ids.clone(), offsets, start_offset, opts),
        slot: slot.clone(),
    };
    let banner = format!(
        "warden daemon: telegram @{} owners={} root={}",
        sanitize_for_display(me.username.as_deref().unwrap_or_default()),
        tg.owner_ids.len(),
        shown(&prepared.root)
    );
    let code = rt.block_on(async {
        if console {
            let stdio = StdioChannel::new(
                tokio::io::BufReader::new(tokio::io::stdin()),
                tokio::io::stdout(),
            );
            run(planner, parts, Pair::new(telegram, stdio), &slot, &banner).await
        } else {
            run(planner, parts, telegram, &slot, &banner).await
        }
    });
    // Every engine task has been awaited. Do not wait on a stdin reader
    // thread (`--console`) that might still be blocked.
    rt.shutdown_timeout(Duration::from_secs(1));
    Ok(code)
}

/// Step 9 and the session: run until the channel closes, a signal asks for
/// shutdown or Telegram fails fatally.
async fn run<P: Planner, C: Channel>(
    planner: P,
    parts: Parts,
    channel: C,
    slot: &FatalSlot,
    banner: &str,
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
    // The sender lives for the whole run: a dropped sender would mean
    // "never shut down" to the engine.
    let (tx, rx) = watch::channel(false);
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
                    tx.send_replace(true);
                }
            }
        }
    }

    if let Err(e) = session_entry(&audit, DAEMON_SESSION, "daemon session ended") {
        err!("warning: could not record the session end in the audit log: {e}");
    }
    match slot.get() {
        Some(f) => {
            err!("error: {f}");
            EXIT_ERROR
        }
        None => EXIT_OK,
    }
}

/// Where the Telegram channel reports a fatal condition, even when it sits
/// inside a [`Pair`] (which has no accessor for its sides).
#[derive(Clone, Default)]
struct FatalSlot {
    fatal: Arc<Mutex<Option<TelegramFatal>>>,
    notify: Arc<Notify>,
}

impl FatalSlot {
    fn get(&self) -> Option<TelegramFatal> {
        self.fatal.lock().ok().and_then(|g| *g)
    }
}

/// [`TelegramChannel`] that copies [`TelegramChannel::fatal`] into a
/// [`FatalSlot`] after every call, and wakes the run loop the first time.
/// Every method delegates; `recv` stays cancel-safe because the copy runs
/// only after the inner call has finished.
struct Watched {
    inner: TelegramChannel,
    slot: FatalSlot,
}

impl Watched {
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

impl Channel for Watched {
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

    fn serves(&self, who: &SenderId) -> bool {
        self.inner.serves(who)
    }
}
