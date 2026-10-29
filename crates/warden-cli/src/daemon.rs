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
//! unwritable) also stops the engine, even with `--console`. Once shutdown
//! has started, every Telegram request gets at most 5 s and no 429 retry,
//! so the last messages fit a service manager's 60 s stop timeout.
//! Afterwards: one best-effort flush of the deletions still owed (replies
//! that may hold the PIN), bounded to 10 s; messages still queued are
//! dropped (delivery is at most once); then audit `daemon session ended`
//! (best effort) and exit 1 if Telegram failed fatally, else 0.
//!
//! The approver store lock is held for the daemon's lifetime; the audit log
//! only while a message is handled, so `warden undo` works while it idles.
//! stderr never carries message text, tokens or keys, and no logger is
//! installed (reqwest could log the token-bearing URL).
//!
//! `warden daemon print-service` ([`cmd_print_service`]) prints a launchd
//! plist or a systemd user unit for the daemon. It reads the config only for
//! the two environment variable names, writes nothing, and puts
//! `REPLACE_ME` where the secrets go.

use std::fmt;
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
    TelegramOptions, OFFSET_FILE,
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
            "error: cannot open the Telegram update offset in {}: {e}; make {OFFSET_FILE} a regular file with mode 0600, or remove it while Warden is stopped (removing {OFFSET_FILE} may replay messages newer than max_message_age_secs)",
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
    // The sender lives for the whole run: a dropped sender would mean
    // "never shut down" to the engine and the channel.
    let (tx, rx) = watch::channel(false);
    let telegram = Watched {
        inner: TelegramChannel::new(api, tg.owner_ids.clone(), offsets, start_offset, opts)
            .with_shutdown(rx.clone()),
        slot: slot.clone(),
    };
    let banner = format!(
        "warden daemon: telegram @{} owners={} root={}",
        sanitize_for_display(me.username.as_deref().unwrap_or_default()),
        tg.owner_ids.len(),
        shown(&prepared.root)
    );
    let code = rt.block_on(async {
        let stdio = console.then(|| {
            StdioChannel::new(
                tokio::io::BufReader::new(tokio::io::stdin()),
                tokio::io::stdout(),
            )
        });
        let channel = Pair::new(Some(telegram), stdio);
        run(planner, parts, channel, &slot, (tx, rx), &banner).await
    });
    // Every engine task has been awaited. Do not wait on a stdin reader
    // thread (`--console`) that might still be blocked.
    rt.shutdown_timeout(Duration::from_secs(1));
    Ok(code)
}

/// Step 9 and the session: run until the channel closes, a signal asks for
/// shutdown or Telegram fails fatally. `shutdown` is the signal the engine
/// and the Telegram channel observe.
async fn run<P: Planner, C: Channel>(
    planner: P,
    parts: Parts,
    channel: C,
    slot: &FatalSlot,
    shutdown: (watch::Sender<bool>, watch::Receiver<bool>),
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
    // Requests from here on get the short shutdown timeout.
    tx.send_replace(true);
    // Deletions still owed (replies that may hold the PIN), best effort and
    // bounded. Messages still queued are dropped (delivery is at most once).
    let _ = tokio::time::timeout(FINAL_FLUSH, engine.channel_mut().flush_pending()).await;

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

/// A condition that ends one of the daemon's channels, and the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelFatal {
    Telegram(TelegramFatal),
}

impl fmt::Display for ChannelFatal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChannelFatal::Telegram(t) => t.fmt(f),
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
/// The config is loaded only to read `api_key_env` and `[telegram]
/// bot_token_env`; their values are never read, and the file holds
/// `REPLACE_ME` in their place. Nothing is written or created, not even the
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
    let Some(tg) = cfg.telegram else {
        err!("error: no channel configured: add a [telegram] table");
        return Err(EXIT_ERROR);
    };
    let config_s = if explicit {
        Some(service_path("the config", &config_path)?)
    } else {
        None
    };
    let env = [cfg.api_key_env.as_str(), tg.bot_token_env.as_str()];
    Ok(match format {
        ServiceFormat::Launchd => launchd_plist(&exe, &home_s, config_s.as_deref(), env),
        ServiceFormat::Systemd => systemd_unit(&exe, &home_s, config_s.as_deref(), env),
    })
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
fn launchd_plist(exe: &str, home: &str, config: Option<&str>, env: [&str; 2]) -> String {
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

  This file will hold secrets: replace each {PLACEHOLDER} below with the API
  key and the Telegram bot token, then make it readable only by you:
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
fn systemd_unit(exe: &str, home: &str, config: Option<&str>, env: [&str; 2]) -> String {
    let config = config
        .map(|c| format!(" --config \"{c}\""))
        .unwrap_or_default();
    let [key, token] = env;
    format!(
        r#"# Warden daemon, systemd user unit.
#
# Save as ~/.config/systemd/user/warden.service. The secrets go in a
# separate file readable only by you:
#   mkdir -p ~/.config/warden
#   install -m 600 /dev/null ~/.config/warden/daemon.env
# then put these two lines in it, with the real values:
#   {key}={PLACEHOLDER}
#   {token}={PLACEHOLDER}
# Start it with:
#   systemctl --user daemon-reload
#   systemctl --user enable --now warden.service
# systemd restarts the daemon only after a failed exit, after 60 s.

[Unit]
Description=Warden agent daemon (Telegram)

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
