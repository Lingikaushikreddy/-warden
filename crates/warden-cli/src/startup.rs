//! Startup shared by `warden agent` and `warden daemon`.
//!
//! Every step fails closed: it prints a message to stderr and returns exit
//! code 1 before anything is executed. Steps 1-3 and the planner key have
//! no side effects beyond creating the data dir, so a bad config, root or
//! missing key leaves no audit log, approver key or snapshot store behind.
//!
//! - steps 1-3, which each command calls in its own order (the daemon takes
//!   its lock between the first two): the data dir ([`check_home`]), the
//!   config ([`load_config`]) and the root ([`resolve_root`]), giving a
//!   [`Prepared`];
//! - [`api_key`] / [`anthropic_planner`]: the planner (Anthropic: the key
//!   from the environment variable named by `api_key_env`, never from the
//!   file);
//! - [`open_parts`]: the audit log (a broken or locked log is refused; from
//!   then on it is leased, see [`LeasedAuditLog`]), the approver store (with
//!   a warning when the clock is behind its high-water mark), the snapshot
//!   store and the executor, with the data dir, the snapshot dir and the
//!   config file protected (the snapshot dir is inside the data dir;
//!   protecting it too is defense in depth). The config file is protected
//!   wherever it lives, so even a `--config` inside the root can never be
//!   read, rewritten or deleted by a tool: the agent cannot change its own
//!   root or provider. Only the file is protected, not its directory, so a
//!   config at the top of the root does not lock the whole root.
//!
//! Secrets policy: the API key, the bot token, the config file's contents
//! and environment values are never printed or audited. Errors name fields,
//! paths and conventional variable names only.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;
use rand::RngCore;
use warden_agent::anthropic::AnthropicPlanner;
use warden_agent::authorize::ApproverStore;
use warden_agent::channel::{sanitize_for_display, SenderId};
use warden_agent::config::{Config, DEFAULT_API_KEY_ENV};
use warden_agent::engine::{AuditSink, EngineConfig};
use warden_agent::exec::Executor;
use warden_agent::lease::LeasedAuditLog;
use warden_core::{SnapshotStore, Tier};

use crate::commands::{audit_open_failed, ensure_home};
use crate::EXIT_ERROR;

/// Default Anthropic API base URL.
const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
/// Audit action id of the session entries.
pub(crate) const SESSION_ID: &str = "session";
/// Audit summary of `warden agent`'s session entries.
pub(crate) const AGENT_SESSION: &str = "agent session";
/// Audit summary of `warden daemon`'s session entries.
pub(crate) const DAEMON_SESSION: &str = "daemon session";
/// Warn (and audit) when the clock is further than this behind the
/// approver store's high-water mark.
const CLOCK_WARN_MS: u64 = 30_000;
/// The only sender the stdio channel produces.
pub(crate) const STDIO_OWNER: &str = "local";

macro_rules! err {
    ($($t:tt)*) => {{
        let _ = writeln!(std::io::stderr(), $($t)*);
    }};
}
pub(crate) use err;

/// Paths in messages, display-sanitized.
pub(crate) fn shown(p: &Path) -> String {
    sanitize_for_display(&p.display().to_string())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// The leased audit log shared by the engine and the session entries.
pub(crate) struct SharedAudit(pub(crate) Arc<Mutex<LeasedAuditLog>>);

impl AuditSink for SharedAudit {
    fn append(
        &mut self,
        action_id: &str,
        summary: &str,
        tier: Tier,
        decision: &str,
    ) -> io::Result<()> {
        let mut log = self
            .0
            .lock()
            .map_err(|_| io::Error::other("audit lock poisoned"))?;
        log.append(action_id, summary, tier, decision)
    }

    fn release(&mut self) {
        if let Ok(mut log) = self.0.lock() {
            log.release();
        }
    }
}

/// Append a session entry (action id `session`, tier `Auto`) to the leased
/// log, then release it whether or not the append worked: outside a
/// message the agent never holds the log.
pub(crate) fn session_entry(
    audit: &Arc<Mutex<LeasedAuditLog>>,
    summary: &str,
    decision: &str,
) -> io::Result<()> {
    let mut shared = SharedAudit(Arc::clone(audit));
    let res = shared.append(SESSION_ID, summary, Tier::Auto, decision);
    shared.release();
    res
}

/// The session summary for an engine serving `owners`: the daemon's when
/// any owner is not the stdio channel's `local`.
fn session_summary(owners: &[SenderId]) -> &'static str {
    if owners.iter().all(|o| o.0 == STDIO_OWNER) {
        AGENT_SESSION
    } else {
        DAEMON_SESSION
    }
}

/// Startup steps 1-3 done: a loaded config and a checked root.
pub(crate) struct Prepared {
    pub(crate) cfg: Config,
    /// The config file, canonical.
    pub(crate) config_path: PathBuf,
    /// The root, canonical and checked ([`resolve_root`]).
    pub(crate) root: PathBuf,
}

/// Everything the engine needs except the planner and the channel.
pub(crate) struct Parts {
    pub(crate) cfg: EngineConfig,
    /// Open (startup check done) until the first session entry releases it.
    pub(crate) audit: Arc<Mutex<LeasedAuditLog>>,
    pub(crate) approvals: ApproverStore,
    pub(crate) executor: Executor,
    pub(crate) home: PathBuf,
    pub(crate) snapshots: PathBuf,
    /// The config file, canonical.
    pub(crate) config: PathBuf,
}

/// A variable name safe to show: the default always; otherwise a
/// conventional `^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$` name of at most 40
/// characters that the redactor leaves unchanged, with no `_`-separated
/// segment longer than 16 characters and at most 6 digits in the whole
/// name (a per-segment cap alone would let `A_4111_1111_1111_1111` through).
/// Anything else might carry data pasted into `api_key_env` (a card number,
/// a token) and is not shown.
pub(crate) fn showable_env_name(name: &str) -> bool {
    if name == DEFAULT_API_KEY_ENV {
        return true;
    }
    let b = name.as_bytes();
    let upper_digit = |c: u8| c.is_ascii_uppercase() || c.is_ascii_digit();
    let segment_ok =
        |part: &str| !part.is_empty() && part.len() <= 16 && part.bytes().all(upper_digit);
    name.len() <= 40
        && b.first().is_some_and(u8::is_ascii_uppercase)
        && name.contains('_')
        && name.split('_').all(segment_ok)
        && name.bytes().filter(u8::is_ascii_digit).count() <= 6
        && warden_agent::redact::redact(name).0.as_str() == name
}

/// The data dir exists, is a real directory (not a symlink), is owned by
/// the current user and is not writable by group or others.
pub(crate) fn check_home(home: &Path) -> Result<(), u8> {
    if let Err(e) = ensure_home(home) {
        err!("error: cannot create data dir {}: {e}", shown(home));
        return Err(EXIT_ERROR);
    }
    let m = match fs::symlink_metadata(home) {
        Ok(m) => m,
        Err(e) => {
            err!("error: cannot inspect data dir {}: {e}", shown(home));
            return Err(EXIT_ERROR);
        }
    };
    if m.file_type().is_symlink() {
        err!(
            "error: data dir {} is a symlink; pass the real directory with --home",
            shown(home)
        );
        return Err(EXIT_ERROR);
    }
    if !m.is_dir() {
        err!("error: data dir {} is not a directory", shown(home));
        return Err(EXIT_ERROR);
    }
    if m.mode() & 0o022 != 0 {
        err!(
            "error: data dir {} is writable by group or others; run `chmod 700` on it",
            shown(home)
        );
        return Err(EXIT_ERROR);
    }
    // Our effective uid, learned without libc: the owner of a file we just
    // created. It is removed right away.
    let probe = home.join(format!(".uid-check-{:016x}", OsRng.next_u64()));
    let my_uid = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&probe)
        .and_then(|f| f.metadata())
        .map(|pm| pm.uid());
    let _ = fs::remove_file(&probe);
    match my_uid {
        Ok(uid) if uid == m.uid() => Ok(()),
        Ok(_) => {
            err!(
                "error: data dir {} is not owned by the current user",
                shown(home)
            );
            Err(EXIT_ERROR)
        }
        Err(e) => {
            err!("error: cannot write in data dir {}: {e}", shown(home));
            Err(EXIT_ERROR)
        }
    }
}

/// Load the config (`<home>/config.toml` or `config`) and resolve its
/// canonical path.
pub(crate) fn load_config(home: &Path, config: Option<PathBuf>) -> Result<(Config, PathBuf), u8> {
    let config_path = config.unwrap_or_else(|| home.join("config.toml"));
    let cfg = Config::load(&config_path).map_err(|e| {
        err!("error: {}", sanitize_for_display(&e.to_string()));
        EXIT_ERROR
    })?;
    // Canonical, so the executor protects the file itself whatever spelling
    // (relative, symlinked parent, `/tmp` vs `/private/tmp`) was given.
    let config_path = fs::canonicalize(&config_path).map_err(|e| {
        err!(
            "error: config {} cannot be resolved: {e}",
            shown(&config_path)
        );
        EXIT_ERROR
    })?;
    Ok((cfg, config_path))
}

/// The Anthropic API key from the variable named by `api_key_env`. A
/// missing or empty variable is named only when [`showable_env_name`].
pub(crate) fn api_key(cfg: &Config) -> Result<String, u8> {
    match std::env::var(&cfg.api_key_env) {
        Ok(k) if !k.is_empty() => Ok(k),
        _ => {
            if showable_env_name(&cfg.api_key_env) {
                err!(
                    "error: environment variable {} is not set or is empty; put your Anthropic API key in it",
                    cfg.api_key_env
                );
            } else {
                err!("error: the configured API key environment variable is not set or is empty");
            }
            Err(EXIT_ERROR)
        }
    }
}

/// The Anthropic planner for `cfg` ([`api_key`]; no files touched).
pub(crate) fn anthropic_planner(cfg: &Config) -> Result<AnthropicPlanner, u8> {
    let key = api_key(cfg)?;
    let base = cfg
        .base_url
        .clone()
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
    AnthropicPlanner::new(key, cfg.model.clone(), base).map_err(|e| {
        err!("error: cannot set up the planner: {e}");
        EXIT_ERROR
    })
}

/// The scripted planner (`provider = "mock"`, test-hooks builds only).
#[cfg(feature = "test-hooks")]
pub(crate) fn mock_planner(script: &Path) -> Result<warden_agent::planner::MockPlanner, u8> {
    warden_agent::planner::MockPlanner::from_script_file(script).map_err(|e| {
        err!("error: cannot load the planner script: {e}");
        EXIT_ERROR
    })
}

/// The audit log first (a broken log stops everything), then the approver
/// store (warning when the clock is behind its high-water mark), the
/// snapshot store and the executor. The engine serves `owners`.
pub(crate) fn open_parts(
    home: &Path,
    prepared: &Prepared,
    owners: Vec<SenderId>,
) -> Result<Parts, u8> {
    let root = prepared.root.clone();
    let config = prepared.config_path.as_path();
    // The data dir exists (step 1). warden-core creates a new log with mode
    // 0o600. Opened now, without waiting, so a broken or locked log stops
    // startup; it stays open until the first session entry.
    let path = home.join("audit.jsonl");
    let mut leased = LeasedAuditLog::new(path.clone());
    leased
        .open_now()
        .map_err(|e| audit_open_failed(&path, &e))?;
    let audit = Arc::new(Mutex::new(leased));
    let approvals = ApproverStore::open(home, now_ms()).map_err(|e| {
        err!(
            "error: cannot open the approver store in {}: {e}",
            shown(home)
        );
        EXIT_ERROR
    })?;
    // The clock went back since the last run: approvals are clamped up to
    // the high-water mark. Say so, and record it.
    let behind_ms = approvals.clock_behind_ms();
    if behind_ms > CLOCK_WARN_MS {
        err!(
            "warning: the system clock is {} s behind the last time Warden ran; approvals use the later time",
            behind_ms / 1000
        );
        SharedAudit(Arc::clone(&audit))
            .append(
                SESSION_ID,
                session_summary(&owners),
                Tier::Auto,
                "clock behind high-water mark",
            )
            .map_err(|e| {
                err!("error: cannot append to audit log: {e}");
                EXIT_ERROR
            })?;
    }
    let snapshots = home.join("snapshots");
    let store = SnapshotStore::open(&snapshots).map_err(|e| {
        err!("error: cannot open the snapshot store: {e}");
        EXIT_ERROR
    })?;
    let protected = vec![home.to_path_buf(), snapshots.clone(), config.to_path_buf()];
    let executor = Executor::new(&root, protected, store).map_err(|e| {
        err!(
            "error: cannot set up the executor for root {}: {e}",
            shown(&root)
        );
        EXIT_ERROR
    })?;
    // Relative tool paths resolve against the (canonical) root, never the
    // process's working directory, and the system prompt names the root.
    let cwd = root.clone();
    let first = owners
        .first()
        .cloned()
        .unwrap_or_else(|| SenderId(prepared.cfg.owner.clone()));
    let mut cfg = EngineConfig::new(first, root, cwd);
    if !owners.is_empty() {
        cfg.owners = owners;
    }
    Ok(Parts {
        cfg,
        audit,
        approvals,
        executor,
        home: home.to_path_buf(),
        snapshots,
        config: config.to_path_buf(),
    })
}

/// Canonical root, refusing a non-directory, `/`, and `$HOME` or any
/// ancestor of it unless allowed. An unset or unresolvable `HOME` cannot be
/// checked, so it also needs the flag.
pub(crate) fn resolve_root(root: &Path, allow_home_root: bool) -> Result<PathBuf, u8> {
    let canon = fs::canonicalize(root).map_err(|e| {
        err!("error: root {} cannot be resolved: {e}", shown(root));
        EXIT_ERROR
    })?;
    if !canon.is_dir() {
        err!("error: root {} is not a directory", shown(&canon));
        return Err(EXIT_ERROR);
    }
    if canon.parent().is_none() {
        err!("error: refusing root `/`: set `root` to the one folder the agent may use");
        return Err(EXIT_ERROR);
    }
    if allow_home_root {
        return Ok(canon);
    }
    let user_home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .and_then(|h| fs::canonicalize(h).ok());
    let Some(user_home) = user_home else {
        err!("error: HOME is not set or does not exist; pass --allow-home-root to continue");
        return Err(EXIT_ERROR);
    };
    if user_home.starts_with(&canon) {
        err!(
            "error: refusing root {}: it is your home directory or contains it; set `root` to a narrower folder (or pass --allow-home-root)",
            shown(&canon)
        );
        return Err(EXIT_ERROR);
    }
    Ok(canon)
}

#[cfg(test)]
mod tests {
    use super::showable_env_name;

    #[test]
    fn env_names_shown_only_when_conventional() {
        for ok in [
            "ANTHROPIC_API_KEY",
            "MY_TEAM_KEY",
            "WARDEN_TEST_KEY_VAR",
            "WARDEN_TELEGRAM_TOKEN",
            "A1_B2",
        ] {
            assert!(showable_env_name(ok), "{ok}");
        }
        for bad in [
            "CARD_4111111111111111",
            "K_123456789012345678901234567890",
            "GHP_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "SK_LIVE_51ABCDEFGHIJKLMNOPQRSTUV",
            "A_4111_1111_1111_1111",
            "NOUNDERSCORE",
            "lower_case",
            "A__B",
        ] {
            assert!(!showable_env_name(bad), "{bad}");
        }
    }
}
