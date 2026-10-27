//! `warden agent`: the agent engine on stdin/stdout.
//!
//! Startup fails closed: every step below that fails prints a message to
//! stderr and exits 1 before anything is executed. Steps 1-4 have no side
//! effects beyond creating the data dir, so a bad config, root or missing
//! key leaves no audit log, approver key or snapshot store behind.
//!
//! 1. create the data dir (0700); refuse it if it is a symlink, not owned by
//!    the current user, or writable by group or others;
//! 2. load the config (`<home>/config.toml` or `--config`); refuse an owner
//!    other than `local` (the stdio channel's only sender);
//! 3. resolve `root`: it must exist, be a directory, not be `/`, and not be
//!    `$HOME` or an ancestor of it unless `--allow-home-root` (an unset or
//!    unresolvable `HOME` also needs the flag);
//! 4. build the planner (Anthropic: the key from the environment variable
//!    named by `api_key_env`, never from the file);
//! 5. open the audit log (a broken or locked log is refused);
//! 6. open the approver store and the snapshot store, build the executor
//!    with the data dir and the snapshot dir protected (the snapshot dir is
//!    inside the data dir; protecting it too is defense in depth);
//! 7. `Engine::try_new` (refuses unprotected state dirs inside the root);
//! 8. audit `agent session started`, run until stdin closes, audit `agent
//!    session ended` (best effort), exit 0.
//!
//! Secrets policy: the API key, the config file's contents and environment
//! values are never printed or audited. Errors name fields, paths and
//! conventional variable names only.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;
use rand::RngCore;
use warden_agent::authorize::ApproverStore;
use warden_agent::channel::{sanitize_for_display, SenderId, StdioChannel};
use warden_agent::config::{Config, Provider, DEFAULT_API_KEY_ENV};
use warden_agent::engine::{AuditSink, Engine, EngineConfig};
use warden_agent::exec::Executor;
use warden_agent::planner::Planner;
use warden_core::{AuditLog, SnapshotStore, Tier};

use crate::commands::{ensure_home, open_audit};
use crate::{EXIT_ERROR, EXIT_OK};

/// Default Anthropic API base URL.
const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
/// Audit action id of the session start/end entries.
const SESSION_ID: &str = "session";
/// The only sender the stdio channel produces.
const STDIO_OWNER: &str = "local";

macro_rules! err {
    ($($t:tt)*) => {{
        let _ = writeln!(std::io::stderr(), $($t)*);
    }};
}

/// Paths in messages, display-sanitized.
fn shown(p: &Path) -> String {
    sanitize_for_display(&p.display().to_string())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// The audit log shared by the engine and the session entries.
struct SharedAudit(Arc<Mutex<AuditLog>>);

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
        log.append(action_id, summary, tier, decision).map(drop)
    }
}

/// Everything the engine needs except the planner.
struct Parts {
    cfg: EngineConfig,
    audit: Arc<Mutex<AuditLog>>,
    approvals: ApproverStore,
    executor: Executor,
    home: PathBuf,
    snapshots: PathBuf,
}

pub fn cmd_agent(home: &Path, config: Option<PathBuf>, allow_home_root: bool) -> u8 {
    match start(home, config, allow_home_root) {
        Ok(code) | Err(code) => code,
    }
}

/// A variable name safe to show: the default always; otherwise a
/// conventional `^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$` name of at most 40
/// characters that the redactor leaves unchanged, with no `_`-separated
/// segment longer than 16 characters and at most 6 digits in the whole
/// name (a per-segment cap alone would let `A_4111_1111_1111_1111` through).
/// Anything else might carry data pasted into `api_key_env` (a card number,
/// a token) and is not shown.
fn showable_env_name(name: &str) -> bool {
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

/// Step 1: the data dir exists, is a real directory (not a symlink), is
/// owned by the current user and is not writable by group or others.
fn check_home(home: &Path) -> Result<(), u8> {
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

fn start(home: &Path, config: Option<PathBuf>, allow_home_root: bool) -> Result<u8, u8> {
    // 1. Data dir.
    check_home(home)?;

    // 2. Config.
    let config_path = config.unwrap_or_else(|| home.join("config.toml"));
    let cfg = Config::load(&config_path).map_err(|e| {
        err!("error: {}", sanitize_for_display(&e.to_string()));
        EXIT_ERROR
    })?;
    if cfg.owner != STDIO_OWNER {
        err!("error: the stdio channel only supports owner = \"local\"; remove `owner` from the config");
        return Err(EXIT_ERROR);
    }

    // 3. Root.
    let root = resolve_root(&cfg.root, allow_home_root)?;

    // 4. Planner (no files touched), then 5-8.
    match &cfg.provider {
        Provider::Anthropic => {
            let key = match std::env::var(&cfg.api_key_env) {
                Ok(k) if !k.is_empty() => k,
                _ => {
                    if showable_env_name(&cfg.api_key_env) {
                        err!(
                            "error: environment variable {} is not set or is empty; put your Anthropic API key in it",
                            cfg.api_key_env
                        );
                    } else {
                        err!("error: the configured API key environment variable is not set or is empty");
                    }
                    return Err(EXIT_ERROR);
                }
            };
            let base = cfg
                .base_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
            let planner =
                warden_agent::anthropic::AnthropicPlanner::new(key, cfg.model.clone(), base)
                    .map_err(|e| {
                        err!("error: cannot set up the planner: {e}");
                        EXIT_ERROR
                    })?;
            run(planner, open_parts(home, &cfg, root)?)
        }
        #[cfg(feature = "test-hooks")]
        Provider::Mock { script } => {
            let planner =
                warden_agent::planner::MockPlanner::from_script_file(script).map_err(|e| {
                    err!("error: cannot load the planner script: {e}");
                    EXIT_ERROR
                })?;
            run(planner, open_parts(home, &cfg, root)?)
        }
    }
}

/// Steps 5-6: the audit log first (a broken log stops everything), then the
/// approver store, the snapshot store and the executor.
fn open_parts(home: &Path, cfg: &Config, root: PathBuf) -> Result<Parts, u8> {
    let audit = Arc::new(Mutex::new(open_audit(home)?));
    let approvals = ApproverStore::open(home, now_ms()).map_err(|e| {
        err!(
            "error: cannot open the approver store in {}: {e}",
            shown(home)
        );
        EXIT_ERROR
    })?;
    let snapshots = home.join("snapshots");
    let store = SnapshotStore::open(&snapshots).map_err(|e| {
        err!("error: cannot open the snapshot store: {e}");
        EXIT_ERROR
    })?;
    let executor = Executor::new(&root, vec![home.to_path_buf(), snapshots.clone()], store)
        .map_err(|e| {
            err!(
                "error: cannot set up the executor for root {}: {e}",
                shown(&root)
            );
            EXIT_ERROR
        })?;
    // Relative tool paths resolve against the (canonical) root, never the
    // process's working directory, and the system prompt names the root.
    let cwd = root.clone();
    Ok(Parts {
        cfg: EngineConfig::new(SenderId(cfg.owner.clone()), root, cwd),
        audit,
        approvals,
        executor,
        home: home.to_path_buf(),
        snapshots,
    })
}

/// Canonical root, refusing a non-directory, `/`, and `$HOME` or any
/// ancestor of it unless allowed. An unset or unresolvable `HOME` cannot be
/// checked, so it also needs the flag.
fn resolve_root(root: &Path, allow_home_root: bool) -> Result<PathBuf, u8> {
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

fn run<P: Planner>(planner: P, parts: Parts) -> Result<u8, u8> {
    let Parts {
        cfg,
        audit,
        approvals,
        executor,
        home,
        snapshots,
    } = parts;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            err!("error: cannot start the async runtime: {e}");
            EXIT_ERROR
        })?;
    let banner = format!(
        "warden agent: owner={} root={}",
        sanitize_for_display(&cfg.owner.0),
        shown(&cfg.root)
    );
    let session = |decision: &str| -> io::Result<()> {
        SharedAudit(Arc::clone(&audit)).append(SESSION_ID, "agent session", Tier::Auto, decision)
    };
    let code = rt.block_on(async {
        let channel = StdioChannel::new(
            tokio::io::BufReader::new(tokio::io::stdin()),
            tokio::io::stdout(),
        );
        let mut engine = match Engine::try_new(
            cfg,
            planner,
            channel,
            SharedAudit(Arc::clone(&audit)),
            approvals,
            executor,
            home,
            &[snapshots],
        ) {
            Ok(e) => e,
            Err(e) => {
                err!("error: {}", sanitize_for_display(&e.to_string()));
                return EXIT_ERROR;
            }
        };
        if let Err(e) = session("agent session started") {
            err!("error: cannot append to audit log: {e}");
            return EXIT_ERROR;
        }
        err!("{banner}");
        engine.run().await;
        if let Err(e) = session("agent session ended") {
            err!("warning: could not record the session end in the audit log: {e}");
        }
        EXIT_OK
    });
    // Nothing is left running: every engine task is awaited. Do not wait on
    // a stdin reader thread that might still be blocked.
    rt.shutdown_timeout(Duration::from_secs(1));
    Ok(code)
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
