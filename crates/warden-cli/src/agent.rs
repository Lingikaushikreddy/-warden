//! `warden agent`: the agent engine on stdin/stdout.
//!
//! Startup fails closed: every step below that fails prints one line to
//! stderr and exits 1 before anything is executed.
//!
//! 1. create the data dir (0700) and refuse it if group/other-writable;
//! 2. load the config (`<home>/config.toml` or `--config`);
//! 3. resolve `root`: it must exist, be a directory, not be `/`, and not be
//!    `$HOME` itself unless `--allow-home-root`;
//! 4. open the audit log (a broken or locked log is refused);
//! 5. open the approver store and the snapshot store, build the executor
//!    with the data dir and the snapshot dir protected;
//! 6. build the planner (Anthropic: key from the environment variable named
//!    by `api_key_env`, never from the file);
//! 7. `Engine::try_new` (refuses unprotected state dirs inside the root);
//! 8. audit `agent session started`, run until stdin closes, audit `agent
//!    session ended` (best effort), exit 0.
//!
//! Secrets policy: the API key, the config file's contents and environment
//! values are never printed or audited. Errors name fields, paths and
//! variable names only.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use warden_agent::authorize::ApproverStore;
use warden_agent::channel::{sanitize_for_display, SenderId, StdioChannel};
use warden_agent::config::{Config, Provider};
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

fn start(home: &Path, config: Option<PathBuf>, allow_home_root: bool) -> Result<u8, u8> {
    // 1. Data dir.
    if let Err(e) = ensure_home(home) {
        err!("error: cannot create data dir {}: {e}", shown(home));
        return Err(EXIT_ERROR);
    }
    match fs::metadata(home) {
        Ok(m) if m.is_dir() && m.mode() & 0o022 == 0 => {}
        Ok(m) if m.is_dir() => {
            err!(
                "error: data dir {} is writable by group or others; run `chmod 700` on it",
                shown(home)
            );
            return Err(EXIT_ERROR);
        }
        _ => {
            err!("error: data dir {} is not a directory", shown(home));
            return Err(EXIT_ERROR);
        }
    }

    // 2. Config.
    let config_path = config.unwrap_or_else(|| home.join("config.toml"));
    let cfg = Config::load(&config_path).map_err(|e| {
        err!("error: {}", sanitize_for_display(&e.to_string()));
        EXIT_ERROR
    })?;

    // 3. Root.
    let root = resolve_root(&cfg.root, allow_home_root)?;

    // 4. Audit log (fail closed; same helper as `run`/`undo`).
    let audit = Arc::new(Mutex::new(open_audit(home)?));

    // 5. Approver store, snapshots, executor.
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

    let cwd = std::env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(|e| {
            err!("error: cannot resolve the current directory: {e}");
            EXIT_ERROR
        })?;
    let parts = Parts {
        cfg: EngineConfig::new(SenderId(cfg.owner.clone()), root, cwd),
        audit,
        approvals,
        executor,
        home: home.to_path_buf(),
        snapshots,
    };

    // 6. Planner, then 7-8.
    match &cfg.provider {
        Provider::Anthropic => {
            let key = match std::env::var(&cfg.api_key_env) {
                Ok(k) if !k.is_empty() => k,
                _ => {
                    err!(
                        "error: environment variable {} is not set or is empty; put your Anthropic API key in it",
                        cfg.api_key_env
                    );
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
            run(planner, parts)
        }
        #[cfg(feature = "test-hooks")]
        Provider::Mock { script } => {
            let planner =
                warden_agent::planner::MockPlanner::from_script_file(script).map_err(|e| {
                    err!("error: cannot load the planner script: {e}");
                    EXIT_ERROR
                })?;
            run(planner, parts)
        }
    }
}

/// Canonical root, refusing `/`, a non-directory, and `$HOME` itself
/// unless allowed.
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
    let user_home = std::env::var_os("HOME").and_then(|h| fs::canonicalize(h).ok());
    if !allow_home_root && user_home.as_deref() == Some(canon.as_path()) {
        err!(
            "error: refusing root {}: it is your home directory; set `root` to a narrower folder (or pass --allow-home-root)",
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
