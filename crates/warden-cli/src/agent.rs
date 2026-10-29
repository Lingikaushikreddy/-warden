//! `warden agent`: the agent engine on stdin/stdout.
//!
//! Startup fails closed: every step below that fails prints a message to
//! stderr and exits 1 before anything is executed. Steps 1-4 have no side
//! effects beyond creating the data dir, so a bad config, root or missing
//! key leaves no audit log, approver key or snapshot store behind. The
//! shared pieces live in [`crate::startup`] (also used by `warden daemon`):
//! the checks of steps 1-4 and the opening of the stores in steps 5-6.
//!
//! 1. create the data dir (0700); refuse it if it is a symlink, not owned by
//!    the current user, or writable by group or others;
//! 2. load the config (`<home>/config.toml` or `--config`) and resolve its
//!    canonical path; refuse an owner other than `local` (the stdio
//!    channel's only sender);
//! 3. resolve `root`: it must exist, be a directory, not be `/`, and not be
//!    `$HOME` or an ancestor of it unless `--allow-home-root` (an unset or
//!    unresolvable `HOME` also needs the flag);
//! 4. build the planner (Anthropic: the key from the environment variable
//!    named by `api_key_env`, never from the file);
//! 5. open the audit log (a broken or locked log is refused). From here on
//!    it is leased ([`LeasedAuditLog`](warden_agent::lease::LeasedAuditLog)):
//!    held while a message is handled or a session entry is written,
//!    released in between, so `warden undo` and the other writing commands
//!    work while the agent is idle;
//! 6. open the approver store and the snapshot store, build the executor
//!    with the data dir, the snapshot dir and the config file protected
//!    (see [`crate::startup`]);
//! 7. `Engine::try_new` (refuses unprotected state dirs or a config file
//!    inside the root);
//! 8. audit `agent session started`, run until stdin closes, audit `agent
//!    session ended` (best effort), exit 0.
//!
//! Secrets policy: the API key, the config file's contents and environment
//! values are never printed or audited. Errors name fields, paths and
//! conventional variable names only.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use warden_agent::channel::{sanitize_for_display, SenderId, StdioChannel};
use warden_agent::config::Provider;
use warden_agent::engine::Engine;
use warden_agent::planner::Planner;

use crate::startup::{
    self, err, open_parts, session_entry, shown, Parts, Prepared, SharedAudit, AGENT_SESSION,
    STDIO_OWNER,
};
use crate::{EXIT_ERROR, EXIT_OK};

pub fn cmd_agent(home: &Path, config: Option<PathBuf>, allow_home_root: bool) -> u8 {
    match start(home, config, allow_home_root) {
        Ok(code) | Err(code) => code,
    }
}

fn start(home: &Path, config: Option<PathBuf>, allow_home_root: bool) -> Result<u8, u8> {
    // 1. Data dir.
    startup::check_home(home)?;
    // 2. Config; the stdio channel has the single owner `local`.
    let (cfg, config_path) = startup::load_config(home, config)?;
    if cfg.owner != STDIO_OWNER {
        err!("error: the stdio channel only supports owner = \"local\"; remove `owner` from the config");
        return Err(EXIT_ERROR);
    }
    // 3. Root.
    let root = startup::resolve_root(&cfg.root, allow_home_root)?;
    let prepared = Prepared {
        cfg,
        config_path,
        root,
    };
    let owners = vec![SenderId(prepared.cfg.owner.clone())];

    // 4. Planner (no files touched), then 5-8.
    match &prepared.cfg.provider {
        Provider::Anthropic => {
            let planner = startup::anthropic_planner(&prepared.cfg)?;
            run(planner, open_parts(home, &prepared, owners)?)
        }
        #[cfg(feature = "test-hooks")]
        Provider::Mock { script } => {
            let planner = startup::mock_planner(script)?;
            run(planner, open_parts(home, &prepared, owners)?)
        }
    }
}

fn run<P: Planner>(planner: P, parts: Parts) -> Result<u8, u8> {
    let Parts {
        cfg,
        audit,
        approvals,
        executor,
        home,
        snapshots,
        config,
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
        sanitize_for_display(cfg.owners.first().map_or("", |o| o.0.as_str())),
        shown(&cfg.root)
    );
    let session = |decision: &str| session_entry(&audit, AGENT_SESSION, decision);
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
            &[snapshots, config],
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
