//! Command-line definitions (clap derive).

use clap::{Parser, Subcommand, ValueEnum};
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "warden",
    version,
    about = "Warden safety core: classify, run, undo, audit"
)]
pub struct Cli {
    /// Data directory (audit log, snapshots, PIN). Default: ~/.warden
    #[arg(long, global = true, value_name = "DIR")]
    pub home: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

/// What kind of action to classify or run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Kind {
    /// Read a path (classify-only)
    Read,
    /// Write <path> <content> (executed)
    Write,
    /// Delete <path> (executed)
    Delete,
    /// Message a person (classify-only)
    Message,
    /// Send an email (classify-only)
    Email,
    /// Install software (classify-only)
    Install,
    /// Format a disk (classify-only, always Blocked)
    FormatDisk,
    /// Edit the registry (classify-only, always Blocked)
    Registry,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Read => "read",
            Kind::Write => "write",
            Kind::Delete => "delete",
            Kind::Message => "message",
            Kind::Email => "email",
            Kind::Install => "install",
            Kind::FormatDisk => "format-disk",
            Kind::Registry => "registry",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print the tier (Auto, Yes, YesPin, Blocked) an action needs.
    Classify {
        /// Allowed root directory for the policy.
        #[arg(long, value_name = "DIR")]
        root: PathBuf,
        kind: Kind,
        args: Vec<OsString>,
    },
    /// Classify an action, check approval, snapshot, then perform it.
    ///
    /// Prefer the WARDEN_PIN environment variable over --pin: command-line
    /// arguments are visible to other users in process lists.
    Run {
        /// Allowed root directory; write/delete outside it are refused.
        #[arg(long, value_name = "DIR")]
        root: PathBuf,
        /// Approve a Yes or YesPin action.
        #[arg(long)]
        yes: bool,
        /// PIN for a YesPin action (visible in process lists; prefer WARDEN_PIN).
        #[arg(long, value_name = "PIN")]
        pin: Option<String>,
        kind: Kind,
        args: Vec<OsString>,
    },
    /// Restore the files recorded in a snapshot.
    ///
    /// Restore can overwrite and delete files, so undo is a YesPin action:
    /// it needs --yes and the PIN (prefer WARDEN_PIN over --pin).
    Undo {
        snapshot_id: String,
        /// The root the snapshot was taken under.
        #[arg(long, value_name = "DIR")]
        root: PathBuf,
        /// Approve the restore.
        #[arg(long)]
        yes: bool,
        /// PIN (visible in process lists; prefer WARDEN_PIN).
        #[arg(long, value_name = "PIN")]
        pin: Option<String>,
        /// Restore even if files changed since the action.
        #[arg(long)]
        force: bool,
    },
    /// Audit log commands.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Delete snapshots older than --days.
    Prune {
        #[arg(long, default_value_t = 30)]
        days: u64,
    },
    /// Set the PIN for YesPin actions (from the argument or WARDEN_PIN).
    InitPin {
        pin: Option<String>,
        /// Replace an existing PIN.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Check the hash chain: prints `ok <n>` or `broken <index>: <reason>`.
    Verify,
}
