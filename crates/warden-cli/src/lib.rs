#![forbid(unsafe_code)]
//! Library behind the `warden` binary; `main.rs` only parses and maps the
//! returned code to an exit status.
//!
//! Exit codes: 0 ok, 1 error or broken audit log, 2 approval missing or bad
//! (or arguments invalid by policy), 3 blocked.

pub mod cli;
pub mod commands;
pub mod pin;

pub use cli::Cli;

pub const EXIT_OK: u8 = 0;
pub const EXIT_ERROR: u8 = 1;
pub const EXIT_DENIED: u8 = 2;
pub const EXIT_BLOCKED: u8 = 3;

/// Run a parsed command line and return its exit code.
pub fn run(cli: Cli) -> u8 {
    commands::dispatch(cli)
}
