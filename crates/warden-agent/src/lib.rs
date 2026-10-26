//! Warden agent engine.
//!
//! Unix-only for now: the approver store (`authorize`) relies on Unix file
//! modes, `O_NOFOLLOW`/`O_NONBLOCK` and advisory `flock` locking, and its
//! home directory must be on a local filesystem.
#![forbid(unsafe_code)]

#[cfg(not(unix))]
compile_error!("warden-agent requires a Unix platform for now");

pub mod authorize;
pub mod redact;
pub mod tools;
