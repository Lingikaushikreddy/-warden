//! The WhatsApp Cloud API channel and its building blocks: webhook
//! signature and handshake checks plus the payload parser ([`webhook`]),
//! and the persisted set of message ids already taken ([`seen`]).
//!
//! Inbound is by webhook only, on a loopback listener the owner exposes
//! with their own tunnel; outbound goes to the Graph API. Secrets come from
//! the environment and never appear in `Debug`, errors or logs.

pub mod seen;
pub mod webhook;

pub use seen::{SeenStore, MAX_SEEN, SEEN_FILE};
pub use webhook::{
    check_signature, handshake, parse_notification, AppSecret, Notification, NotificationError,
    RefuseReason, SignatureCheck, VerifyToken, WaEvent, WebhookBatch, MAX_EVENTS,
};
