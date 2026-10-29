//! The WhatsApp Cloud API channel and its building blocks: a Graph API
//! client over reqwest ([`api`]) for outbound text, webhook signature and
//! handshake checks plus the payload parser ([`webhook`]), and the persisted
//! set of message ids already taken ([`seen`]).
//!
//! Inbound messages arrive by webhook only, on a loopback-only listener
//! that the owner exposes with their own tunnel; Warden never opens a
//! public port. Outbound text goes to the Graph API. The access token, app
//! secret and verify token come from the environment and never appear in
//! `Debug`, errors or logs.

pub mod api;
pub mod seen;
pub mod webhook;

pub use api::{AccessToken, ErrorClass, GraphApi, PhoneInfo, WhatsAppError};
pub use seen::{SeenStore, MAX_SEEN, SEEN_FILE};
pub use webhook::{
    check_signature, handshake, parse_notification, AppSecret, Notification, NotificationError,
    RefuseReason, SignatureCheck, VerifyToken, WaEvent, WebhookBatch, MAX_EVENTS,
};
