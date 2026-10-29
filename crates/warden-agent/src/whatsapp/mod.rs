//! The WhatsApp Cloud API channel and its building blocks: a Graph API
//! client over reqwest ([`api`]) for outbound text.
//!
//! Inbound messages arrive by webhook only, on a loopback-only listener
//! that the owner exposes with their own tunnel; Warden never opens a
//! public port. Outbound text goes to the Graph API. The access token, app
//! secret and verify token come from the environment and never appear in
//! `Debug`, errors or logs.

pub mod api;

pub use api::{AccessToken, ErrorClass, GraphApi, PhoneInfo, WhatsAppError};
