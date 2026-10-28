//! Telegram channel building blocks: a Bot API client over reqwest
//! ([`api`]) and the filter that decides which updates may reach the
//! engine as owner text ([`update`]).
//!
//! Long polling only: Warden opens no inbound port. The bot token comes
//! from the environment and never appears in `Debug`, errors or logs.

pub mod api;
pub mod update;

pub use api::{BotInfo, BotToken, TelegramApi, TelegramError};
pub use update::{classify_update, RefuseReason, Update, UpdateKind};
