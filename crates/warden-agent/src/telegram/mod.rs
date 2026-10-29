//! The Telegram channel ([`channel`]) and its building blocks: a Bot API
//! client over reqwest ([`api`]), the filter that decides which updates may
//! reach the engine as owner text ([`update`]), and the persisted update
//! offset ([`offset`]).
//!
//! Long polling only: Warden opens no inbound port. The bot token comes
//! from the environment and never appears in `Debug`, errors or logs.

pub mod api;
pub mod channel;
pub mod offset;
pub mod update;

pub use api::{BotInfo, BotToken, TelegramApi, TelegramError};
pub use channel::{sender_id, TelegramChannel, TelegramFatal, TelegramOptions};
pub use offset::OffsetStore;
pub use update::{classify_update, RefuseReason, Update, UpdateKind};
