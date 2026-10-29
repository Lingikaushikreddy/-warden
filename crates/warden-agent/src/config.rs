//! The `warden agent` config file (TOML).
//!
//! ```toml
//! root = "/Users/me/Documents/warden-folder"   # required, absolute
//! owner = "local"                # default; the stdio channel's sender id
//! provider = "anthropic"         # default; the only provider
//! model = "claude-sonnet-5-5"    # default
//! # base_url = "https://api.anthropic.com"   # default when unset
//! api_key_env = "ANTHROPIC_API_KEY"         # default
//!
//! [telegram]                     # optional; enables the Telegram channel
//! owner_ids = [123456789]        # required, 1-8 numeric Telegram user ids
//! bot_token_env = "WARDEN_TELEGRAM_TOKEN"   # default
//! allow_pin_approvals = false    # default
//! max_message_age_secs = 120     # default, 10-3600
//! # api_base = "https://api.telegram.org"   # default when unset
//!
//! [whatsapp]                     # optional; enables the WhatsApp channel
//! owner_numbers = ["+15551234567"]   # required, 1-8 E.164 numbers
//! phone_number_id = "106540352242922" # required, the Cloud API sender id
//! access_token_env = "WARDEN_WHATSAPP_TOKEN"            # default
//! app_secret_env = "WARDEN_WHATSAPP_APP_SECRET"         # default
//! verify_token_env = "WARDEN_WHATSAPP_VERIFY_TOKEN"     # default
//! listen = "127.0.0.1:8097"      # default; loopback only
//! max_message_age_secs = 120     # default, 10-3600
//! graph_version = "v26.0"        # default
//! # api_base = "https://graph.facebook.com" # default when unset
//! ```
//!
//! Rules (all fail closed):
//!
//! - **No secrets in the file.** A key named `api_key`, `apikey`, `key`,
//!   `token`, `secret`, `password`, `bot_token`, `telegram_token`,
//!   `telegram_bot_token`, `access_token`, `app_secret`, `verify_token` or
//!   `whatsapp_token` (any case, `-` or `_` ignored, at any depth) is
//!   refused: the API key comes from the environment variable named by
//!   `api_key_env`, the Telegram bot token from the one named by
//!   `[telegram] bot_token_env`, and the WhatsApp secrets from the ones
//!   named by `[whatsapp] access_token_env`, `app_secret_env` and
//!   `verify_token_env`, never from the file.
//! - **Secret variables are distinct.** `api_key_env`, `[telegram]
//!   bot_token_env` and the three `[whatsapp]` `*_env` names must all name
//!   different environment variables.
//! - **No values in errors.** [`ConfigError`] names fields, lines and the
//!   file path, never a value from the file (a TOML parse error reports its
//!   line only, because toml's own message quotes the source).
//! - **`root` is required** and must be absolute; there is no default, so
//!   the agent never falls back to `$HOME` or `/`.
//! - Unknown fields are refused. The only nested tables are `[telegram]`
//!   and `[whatsapp]`; any other is refused. Top-level fields are strings.
//! - **`[whatsapp] listen` is loopback only** (`127.0.0.0/8` or `::1`, as
//!   an IP and port: no host names). Warden never opens a public port; the
//!   owner exposes it through their own tunnel.
//! - The file must be a regular file (symlinks are followed; it is opened
//!   with `O_NONBLOCK` and checked through the handle, so a FIFO is refused
//!   instead of hanging) that is not writable by group or others, and at
//!   most 64 KiB.
//! - `owner` must be `[A-Za-z0-9._@:-]{1,64}` and must not look like a
//!   secret to the redactor.

use std::fmt;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::redact::redact;

/// Default sender id: the stdio channel's.
pub const DEFAULT_OWNER: &str = "local";
/// Default model id.
pub const DEFAULT_MODEL: &str = "claude-sonnet-5-5";
/// Default environment variable holding the Anthropic API key.
pub const DEFAULT_API_KEY_ENV: &str = "ANTHROPIC_API_KEY";
/// Default environment variable holding the Telegram bot token.
pub const DEFAULT_TELEGRAM_TOKEN_ENV: &str = "WARDEN_TELEGRAM_TOKEN";
/// Default Telegram Bot API base URL.
pub const DEFAULT_TELEGRAM_API_BASE: &str = "https://api.telegram.org";
/// Default environment variable holding the WhatsApp Cloud API access token.
pub const DEFAULT_WHATSAPP_TOKEN_ENV: &str = "WARDEN_WHATSAPP_TOKEN";
/// Default environment variable holding the Meta app secret (webhook HMAC key).
pub const DEFAULT_WHATSAPP_APP_SECRET_ENV: &str = "WARDEN_WHATSAPP_APP_SECRET";
/// Default environment variable holding the webhook verify token.
pub const DEFAULT_WHATSAPP_VERIFY_TOKEN_ENV: &str = "WARDEN_WHATSAPP_VERIFY_TOKEN";
/// Default `[whatsapp] listen`: loopback only.
pub const DEFAULT_WHATSAPP_LISTEN: &str = "127.0.0.1:8097";
/// Default Graph API version. Must be bumped as Meta retires versions.
pub const DEFAULT_GRAPH_VERSION: &str = "v26.0";
/// Default Graph API base URL.
pub const DEFAULT_GRAPH_API_BASE: &str = "https://graph.facebook.com";
/// Default `[telegram]` and `[whatsapp]` `max_message_age_secs`.
const DEFAULT_MAX_MESSAGE_AGE_SECS: u64 = 120;
/// Most `[telegram] owner_ids`, and most `[whatsapp] owner_numbers`.
const MAX_OWNER_IDS: usize = 8;
/// Longest `[whatsapp] phone_number_id`, in digits.
const MAX_PHONE_NUMBER_ID_DIGITS: usize = 32;
/// Largest owner id accepted (2^52; Telegram user ids fit in 52 bits).
const MAX_OWNER_ID: i64 = 1 << 52;
/// Largest config file accepted, in bytes.
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
/// Key names (lowercased, `-` and `_` removed) that would hold a secret.
const SECRET_KEYS: [&str; 12] = [
    "apikey",
    "key",
    "token",
    "secret",
    "password",
    "bottoken",
    "telegramtoken",
    "telegrambottoken",
    "accesstoken",
    "appsecret",
    "verifytoken",
    "whatsapptoken",
];

/// Which planner the agent talks to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provider {
    /// The Anthropic Messages API.
    Anthropic,
    /// A scripted planner read from a JSON file. Exists only in builds with
    /// the `test-hooks` feature; elsewhere `provider = "mock"` is an
    /// unknown provider.
    #[cfg(feature = "test-hooks")]
    Mock { script: PathBuf },
}

/// A loaded, validated config. Holds no secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub owner: String,
    pub root: PathBuf,
    pub provider: Provider,
    pub model: String,
    /// `None` means the provider's default (`https://api.anthropic.com`).
    pub base_url: Option<String>,
    /// Name of the environment variable holding the API key.
    pub api_key_env: String,
    /// The `[telegram]` table; `None` when absent.
    pub telegram: Option<TelegramConfig>,
    /// The `[whatsapp]` table; `None` when absent.
    pub whatsapp: Option<WhatsAppConfig>,
}

/// The `[telegram]` table. Holds no secrets: the bot token is read from the
/// environment variable named by `bot_token_env`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramConfig {
    /// Allowlisted Telegram user ids (1-8, each in `1..=2^52`).
    pub owner_ids: Vec<i64>,
    /// Name of the environment variable holding the bot token.
    pub bot_token_env: String,
    /// Whether PIN-tier approvals may be given over Telegram. Default off.
    pub allow_pin_approvals: bool,
    /// Messages older than this (by Telegram's `date`) are never acted on.
    pub max_message_age_secs: u64,
    /// `None` means [`DEFAULT_TELEGRAM_API_BASE`].
    pub api_base: Option<String>,
}

/// The `[whatsapp]` table. Holds no secrets: the access token, app secret
/// and verify token are read from the environment variables it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhatsAppConfig {
    /// Allowlisted owner numbers (1-8), digits only (E.164 without `+`).
    pub owner_numbers: Vec<String>,
    /// The Cloud API phone number id that sends and receives (1-32 digits).
    pub phone_number_id: String,
    /// Name of the environment variable holding the access token.
    pub access_token_env: String,
    /// Name of the environment variable holding the app secret.
    pub app_secret_env: String,
    /// Name of the environment variable holding the webhook verify token.
    pub verify_token_env: String,
    /// Webhook listener address; always a loopback IP.
    pub listen: std::net::SocketAddr,
    /// Messages older than this (by WhatsApp's `timestamp`) are never acted on.
    pub max_message_age_secs: u64,
    /// Graph API version path segment, `v<major>.<minor>`.
    pub graph_version: String,
    /// `None` means [`DEFAULT_GRAPH_API_BASE`].
    pub api_base: Option<String>,
}

/// Why a config could not be loaded. `Display` never contains a value from
/// the file.
#[derive(Debug)]
pub enum ConfigError {
    /// The file does not exist.
    NotFound(PathBuf),
    /// The file could not be opened or read.
    Io(PathBuf, io::ErrorKind),
    /// Not a regular file.
    NotAFile(PathBuf),
    /// Larger than 64 KiB.
    TooLarge(PathBuf),
    /// Writable by group or others.
    Insecure(PathBuf),
    /// Not valid TOML (1-based line, if known).
    Syntax(Option<usize>),
    /// A field whose name suggests a secret (the sanitized field name).
    SecretInFile(String),
    /// A field this version does not know (the sanitized field name).
    UnknownField(String),
    /// A known field with a value of the wrong type (strings only).
    WrongType(&'static str),
    /// A known non-string field with a value of the wrong type: the field
    /// and what it must be (`"an integer"`, `"a boolean"`, ...).
    WrongKind(&'static str, &'static str),
    /// A known field with an invalid value, and why.
    Invalid(&'static str, &'static str),
    /// `root` is missing.
    MissingRoot,
    /// `provider` names no supported provider.
    UnknownProvider,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::NotFound(p) => write!(
                f,
                "config file {} not found; create it with at least `root = \"/absolute/path\"`",
                p.display()
            ),
            ConfigError::Io(p, k) => write!(f, "cannot read config file {}: {k}", p.display()),
            ConfigError::NotAFile(p) => {
                write!(f, "config file {} is not a regular file", p.display())
            }
            ConfigError::TooLarge(p) => {
                write!(f, "config file {} is larger than 64 KiB", p.display())
            }
            ConfigError::Insecure(p) => write!(
                f,
                "config file {} is writable by group or others; run `chmod go-w` on it",
                p.display()
            ),
            ConfigError::Syntax(Some(line)) => {
                write!(f, "config file is not valid TOML (line {line})")
            }
            ConfigError::Syntax(None) => write!(f, "config file is not valid TOML"),
            ConfigError::SecretInFile(k) => write!(
                f,
                "config field `{k}` looks like a secret; secrets must not be stored in the \
                 config file: remove it and put the API key in the environment variable named \
                 by `api_key_env` (default {DEFAULT_API_KEY_ENV}), the Telegram bot token in \
                 the one named by `[telegram] bot_token_env` (default \
                 {DEFAULT_TELEGRAM_TOKEN_ENV}), or the WhatsApp secrets in the ones named by \
                 `[whatsapp] access_token_env`, `app_secret_env` and `verify_token_env` \
                 (defaults {DEFAULT_WHATSAPP_TOKEN_ENV}, {DEFAULT_WHATSAPP_APP_SECRET_ENV}, \
                 {DEFAULT_WHATSAPP_VERIFY_TOKEN_ENV})"
            ),
            ConfigError::UnknownField(k) => write!(f, "unknown field `{k}` in config file"),
            ConfigError::WrongType(k) => write!(f, "config field `{k}` must be a string"),
            ConfigError::WrongKind(k, kind) => write!(f, "config field `{k}` must be {kind}"),
            ConfigError::Invalid(k, why) => write!(f, "config field `{k}` {why}"),
            ConfigError::MissingRoot => write!(
                f,
                "config field `root` is required (the one folder the agent may use); \
                 there is no default"
            ),
            ConfigError::UnknownProvider => {
                write!(f, "unknown provider in config (supported: anthropic)")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// The file's fields, all optional here; requirements are checked after.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    owner: Option<String>,
    root: Option<PathBuf>,
    provider: Option<String>,
    model: Option<String>,
    base_url: Option<String>,
    api_key_env: Option<String>,
    #[cfg(feature = "test-hooks")]
    script: Option<PathBuf>,
}

/// Every field `Raw` accepts, in this build.
fn known_fields() -> Vec<&'static str> {
    #[allow(unused_mut)]
    let mut v = vec![
        "owner",
        "root",
        "provider",
        "model",
        "base_url",
        "api_key_env",
    ];
    #[cfg(feature = "test-hooks")]
    v.push("script");
    v
}

/// Every field the `[telegram]` table accepts, as `telegram.<name>`.
const TELEGRAM_FIELDS: [(&str, &str); 5] = [
    ("owner_ids", "telegram.owner_ids"),
    ("bot_token_env", "telegram.bot_token_env"),
    ("allow_pin_approvals", "telegram.allow_pin_approvals"),
    ("max_message_age_secs", "telegram.max_message_age_secs"),
    ("api_base", "telegram.api_base"),
];

/// Every field the `[whatsapp]` table accepts.
const WHATSAPP_FIELDS: [&str; 9] = [
    "owner_numbers",
    "phone_number_id",
    "access_token_env",
    "app_secret_env",
    "verify_token_env",
    "listen",
    "max_message_age_secs",
    "graph_version",
    "api_base",
];

/// A key name safe to show: `[A-Za-z0-9_-]`, at most 64 characters.
fn shown_key(k: &str) -> String {
    let ok = !k.is_empty()
        && k.len() <= 64
        && k.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok {
        k.to_string()
    } else {
        "<unprintable>".to_string()
    }
}

fn is_secret_key(k: &str) -> bool {
    let n: String = k
        .chars()
        .filter(|c| *c != '-' && *c != '_')
        .flat_map(char::to_lowercase)
        .collect();
    SECRET_KEYS.contains(&n.as_str())
}

/// The first secret-looking key at any depth.
fn find_secret_key(t: &toml::Table) -> Option<String> {
    for (k, v) in t {
        if is_secret_key(k) {
            return Some(shown_key(k));
        }
        let nested = match v {
            toml::Value::Table(inner) => find_secret_key(inner),
            toml::Value::Array(items) => items.iter().find_map(|i| match i {
                toml::Value::Table(inner) => find_secret_key(inner),
                _ => None,
            }),
            _ => None,
        };
        if nested.is_some() {
            return nested;
        }
    }
    None
}

/// A portable environment variable name: `[A-Za-z_][A-Za-z0-9_]{0,63}`.
fn valid_env_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

/// `valid_env_name` and left unchanged by the redactor. `field` names the
/// field in the error.
fn check_env_name(field: &'static str, s: &str) -> Result<(), ConfigError> {
    if !valid_env_name(s) {
        return Err(ConfigError::Invalid(
            field,
            "must be an environment variable NAME ([A-Za-z_][A-Za-z0-9_]*), not a key",
        ));
    }
    if redact(s).0.as_str() != s {
        return Err(ConfigError::Invalid(
            field,
            "looks like a secret; it must name the environment variable that holds the key",
        ));
    }
    Ok(())
}

/// Parse the `[telegram]` table. Secret-looking keys were refused before.
/// `api_key_env` is the effective planner key variable, which the bot token
/// variable must differ from.
fn telegram(t: &toml::Table, api_key_env: &str) -> Result<TelegramConfig, ConfigError> {
    for k in t.keys() {
        if !TELEGRAM_FIELDS.iter().any(|(f, _)| f == k) {
            return Err(ConfigError::UnknownField(format!(
                "telegram.{}",
                shown_key(k)
            )));
        }
    }
    const IDS: &str = "telegram.owner_ids";
    const ENV: &str = "telegram.bot_token_env";
    const PIN: &str = "telegram.allow_pin_approvals";
    const AGE: &str = "telegram.max_message_age_secs";
    const BASE: &str = "telegram.api_base";

    let owner_ids = match t.get("owner_ids") {
        None => {
            return Err(ConfigError::Invalid(
                IDS,
                "is required: the numeric Telegram user ids allowed to use the bot",
            ))
        }
        Some(toml::Value::Array(items)) => items
            .iter()
            .map(|i| {
                i.as_integer()
                    .ok_or(ConfigError::WrongKind(IDS, "a list of integers"))
            })
            .collect::<Result<Vec<i64>, ConfigError>>()?,
        Some(_) => return Err(ConfigError::WrongKind(IDS, "a list of integers")),
    };
    if owner_ids.is_empty() || owner_ids.len() > MAX_OWNER_IDS {
        return Err(ConfigError::Invalid(IDS, "must list 1 to 8 user ids"));
    }
    if owner_ids.iter().any(|id| !(1..=MAX_OWNER_ID).contains(id)) {
        return Err(ConfigError::Invalid(
            IDS,
            "must hold positive Telegram user ids (at most 2^52)",
        ));
    }

    let bot_token_env = match t.get("bot_token_env") {
        None => DEFAULT_TELEGRAM_TOKEN_ENV.to_string(),
        Some(toml::Value::String(s)) => s.clone(),
        Some(_) => return Err(ConfigError::WrongType(ENV)),
    };
    check_env_name(ENV, &bot_token_env)?;
    // The bot token goes into a URL path sent to the Telegram API; the same
    // variable would send the planner's API key there.
    if bot_token_env == api_key_env {
        return Err(ConfigError::Invalid(
            ENV,
            "must name a different environment variable than `api_key_env`",
        ));
    }

    let allow_pin_approvals = match t.get("allow_pin_approvals") {
        None => false,
        Some(toml::Value::Boolean(b)) => *b,
        Some(_) => return Err(ConfigError::WrongKind(PIN, "a boolean")),
    };

    let max_message_age_secs = match t.get("max_message_age_secs") {
        None => DEFAULT_MAX_MESSAGE_AGE_SECS,
        Some(toml::Value::Integer(n)) => match u64::try_from(*n) {
            Ok(n) if (10..=3600).contains(&n) => n,
            _ => {
                return Err(ConfigError::Invalid(
                    AGE,
                    "must be between 10 and 3600 seconds",
                ))
            }
        },
        Some(_) => return Err(ConfigError::WrongKind(AGE, "an integer")),
    };

    let api_base = match t.get("api_base") {
        None => None,
        Some(toml::Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(ConfigError::WrongType(BASE)),
    };

    Ok(TelegramConfig {
        owner_ids,
        bot_token_env,
        allow_pin_approvals,
        max_message_age_secs,
        api_base,
    })
}

/// The error for an env name that repeats `other`, a field already taken.
fn same_env_as(field: &'static str, other: &'static str) -> ConfigError {
    let why = match other {
        "api_key_env" => "must name a different environment variable than `api_key_env`",
        "telegram.bot_token_env" => {
            "must name a different environment variable than `telegram.bot_token_env`"
        }
        "whatsapp.access_token_env" => {
            "must name a different environment variable than `whatsapp.access_token_env`"
        }
        "whatsapp.app_secret_env" => {
            "must name a different environment variable than `whatsapp.app_secret_env`"
        }
        _ => "must name a different environment variable than the other secret variables",
    };
    ConfigError::Invalid(field, why)
}

/// One `[whatsapp]` `*_env` field: default, string, variable name, and
/// different from every name in `taken`, which it then joins.
fn whatsapp_env(
    t: &toml::Table,
    key: &str,
    field: &'static str,
    default: &str,
    taken: &mut Vec<(&'static str, String)>,
) -> Result<String, ConfigError> {
    let name = match t.get(key) {
        None => default.to_string(),
        Some(toml::Value::String(s)) => s.clone(),
        Some(_) => return Err(ConfigError::WrongType(field)),
    };
    check_env_name(field, &name)?;
    if let Some((other, _)) = taken.iter().find(|(_, n)| *n == name) {
        return Err(same_env_as(field, other));
    }
    taken.push((field, name.clone()));
    Ok(name)
}

/// `v<1-3 digits>.<1-2 digits>`, a Graph API version path segment.
fn valid_graph_version(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('v') else {
        return false;
    };
    let Some((major, minor)) = rest.split_once('.') else {
        return false;
    };
    let digits = |p: &str, max: usize| {
        !p.is_empty() && p.len() <= max && p.bytes().all(|b| b.is_ascii_digit())
    };
    digits(major, 3) && digits(minor, 2)
}

/// Parse the `[whatsapp]` table. Secret-looking keys were refused before.
/// `taken` holds the secret variable names already in use (`api_key_env`
/// and, if present, `[telegram] bot_token_env`), which the three WhatsApp
/// names must differ from, as they must from each other.
fn whatsapp(
    t: &toml::Table,
    taken: &[(&'static str, &str)],
) -> Result<WhatsAppConfig, ConfigError> {
    for k in t.keys() {
        if !WHATSAPP_FIELDS.contains(&k.as_str()) {
            return Err(ConfigError::UnknownField(format!(
                "whatsapp.{}",
                shown_key(k)
            )));
        }
    }
    const NUMS: &str = "whatsapp.owner_numbers";
    const PID: &str = "whatsapp.phone_number_id";
    const LISTEN: &str = "whatsapp.listen";
    const AGE: &str = "whatsapp.max_message_age_secs";
    const VER: &str = "whatsapp.graph_version";
    const BASE: &str = "whatsapp.api_base";

    let owner_numbers = match t.get("owner_numbers") {
        None => {
            return Err(ConfigError::Invalid(
                NUMS,
                "is required: the WhatsApp numbers (E.164) allowed to use the agent",
            ))
        }
        Some(toml::Value::Array(items)) => items
            .iter()
            .map(|i| {
                i.as_str()
                    .ok_or(ConfigError::WrongKind(NUMS, "a list of strings"))
            })
            .collect::<Result<Vec<&str>, ConfigError>>()?,
        Some(_) => return Err(ConfigError::WrongKind(NUMS, "a list of strings")),
    };
    if owner_numbers.is_empty() || owner_numbers.len() > MAX_OWNER_IDS {
        return Err(ConfigError::Invalid(NUMS, "must list 1 to 8 numbers"));
    }
    let owner_numbers = owner_numbers
        .into_iter()
        .map(|n| {
            let d = n.strip_prefix('+').unwrap_or(n);
            // E.164: no country code starts with 0.
            if (7..=15).contains(&d.len())
                && d.bytes().all(|b| b.is_ascii_digit())
                && !d.starts_with('0')
            {
                Ok(d.to_string())
            } else {
                Err(ConfigError::Invalid(
                    NUMS,
                    "must hold E.164 numbers: an optional `+` then 7-15 digits, \
                     the first not 0, no spaces or dashes",
                ))
            }
        })
        .collect::<Result<Vec<String>, ConfigError>>()?;

    let phone_number_id = match t.get("phone_number_id") {
        None => {
            return Err(ConfigError::Invalid(
                PID,
                "is required: the Cloud API phone number id, as a string of digits",
            ))
        }
        Some(toml::Value::String(s)) => s.clone(),
        Some(_) => return Err(ConfigError::WrongType(PID)),
    };
    if phone_number_id.is_empty()
        || phone_number_id.len() > MAX_PHONE_NUMBER_ID_DIGITS
        || !phone_number_id.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(ConfigError::Invalid(PID, "must be 1-32 digits"));
    }

    let mut names: Vec<(&'static str, String)> =
        taken.iter().map(|(f, n)| (*f, n.to_string())).collect();
    let access_token_env = whatsapp_env(
        t,
        "access_token_env",
        "whatsapp.access_token_env",
        DEFAULT_WHATSAPP_TOKEN_ENV,
        &mut names,
    )?;
    let app_secret_env = whatsapp_env(
        t,
        "app_secret_env",
        "whatsapp.app_secret_env",
        DEFAULT_WHATSAPP_APP_SECRET_ENV,
        &mut names,
    )?;
    let verify_token_env = whatsapp_env(
        t,
        "verify_token_env",
        "whatsapp.verify_token_env",
        DEFAULT_WHATSAPP_VERIFY_TOKEN_ENV,
        &mut names,
    )?;

    let listen = match t.get("listen") {
        None => DEFAULT_WHATSAPP_LISTEN.to_string(),
        Some(toml::Value::String(s)) => s.clone(),
        Some(_) => return Err(ConfigError::WrongType(LISTEN)),
    };
    // A `SocketAddr` is an IP and a port, so host names never parse.
    // `::ffff:127.0.0.1` is not loopback to `Ipv6Addr::is_loopback`.
    let listen = match listen.parse::<std::net::SocketAddr>() {
        Ok(a) if a.ip().is_loopback() => a,
        _ => return Err(ConfigError::Invalid(
            LISTEN,
            "must be a loopback address such as 127.0.0.1:8097; expose it through your own tunnel",
        )),
    };

    let max_message_age_secs = match t.get("max_message_age_secs") {
        None => DEFAULT_MAX_MESSAGE_AGE_SECS,
        Some(toml::Value::Integer(n)) => match u64::try_from(*n) {
            Ok(n) if (10..=3600).contains(&n) => n,
            _ => {
                return Err(ConfigError::Invalid(
                    AGE,
                    "must be between 10 and 3600 seconds",
                ))
            }
        },
        Some(_) => return Err(ConfigError::WrongKind(AGE, "an integer")),
    };

    let graph_version = match t.get("graph_version") {
        None => DEFAULT_GRAPH_VERSION.to_string(),
        Some(toml::Value::String(s)) => s.clone(),
        Some(_) => return Err(ConfigError::WrongType(VER)),
    };
    if !valid_graph_version(&graph_version) {
        return Err(ConfigError::Invalid(
            VER,
            "must be a Graph API version such as v26.0",
        ));
    }

    let api_base = match t.get("api_base") {
        None => None,
        Some(toml::Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(ConfigError::WrongType(BASE)),
    };

    Ok(WhatsAppConfig {
        owner_numbers,
        phone_number_id,
        access_token_env,
        app_secret_env,
        verify_token_env,
        listen,
        max_message_age_secs,
        graph_version,
        api_base,
    })
}

/// `[A-Za-z0-9._@:-]{1,64}` and left unchanged by the redactor, so it is
/// safe to show (banner, logs) and cannot be a pasted secret.
fn valid_owner(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._@:-".contains(&b))
        && redact(s).0.as_str() == s
}

fn read_file(path: &Path) -> Result<String, ConfigError> {
    // O_NONBLOCK: opening a FIFO (or a device) must not wait for a writer;
    // the handle is then checked to be a regular file before any read.
    let mut f: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => ConfigError::NotFound(path.to_path_buf()),
            k => ConfigError::Io(path.to_path_buf(), k),
        })?;
    // Checked through the open handle, so the file read is the one checked.
    let m = f
        .metadata()
        .map_err(|e| ConfigError::Io(path.to_path_buf(), e.kind()))?;
    if !m.is_file() {
        return Err(ConfigError::NotAFile(path.to_path_buf()));
    }
    if m.mode() & 0o022 != 0 {
        return Err(ConfigError::Insecure(path.to_path_buf()));
    }
    if m.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge(path.to_path_buf()));
    }
    let mut bytes = Vec::new();
    (&mut f)
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| ConfigError::Io(path.to_path_buf(), e.kind()))?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge(path.to_path_buf()));
    }
    String::from_utf8(bytes).map_err(|_| ConfigError::Syntax(None))
}

/// 1-based line of a byte offset.
fn line_of(text: &str, offset: usize) -> usize {
    let end = offset.min(text.len());
    text.as_bytes()[..end]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}

impl Config {
    /// Load and validate the config at `path`. See the module docs.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = read_file(path)?;
        let mut table: toml::Table = toml::from_str(&text)
            .map_err(|e| ConfigError::Syntax(e.span().map(|s| line_of(&text, s.start))))?;
        drop(text);
        // Secrets first: `api_key` is also an unknown field, and the
        // message must point the user at the environment variable.
        if let Some(k) = find_secret_key(&table) {
            return Err(ConfigError::SecretInFile(k));
        }
        // The nested tables. Taken out before the string-only checks.
        let telegram = match table.remove("telegram") {
            None => None,
            Some(toml::Value::Table(t)) => Some(t),
            Some(_) => return Err(ConfigError::WrongKind("telegram", "a table")),
        };
        let whatsapp = match table.remove("whatsapp") {
            None => None,
            Some(toml::Value::Table(t)) => Some(t),
            Some(_) => return Err(ConfigError::WrongKind("whatsapp", "a table")),
        };
        let known = known_fields();
        for (k, v) in &table {
            if !known.contains(&k.as_str()) {
                return Err(ConfigError::UnknownField(shown_key(k)));
            }
            if !v.is_str() {
                let k = known.iter().copied().find(|f| f == k).unwrap_or("?");
                return Err(ConfigError::WrongType(k));
            }
        }
        // Types and names are checked above, so this cannot fail on a value;
        // its error is reported without detail all the same.
        let raw: Raw = table.try_into().map_err(|_| ConfigError::Syntax(None))?;
        let mut config = Config::from_raw(raw)?;
        config.telegram = telegram
            .as_ref()
            .map(|t| self::telegram(t, &config.api_key_env))
            .transpose()?;
        let mut taken: Vec<(&'static str, &str)> = vec![("api_key_env", &config.api_key_env)];
        if let Some(tg) = &config.telegram {
            taken.push(("telegram.bot_token_env", &tg.bot_token_env));
        }
        let whatsapp = whatsapp
            .as_ref()
            .map(|t| self::whatsapp(t, &taken))
            .transpose()?;
        config.whatsapp = whatsapp;
        Ok(config)
    }

    fn from_raw(raw: Raw) -> Result<Config, ConfigError> {
        let root = raw.root.ok_or(ConfigError::MissingRoot)?;
        if !root.is_absolute() {
            return Err(ConfigError::Invalid("root", "must be an absolute path"));
        }
        let owner = raw.owner.unwrap_or_else(|| DEFAULT_OWNER.to_string());
        if !valid_owner(&owner) {
            return Err(ConfigError::Invalid(
                "owner",
                "must be 1-64 characters from [A-Za-z0-9._@:-] and must not look like a secret",
            ));
        }
        let model = raw.model.unwrap_or_else(|| DEFAULT_MODEL.to_string());
        let api_key_env = raw
            .api_key_env
            .unwrap_or_else(|| DEFAULT_API_KEY_ENV.to_string());
        check_env_name("api_key_env", &api_key_env)?;
        #[cfg(feature = "test-hooks")]
        let provider = provider(raw.provider.as_deref(), raw.script)?;
        #[cfg(not(feature = "test-hooks"))]
        let provider = provider(raw.provider.as_deref())?;
        Ok(Config {
            owner,
            root,
            provider,
            model,
            base_url: raw.base_url,
            api_key_env,
            telegram: None,
            whatsapp: None,
        })
    }
}

#[cfg(not(feature = "test-hooks"))]
fn provider(name: Option<&str>) -> Result<Provider, ConfigError> {
    match name {
        None | Some("anthropic") => Ok(Provider::Anthropic),
        Some(_) => Err(ConfigError::UnknownProvider),
    }
}

#[cfg(feature = "test-hooks")]
fn provider(name: Option<&str>, script: Option<PathBuf>) -> Result<Provider, ConfigError> {
    match (name, script) {
        (None | Some("anthropic"), None) => Ok(Provider::Anthropic),
        (Some("mock"), Some(script)) => Ok(Provider::Mock { script }),
        (Some("mock"), None) => Err(ConfigError::Invalid(
            "script",
            "is required with the scripted provider",
        )),
        (None | Some("anthropic"), Some(_)) => Err(ConfigError::Invalid(
            "script",
            "is only valid with the scripted provider",
        )),
        (Some(_), _) => Err(ConfigError::UnknownProvider),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_names() {
        for k in [
            "api_key", "APIKEY", "Api-Key", "key", "token", "secret", "password",
        ] {
            assert!(is_secret_key(k), "{k}");
        }
        for k in ["bot_token", "TELEGRAM_TOKEN", "telegram-bot-token"] {
            assert!(is_secret_key(k), "{k}");
        }
        for k in [
            "access_token",
            "APP_SECRET",
            "verify-token",
            "whatsapp_token",
            "AccessToken",
        ] {
            assert!(is_secret_key(k), "{k}");
        }
        for k in [
            "api_key_env",
            "root",
            "model",
            "keys",
            "base_url",
            "bot_token_env",
            "owner_ids",
            "access_token_env",
            "app_secret_env",
            "verify_token_env",
            "phone_number_id",
            "owner_numbers",
        ] {
            assert!(!is_secret_key(k), "{k}");
        }
    }

    #[test]
    fn shown_key_hides_odd_names() {
        assert_eq!(shown_key("modle"), "modle");
        assert_eq!(shown_key("a b"), "<unprintable>");
        assert_eq!(shown_key(&"x".repeat(65)), "<unprintable>");
    }

    /// Only compiled without `test-hooks`, which `cargo test` never does
    /// (the self dev-dependency turns the feature on); the release binary
    /// check in the task report covers the same rule end to end.
    #[cfg(not(feature = "test-hooks"))]
    #[test]
    fn mock_provider_rejected_without_test_hooks() {
        assert!(matches!(
            provider(Some("mock")),
            Err(ConfigError::UnknownProvider)
        ));
    }
}
