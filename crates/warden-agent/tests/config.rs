//! Tests for `warden agent` config loading.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use warden_agent::config::{
    Config, ConfigError, Provider, TelegramConfig, WhatsAppConfig, DEFAULT_GRAPH_API_BASE,
    DEFAULT_GRAPH_VERSION, DEFAULT_TELEGRAM_API_BASE, DEFAULT_TELEGRAM_TOKEN_ENV,
    DEFAULT_WHATSAPP_APP_SECRET_ENV, DEFAULT_WHATSAPP_LISTEN, DEFAULT_WHATSAPP_TOKEN_ENV,
    DEFAULT_WHATSAPP_VERIFY_TOKEN_ENV,
};

fn write(dir: &Path, body: &str) -> PathBuf {
    let p = dir.join("config.toml");
    fs::write(&p, body).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    p
}

#[test]
fn defaults_apply() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "root = \"/srv/files\"\n");
    let c = Config::load(&p).unwrap();
    assert_eq!(
        c,
        Config {
            owner: "local".into(),
            root: PathBuf::from("/srv/files"),
            provider: Provider::Anthropic,
            model: "claude-sonnet-5-5".into(),
            base_url: None,
            api_key_env: "ANTHROPIC_API_KEY".into(),
            telegram: None,
            whatsapp: None,
        }
    );
}

#[test]
fn every_field_can_be_set() {
    let d = tempfile::tempdir().unwrap();
    let p = write(
        d.path(),
        r#"
owner = "me"
root = "/srv/files"
provider = "anthropic"
model = "claude-opus-5-5"
base_url = "http://127.0.0.1:9999"
api_key_env = "MY_KEY_VAR"
"#,
    );
    let c = Config::load(&p).unwrap();
    assert_eq!(c.owner, "me");
    assert_eq!(c.model, "claude-opus-5-5");
    assert_eq!(c.base_url.as_deref(), Some("http://127.0.0.1:9999"));
    assert_eq!(c.api_key_env, "MY_KEY_VAR");
}

#[test]
fn root_is_required() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "owner = \"local\"\n");
    let e = Config::load(&p).unwrap_err();
    assert!(matches!(e, ConfigError::MissingRoot), "{e:?}");
    assert!(e.to_string().contains("root"), "{e}");
}

#[test]
fn relative_root_is_rejected() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "root = \"files\"\n");
    let e = Config::load(&p).unwrap_err();
    assert!(e.to_string().contains("absolute"), "{e}");
}

#[test]
fn unknown_field_is_rejected() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "root = \"/srv\"\nmodle = \"x\"\n");
    let e = Config::load(&p).unwrap_err();
    assert!(e.to_string().contains("unknown field `modle`"), "{e}");
    // Nested tables are unknown too.
    let p = write(d.path(), "root = \"/srv\"\n[extra]\nx = 1\n");
    assert!(Config::load(&p).is_err());
}

#[test]
fn wrong_type_is_rejected_without_echoing_the_value() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "root = \"/srv\"\nmodel = 12345987\n");
    let e = Config::load(&p).unwrap_err().to_string();
    assert!(e.contains("model"), "{e}");
    assert!(!e.contains("12345987"), "{e}");
}

#[test]
fn syntax_error_names_the_line_not_the_text() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "root = \"/srv\"\nmodel = sk-ant-oops-value\n");
    let e = Config::load(&p).unwrap_err().to_string();
    assert!(e.contains("line 2"), "{e}");
    assert!(!e.contains("oops"), "{e}");
}

#[test]
fn api_key_in_file_is_rejected_with_message_that_does_not_echo_the_value() {
    let d = tempfile::tempdir().unwrap();
    for key in [
        "api_key", "apikey", "key", "token", "secret", "password", "API_KEY", "api-key",
    ] {
        let value = "sk-ant-api03-SuperSecretValue0123456789";
        let p = write(d.path(), &format!("root = \"/srv\"\n{key} = \"{value}\"\n"));
        let e = Config::load(&p).unwrap_err();
        assert!(matches!(e, ConfigError::SecretInFile(_)), "{key}: {e:?}");
        let msg = e.to_string();
        assert!(msg.contains("environment variable"), "{msg}");
        assert!(msg.contains("ANTHROPIC_API_KEY"), "{msg}");
        assert!(!msg.contains("SuperSecret"), "{msg}");
        assert!(!format!("{e:?}").contains("SuperSecret"));
    }
    // Also inside a nested table, and with a non-string value.
    let p = write(d.path(), "root = \"/srv\"\n[x]\ntoken = 123456\n");
    let e = Config::load(&p).unwrap_err();
    assert!(matches!(e, ConfigError::SecretInFile(_)), "{e:?}");
    assert!(!e.to_string().contains("123456"));
}

#[test]
fn api_key_env_must_be_a_variable_name() {
    let d = tempfile::tempdir().unwrap();
    for bad in ["sk-ant-api03-SuperSecretValue0123456789", "", "1ABC", "A B"] {
        let p = write(
            d.path(),
            &format!("root = \"/srv\"\napi_key_env = \"{bad}\"\n"),
        );
        let e = Config::load(&p).unwrap_err().to_string();
        assert!(e.contains("api_key_env"), "{e}");
        assert!(!e.contains("SuperSecret"), "{e}");
    }
    // A real secret shaped like a variable name (AWS access key id).
    let p = write(
        d.path(),
        "root = \"/srv\"\napi_key_env = \"AKIAIOSFODNN7EXAMPLE\"\n",
    );
    let e = Config::load(&p).unwrap_err().to_string();
    assert!(!e.contains("AKIAIOSFODNN7EXAMPLE"), "{e}");
}

#[test]
fn missing_file_is_an_error_naming_the_path() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("nope.toml");
    let e = Config::load(&p).unwrap_err();
    assert!(matches!(e, ConfigError::NotFound(_)), "{e:?}");
    assert!(e.to_string().contains(&p.display().to_string()), "{e}");
}

#[test]
fn group_writable_config_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "root = \"/srv\"\n");
    for mode in [0o620, 0o602, 0o666] {
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        let e = Config::load(&p).unwrap_err();
        assert!(matches!(e, ConfigError::Insecure(_)), "{mode:o}: {e:?}");
        assert!(e.to_string().contains("writable"), "{e}");
    }
    // Readable by others is fine (it holds no secrets).
    fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Config::load(&p).is_ok());
}

#[test]
fn a_directory_is_not_a_config_file() {
    let d = tempfile::tempdir().unwrap();
    assert!(Config::load(d.path()).is_err());
}

#[test]
fn unknown_provider_is_rejected() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "root = \"/srv\"\nprovider = \"openai\"\n");
    let e = Config::load(&p).unwrap_err();
    assert!(matches!(e, ConfigError::UnknownProvider), "{e:?}");
    assert!(!e.to_string().contains("openai"));
}

#[test]
fn mock_provider_parses_with_test_hooks() {
    // Tests build warden-agent with `test-hooks` (self dev-dependency).
    let d = tempfile::tempdir().unwrap();
    let p = write(
        d.path(),
        "root = \"/srv\"\nprovider = \"mock\"\nscript = \"/tmp/s.json\"\n",
    );
    let c = Config::load(&p).unwrap();
    assert_eq!(
        c.provider,
        Provider::Mock {
            script: PathBuf::from("/tmp/s.json")
        }
    );
    // `script` only goes with the mock provider; mock needs a script.
    let p = write(d.path(), "root = \"/srv\"\nscript = \"/tmp/s.json\"\n");
    assert!(Config::load(&p).is_err());
    let p = write(d.path(), "root = \"/srv\"\nprovider = \"mock\"\n");
    assert!(Config::load(&p).is_err());
}

// ------------------------------------------------- review round 1

#[test]
fn a_fifo_config_is_refused_without_hanging() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("config.toml");
    let c = std::ffi::CString::new(p.as_os_str().to_str().unwrap()).unwrap();
    // SAFETY: a valid NUL-terminated path; mkfifo has no other preconditions.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
    assert_eq!(rc, 0);
    let (tx, rx) = std::sync::mpsc::channel();
    let q = p.clone();
    std::thread::spawn(move || {
        let _ = tx.send(Config::load(&q).map(drop).map_err(|e| e.to_string()));
    });
    let r = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("Config::load hung on a FIFO");
    let e = r.unwrap_err();
    assert!(e.contains("not a regular file"), "{e}");
}

#[test]
fn owner_must_be_a_plain_identifier_and_is_never_echoed() {
    let d = tempfile::tempdir().unwrap();
    for bad in [
        "sk-ant-api03-SuperSecretValue0123456789",
        "AKIAIOSFODNN7EXAMPLE",
        "has space",
        "evil\u{1b}[2J",
        "x/../y",
        "",
    ] {
        let p = write(
            d.path(),
            &format!(
                "root = \"/srv\"\nowner = \"{}\"\n",
                bad.replace('\u{1b}', "\\u001b")
            ),
        );
        let e = Config::load(&p).unwrap_err().to_string();
        assert!(e.contains("owner"), "{bad:?}: {e}");
        assert!(bad.is_empty() || !e.contains(bad), "{e}");
        assert!(!e.contains("SuperSecret") && !e.contains("AKIA"), "{e}");
    }
    let long = "a".repeat(65);
    let p = write(d.path(), &format!("root = \"/srv\"\nowner = \"{long}\"\n"));
    assert!(Config::load(&p).is_err());
    for good in ["local", "alice@example.com", "user.name:1", "A-b_c"] {
        let p = write(d.path(), &format!("root = \"/srv\"\nowner = \"{good}\"\n"));
        assert_eq!(Config::load(&p).unwrap().owner, good);
    }
}

fn tg(body: &str) -> Result<Config, ConfigError> {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), &format!("root = \"/srv\"\n[telegram]\n{body}"));
    Config::load(&p)
}

#[test]
fn telegram_table_parses_with_defaults() {
    let c = tg("owner_ids = [42]\n").unwrap();
    let t = c.telegram.expect("telegram table");
    assert_eq!(
        t,
        TelegramConfig {
            owner_ids: vec![42],
            bot_token_env: "WARDEN_TELEGRAM_TOKEN".into(),
            allow_pin_approvals: false,
            max_message_age_secs: 120,
            api_base: None,
        }
    );
    assert_eq!(DEFAULT_TELEGRAM_TOKEN_ENV, "WARDEN_TELEGRAM_TOKEN");
    assert_eq!(DEFAULT_TELEGRAM_API_BASE, "https://api.telegram.org");
    // Every field set.
    let c = tg(r#"owner_ids = [1, 4503599627370496]
bot_token_env = "MY_BOT_VAR"
allow_pin_approvals = true
max_message_age_secs = 3600
api_base = "http://127.0.0.1:9999"
"#)
    .unwrap();
    let t = c.telegram.unwrap();
    assert_eq!(t.owner_ids, vec![1, 4503599627370496]);
    assert_eq!(t.bot_token_env, "MY_BOT_VAR");
    assert!(t.allow_pin_approvals);
    assert_eq!(t.max_message_age_secs, 3600);
    assert_eq!(t.api_base.as_deref(), Some("http://127.0.0.1:9999"));
    // No table: no Telegram.
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "root = \"/srv\"\n");
    assert_eq!(Config::load(&p).unwrap().telegram, None);
}

#[test]
fn telegram_owner_ids_required_nonempty_positive_and_at_most_8() {
    for body in [
        "",
        "allow_pin_approvals = true\n",
        "owner_ids = []\n",
        "owner_ids = [0]\n",
        "owner_ids = [-5]\n",
        "owner_ids = [4503599627370497]\n",
        "owner_ids = [1, 2, 3, 4, 5, 6, 7, 8, 9]\n",
    ] {
        let e = tg(body).unwrap_err();
        assert!(
            matches!(e, ConfigError::Invalid("telegram.owner_ids", _)),
            "{body:?}: {e:?}"
        );
        assert!(e.to_string().contains("telegram.owner_ids"), "{e}");
        assert!(!e.to_string().contains("4503599627370497"), "{e}");
    }
    let c = tg("owner_ids = [1, 2, 3, 4, 5, 6, 7, 8]\n").unwrap();
    assert_eq!(c.telegram.unwrap().owner_ids.len(), 8);
}

#[test]
fn bot_token_in_file_is_rejected_with_message() {
    let value = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ";
    for key in [
        "bot_token",
        "telegram_token",
        "telegram-bot-token",
        "BotToken",
    ] {
        let e = tg(&format!("owner_ids = [42]\n{key} = \"{value}\"\n")).unwrap_err();
        assert!(matches!(e, ConfigError::SecretInFile(_)), "{key}: {e:?}");
        let msg = e.to_string();
        assert!(msg.contains("bot_token_env"), "{msg}");
        assert!(msg.contains("api_key_env"), "{msg}");
        assert!(!msg.contains(value), "{msg}");
        assert!(!msg.contains("AAHdq"), "{msg}");
        assert!(!format!("{e:?}").contains("AAHdq"));
    }
    // Also at the top level.
    let d = tempfile::tempdir().unwrap();
    let p = write(
        d.path(),
        &format!("root = \"/srv\"\nbot_token = \"{value}\"\n"),
    );
    assert!(matches!(
        Config::load(&p).unwrap_err(),
        ConfigError::SecretInFile(_)
    ));
}

#[test]
fn unknown_telegram_field_is_rejected() {
    let e = tg("owner_ids = [42]\nowner_id = 42\n").unwrap_err();
    assert!(matches!(e, ConfigError::UnknownField(_)), "{e:?}");
    assert!(
        e.to_string().contains("unknown field `telegram.owner_id`"),
        "{e}"
    );
}

#[test]
fn other_nested_tables_still_rejected() {
    let d = tempfile::tempdir().unwrap();
    for body in [
        "root = \"/srv\"\n[extra]\nx = 1\n",
        "root = \"/srv\"\n[telegram]\nowner_ids = [42]\n[slack]\nx = 1\n",
        "root = \"/srv\"\n[telegram]\nowner_ids = [42]\n[telegram.inner]\nx = 1\n",
        "root = \"/srv\"\n[[telegram]]\nowner_ids = [42]\n",
    ] {
        let p = write(d.path(), body);
        assert!(Config::load(&p).is_err(), "{body:?}");
    }
    let p = write(d.path(), "root = \"/srv\"\n[extra]\nx = 1\n");
    let e = Config::load(&p).unwrap_err();
    assert!(e.to_string().contains("unknown field `extra`"), "{e}");
    // Top-level fields stay strings.
    let p = write(d.path(), "root = \"/srv\"\nowner = 42\n");
    assert!(matches!(
        Config::load(&p).unwrap_err(),
        ConfigError::WrongType("owner")
    ));
}

#[test]
fn max_message_age_out_of_range_is_invalid() {
    for v in [9, 3601, 0, -1] {
        let e = tg(&format!("owner_ids = [42]\nmax_message_age_secs = {v}\n")).unwrap_err();
        assert!(
            matches!(e, ConfigError::Invalid("telegram.max_message_age_secs", _)),
            "{v}: {e:?}"
        );
    }
    for v in [10, 3600] {
        let c = tg(&format!("owner_ids = [42]\nmax_message_age_secs = {v}\n")).unwrap();
        assert_eq!(c.telegram.unwrap().max_message_age_secs, v);
    }
}

#[test]
fn wrong_kinds_are_named() {
    let e = tg("owner_ids = \"42\"\n").unwrap_err();
    assert!(
        matches!(
            e,
            ConfigError::WrongKind("telegram.owner_ids", "a list of integers")
        ),
        "{e:?}"
    );
    assert!(e.to_string().contains("telegram.owner_ids"), "{e}");
    assert!(e.to_string().contains("a list of integers"), "{e}");
    let e = tg("owner_ids = [\"42\"]\n").unwrap_err();
    assert!(
        matches!(
            e,
            ConfigError::WrongKind("telegram.owner_ids", "a list of integers")
        ),
        "{e:?}"
    );
    let e = tg("owner_ids = [42]\nallow_pin_approvals = \"yes\"\n").unwrap_err();
    assert!(
        matches!(
            e,
            ConfigError::WrongKind("telegram.allow_pin_approvals", "a boolean")
        ),
        "{e:?}"
    );
    assert!(!e.to_string().contains("yes"), "{e}");
    let e = tg("owner_ids = [42]\nmax_message_age_secs = \"60\"\n").unwrap_err();
    assert!(
        matches!(
            e,
            ConfigError::WrongKind("telegram.max_message_age_secs", "an integer")
        ),
        "{e:?}"
    );
    let e = tg("owner_ids = [42]\nbot_token_env = 5\n").unwrap_err();
    assert!(
        matches!(e, ConfigError::WrongType("telegram.bot_token_env")),
        "{e:?}"
    );
    let e = tg("owner_ids = [42]\napi_base = 5\n").unwrap_err();
    assert!(
        matches!(e, ConfigError::WrongType("telegram.api_base")),
        "{e:?}"
    );
    // `telegram` must be a table.
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "root = \"/srv\"\ntelegram = \"on\"\n");
    assert!(Config::load(&p).is_err());
}

#[test]
fn telegram_bot_token_env_must_be_a_variable_name() {
    for bad in [
        "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ",
        "",
        "1ABC",
        "A B",
        "AKIAIOSFODNN7EXAMPLE",
    ] {
        let e = tg(&format!("owner_ids = [42]\nbot_token_env = \"{bad}\"\n")).unwrap_err();
        assert!(
            matches!(e, ConfigError::Invalid("telegram.bot_token_env", _)),
            "{bad:?}: {e:?}"
        );
        assert!(!e.to_string().contains("AAHdq"), "{e}");
        assert!(!e.to_string().contains("AKIA"), "{e}");
    }
}

#[test]
fn bot_token_env_must_differ_from_api_key_env() {
    // Against the default api_key_env.
    let e = tg("owner_ids = [42]\nbot_token_env = \"ANTHROPIC_API_KEY\"\n").unwrap_err();
    assert!(
        matches!(e, ConfigError::Invalid("telegram.bot_token_env", _)),
        "{e:?}"
    );
    assert!(e.to_string().contains("api_key_env"), "{e}");
    // Against a configured api_key_env.
    let d = tempfile::tempdir().unwrap();
    let p = write(
        d.path(),
        "root = \"/srv\"\napi_key_env = \"MY_KEY\"\n[telegram]\nowner_ids = [42]\nbot_token_env = \"MY_KEY\"\n",
    );
    let e = Config::load(&p).unwrap_err();
    assert!(
        matches!(e, ConfigError::Invalid("telegram.bot_token_env", _)),
        "{e:?}"
    );
    // A configured api_key_env frees the default name.
    let p = write(
        d.path(),
        "root = \"/srv\"\napi_key_env = \"MY_KEY\"\n[telegram]\nowner_ids = [42]\nbot_token_env = \"ANTHROPIC_API_KEY\"\n",
    );
    assert!(Config::load(&p).is_ok());
}

// ------------------------------------------------- plan 4: [whatsapp]

/// A minimal valid `[whatsapp]` table body.
const WA_MIN: &str = "owner_numbers = [\"15551234567\"]\nphone_number_id = \"106540352242922\"\n";

fn wa(body: &str) -> Result<Config, ConfigError> {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), &format!("root = \"/srv\"\n[whatsapp]\n{body}"));
    Config::load(&p)
}

fn load(body: &str) -> Result<Config, ConfigError> {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), body);
    Config::load(&p)
}

#[test]
fn whatsapp_table_parses_with_defaults() {
    let c = wa(WA_MIN).unwrap();
    let w = c.whatsapp.expect("whatsapp table");
    assert_eq!(
        w,
        WhatsAppConfig {
            owner_numbers: vec!["15551234567".into()],
            phone_number_id: "106540352242922".into(),
            access_token_env: "WARDEN_WHATSAPP_TOKEN".into(),
            app_secret_env: "WARDEN_WHATSAPP_APP_SECRET".into(),
            verify_token_env: "WARDEN_WHATSAPP_VERIFY_TOKEN".into(),
            listen: "127.0.0.1:8097".parse().unwrap(),
            max_message_age_secs: 120,
            graph_version: "v26.0".into(),
            api_base: None,
        }
    );
    assert_eq!(DEFAULT_WHATSAPP_TOKEN_ENV, "WARDEN_WHATSAPP_TOKEN");
    assert_eq!(
        DEFAULT_WHATSAPP_APP_SECRET_ENV,
        "WARDEN_WHATSAPP_APP_SECRET"
    );
    assert_eq!(
        DEFAULT_WHATSAPP_VERIFY_TOKEN_ENV,
        "WARDEN_WHATSAPP_VERIFY_TOKEN"
    );
    assert_eq!(DEFAULT_WHATSAPP_LISTEN, "127.0.0.1:8097");
    assert_eq!(DEFAULT_GRAPH_VERSION, "v26.0");
    assert_eq!(DEFAULT_GRAPH_API_BASE, "https://graph.facebook.com");
    assert_eq!(c.telegram, None);
    // Every field set.
    let c = wa(r#"owner_numbers = ["+15551234567", "447700900123"]
phone_number_id = "1"
access_token_env = "WA_TOK"
app_secret_env = "WA_APP"
verify_token_env = "WA_VER"
listen = "[::1]:9000"
max_message_age_secs = 3600
graph_version = "v27.1"
api_base = "http://127.0.0.1:9999"
"#)
    .unwrap();
    let w = c.whatsapp.unwrap();
    assert_eq!(w.owner_numbers, vec!["15551234567", "447700900123"]);
    assert_eq!(w.phone_number_id, "1");
    assert_eq!(w.access_token_env, "WA_TOK");
    assert_eq!(w.app_secret_env, "WA_APP");
    assert_eq!(w.verify_token_env, "WA_VER");
    assert_eq!(w.listen, "[::1]:9000".parse().unwrap());
    assert_eq!(w.max_message_age_secs, 3600);
    assert_eq!(w.graph_version, "v27.1");
    assert_eq!(w.api_base.as_deref(), Some("http://127.0.0.1:9999"));
    // No table: no WhatsApp.
    assert_eq!(load("root = \"/srv\"\n").unwrap().whatsapp, None);
}

#[test]
fn whatsapp_owner_numbers_rules() {
    const F: &str = "whatsapp.owner_numbers";
    let pid = "phone_number_id = \"1\"\n";
    for nums in [
        "[]".to_string(),
        format!("[{}]", ["\"15551234567\""; 9].join(", ")),
        "[\"+1 555 123 4567\"]".to_string(),
        "[\"+1-555-123-4567\"]".to_string(),
        "[\"abc\"]".to_string(),
        "[\"123456\"]".to_string(),
        "[\"1234567890123456\"]".to_string(),
        "[\"++15551234567\"]".to_string(),
        "[\"\"]".to_string(),
    ] {
        let e = wa(&format!("owner_numbers = {nums}\n{pid}")).unwrap_err();
        assert!(matches!(e, ConfigError::Invalid(F, _)), "{nums}: {e:?}");
        assert!(e.to_string().contains(F), "{e}");
        assert!(!e.to_string().contains("555"), "{e}");
    }
    // Required.
    let e = wa(pid).unwrap_err();
    assert!(matches!(e, ConfigError::Invalid(F, _)), "{e:?}");
    // `+` is stripped; 7 and 15 digits and 8 entries are fine.
    let c = wa(&format!("owner_numbers = [\"+15551234567\"]\n{pid}")).unwrap();
    assert_eq!(c.whatsapp.unwrap().owner_numbers, vec!["15551234567"]);
    let c = wa(&format!(
        "owner_numbers = [\"1234567\", \"+123456789012345\"]\n{pid}"
    ))
    .unwrap();
    assert_eq!(
        c.whatsapp.unwrap().owner_numbers,
        vec!["1234567", "123456789012345"]
    );
    let eight = ["\"15551234567\""; 8].join(", ");
    let c = wa(&format!("owner_numbers = [{eight}]\n{pid}")).unwrap();
    assert_eq!(c.whatsapp.unwrap().owner_numbers.len(), 8);
}

#[test]
fn whatsapp_phone_number_id_required_digits() {
    const F: &str = "whatsapp.phone_number_id";
    let owners = "owner_numbers = [\"15551234567\"]\n";
    let e = wa(owners).unwrap_err();
    assert!(matches!(e, ConfigError::Invalid(F, _)), "{e:?}");
    for bad in ["", "12a4", "+123", "1 2", &"1".repeat(33), "../x"] {
        let e = wa(&format!("{owners}phone_number_id = \"{bad}\"\n")).unwrap_err();
        assert!(matches!(e, ConfigError::Invalid(F, _)), "{bad:?}: {e:?}");
    }
    // An integer is the wrong kind: ids are strings.
    let e = wa(&format!("{owners}phone_number_id = 123\n")).unwrap_err();
    assert!(matches!(e, ConfigError::WrongType(F)), "{e:?}");
    let max = "9".repeat(32);
    let c = wa(&format!("{owners}phone_number_id = \"{max}\"\n")).unwrap();
    assert_eq!(c.whatsapp.unwrap().phone_number_id, max);
}

#[test]
fn whatsapp_listen_must_be_loopback() {
    const F: &str = "whatsapp.listen";
    for bad in [
        "0.0.0.0:8097",
        "[::]:8097",
        "192.168.1.5:8097",
        "localhost:8097",
        "[::ffff:127.0.0.1]:8097",
        "127.0.0.1",
        "",
    ] {
        let e = wa(&format!("{WA_MIN}listen = \"{bad}\"\n")).unwrap_err();
        assert!(matches!(e, ConfigError::Invalid(F, _)), "{bad:?}: {e:?}");
        let msg = e.to_string();
        assert!(msg.contains("loopback"), "{msg}");
        assert!(msg.contains("tunnel"), "{msg}");
    }
    for good in [
        "127.0.0.1:0",
        "[::1]:8097",
        "127.0.0.1:8097",
        "127.1.2.3:80",
    ] {
        let c = wa(&format!("{WA_MIN}listen = \"{good}\"\n")).unwrap();
        assert_eq!(c.whatsapp.unwrap().listen, good.parse().unwrap());
    }
}

#[test]
fn whatsapp_secret_fields_in_file_are_rejected() {
    let value = "EAAGm0PX4ZCpsBAKZB0123456789abcdefghijklmnopqrstuvwxyz";
    for key in [
        "access_token",
        "app_secret",
        "verify_token",
        "whatsapp_token",
        "AccessToken",
        "app-secret",
    ] {
        let e = wa(&format!("{WA_MIN}{key} = \"{value}\"\n")).unwrap_err();
        assert!(matches!(e, ConfigError::SecretInFile(_)), "{key}: {e:?}");
        let msg = e.to_string();
        assert!(msg.contains("access_token_env"), "{msg}");
        assert!(msg.contains("app_secret_env"), "{msg}");
        assert!(msg.contains("verify_token_env"), "{msg}");
        assert!(!msg.contains(value), "{msg}");
        assert!(!msg.contains("EAAG"), "{msg}");
        assert!(!format!("{e:?}").contains("EAAG"));
        // Also at the top level, and inside another table.
        let e = load(&format!("root = \"/srv\"\n{key} = \"{value}\"\n")).unwrap_err();
        assert!(matches!(e, ConfigError::SecretInFile(_)), "{key}: {e:?}");
        let e = load(&format!(
            "root = \"/srv\"\n[telegram]\nowner_ids = [42]\n{key} = \"{value}\"\n"
        ))
        .unwrap_err();
        assert!(matches!(e, ConfigError::SecretInFile(_)), "{key}: {e:?}");
    }
}

#[test]
fn whatsapp_env_names_must_all_differ() {
    const TOK: &str = "whatsapp.access_token_env";
    const APP: &str = "whatsapp.app_secret_env";
    const VER: &str = "whatsapp.verify_token_env";
    // Every pair among the three: the later field is named.
    for (body, field) in [
        ("access_token_env = \"X\"\napp_secret_env = \"X\"\n", APP),
        ("access_token_env = \"X\"\nverify_token_env = \"X\"\n", VER),
        ("app_secret_env = \"X\"\nverify_token_env = \"X\"\n", VER),
        // Against the other field's default.
        ("app_secret_env = \"WARDEN_WHATSAPP_TOKEN\"\n", APP),
        ("verify_token_env = \"WARDEN_WHATSAPP_APP_SECRET\"\n", VER),
    ] {
        let e = wa(&format!("{WA_MIN}{body}")).unwrap_err();
        assert!(
            matches!(e, ConfigError::Invalid(f, _) if f == field),
            "{body:?}: {e:?}"
        );
        assert!(
            e.to_string()
                .contains("must name a different environment variable than"),
            "{e}"
        );
    }
    // Each against the default and a configured `api_key_env`.
    for field in [TOK, APP, VER] {
        let name = field.trim_start_matches("whatsapp.");
        let e = wa(&format!("{WA_MIN}{name} = \"ANTHROPIC_API_KEY\"\n")).unwrap_err();
        assert!(
            matches!(e, ConfigError::Invalid(f, _) if f == field),
            "{e:?}"
        );
        assert!(e.to_string().contains("`api_key_env`"), "{e}");
        let e = load(&format!(
            "root = \"/srv\"\napi_key_env = \"MY_KEY\"\n[whatsapp]\n{WA_MIN}{name} = \"MY_KEY\"\n"
        ))
        .unwrap_err();
        assert!(
            matches!(e, ConfigError::Invalid(f, _) if f == field),
            "{e:?}"
        );
        // Each against `[telegram] bot_token_env`, set and default.
        let e = load(&format!(
            "root = \"/srv\"\n[telegram]\nowner_ids = [42]\nbot_token_env = \"BOT\"\n[whatsapp]\n{WA_MIN}{name} = \"BOT\"\n"
        ))
        .unwrap_err();
        assert!(
            matches!(e, ConfigError::Invalid(f, _) if f == field),
            "{e:?}"
        );
        assert!(e.to_string().contains("`telegram.bot_token_env`"), "{e}");
        let e = load(&format!(
            "root = \"/srv\"\n[telegram]\nowner_ids = [42]\n[whatsapp]\n{WA_MIN}{name} = \"WARDEN_TELEGRAM_TOKEN\"\n"
        ))
        .unwrap_err();
        assert!(
            matches!(e, ConfigError::Invalid(f, _) if f == field),
            "{e:?}"
        );
        // Without a [telegram] table the bot token name is free.
        let c = wa(&format!("{WA_MIN}{name} = \"WARDEN_TELEGRAM_TOKEN\"\n")).unwrap();
        assert!(c.whatsapp.is_some());
    }
    // Each must be a variable name, and is never echoed.
    for field in [TOK, APP, VER] {
        let name = field.trim_start_matches("whatsapp.");
        for bad in ["", "1ABC", "A B", "AKIAIOSFODNN7EXAMPLE"] {
            let e = wa(&format!("{WA_MIN}{name} = \"{bad}\"\n")).unwrap_err();
            assert!(
                matches!(e, ConfigError::Invalid(f, _) if f == field),
                "{bad:?}: {e:?}"
            );
            assert!(!e.to_string().contains("AKIA"), "{e}");
        }
        let e = wa(&format!("{WA_MIN}{name} = 5\n")).unwrap_err();
        assert!(
            matches!(e, ConfigError::WrongType(f) if f == field),
            "{e:?}"
        );
    }
}

#[test]
fn whatsapp_graph_version_shape() {
    const F: &str = "whatsapp.graph_version";
    for bad in [
        "23.0",
        "v23",
        "v26.0/../x",
        "v1234.0",
        "v1.123",
        "V26.0",
        "",
    ] {
        let e = wa(&format!("{WA_MIN}graph_version = \"{bad}\"\n")).unwrap_err();
        assert!(matches!(e, ConfigError::Invalid(F, _)), "{bad:?}: {e:?}");
        assert!(bad.is_empty() || !e.to_string().contains(bad), "{e}");
    }
    let e = wa(&format!("{WA_MIN}graph_version = 26\n")).unwrap_err();
    assert!(matches!(e, ConfigError::WrongType(F)), "{e:?}");
    for good in ["v1.0", "v26.0", "v999.99"] {
        let c = wa(&format!("{WA_MIN}graph_version = \"{good}\"\n")).unwrap();
        assert_eq!(c.whatsapp.unwrap().graph_version, good);
    }
}

#[test]
fn unknown_whatsapp_field_is_rejected() {
    let e = wa(&format!("{WA_MIN}owner_number = \"1\"\n")).unwrap_err();
    assert!(matches!(e, ConfigError::UnknownField(_)), "{e:?}");
    assert!(
        e.to_string()
            .contains("unknown field `whatsapp.owner_number`"),
        "{e}"
    );
    // A Telegram-only field is unknown here.
    let e = wa(&format!("{WA_MIN}allow_pin_approvals = false\n")).unwrap_err();
    assert!(
        e.to_string()
            .contains("unknown field `whatsapp.allow_pin_approvals`"),
        "{e}"
    );
}

#[test]
fn both_channel_tables_parse_together() {
    let c = load(&format!(
        "root = \"/srv\"\n[telegram]\nowner_ids = [42]\n[whatsapp]\n{WA_MIN}"
    ))
    .unwrap();
    assert_eq!(c.telegram.unwrap().owner_ids, vec![42]);
    assert_eq!(c.whatsapp.unwrap().owner_numbers, vec!["15551234567"]);
    // Order in the file does not matter.
    let c = load(&format!(
        "root = \"/srv\"\n[whatsapp]\n{WA_MIN}[telegram]\nowner_ids = [42]\n"
    ))
    .unwrap();
    assert!(c.telegram.is_some() && c.whatsapp.is_some());
}

#[test]
fn third_nested_table_still_rejected() {
    for body in [
        format!(
            "root = \"/srv\"\n[telegram]\nowner_ids = [42]\n[whatsapp]\n{WA_MIN}[slack]\nx = 1\n"
        ),
        format!("root = \"/srv\"\n[whatsapp]\n{WA_MIN}[whatsapp.inner]\nx = 1\n"),
        format!("root = \"/srv\"\n[[whatsapp]]\n{WA_MIN}"),
        "root = \"/srv\"\nwhatsapp = \"on\"\n".to_string(),
    ] {
        assert!(load(&body).is_err(), "{body:?}");
    }
    let e = load(&format!(
        "root = \"/srv\"\n[whatsapp]\n{WA_MIN}[slack]\nx = 1\n"
    ))
    .unwrap_err();
    assert!(e.to_string().contains("unknown field `slack`"), "{e}");
    let e = load("root = \"/srv\"\nwhatsapp = \"on\"\n").unwrap_err();
    assert!(
        matches!(e, ConfigError::WrongKind("whatsapp", "a table")),
        "{e:?}"
    );
}

#[test]
fn whatsapp_max_message_age_out_of_range_is_invalid() {
    for v in [9, 3601, 0, -1] {
        let e = wa(&format!("{WA_MIN}max_message_age_secs = {v}\n")).unwrap_err();
        assert!(
            matches!(e, ConfigError::Invalid("whatsapp.max_message_age_secs", _)),
            "{v}: {e:?}"
        );
    }
    for v in [10, 3600] {
        let c = wa(&format!("{WA_MIN}max_message_age_secs = {v}\n")).unwrap();
        assert_eq!(c.whatsapp.unwrap().max_message_age_secs, v);
    }
}

#[test]
fn whatsapp_wrong_kinds_are_named() {
    let pid = "phone_number_id = \"1\"\n";
    for body in [
        format!("owner_numbers = \"155\"\n{pid}"),
        format!("owner_numbers = [155]\n{pid}"),
    ] {
        let e = wa(&body).unwrap_err();
        assert!(
            matches!(
                e,
                ConfigError::WrongKind("whatsapp.owner_numbers", "a list of strings")
            ),
            "{body:?}: {e:?}"
        );
        assert!(e.to_string().contains("whatsapp.owner_numbers"), "{e}");
        assert!(!e.to_string().contains("155"), "{e}");
    }
    let e = wa(&format!("{WA_MIN}listen = 8097\n")).unwrap_err();
    assert!(
        matches!(e, ConfigError::WrongType("whatsapp.listen")),
        "{e:?}"
    );
    assert!(!e.to_string().contains("8097"), "{e}");
    let e = wa(&format!("{WA_MIN}max_message_age_secs = \"60\"\n")).unwrap_err();
    assert!(
        matches!(
            e,
            ConfigError::WrongKind("whatsapp.max_message_age_secs", "an integer")
        ),
        "{e:?}"
    );
    let e = wa(&format!("{WA_MIN}api_base = 5\n")).unwrap_err();
    assert!(
        matches!(e, ConfigError::WrongType("whatsapp.api_base")),
        "{e:?}"
    );
}
