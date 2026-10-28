//! Tests for `warden agent` config loading.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use warden_agent::config::{
    Config, ConfigError, Provider, TelegramConfig, DEFAULT_TELEGRAM_API_BASE,
    DEFAULT_TELEGRAM_TOKEN_ENV,
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
