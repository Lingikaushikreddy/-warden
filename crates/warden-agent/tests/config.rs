//! Tests for `warden agent` config loading.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use warden_agent::config::{Config, ConfigError, Provider};

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
