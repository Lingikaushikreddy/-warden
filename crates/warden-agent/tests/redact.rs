use serde_json::json;
use std::time::{Duration, Instant};
use warden_agent::redact::{redact, redact_json};

fn out(s: &str) -> String {
    redact(s).0.into_string()
}

#[test]
fn api_key_is_redacted() {
    let cases = [
        "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "sk-proj1234567890abcdefghijKLMN",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "gho_abcdefghijklmnopqrstuvwxyz0123456789",
        "ghu_abcdefghijklmnopqrstuvwxyz0123456789",
        "ghs_abcdefghijklmnopqrstuvwxyz0123456789",
        "ghr_abcdefghijklmnopqrstuvwxyz0123456789",
        "ASIAIOSFODNN7EXAMPLE",
        "sk_t\x65st_4eC39HqLyjWDarjtT1zdp7dc",
        "rk_l\x69ve_4eC39HqLyjWDarjtT1zdp7dc",
        "hf_abcdefghijklmnopqrstuvwxyzABCDEF",
        "glpat-abcdefghij0123456789",
        "xapp-1-A024BE91L1V-1234567890123-abcdef",
        "github_pat_11ABCDEFG0123456789abcd_efghij",
        "xoxb-123456789012-abcdefghijkl",
        "AKIAIOSFODNN7EXAMPLE",
        "AIzaSyA-1234567890abcdefghijklmnopqrstu",
    ];
    for c in cases {
        let (r, rep) = redact(&format!("key {c} end"));
        assert_eq!(r.as_str(), "key [REDACTED:api_key] end", "{c}");
        assert_eq!(rep.kinds, vec!["api_key"]);
        assert_eq!(rep.count, 1);
    }
}

#[test]
fn bearer_is_redacted() {
    let (r, rep) = redact("Authorization: Bearer abcDEF0123456789xyz.tokenpart");
    assert_eq!(r.as_str(), "Authorization: [REDACTED:bearer]");
    assert_eq!(rep.kinds, vec!["bearer"]);
}

#[test]
fn private_key_is_redacted() {
    let s = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
    let (r, rep) = redact(s);
    assert_eq!(r.as_str(), "[REDACTED:private_key]");
    assert_eq!(rep.kinds, vec!["private_key"]);
}

#[test]
fn kv_secret_is_redacted() {
    let (r, rep) = redact("db password=hunter2hunter2 ok");
    assert_eq!(r.as_str(), "db password=[REDACTED:kv_secret] ok");
    assert_eq!(rep.kinds, vec!["kv_secret"]);
}

#[test]
fn card_is_redacted() {
    let (r, rep) = redact("paid with 4111111111111111 today");
    assert_eq!(r.as_str(), "paid with [REDACTED:card] today");
    assert_eq!(rep.kinds, vec!["card"]);
}

#[test]
fn jwt_is_redacted() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let (r, rep) = redact(&format!("id_token {jwt}"));
    assert_eq!(r.as_str(), "id_token [REDACTED:jwt]");
    assert_eq!(rep.kinds, vec!["jwt"]);
}

#[test]
fn luhn_invalid_digits_are_not_redacted() {
    let s = "order number 1234 5678 9012 3456 shipped";
    let (r, rep) = redact(s);
    assert_eq!(r.as_str(), s);
    assert_eq!(rep.count, 0);
}

#[test]
fn valid_card_with_spaces_and_hyphens_is_redacted() {
    assert_eq!(out("card 4111 1111 1111 1111."), "card [REDACTED:card].");
    assert_eq!(out("card 4111-1111-1111-1111."), "card [REDACTED:card].");
}

#[test]
fn pem_block_across_lines_is_redacted() {
    let s = "before\n-----BEGIN PRIVATE KEY-----\nAAA\nBBB\nCCC\n-----END PRIVATE KEY-----\nafter";
    assert_eq!(out(s), "before\n[REDACTED:private_key]\nafter");
}

#[test]
fn unterminated_pem_redacts_to_end() {
    let s = "x\n-----BEGIN EC PRIVATE KEY-----\nAAA\nBBB trailing";
    assert_eq!(out(s), "x\n[REDACTED:private_key]");
}

#[test]
fn kv_secret_keeps_key_name_and_hides_value() {
    assert_eq!(
        out("API_KEY: \"abc123\","),
        "API_KEY: \"[REDACTED:kv_secret]\","
    );
    assert_eq!(out("Passwd = s3cr3t;"), "Passwd = [REDACTED:kv_secret];");
    assert_eq!(
        out("{\"token\":\"zzz\"}"),
        "{\"token\":\"[REDACTED:kv_secret]\"}"
    );
}

#[test]
fn placeholder_keeps_json_valid() {
    let v = json!({"msg": "say \"hi\" password=\"abc\" sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv"});
    let (r, rep) = redact_json(&v);
    let text = serde_json::to_string(&r).unwrap();
    let back: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(back, r);
    assert_eq!(
        r["msg"],
        "say \"hi\" password=\"[REDACTED:kv_secret]\" [REDACTED:api_key]"
    );
    assert_eq!(rep.count, 2);
}

#[test]
fn redact_json_redacts_keys_and_values() {
    let v = json!({
        "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv": ["4111 1111 1111 1111", 5, null, true],
        "n": {"header": "Bearer abcDEF0123456789xyzXYZ"}
    });
    let (r, rep) = redact_json(&v);
    assert_eq!(
        r,
        json!({
            "[REDACTED:api_key]": ["[REDACTED:card]", 5, null, true],
            "n": {"header": "[REDACTED:bearer]"}
        })
    );
    assert_eq!(rep.count, 3);
    assert_eq!(rep.kinds, vec!["bearer", "api_key", "card"]);
}

#[test]
fn unicode_and_emoji_pass_through_unchanged() {
    let s = "héllo wörld 日本語 🚀🔥 Ünïcode ✓ \u{0663}\u{0664}";
    assert_eq!(out(s), s);
}

#[test]
fn very_long_input_is_linear() {
    let chunk =
        "lorem ipsum 12345 password=abcd1234 sk-aaaaaaaaaaaaaaaaaaaaaaaa 4111 1111 1111 1111 - ";
    let mut s = String::new();
    let mut chunks = 0;
    while s.len() < 2_000_000 {
        s.push_str(chunk);
        chunks += 1;
    }
    s.push_str(&"password".repeat(50_000));
    s.push_str(&"1 ".repeat(50_000));
    s.push_str("-----BEGIN PRIVATE KEY-----");
    s.push_str(&"A".repeat(100_000));
    let start = Instant::now();
    let (r, rep) = redact(&s);
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(rep.count, chunks * 3 + 1);
    assert!(!r.as_str().contains("abcd1234"));
    assert!(!r.as_str().contains("sk-aaaa"));
}

#[test]
fn idempotent() {
    let inputs = [
        "password=abc sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv Bearer abcDEF0123456789xyzXYZ",
        "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY----- 4111 1111 1111 1111",
        "api_key=sk-aaaaaaaaaaaaaaaaaaaaaaaa token: \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc_-123\"",
        "plain text 🚀",
        "postgres://admin:s3cretpw@db.example.com/app Authorization: Basic dXNlcjpwYXNz",
        "password=\"correct horse battery staple\" pwd='a b c' x password=\"unterminated",
        "password = 4111 1111 1111 1111 12/26 123 and 1 4111111111111111",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc\n-----END PGP PRIVATE KEY BLOCK-----",
        "DB_PASSWORD=hunter22x STRIPE_SECRET_KEY=sk_t\x65st_4eC39HqLyjWDarjtT1zdp7dc",
        "fn f(token: &str) -> Token::Kind { let token = next_token(); if secret == other {} }",
        "secret=[REDACTED:kv_secret] -----BEGIN RSA PRIVATE KEY-----\nunterminated",
    ];
    for i in inputs {
        let once = out(i);
        let twice = out(&once);
        assert_eq!(once, twice, "{i}");
    }
}

#[test]
fn report_counts_each_match() {
    let (_, rep) = redact("password=abcd1 token=efgh2 4111111111111111 AKIAIOSFODNN7EXAMPLE");
    assert_eq!(rep.count, 4);
    assert_eq!(rep.kinds, vec!["api_key", "card", "kv_secret"]);
}

#[test]
fn text_without_secrets_is_unchanged() {
    let s = "The quick brown fox, 42 items, v1.2.3 at 10:30.";
    let (r, rep) = redact(s);
    assert_eq!(r.as_str(), s);
    assert_eq!(rep.count, 0);
    assert!(rep.kinds.is_empty());
}

#[test]
fn secret_split_by_newline_is_not_claimed_caught() {
    // Documented known limit: patterns are matched per contiguous token.
    let s = "sk-aaaaaaaaaa\naaaaaaaaaaaa";
    assert_eq!(out(s), s);
}

#[test]
fn card_with_adjacent_digits_is_redacted() {
    for (input, rest) in [
        ("4111 1111 1111 1111 12/26 123", "12/26 123"),
        ("1 4111111111111111", "1 "),
        ("4111111111111111-1", "-1"),
    ] {
        let o = out(input);
        assert!(o.contains("[REDACTED:card]"), "{input} -> {o}");
        assert!(!o.contains("4111"), "{input} -> {o}");
        assert!(o.contains(rest), "{input} -> {o}");
    }
}

#[test]
fn card_must_start_with_issuer_digit() {
    // 1234567890123452 is Luhn-valid but starts with 1: left alone.
    let s = "ref 1234567890123452 ok";
    assert_eq!(out(s), s);
}

#[test]
fn json_secret_keys_hide_string_values() {
    let v = json!({"password":"hunter2","api_key":"abcd1234efgh","name":"bob"});
    let (r, rep) = redact_json(&v);
    assert_eq!(
        r,
        json!({"password":"[REDACTED:kv_secret]","api_key":"[REDACTED:kv_secret]","name":"bob"})
    );
    assert_eq!(rep.count, 2);
    assert_eq!(rep.kinds, vec!["kv_secret"]);
}

#[test]
fn json_secret_keys_replace_every_string_and_number_leaf() {
    let v = json!({
        "token": 5, "secret": true, "pwd": "", "flag_password": null,
        "password": {"inner": "x"},
        "tokens": ["a1b2c3d4e5", 7, false],
        "credentials": {"user": "a", "pass": "b"}
    });
    let (r, rep) = redact_json(&v);
    let ph = "[REDACTED:kv_secret]";
    assert_eq!(
        r,
        json!({
            "token": ph, "secret": true, "pwd": "", "flag_password": null,
            "password": {"inner": ph},
            "tokens": [ph, ph, false],
            "credentials": {"user": ph, "pass": ph}
        })
    );
    assert_eq!(rep.count, 6);
}

#[test]
fn json_plural_and_word_keys_follow_the_rules() {
    let v = json!({
        "max_tokens": 1024, "tokens": "plainstring", "author": "alice", "tokenizer": "x",
        "secretary": "alice", "password_hash": "abc", "token_count": 5,
        "auth": "abcd", "pass": "abcd", "passphrase": "abcd", "x_auth_token": "abcd"
    });
    let (r, _) = redact_json(&v);
    let ph = "[REDACTED:kv_secret]";
    assert_eq!(
        r,
        json!({
            "max_tokens": 1024, "tokens": "plainstring", "author": "alice", "tokenizer": "x",
            "secretary": "alice", "password_hash": "abc", "token_count": 5,
            "auth": ph, "pass": ph, "passphrase": ph, "x_auth_token": ph
        })
    );
}

#[test]
fn quoted_kv_values_are_fully_redacted() {
    assert_eq!(
        out("password=\"correct horse battery staple\" end"),
        "password=\"[REDACTED:kv_secret]\" end"
    );
    assert_eq!(out("pwd='a b c' end"), "pwd='[REDACTED:kv_secret]' end");
    assert_eq!(
        out("password=\"abc\ndef"),
        "password=\"[REDACTED:kv_secret]\ndef"
    );
}

#[test]
fn kv_card_value_leaves_no_digits() {
    let o = out("password = 4111 1111 1111 1111");
    assert!(!o.chars().any(|c| c.is_ascii_digit()), "{o}");
}

#[test]
fn url_userinfo_password_is_redacted() {
    assert_eq!(
        out("postgres://admin:s3cretpw@db.example.com:5432/app"),
        "postgres://admin:[REDACTED:kv_secret]@db.example.com:5432/app"
    );
    let plain = "http://localhost:8080/path@x";
    assert_eq!(out(plain), plain);
}

#[test]
fn basic_auth_is_redacted() {
    assert_eq!(
        out("Authorization: Basic dXNlcjpwYXNzd29yZA=="),
        "Authorization: [REDACTED:bearer]"
    );
    assert_eq!(
        out("use basic dXNlcjpwYXNzd29yZA== now"),
        "use [REDACTED:bearer] now"
    );
    let prose = "Basic configuration steps";
    assert_eq!(out(prose), prose);
}

#[test]
fn identifier_wrapped_secret_names_are_redacted() {
    assert_eq!(
        out("DB_PASSWORD=hunter22x"),
        "DB_PASSWORD=[REDACTED:kv_secret]"
    );
    assert_eq!(
        out("SECRET_KEY=django-abc"),
        "SECRET_KEY=[REDACTED:kv_secret]"
    );
    assert_eq!(
        out("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG"),
        "AWS_SECRET_ACCESS_KEY=[REDACTED:kv_secret]"
    );
    assert_eq!(
        out("client_secret: abcd1234"),
        "client_secret: [REDACTED:kv_secret]"
    );
    assert_eq!(
        out("STRIPE_SECRET_KEY=sk_t\x65st_4eC39HqLyjWDarjtT1zdp7dc"),
        "STRIPE_SECRET_KEY=[REDACTED:api_key]"
    );
}

#[test]
fn pgp_private_key_block_is_redacted() {
    let s = "a\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nxyz\n-----END PGP PRIVATE KEY BLOCK-----\nb";
    assert_eq!(out(s), "a\n[REDACTED:private_key]\nb");
}

#[test]
fn source_code_is_not_mangled() {
    let s = "fn f(token: &str) -> Token::Kind { let token = next_token(); if secret == other {} }";
    assert_eq!(out(s), s);
    let with_secret = format!("{s} let k = \"sk-aaaaaaaaaaaaaaaaaaaaaaaa\";");
    assert_eq!(
        out(&with_secret),
        format!("{s} let k = \"[REDACTED:api_key]\";")
    );
}

#[test]
fn separator_does_not_cross_newlines() {
    let s = "Password:\nusername=bob";
    assert_eq!(out(s), s);
}

#[test]
fn idempotent_on_generated_mixtures() {
    let frags = [
        "password=",
        "Bearer ",
        "sk-",
        "aaaaaaaaaaaaaaaaaaaaaaaa",
        " ",
        "\n",
        "\"",
        "'",
        "4111 1111 1111 1111",
        "4111",
        "-",
        "://u:",
        "@h",
        "token: ",
        "Basic ",
        "dXNlcjpwYXNz",
        "-----BEGIN PRIVATE KEY-----",
        "x",
        "eyJa.b.c",
        "[REDACTED:card]",
        "12",
        "=",
        "\\",
        "sk_t\x65st_4eC39HqLyjWDarjtT1zdp7dc",
        "hf_abcdefghijklmnopqrstuvwxyzABCDEF",
        "glpat-abcdefghij0123456789",
        "xapp-1-A024BE91L1V-1234567890123-abcdef",
        "ASIAIOSFODNN7EXAMPLE",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "DB_PASSWORD=",
        "redis://:",
        "hunter2pass@cache",
        "5 5 5 5",
        "3782 822463 10005",
        "4444 4444 4444 4444 444",
        "{\"password\":\"",
        "[REDACTED:kv_secret]",
        "dXNlcjpwYXNzd29yZA==",
        "Authorization: ",
        "risk-assessment-for-the-quarter",
        "task",
        "-management-system-configuration",
        "network_test_connectivitycheckall",
        "AKIAIOSFODNN7EXAMPLE",
        "sk-proj1234567890abcdefghijKLMN",
        "(",
        "token_budget: ",
        "2200 1234 5678 9019",
    ];
    let mut seed: u64 = 0x9E3779B97F4A7C15;
    for _ in 0..20_000 {
        let mut s = String::new();
        for _ in 0..12 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            s.push_str(frags[(seed >> 33) as usize % frags.len()]);
        }
        let once = out(&s);
        assert_eq!(once, out(&once), "{s:?}");
    }
}

#[test]
fn card_scan_is_linear_on_digit_runs() {
    for unit in ["5 ", "5-", "55 55 55 ", "4 ", "4444 "] {
        let s = unit.repeat(2_000_000 / unit.len());
        let start = Instant::now();
        let (_, rep) = redact(&s);
        let t = start.elapsed();
        eprintln!("digit run {unit:?} x {}: {t:?}", s.len());
        assert!(t < Duration::from_secs(2), "{unit:?}: {t:?}");
        assert_eq!(rep.count, 0, "{unit:?}");
    }
}

#[test]
fn lists_of_small_numbers_are_not_cards() {
    let mut cases = vec![
        format!(
            "values {}",
            (1..=14)
                .map(|n| (n * 5).to_string())
                .collect::<Vec<_>>()
                .join(" ")
        ),
        format!(
            "ids: {}",
            (2..=17)
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        ),
    ];
    let mut seed: u64 = 12345;
    let mut next = |m: u64| {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) % m
    };
    for _ in 0..1000 {
        cases.push(
            (0..20)
                .map(|_| next(100).to_string())
                .collect::<Vec<_>>()
                .join(" "),
        );
        cases.push(
            (0..10)
                .map(|_| next(1000).to_string())
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    for c in cases {
        let (r, rep) = redact(&c);
        assert_eq!(rep.count, 0, "{c}");
        assert_eq!(r.as_str(), c);
    }
}

#[test]
fn amex_and_other_real_formats_are_redacted() {
    assert_eq!(out("amex 3782 822463 10005 ok"), "amex [REDACTED:card] ok");
    assert_eq!(
        out("diners 3056 930902 5904 ok"),
        "diners [REDACTED:card] ok"
    );
    assert!(out("19 digits 6200 0000 0000 0000 000 x").contains("[REDACTED:card]"));
}

#[test]
fn kv_does_not_fire_on_lookalike_identifiers() {
    for s in [
        "max_tokens: 1024",
        "\"token_count\": 12345",
        "tokens: list[str] = []",
        "password_hash: hashlib.sha256",
        "tokenizer: bert-base-uncased",
        "{\"tokenizer\":\"x\",\"secretary\":\"alice\"}",
        "Basic HTTPServer setup",
    ] {
        assert_eq!(out(s), s);
    }
    assert_eq!(
        out("auth_token=abcd1234"),
        "auth_token=[REDACTED:kv_secret]"
    );
}

#[test]
fn standalone_basic_needs_long_base64() {
    let s = "Basic abcd1234";
    assert_eq!(out(s), s);
    assert_eq!(out("Basic dXNlcjpwYXNzd29yZA=="), "[REDACTED:bearer]");
}

#[test]
fn empty_username_url_password_is_redacted() {
    assert_eq!(
        out("redis://:hunter2pass@cache:6379/0"),
        "redis://:[REDACTED:kv_secret]@cache:6379/0"
    );
}

#[test]
fn url_with_card_in_password_is_idempotent() {
    let once = out("postgres://u:=3782 822463 10005@h");
    assert!(!once.contains("3782"));
    assert_eq!(out(&once), once);
}

#[test]
fn quoted_value_containing_a_placeholder_is_hidden_whole() {
    let o = out("password = \"4111111111111111 hunter2\"");
    assert!(!o.contains("hunter2"), "{o}");
    assert_eq!(o, "password = \"[REDACTED:kv_secret]\"");
    let o = out("password=sk-aaaaaaaaaaaaaaaaaaaaaaaa.hunter2");
    assert!(!o.contains("hunter2"), "{o}");
}

#[test]
fn escaped_quote_inside_json_value_is_covered() {
    let o = out("{\"password\":\"abc\\\"def\"}");
    assert_eq!(o, "{\"password\":\"[REDACTED:kv_secret]\"}");
}

#[test]
fn kv_suffixes_are_not_a_leak() {
    for (input, expected) in [
        (
            "SECRET_KEY_BASE=abcd1234",
            "SECRET_KEY_BASE=[REDACTED:kv_secret]",
        ),
        (
            "secret_key_base: abcd1234",
            "secret_key_base: [REDACTED:kv_secret]",
        ),
        (
            "DATABASE_PASSWORD_PROD=abcd1234",
            "DATABASE_PASSWORD_PROD=[REDACTED:kv_secret]",
        ),
        (
            "OPENAI_API_KEY_2=abcd1234",
            "OPENAI_API_KEY_2=[REDACTED:kv_secret]",
        ),
        ("TOKEN_PROD=abcd1234", "TOKEN_PROD=[REDACTED:kv_secret]"),
        ("password1=abcd1234", "password1=[REDACTED:kv_secret]"),
    ] {
        assert_eq!(out(input), expected);
    }
    let (r, _) =
        redact_json(&json!({"SECRET_KEY_BASE":"x1","db_password_prod":"y1","tokenizer":"z"}));
    assert_eq!(
        r,
        json!({"SECRET_KEY_BASE":"[REDACTED:kv_secret]","db_password_prod":"[REDACTED:kv_secret]","tokenizer":"z"})
    );
}

#[test]
fn deny_listed_suffixes_stay_untouched() {
    for s in [
        "max_tokens: 1024",
        "token_count=123456",
        "password_hash: abcdefgh",
        "tokenizer: bert-base",
        "secretary: alice-smith",
        "token_path = /etc/token",
        "secret_name: my-secret-name",
        "token_ttl: 360000",
        "api_key_id: abcd1234",
        "password_confirmation: abcd1234",
        "token-count: 123456",
    ] {
        assert_eq!(out(s), s);
    }
}

#[test]
fn credentials_are_secret() {
    assert_eq!(
        out("credentials: \"user:hunter22\""),
        "credentials: \"[REDACTED:kv_secret]\""
    );
    assert_eq!(
        out("credentials: abcd1234"),
        "credentials: [REDACTED:kv_secret]"
    );
    let (r, _) = redact_json(&json!({"credentials":"user:hunter22"}));
    assert_eq!(r, json!({"credentials":"[REDACTED:kv_secret]"}));
}

#[test]
fn chained_aws_keys_are_fully_redacted_in_one_pass() {
    for n in [10, 100, 1000] {
        let s = "AKIAIOSFODNN7EXAMPLE".repeat(n);
        let (r, rep) = redact(&s);
        assert!(!r.as_str().contains("AKIA"), "n={n}");
        assert_eq!(r.as_str(), "[REDACTED:api_key]".repeat(n));
        assert_eq!(rep.count, n);
        assert_eq!(out(r.as_str()), r.as_str());
    }
}

#[test]
fn adversarial_key_chain_with_digit_spam_is_linear() {
    let mut s = "AKIAIOSFODNN7EXAMPLE".repeat(50_000);
    s.push_str(&"5 4 ".repeat(250_000));
    let start = Instant::now();
    let (r, _) = redact(&s);
    let t = start.elapsed();
    eprintln!("AKIA chain + digit spam x {}: {t:?}", s.len());
    assert!(t < Duration::from_secs(2), "{t:?}");
    assert!(!r.as_str().contains("AKIA"));
}

#[test]
fn real_card_shapes_are_redacted() {
    for (input, ok) in [
        ("6011 1111 1111 1117", true),
        ("6011-1111-1111-1117", true),
        ("2221 0000 0000 0009", true),
        ("5555 5555 5555 4444", true),
        ("3782 822463 10005", true),
        ("3787 344936 71000", true),
        ("3056 930902 5904", true),
        ("3782 8224 6310 005", true),
        ("4000 0000 0000 0000 006", true),
        ("4000-0000-0000-0000-006", true),
        ("4111 1111-1111 1111", false),
    ] {
        let o = out(&format!("n {input} x"));
        assert_eq!(o.contains("[REDACTED:card]"), ok, "{input} -> {o}");
    }
    assert!(out("n 4111 1111-1111 1111 x").contains("4111 1111-1111"));
}

#[test]
fn number_lists_that_pass_luhn_are_not_cards() {
    for s in ["2000 3000 4000 5000 600", "bytes 2048 4096 8192 1638 400"] {
        assert_eq!(out(s), s);
    }
}

fn luhn_ref(d: &[u8]) -> bool {
    let mut sum = 0u32;
    for (i, b) in d.iter().rev().enumerate() {
        let mut n = u32::from(b - b'0');
        if i % 2 == 1 {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
    }
    #[allow(clippy::manual_is_multiple_of)]
    let ok = sum % 10 == 0;
    ok
}

/// Independent reference: leftmost, longest window of a real shape that passes
/// Luhn and starts with a plausible prefix (single spaces only).
fn expected_cards(nums: &[String]) -> usize {
    let shapes: [&[usize]; 5] = [
        &[4, 4, 4, 4],
        &[4, 4, 4, 4, 3],
        &[4, 6, 5],
        &[4, 6, 4],
        &[4, 4, 4, 3],
    ];
    let plausible = |d: &str| {
        let b = d.as_bytes();
        match b[0] {
            b'4' | b'5' | b'6' => true,
            b'2' => {
                let n = d[..4].parse::<u32>().unwrap();
                (2200..=2204).contains(&n) || (2221..=2720).contains(&n)
            }
            b'3' => matches!(b[1], b'0' | b'4'..=b'9'),
            _ => false,
        }
    };
    let mut count = 0;
    let mut i = 0;
    while i < nums.len() {
        let mut hit = None;
        for j in (i..nums.len().min(i + 5)).rev() {
            let w = &nums[i..=j];
            let digits: String = w.concat();
            let single = w.len() == 1
                && (13..=19).contains(&digits.len())
                && (b'2'..=b'6').contains(&digits.as_bytes()[0]);
            let multi = w.len() > 1
                && shapes
                    .iter()
                    .any(|s| s.len() == w.len() && s.iter().zip(w).all(|(l, g)| g.len() == *l))
                && plausible(&digits);
            if (single || multi) && luhn_ref(digits.as_bytes()) {
                hit = Some(j);
                break;
            }
        }
        match hit {
            Some(j) => {
                count += 1;
                i = j + 1;
            }
            None => i += 1,
        }
    }
    count
}

#[test]
fn generated_number_rows_only_redact_real_luhn_valid_windows() {
    let mut seed: u64 = 777;
    let mut next = |m: u64| {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) % m
    };
    let (mut total_expected, mut total_actual) = (0, 0);
    for shape in 0..3 {
        for _ in 0..5000 {
            let nums: Vec<String> = match shape {
                0 => (0..5).map(|_| format!("{:04}", next(10000))).collect(),
                1 => (0..6).map(|_| format!("{:04}", next(10000))).collect(),
                _ => (0..8).map(|_| next(100000).to_string()).collect(),
            };
            let row = nums.join(" ");
            let (_, rep) = redact(&row);
            let exp = expected_cards(&nums);
            assert_eq!(rep.count, exp, "{row}");
            total_expected += exp;
            total_actual += rep.count;
        }
    }
    assert_eq!(total_expected, total_actual);
    // Roughly one Luhn pass in ten per four-digit window: a handful, not thousands.
    assert!(total_actual < 4000, "{total_actual}");
}

const KEBAB_NAMES: [&str; 12] = [
    "risk-assessment-for-the-quarter",
    "disk-usage-monitoring-dashboard.md",
    "task-management-system-configuration",
    "desk-reservation-service-handler",
    "mask-sensitive-fields-in-logs",
    "ask-for-approval-before-executing",
    "git checkout fix/task-queue-deadlock-on-shutdown",
    "docs/risk-register-template-2026.md",
    "kiosk-mode-browser-launcher",
    "network_test_connectivitycheckall",
    "benchmark_test_serializationspeed",
    "whisk_live_streamingdashboardconfigv2",
];

#[test]
fn kebab_and_snake_names_are_not_mangled() {
    for s in KEBAB_NAMES {
        assert_eq!(out(s), s);
        let quoted = format!("open \"{s}\" now");
        assert_eq!(out(&quoted), quoted);
    }
}

#[test]
fn generated_sk_word_grid_is_not_mangled() {
    let words = [
        "risk", "disk", "task", "desk", "mask", "ask", "kiosk", "whisk", "flask", "dusk", "husk",
        "tusk",
    ];
    let tails = [
        "-assessment-for-the-quarter",
        "-usage-monitoring-dashboard",
        "-management-system-configuration",
        "-reservation-service-handler-v2",
        "-sensitive-fields-in-the-logs",
        "-queue-deadlock-on-shutdown-fix",
        "-register-template-2026-final",
        "_test_connectivitycheckallnodes",
    ];
    let mut n = 0;
    for w in words {
        for t in tails {
            let s = format!("see {w}{t} and branch fix/{w}{t}");
            assert_eq!(out(&s), s);
            n += 1;
        }
    }
    assert_eq!(n, 96);
}

#[test]
fn bounded_prefix_keys_after_delimiters_are_redacted() {
    let keys = [
        "sk-proj1234567890abcdefghijKLMN",
        "sk_l\x69ve_4eC39HqLyjWDarjtT1zdp7dc",
        "rk_t\x65st_4eC39HqLyjWDarjtT1zdp7dc",
        "hf_abcdefghijklmnopqrstuvwxyzABCDEF",
        "glpat-abcdefghij0123456789",
        "xapp-1-A024BE91L1V-1234567890123-abcdef",
        "xoxb-123456789012-abcdefghijkl",
        "github_pat_11ABCDEFG0123456789abcd_efghij",
    ];
    for k in keys {
        for (pre, post) in [
            ("", ""),
            (" ", ""),
            ("\"", "\""),
            ("x=", ""),
            ("(", ")"),
            ("a\n", ""),
            ("'", "'"),
            ("é ", ""),
        ] {
            let s = format!("{pre}{k}{post}");
            let o = out(&s);
            assert_eq!(o, format!("{pre}[REDACTED:api_key]{post}"), "{s:?}");
        }
    }
    // Distinctive or fixed-length prefixes stay boundary-free.
    for k in [
        "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "AIzaSyA-1234567890abcdefghijklmnopqrstu",
    ] {
        assert_eq!(out(&format!("xyz{k}")), "xyz[REDACTED:api_key]", "{k}");
    }
}

#[test]
fn mixed_key_chains_are_fully_redacted() {
    let sk = "sk-proj1234567890abcdefghijKLMN";
    let aws = "AKIAIOSFODNN7EXAMPLE";
    for s in [
        format!("{aws}{sk}"),
        format!("{aws}{sk}{aws}{sk}"),
        format!("x {aws}{aws}{aws}{sk}"),
        format!("{}{sk}", aws.repeat(200)),
    ] {
        let (r, _) = redact(&s);
        assert!(!r.as_str().contains("AKIA"), "{s}");
        assert!(!r.as_str().contains("sk-"), "{s} -> {r}");
        assert!(!r.as_str().contains("overflow"), "{s} -> {r}");
        assert_eq!(out(r.as_str()), r.as_str());
    }
}

#[test]
fn compound_non_secret_suffixes_are_left_alone() {
    for s in [
        "token_budget: 4096",
        "password_field: input_pw",
        "token_endpoint: https://auth.example.com/oauth/token",
        "secret_arn: arn:aws:secretsmanager:us-east-1:123:secret:x",
        "api_key_header: X-Api-Key",
        "token_usage: 123456",
        "secret_ref: vault-main",
        "password_strength: strong",
        "token_lifetime: 3600s",
        "secret_version: v12345",
        "token_index: 12345",
        "password_required: false",
        "token_position: 12345",
        "password_min_length: 12345",
        "password_max_length: 12345",
        "token_budget_total: 4096",
        "token_count_total: 12345",
    ] {
        assert_eq!(out(s), s);
    }
    let v = json!({"password_min_length":12,"token_budget":4096,"password_required":true,
                   "token_usage":{"prompt":5}});
    let (r, rep) = redact_json(&v);
    assert_eq!(r, v);
    assert_eq!(rep.count, 0);
}

#[test]
fn compound_suffixes_do_not_hide_real_secrets() {
    for k in [
        "JWT_SECRET",
        "SECRET_KEY_BASE",
        "DATABASE_PASSWORD_PROD",
        "TOKEN_PROD",
        "OPENAI_API_KEY_2",
        "password1",
        "SECRET_TOKEN_VALUE",
        "PASSWORD_SALT",
        "secret_value",
        "api_key_secret",
        "SECRET_KEY_FILE",
    ] {
        assert_eq!(
            out(&format!("{k}=abcd1234")),
            format!("{k}=[REDACTED:kv_secret]")
        );
        let (r, _) = redact_json(&json!({ k: 4096 }));
        assert_eq!(r, json!({ k: "[REDACTED:kv_secret]" }), "{k}");
    }
}

#[test]
fn mir_cards_are_redacted() {
    for s in [
        "2200 1234 5678 9019",
        "2200-1234-5678-9019",
        "2204 1234 5678 9015",
    ] {
        assert_eq!(out(&format!("n {s} x")), "n [REDACTED:card] x", "{s}");
    }
}

#[test]
fn many_short_kv_matches_are_fast() {
    for unit in ["pwd:\"x\" ", "token=abcd "] {
        let s = unit.repeat(2_000_000 / unit.len());
        let start = Instant::now();
        let (r, rep) = redact(&s);
        let t = start.elapsed();
        eprintln!("kv run {unit:?} x {}: {t:?}", s.len());
        assert!(t < Duration::from_secs(2), "{unit:?}: {t:?}");
        assert_eq!(rep.count, 2_000_000 / unit.len());
        assert!(!r.as_str().contains("abcd") && !r.as_str().contains("\"x\""));
    }
}

fn no_panic(s: &str) -> String {
    let r = std::panic::catch_unwind(|| redact(s).0.into_string());
    match r {
        Ok(o) => o,
        Err(_) => panic!("redact panicked on a generated input (len {})", s.len()),
    }
}

#[test]
fn unicode_case_folded_keywords_do_not_panic_and_are_redacted() {
    for (input, secret) in [
        ("ſecret=hunter22", "hunter22"),
        ("to\u{212A}en=hunter22", "hunter22"),
        ("password\u{212A}=hunter22", "hunter22"),
        ("tokenſ: hunter22", "hunter22"),
        ("paſſword: \"x y\"", "x y"),
        ("api_\u{212A}ey=abcd1234", "abcd1234"),
        ("secret_\u{212A}=abcd1234", "abcd1234"),
        ("ſecret=hunter22-REAL-SECRET-VALUE", "REAL-SECRET"),
    ] {
        let o = no_panic(input);
        assert!(o.contains("[REDACTED:kv_secret]"), "{input} -> {o}");
        assert!(!o.contains(secret), "{input} -> {o}");
        assert_eq!(no_panic(&o), o);
    }
    let v = json!({"ſecret": "hunter22", "to\u{212A}en": 5, "paſſ": "x"});
    let (r, _) = std::panic::catch_unwind(|| redact_json(&v)).expect("no panic");
    let ph = "[REDACTED:kv_secret]";
    assert_eq!(r, json!({"ſecret": ph, "to\u{212A}en": ph, "paſſ": ph}));
}

#[test]
fn generated_unicode_corpus_never_panics() {
    let frags = [
        "password",
        "PASSWD",
        "pwd",
        "secret",
        "Token",
        "api_key",
        "api-key",
        "apikey",
        "access_key",
        "private-key",
        "credentials",
        "auth",
        "pass",
        "passphrase",
        "ſ",
        "\u{212A}",
        "\u{212B}",
        "é",
        "日本",
        "🚀",
        "\u{0301}",
        "İ",
        "ı",
        "ß",
        "=",
        ":",
        "\"",
        "'",
        "\\",
        " ",
        "\t",
        "\n",
        "_",
        "-",
        "s",
        "k",
        "sk-",
        "sk_l\x69ve_",
        "rk_t\x65st_",
        "hf_",
        "glpat-",
        "xapp-",
        "xoxb-",
        "github_pat_",
        "AKIA",
        "ghp_",
        "AIza",
        "sk-ant-api03-",
        "Bearer ",
        "Basic ",
        "://u:",
        "@h",
        "4111 1111",
        "2200",
        "[REDACTED:kv_secret]",
        "[REDACTED:",
        "aaaaaaaaaaaaaaaaaaaaaaaa",
        "-----BEGIN PRIVATE KEY-----",
        "eyJa.b.c",
        "{",
        "}",
    ];
    let mut seed: u64 = 0xDEADBEEF;
    let mut next = |m: usize| {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as usize % m
    };
    for _ in 0..10_000 {
        let mut s = String::new();
        for _ in 0..12 {
            s.push_str(frags[next(frags.len())]);
        }
        // A truncated copy at a random char boundary.
        let cut = s
            .char_indices()
            .map(|(i, _)| i)
            .nth(next(s.chars().count().max(1)))
            .unwrap_or(0);
        for t in [s.as_str(), &s[..cut], &s[cut..]] {
            let once = no_panic(t);
            assert_eq!(no_panic(&once), once, "{t:?}");
            let v = json!({ t: t, "k": [t, {"password": t}] });
            assert!(
                std::panic::catch_unwind(|| redact_json(&v)).is_ok(),
                "redact_json panicked (len {})",
                t.len()
            );
        }
    }
}

const COMPOUND_SECRET_NAMES: [&str; 16] = [
    "TOKEN_HASH_SECRET",
    "SECRET_NAME_PASSWORD",
    "SECRET_FILE_PASSWORD",
    "TOKEN_TYPE_SECRET",
    "TOKEN_ENDPOINT_SECRET",
    "TOKEN_PATH_SECRET",
    "TOKEN_ID_SECRET",
    "API_KEY_REF_SECRET",
    "SECRET_REF_TOKEN",
    "SECRET_VERSION_KEY",
    "SECRET_MAX_KEY",
    "TOKEN_URL_WITH_KEY",
    "PASSWORD_FILE_CONTENTS",
    "PASSWORD_FIELD_VALUE",
    "SECRET_ID_VALUE",
    "API_KEY_HEADER_VALUE",
];

const COMPOUND_PLAIN_NAMES: [&str; 22] = [
    "API_KEY_ID",
    "ACCESS_KEY_ID",
    "PASSWORD_FILE",
    "TOKEN_FILE",
    "token_budget",
    "password_field",
    "token_endpoint",
    "secret_arn",
    "api_key_header",
    "token_usage",
    "secret_ref",
    "password_strength",
    "token_lifetime",
    "secret_version",
    "token_index",
    "password_required",
    "token_position",
    "password_hash",
    "max_tokens",
    "token_count",
    "tokenizer",
    "secretary",
];

#[test]
fn compound_names_with_a_secret_word_after_the_deny_word_are_redacted() {
    let ph = "[REDACTED:kv_secret]";
    for k in COMPOUND_SECRET_NAMES {
        let lower = k.to_ascii_lowercase();
        for name in [k.to_string(), lower] {
            assert_eq!(out(&format!("{name}=Zx9qWm2Lp7Rt")), format!("{name}={ph}"));
            assert_eq!(
                out(&format!("{name}: \"Zx9qWm2Lp7Rt\"")),
                format!("{name}: \"{ph}\"")
            );
            let (r, _) = redact_json(&json!({ name.as_str(): "Zx9qWm2Lp7Rt", "n": 1 }));
            assert_eq!(r, json!({ name.as_str(): ph, "n": 1 }), "{name}");
        }
    }
    // camelCase words count as delimited words too.
    assert_eq!(
        out("tokenHash_mySecret=Zx9qWm2Lp7Rt"),
        format!("tokenHash_mySecret={ph}")
    );
    assert_eq!(
        out("token_hashSecret=Zx9qWm2Lp7Rt"),
        format!("token_hashSecret={ph}")
    );
}

#[test]
fn compound_names_without_a_secret_word_stay_plain() {
    for k in COMPOUND_PLAIN_NAMES {
        let s = format!("{k}=Zx9qWm2Lp7Rt");
        assert_eq!(out(&s), s);
        let v = json!({ k: "Zx9qWm2Lp7Rt", "n": 4096 });
        let (r, _) = redact_json(&v);
        assert_eq!(r, v, "{k}");
        let v = json!({ k: 4096 });
        assert_eq!(redact_json(&v).0, v, "{k}");
    }
}

#[test]
fn anthropic_prefix_needs_the_real_layout_mid_word() {
    for s in [
        "risk-ant-colony-optimization-algorithm-v2",
        "task-ant-design-component-library",
        "see risk-ant-colony-optimization-algorithm-v2 and fix/task-ant-design-component-library",
    ] {
        assert_eq!(out(s), s);
    }
    for k in [
        "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv",
        "sk-ant-admin01-AbCdEfGhIjKlMnOpQrStUv",
    ] {
        assert_eq!(out(&format!("xyz{k}")), "xyz[REDACTED:api_key]");
        assert_eq!(out(&format!("key {k} end")), "key [REDACTED:api_key] end");
    }
    // Documented: `-` is a boundary, so a word that starts with `sk-` and runs
    // 20+ chars after it is still redacted.
    assert_eq!(
        out("use-sk-learn-pipeline-configuration-v2"),
        "use-[REDACTED:api_key]"
    );
}

const NEW_SECRET_NAMES: &[&str] = &[
    "SECRET_HASH_PEPPER",
    "TOKEN_ID_PRIVATE",
    "TOKEN_HASH_SIGNING",
    "PASSWORD_FILE_CLEAR",
    "SECRET_REF_CREDENTIALS",
    "TOKEN_HASH_HMAC",
    "TOKEN_TYPE_JWT",
    "SECRET_ID_CERT",
    "PASSWORD_MIN_PIN",
    "TOKEN_FILE_PASS",
    "SECRET_PATH_PASSPHRASE",
    "SECRET_ID_AUTH",
];

#[test]
fn extended_secret_words_are_redacted_in_text_and_json() {
    for name in NEW_SECRET_NAMES {
        let text = format!("{name}=Zx9qWm2Lp7Rt");
        assert!(!out(&text).contains("Zx9qWm2Lp7Rt"), "text {name}");
        let (v, _) = redact_json(&json!({ *name: "Zx9qWm2Lp7Rt" }));
        assert!(!v.to_string().contains("Zx9qWm2Lp7Rt"), "json {name}");
    }
}

#[test]
fn non_secret_names_stay_unredacted() {
    for line in [
        "API_KEY_ID=AbCdEf123456",
        "ACCESS_KEY_ID=AbCdEf123456",
        "PASSWORD_FILE=/run/secrets/pw",
        "TOKEN_FILE=/run/secrets/t",
        "token_budget: 4096",
        "max_tokens: 1024",
        "secretary: alice",
    ] {
        assert_eq!(out(line), line, "{line}");
    }
}

/// Pinned behavior (documented, not necessarily ideal): SECRET_WORDS contain
/// `pass`, `clear`, so these deny-word names become secret again and ARE
/// redacted, while names with no secret word after the deny word stay clear.
#[test]
fn new_secret_words_false_positive_guards() {
    // `max` is a deny word and `pass` a secret word: redacted (pinned).
    assert!(!out("token_max_pass: xyz123456").contains("xyz123456"));
    // `field` deny, `clear` secret: redacted (pinned).
    assert!(!out("password_field_clear: xyz123456").contains("xyz123456"));
    // No secret word in the suffix: unredacted.
    assert_eq!(out("token_budget_total: 4096"), "token_budget_total: 4096");
    assert_eq!(out("password_min_length: 12"), "password_min_length: 12");
    // `pass` only as a glued fragment is not a word.
    assert_eq!(out("token_bypass_count: 3"), "token_bypass_count: 3");
}

#[test]
fn telegram_bot_token_is_redacted() {
    let tail = "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ";
    assert_eq!(tail.len(), 35);
    for c in [
        format!("123456789:{tail}"),
        format!("12345678:{tail}"),
        format!("1234567890:{tail}"),
    ] {
        let (r, rep) = redact(&format!("key {c} end"));
        assert_eq!(r.as_str(), "key [REDACTED:api_key] end", "{c}");
        assert_eq!(rep.kinds, vec!["api_key"]);
        assert_eq!(rep.count, 1);
        // At the start of the text and after a boundary char.
        assert_eq!(out(&c), "[REDACTED:api_key]", "{c}");
        assert_eq!(
            out(&format!("bot{c}")),
            format!("bot{c}"),
            "needs a boundary"
        );
        assert_eq!(
            out(&format!("url=/bot/{c}/x")),
            "url=/bot/[REDACTED:api_key]/x"
        );
    }
}

#[test]
fn ratios_and_times_are_not_redacted() {
    let short = "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw";
    assert_eq!(short.len(), 34);
    for line in [
        "meet at 10:30".to_string(),
        "ratio 12345678:abc".to_string(),
        format!("x 123456789:{short}"),
        format!("x 1234567:{short}Q"),
    ] {
        assert_eq!(out(&line), line, "{line}");
    }
}
