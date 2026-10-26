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
