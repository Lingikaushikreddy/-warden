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
    assert_eq!(rep.count, 2);
    assert!(!text.contains("abc\\\""));
}

#[test]
fn redact_json_redacts_keys_and_values() {
    let v = json!({
        "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv": ["4111 1111 1111 1111", 5, null, true],
        "n": {"auth": "Bearer abcDEF0123456789xyzXYZ"}
    });
    let (r, rep) = redact_json(&v);
    assert_eq!(
        r,
        json!({
            "[REDACTED:api_key]": ["[REDACTED:card]", 5, null, true],
            "n": {"auth": "[REDACTED:bearer]"}
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
    let chunk = "lorem ipsum 12345 password=abc sk-aaaaaaaaaaaaaaaaaaaaaaaa 4111 1111 1111 1111 - ";
    let mut s = String::new();
    while s.len() < 2_000_000 {
        s.push_str(chunk);
    }
    s.push_str("-----BEGIN PRIVATE KEY-----");
    s.push_str(&"A".repeat(100_000));
    let start = Instant::now();
    let (r, rep) = redact(&s);
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "{:?}",
        start.elapsed()
    );
    assert!(rep.count > 1000);
    assert!(!r.as_str().contains("hunter"));
}

#[test]
fn idempotent() {
    let inputs = [
        "password=abc sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv Bearer abcDEF0123456789xyzXYZ",
        "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY----- 4111 1111 1111 1111",
        "api_key=sk-aaaaaaaaaaaaaaaaaaaaaaaa token: \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc_-123\"",
        "plain text 🚀",
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
    let (_, rep) = redact("password=a1 token=b2 4111111111111111 AKIAIOSFODNN7EXAMPLE");
    assert_eq!(rep.count, 4);
    assert_eq!(rep.kinds, vec!["api_key", "kv_secret", "card"]);
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
