//! Differential fuzz: the current redactor against the frozen round-3
//! redactor (c9ca68f) on an ASCII corpus that avoids the intended later
//! changes (no mid-word key prefixes, no deny-list words, no Mir cards,
//! no non-ASCII). The oracle is one-sided: the current redactor may redact
//! more than the frozen one (later rounds widened the secret words) but must
//! never leak a value the old one removed. On every input it must not panic
//! and must be idempotent.

#[allow(dead_code)]
#[path = "support/redact_c9ca68f.rs"]
mod old;

use warden_agent::redact::redact;

const FRAGS: &[&str] = &[
    // Secret names and parts (no deny-list words).
    "password",
    "PASSWORD",
    "passwd",
    "pwd",
    "secret",
    "SECRET",
    "token",
    "api_key",
    "API-KEY",
    "apikey",
    "access_key",
    "private_key",
    "credentials",
    "DB_",
    "JWT_",
    "_PROD",
    "_2",
    "_VALUE",
    "_SECRET",
    "_KEY",
    "1",
    // Separators and quotes.
    "=",
    ": ",
    " = ",
    ":",
    "\"",
    "'",
    "\\",
    // Secret-looking values and keys (keys always after a space).
    "Zx9qWm2Lp7Rt",
    "hunter22pass",
    " sk-proj1234567890abcdefghijKLMN",
    " AKIAIOSFODNN7EXAMPLE",
    " ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    " sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv",
    " sk_l\x69ve_4eC39HqLyjWDarjtT1zdp7dc",
    " hf_abcdefghijklmnopqrstuvwxyzABCDEF",
    " glpat-abcdefghij0123456789",
    " xoxb-123456789012-abcdefghijkl",
    " Bearer abcDEF0123456789xyzXYZ",
    " Basic dXNlcjpwYXNzd29yZA==",
    " postgres://admin:s3cretpw@db",
    " 4111 1111 1111 1111",
    " 5555555555554444",
    " eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc_-123",
    " -----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----",
    // Filler.
    " ",
    "\n",
    "x",
    "the ",
    ",",
    ";",
    "(",
    ")",
    "{",
    "}",
];

/// Literal secret values present in the corpus. If the old redactor removed
/// one of these from an input, the new output must not contain it either.
const VALUES: &[&str] = &[
    "Zx9qWm2Lp7Rt",
    "hunter22pass",
    "sk-proj1234567890abcdefghijKLMN",
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv",
    "sk_l\x69ve_4eC39HqLyjWDarjtT1zdp7dc",
    "hf_abcdefghijklmnopqrstuvwxyzABCDEF",
    "glpat-abcdefghij0123456789",
    "xoxb-123456789012-abcdefghijkl",
    "abcDEF0123456789xyzXYZ",
    "dXNlcjpwYXNzd29yZA==",
    "s3cretpw",
    "4111 1111 1111 1111",
    "5555555555554444",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc_-123",
];

#[test]
fn ascii_corpus_never_leaks_what_round_3_redacted() {
    let mut seed: u64 = 0x5EED_0005;
    let mut next = |m: usize| {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as usize % m
    };
    let mut redacted_cases = 0;
    // Cases where the guard below actually fired: input has V, old removed V.
    let mut guard_hits = 0usize;
    let mut per_value = vec![0usize; VALUES.len()];
    // Span-count comparison on inputs with no newly added secret word.
    let mut span_cases = 0usize;
    let mut span_deficit = 0usize;
    for _ in 0..60_000 {
        let mut s = String::new();
        for _ in 0..10 {
            s.push_str(FRAGS[next(FRAGS.len())]);
        }
        let new = std::panic::catch_unwind(|| redact(&s).0.into_string())
            .unwrap_or_else(|_| panic!("panic on generated input (len {})", s.len()));
        let old = old::redact(&s).0.into_string();
        // A value present in the input and removed by the old redactor must
        // be absent from the new output (new redacts a superset).
        for (i, v) in VALUES.iter().enumerate() {
            if s.contains(v) && !old.contains(v) {
                guard_hits += 1;
                per_value[i] += 1;
                assert!(!new.contains(v), "leaked {v:?} in {s:?}");
            }
        }
        let lower = s.to_ascii_lowercase();
        if !["credentials", "private", "jwt"]
            .iter()
            .any(|w| lower.contains(w))
        {
            span_cases += 1;
            let (n, o) = (
                new.matches("[REDACTED:").count(),
                old.matches("[REDACTED:").count(),
            );
            if n < o {
                span_deficit += o - n;
            }
        }
        assert_eq!(redact(&new).0.as_str(), new, "{s:?}");
        if new != s {
            redacted_cases += 1;
        }
    }
    // The corpus really exercises the redactor.
    assert!(redacted_cases > 50_000, "{redacted_cases}");
    // The one-sided guard is really exercised, for every value.
    assert!(guard_hits > 1000, "guard fired only {guard_hits} times");
    for (v, n) in VALUES.iter().zip(&per_value) {
        assert!(*n >= 5, "value {v:?} exercised only {n} times");
    }
    assert!(span_cases > 1000, "{span_cases}");
    assert_eq!(
        span_deficit, 0,
        "new redactor has {span_deficit} fewer [REDACTED: spans than the old one over {span_cases} cases"
    );
}
