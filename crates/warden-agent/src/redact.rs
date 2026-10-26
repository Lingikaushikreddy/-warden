//! Secret redaction: the gate in front of every cloud model call.
//!
//! Nothing may be sent to a cloud model unless it has the type [`Redacted`],
//! and `Redacted` can only be produced by [`redact`] / [`redact_json`] in this
//! module (its field is private and there is no public constructor).
//!
//! # Known limits
//!
//! Redaction is pattern-based. It does not catch:
//! - secret formats it has no pattern for;
//! - secrets that were base64- or otherwise obfuscated;
//! - secrets split across tokens or lines (for example a key broken by a
//!   newline), or a secret whose name and value live in separate JSON fields
//!   (`{"password": "x"}` is caught only when the value itself looks secret).
//!
//! It is a safety net, not a guarantee. All matching uses the `regex` crate
//! (finite automata, linear time in the input). Inputs are never logged.
//!
//! ```compile_fail
//! let _ = warden_agent::redact::Redacted("x".to_string());
//! ```

use regex::{Captures, Regex};
use serde_json::{Map, Value};
use std::fmt;
use std::sync::OnceLock;

/// Text that has passed through the redactor. Cannot be built any other way.
#[derive(Clone, PartialEq, Eq)]
pub struct Redacted(String);

impl Redacted {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Redacted({:?})", self.0)
    }
}

/// What was redacted: total matches and the distinct kinds, in apply order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedactionReport {
    pub count: usize,
    pub kinds: Vec<&'static str>,
}

impl RedactionReport {
    fn record(&mut self, kind: &'static str, n: usize) {
        if n == 0 {
            return;
        }
        self.count += n;
        if !self.kinds.contains(&kind) {
            self.kinds.push(kind);
        }
    }

    fn merge(&mut self, other: RedactionReport) {
        self.count += other.count;
        for k in other.kinds {
            if !self.kinds.contains(&k) {
                self.kinds.push(k);
            }
        }
    }
}

const PLACEHOLDER_PREFIX: &str = "[REDACTED:";

fn placeholder(kind: &str) -> String {
    format!("{PLACEHOLDER_PREFIX}{kind}]")
}

struct Patterns {
    pem: Regex,
    jwt: Regex,
    api_key: Regex,
    bearer: Regex,
    kv: Regex,
    card: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        pem: Regex::new(
            r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\z)",
        )
        .unwrap(),
        jwt: Regex::new(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap(),
        api_key: Regex::new(concat!(
            r"\bsk-[A-Za-z0-9_-]{20,}",
            r"|gh[pous]_[A-Za-z0-9]{36}",
            r"|github_pat_[A-Za-z0-9_]{22,}",
            r"|xox[abprs]-[A-Za-z0-9-]{10,}",
            r"|AKIA[0-9A-Z]{16}",
            r"|AIza[0-9A-Za-z_-]{35}",
        ))
        .unwrap(),
        bearer: Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}").unwrap(),
        kv: Regex::new(
            r#"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key)["']?\s*[=:]\s*["']?)([^\s"',;]+)"#,
        )
        .unwrap(),
        card: Regex::new(r"\b[0-9](?:[ -]?[0-9]){12,18}\b").unwrap(),
    })
}

fn replace_simple(
    text: &str,
    re: &Regex,
    kind: &'static str,
    report: &mut RedactionReport,
) -> String {
    let mut n = 0;
    let out = re.replace_all(text, |_: &Captures| {
        n += 1;
        placeholder(kind)
    });
    report.record(kind, n);
    out.into_owned()
}

fn luhn_valid(digits: &[u32]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 {
                    x - 9
                } else {
                    x
                }
            } else {
                d
            }
        })
        .sum();
    // is_multiple_of needs Rust 1.90; the workspace MSRV is 1.89.
    #[allow(clippy::manual_is_multiple_of)]
    let ok = sum % 10 == 0;
    ok
}

/// Redact secrets from text. Order matters: PEM, JWT, API keys, bearer,
/// key/value secrets, then cards, so earlier placeholders are never re-matched.
pub fn redact(input: &str) -> (Redacted, RedactionReport) {
    let p = patterns();
    let mut report = RedactionReport::default();

    let s = replace_simple(input, &p.pem, "private_key", &mut report);
    let s = replace_simple(&s, &p.jwt, "jwt", &mut report);
    let s = replace_simple(&s, &p.api_key, "api_key", &mut report);
    let s = replace_simple(&s, &p.bearer, "bearer", &mut report);

    let mut n = 0;
    let s =
        p.kv.replace_all(&s, |c: &Captures| {
            let value = &c[2];
            if value.starts_with(PLACEHOLDER_PREFIX) {
                c[0].to_string()
            } else {
                n += 1;
                format!("{}{}", &c[1], placeholder("kv_secret"))
            }
        })
        .into_owned();
    report.record("kv_secret", n);

    let mut n = 0;
    let s = p
        .card
        .replace_all(&s, |c: &Captures| {
            let digits: Vec<u32> = c[0].chars().filter_map(|ch| ch.to_digit(10)).collect();
            if (13..=19).contains(&digits.len()) && luhn_valid(&digits) {
                n += 1;
                placeholder("card")
            } else {
                c[0].to_string()
            }
        })
        .into_owned();
    report.record("card", n);

    (Redacted(s), report)
}

/// Redact every string value and every object key, recursively. The result is
/// always valid JSON. If two keys redact to the same text, the later wins.
pub fn redact_json(value: &Value) -> (Value, RedactionReport) {
    let mut report = RedactionReport::default();
    let v = walk(value, &mut report);
    (v, report)
}

fn walk(value: &Value, report: &mut RedactionReport) -> Value {
    match value {
        Value::String(s) => {
            let (r, rep) = redact(s);
            report.merge(rep);
            Value::String(r.into_string())
        }
        Value::Array(a) => Value::Array(a.iter().map(|v| walk(v, report)).collect()),
        Value::Object(o) => {
            let mut m = Map::new();
            for (k, v) in o {
                let (rk, rep) = redact(k);
                report.merge(rep);
                m.insert(rk.into_string(), walk(v, report));
            }
            Value::Object(m)
        }
        other => other.clone(),
    }
}
