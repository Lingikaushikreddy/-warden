//! Secret redaction: the gate in front of every cloud model call.
//!
//! Nothing may be sent to a cloud model as text unless it has the type
//! [`Redacted`], and `Redacted` can only be produced by [`redact`] in this
//! module (its field is private and there is no public constructor).
//! [`redact_json`] returns a plain `serde_json::Value`, not a `Redacted`:
//! callers MUST pass tool-call arguments through `redact_json` before building
//! a planner request.
//!
//! # Known limits
//!
//! Redaction is pattern-based, tuned for bounded recall with few false
//! positives. It does not catch:
//! - secret formats it has no pattern for;
//! - secrets that were base64- or otherwise obfuscated;
//! - secrets split across tokens or lines (for example a key broken by a
//!   newline), or an unquoted value with spaces (`password: correct horse`
//!   redacts only `correct`; quote the value and the whole value is caught);
//! - escaped-quote JSON inside a string (`{\"password\":\"x\"}` from doubly
//!   serialized text), because the key is followed by `\"`, not `"`;
//! - bare numbers under a secret key in text (`password = 1234 5678` redacts
//!   only the first group; valid card numbers are caught by the card rule).
//!
//! Remaining false positives: key/value redaction fires on identifiers that
//! merely contain a keyword (`token_count=12345`, a struct field
//! `pub token: String`, `max_tokens_note: "abc"`). To keep source code intact,
//! unquoted values that start with `& ( { [ : =`, end with `(` or `)`, or are
//! shorter than 4 characters are left alone. Card numbers must start with
//! 2-6 (the major issuer ranges) and pass Luhn; an unlucky Luhn-valid number
//! in that range is redacted. `Basic <word>` outside an `Authorization:`
//! header is redacted only when the word looks like base64 (digit, `+/=`, or
//! interior capital).
//!
//! All matching uses the `regex` crate (finite automata, linear time in the
//! input). Inputs are never logged.
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

const KEYWORDS: &str =
    "password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential";

struct Patterns {
    pem: Regex,
    jwt: Regex,
    api_key: Regex,
    url_userinfo: Regex,
    bearer: Regex,
    basic: Regex,
    kv: Regex,
    card: Regex,
    secret_key_name: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        pem: Regex::new(
            r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|\z)",
        )
        .unwrap(),
        jwt: Regex::new(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap(),
        api_key: Regex::new(concat!(
            r"\bsk-[A-Za-z0-9_-]{20,}",
            r"|gh[pousr]_[A-Za-z0-9]{36}",
            r"|github_pat_[A-Za-z0-9_]{22,}",
            r"|xox[abprs]-[A-Za-z0-9-]{10,}",
            r"|\bxapp-[A-Za-z0-9-]{10,}",
            r"|\b(?:AKIA|ASIA)[0-9A-Z]{16}",
            r"|AIza[0-9A-Za-z_-]{35}",
            r"|\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}",
            r"|\bhf_[A-Za-z0-9]{30,}",
            r"|\bglpat-[A-Za-z0-9_-]{20,}",
        ))
        .unwrap(),
        url_userinfo: Regex::new(
            r#"([A-Za-z][A-Za-z0-9+.-]*://[^\s/:@"'<>]+:)([^\s/@"'<>]+)@"#,
        )
        .unwrap(),
        bearer: Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}").unwrap(),
        basic: Regex::new(
            r"(?i)(authorization[ \t]*:[ \t]*)?\bBasic[ \t]+([A-Za-z0-9+/]{8,}={0,2})",
        )
        .unwrap(),
        kv: Regex::new(&format!(
            r#"(?i)(?P<pre>(?:{KEYWORDS})[A-Za-z0-9_-]*["']?[ \t]*[=:][ \t]*)(?:"(?P<dq>[^"\n]*)(?P<dqc>"?)|'(?P<sq>[^'\n]*)(?P<sqc>'?)|(?P<bare>[^\s"',;]+))"#
        ))
        .unwrap(),
        // Maximal runs of digit groups joined by single spaces or hyphens;
        // card windows are searched inside each run.
        card: Regex::new(r"\b[0-9]+(?:[ -][0-9]+)*\b").unwrap(),
        secret_key_name: Regex::new(&format!("(?i)(?:{KEYWORDS})")).unwrap(),
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

/// Find card numbers inside a run of digit groups: every group-aligned window
/// of 13-19 digits starting with 2-6 that passes Luhn (longest first).
fn card_spans(run: &str, base: usize) -> Vec<(usize, usize)> {
    let bytes = run.as_bytes();
    let mut groups: Vec<(usize, usize)> = Vec::new();
    let mut start: Option<usize> = None;
    for (i, b) in bytes.iter().enumerate() {
        if b.is_ascii_digit() {
            start.get_or_insert(i);
        } else if let Some(st) = start.take() {
            groups.push((st, i));
        }
    }
    if let Some(st) = start {
        groups.push((st, bytes.len()));
    }

    let mut spans = Vec::new();
    let mut i = 0;
    while i < groups.len() {
        let first = bytes[groups[i].0];
        let mut found = None;
        if (b'2'..=b'6').contains(&first) {
            let mut total = 0;
            let mut max_j = None;
            for (j, g) in groups.iter().enumerate().skip(i) {
                total += g.1 - g.0;
                if total > 19 {
                    break;
                }
                max_j = Some(j);
            }
            if let Some(max_j) = max_j {
                for j in (i..=max_j).rev() {
                    let digits: Vec<u32> = groups[i..=j]
                        .iter()
                        .flat_map(|g| bytes[g.0..g.1].iter().map(|b| u32::from(b - b'0')))
                        .collect();
                    if (13..=19).contains(&digits.len()) && luhn_valid(&digits) {
                        found = Some(j);
                        break;
                    }
                }
            }
        }
        match found {
            Some(j) => {
                spans.push((base + groups[i].0, base + groups[j].1));
                i = j + 1;
            }
            None => i += 1,
        }
    }
    spans
}

fn redact_cards(text: &str, report: &mut RedactionReport) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    let mut n = 0;
    for m in patterns().card.find_iter(text) {
        for (s, e) in card_spans(m.as_str(), m.start()) {
            out.push_str(&text[last..s]);
            out.push_str(&placeholder("card"));
            last = e;
            n += 1;
        }
    }
    out.push_str(&text[last..]);
    report.record("card", n);
    out
}

fn bare_looks_like_code(v: &str) -> bool {
    v.chars().count() < 4
        || v.starts_with(['&', '(', '{', '[', ':', '='])
        || v.ends_with(['(', ')'])
}

fn looks_like_base64_credential(w: &str) -> bool {
    w.contains(|c: char| c.is_ascii_digit() || matches!(c, '+' | '/' | '='))
        || w.chars().skip(1).any(|c| c.is_ascii_uppercase())
}

/// Redact secrets from text. Order matters: PEM, JWT, API keys, URL
/// passwords, bearer/basic, cards, then key/value secrets (so a card number
/// after `password =` is caught whole), so earlier placeholders are never
/// re-matched.
pub fn redact(input: &str) -> (Redacted, RedactionReport) {
    let p = patterns();
    let mut report = RedactionReport::default();

    let s = replace_simple(input, &p.pem, "private_key", &mut report);
    let s = replace_simple(&s, &p.jwt, "jwt", &mut report);
    let s = replace_simple(&s, &p.api_key, "api_key", &mut report);

    let mut n = 0;
    let s = p
        .url_userinfo
        .replace_all(&s, |c: &Captures| {
            if c[2].starts_with(PLACEHOLDER_PREFIX) {
                c[0].to_string()
            } else {
                n += 1;
                format!("{}{}@", &c[1], placeholder("kv_secret"))
            }
        })
        .into_owned();
    report.record("kv_secret", n);

    let s = replace_simple(&s, &p.bearer, "bearer", &mut report);

    let mut n = 0;
    let s = p
        .basic
        .replace_all(&s, |c: &Captures| {
            let prefix = c.get(1).map_or("", |m| m.as_str());
            if !prefix.is_empty() || looks_like_base64_credential(&c[2]) {
                n += 1;
                format!("{prefix}{}", placeholder("bearer"))
            } else {
                c[0].to_string()
            }
        })
        .into_owned();
    report.record("bearer", n);

    let s = redact_cards(&s, &mut report);

    let mut n = 0;
    let s =
        p.kv.replace_all(&s, |c: &Captures| {
            let pre = &c["pre"];
            let (open, value, close) = if let Some(v) = c.name("dq") {
                ("\"", v.as_str(), c.name("dqc").map_or("", |m| m.as_str()))
            } else if let Some(v) = c.name("sq") {
                ("'", v.as_str(), c.name("sqc").map_or("", |m| m.as_str()))
            } else {
                ("", &c["bare"], "")
            };
            let skip = value.is_empty()
                || value.starts_with(PLACEHOLDER_PREFIX)
                || (open.is_empty() && bare_looks_like_code(value));
            if skip {
                c[0].to_string()
            } else {
                n += 1;
                format!("{pre}{open}{}{close}", placeholder("kv_secret"))
            }
        })
        .into_owned();
    report.record("kv_secret", n);

    (Redacted(s), report)
}

/// Redact every string value and every object key, recursively. A non-empty
/// string under a secret-named key (`password`, `token`, ...) is replaced
/// wholesale. The result is always valid JSON. If two keys redact to the same text, the later wins.
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
                let secret_named = patterns().secret_key_name.is_match(k);
                let nv = match v {
                    Value::String(sv)
                        if secret_named
                            && !sv.is_empty()
                            && !sv.starts_with(PLACEHOLDER_PREFIX) =>
                    {
                        report.record("kv_secret", 1);
                        Value::String(placeholder("kv_secret"))
                    }
                    other => walk(other, report),
                };
                m.insert(rk.into_string(), nv);
            }
            Value::Object(m)
        }
        other => other.clone(),
    }
}
