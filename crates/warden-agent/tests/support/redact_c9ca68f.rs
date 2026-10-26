// Frozen copy of crates/warden-agent/src/redact.rs at c9ca68f (round 3),
// used only as a differential oracle by tests/redact_differential.rs.

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
//! - secret formats it has no pattern for, or auth-header values without a
//!   scheme (`X-Api-Auth: abcd1234` with no `Bearer`/`Basic`);
//! - secrets that were base64- or otherwise obfuscated;
//! - secrets split across tokens or lines (for example a key broken by a
//!   newline), or an unquoted value with spaces (`password: correct horse`
//!   redacts only `correct`; quote the value and the whole value is caught);
//! - escaped-quote JSON inside a string (`{\"password\":\"x\"}` from doubly
//!   serialized text), because the key is followed by `\"`, not `"`;
//! - card numbers embedded in a longer digit run (a 25-digit order number).
//!   A spaced or hyphenated card must have a real shape (4-4-4-4, 4-4-4-4-3,
//!   4-6-5, 4-6-4, 4-4-4-3, one separator kind throughout) and a plausible
//!   issuer prefix (4, 51-59, 2221-2720, 30/34-39, 6x); an unspaced one is 13-19
//!   digits starting 2-6. All need a valid Luhn checksum. Other layouts, such
//!   as `4111-111111-111111`, are not caught;
//! - bare numbers under a secret key in text (`password = 1234 5678` redacts
//!   only the first group; valid card numbers are caught by the card rule).
//!
//! Remaining false positives (over-redaction costs model context but leaks
//! nothing): key/value redaction fires on code that assigns to a secret-named
//! identifier (`token = request.headers["x"]`, `self.token = token`,
//! `const token: string = ...`, `pub token: String`). A secret keyword may
//! carry any identifier prefix and any suffix (`DB_PASSWORD`,
//! `SECRET_KEY_BASE`, `OPENAI_API_KEY_2`, `password1`), except a short deny
//! list of known non-secrets: `s`, `izer`/`ize`/`ized`/`izing`, `ary`,
//! `_hash`, `_count`, `_path`, `_file`, `_id(s)`, `_type`, `_length`, `_len`,
//! `_limit`, `_expiry`, `_confirmation`, `_policy`, `_ttl`, `_url`, `_name`
//! (so `tokens`, `tokenizer`, `secretary`, `password_hash`, `token_count`,
//! `max_tokens` are left alone; `tokens_used: 12345` is not). To keep source
//! code intact, unquoted values that start with `& ( { [ : =`, end with `(`
//! or `)`, or are shorter than 4 characters are left alone.
//! In JSON the same keyword/deny-list rule applies to keys; plural keys
//! (`tokens`, `api_keys`) are secret only when their value is an array or
//! object, `credential(s)` is always secret, and `auth`, `pass`, `passphrase`
//! count as secret keys only as a whole key or `_`/`-` delimited word. Every
//! string and number leaf under a secret JSON key is replaced. Card numbers
//! are matched by checksum, so an unlucky Luhn-valid number is redacted.
//! `Basic <x>` outside an `Authorization:` header is redacted only when `x`
//! is 12+ base64 characters containing a digit or `+/=`.
//!
//! Fixed-prefix tokens (`AKIA`, `ASIA`, `sk-`, `sk_l\x69ve_`, `ghp_`, `github_pat_`,
//! `glpat-`, `hf_`, `xox?-`, `xapp-`, `AIza`) are matched anywhere, even in the
//! middle of a word, so chains of keys are caught in one pass; this can
//! over-redact ordinary text such as `risk-assessment-for-the-quarter`.
//!
//! Fail closed: `redact` repeats its passes until the text stops changing
//! (a placeholder can create a new boundary for a later pattern). If it has
//! not converged after 8 passes, it returns the single string
//! `[REDACTED:overflow]` (kind `overflow`) instead of partially redacted text.
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

const KEY_SUFFIX: &str = "(?:[_-]?(?:key|token|secret|password))?";
const KEYWORDS: &str =
    "password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credentials?";

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
    word_key_name: Regex,
    plural_key_name: Regex,
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
            r"sk-[A-Za-z0-9_-]{20,}",
            r"|gh[pousr]_[A-Za-z0-9]{36}",
            r"|github_pat_[A-Za-z0-9_]{22,}",
            r"|xox[abprs]-[A-Za-z0-9-]{10,}",
            r"|xapp-[A-Za-z0-9-]{10,}",
            r"|(?:AKIA|ASIA)[0-9A-Z]{16}",
            r"|AIza[0-9A-Za-z_-]{35}",
            r"|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}",
            r"|hf_[A-Za-z0-9]{30,}",
            r"|glpat-[A-Za-z0-9_-]{20,}",
        ))
        .unwrap(),
        url_userinfo: Regex::new(
            r#"([A-Za-z][A-Za-z0-9+.-]*://[^\s/:@"'<>]*:)([^\s/@"'<>]+)@"#,
        )
        .unwrap(),
        bearer: Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}").unwrap(),
        basic: Regex::new(
            r"(?i)(authorization[ \t]*:[ \t]*)?\bBasic[ \t]+([A-Za-z0-9+/]{8,}={0,2})",
        )
        .unwrap(),
        kv: Regex::new(&format!(
            r#"(?i)(?P<pre>(?:{KEYWORDS})(?P<suffix>[A-Za-z0-9_-]*)["']?[ \t]*[=:][ \t]*)(?:"(?P<dq>(?:[^"\\\n]|\\[^\n])*)(?P<dqc>"?)|'(?P<sq>(?:[^'\\\n]|\\[^\n])*)(?P<sqc>'?)|(?P<bare>[^\s"',;]+))"#
        ))
        .unwrap(),
        // Maximal runs of digit groups joined by single spaces or hyphens;
        // card windows are searched inside each run.
        card: Regex::new(r"\b[0-9]+(?:[ -][0-9]+)*\b").unwrap(),
        secret_key_name: Regex::new(&format!("(?i)(?:{KEYWORDS})(?P<suffix>[A-Za-z0-9_-]*)$")).unwrap(),
        word_key_name: Regex::new(&format!(
            "(?i)(?:^|[_-])(?:auth|passphrase|pass){KEY_SUFFIX}$"
        ))
        .unwrap(),
        plural_key_name: Regex::new(&format!("(?i)(?:{KEYWORDS})s$")).unwrap(),
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

/// True when the digits of `groups[i..=j]` (read right to left) pass Luhn.
/// No allocation: walks the bytes in place.
fn window_luhn(bytes: &[u8], groups: &[(usize, usize)]) -> bool {
    let mut sum = 0u32;
    let mut idx = 0usize;
    for g in groups.iter().rev() {
        for b in bytes[g.0..g.1].iter().rev() {
            let mut d = u32::from(b - b'0');
            if idx % 2 == 1 {
                d *= 2;
                if d > 9 {
                    d -= 9;
                }
            }
            sum += d;
            idx += 1;
        }
    }
    // is_multiple_of needs Rust 1.90; the workspace MSRV is 1.89.
    #[allow(clippy::manual_is_multiple_of)]
    let ok = sum % 10 == 0;
    ok
}

/// Digit-group lengths of real multi-group card layouts.
const CARD_SHAPES: &[&[usize]] = &[
    &[4, 4, 4, 4],
    &[4, 4, 4, 4, 3],
    &[4, 6, 5],
    &[4, 6, 4],
    &[4, 4, 4, 3],
];

/// Plausible issuer prefix for a multi-group card (first four digits).
fn iin_plausible(b: &[u8]) -> bool {
    match b[0] {
        b'4' | b'5' | b'6' => true,
        b'2' => {
            let n = (u32::from(b[0] - b'0') * 1000)
                + (u32::from(b[1] - b'0') * 100)
                + (u32::from(b[2] - b'0') * 10)
                + u32::from(b[3] - b'0');
            (2221..=2720).contains(&n)
        }
        b'3' => matches!(b[1], b'0' | b'4'..=b'9'),
        _ => false,
    }
}

fn window_shape_ok(bytes: &[u8], groups: &[(usize, usize)]) -> bool {
    if groups.len() == 1 {
        let len = groups[0].1 - groups[0].0;
        return (13..=19).contains(&len) && (b'2'..=b'6').contains(&bytes[groups[0].0]);
    }
    let shape_ok = CARD_SHAPES
        .iter()
        .any(|s| s.len() == groups.len() && s.iter().zip(groups).all(|(l, g)| g.1 - g.0 == *l));
    let sep = bytes[groups[1].0 - 1];
    shape_ok
        && groups[1..].iter().all(|g| bytes[g.0 - 1] == sep)
        && iin_plausible(&bytes[groups[0].0..groups[0].0 + 4])
}

/// Find card numbers inside a run of digit groups: a single group of 13-19
/// digits starting 2-6, or a window of groups with a real card layout (see
/// [`CARD_SHAPES`]), one separator kind and a plausible issuer prefix. Every
/// window must pass Luhn; the longest passing window wins. Each start tries at
/// most five windows, so the scan is linear and allocation-free per window.
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
        let mut found = None;
        let last = (i + 4).min(groups.len() - 1);
        for j in (i..=last).rev() {
            let w = &groups[i..=j];
            if window_shape_ok(bytes, w) && window_luhn(bytes, w) {
                found = Some(j);
                break;
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

/// True when `v` is exactly one placeholder, like `[REDACTED:card]`.
fn is_placeholder(v: &str) -> bool {
    v.strip_prefix(PLACEHOLDER_PREFIX)
        .and_then(|r| r.strip_suffix(']'))
        .is_some_and(|k| !k.is_empty() && k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
}

/// Suffixes after a secret keyword that mark a known non-secret
/// (`tokens`, `tokenizer`, `password_hash`, `token_count`, ...).
fn suffix_denied(suffix: &str) -> bool {
    let l = suffix.to_ascii_lowercase().replace('-', "_");
    matches!(
        l.as_str(),
        "s" | "izer"
            | "ize"
            | "ized"
            | "izing"
            | "ary"
            | "_hash"
            | "hash"
            | "_count"
            | "count"
            | "_path"
            | "_file"
            | "_id"
            | "_ids"
            | "_type"
            | "_length"
            | "_len"
            | "_limit"
            | "_expiry"
            | "_confirmation"
            | "_policy"
            | "_ttl"
            | "_url"
            | "_name"
    )
}

fn bare_looks_like_code(v: &str) -> bool {
    v.chars().count() < 4
        || v.starts_with(['&', '(', '{', '[', ':', '='])
        || v.ends_with(['(', ')'])
}

fn looks_like_base64_credential(w: &str) -> bool {
    w.len() >= 12 && w.contains(|c: char| c.is_ascii_digit() || matches!(c, '+' | '/' | '='))
}

/// Redact secrets from text. Order matters: PEM, JWT, API keys, URL
/// passwords, bearer/basic, cards, then key/value secrets (so a card number
/// after `password =` is caught whole), so earlier placeholders are never
/// re-matched.
pub fn redact(input: &str) -> (Redacted, RedactionReport) {
    redact_with_max_passes(input, MAX_PASSES)
}

const MAX_PASSES: usize = 8;

/// Runs passes until one changes nothing (a placeholder can create a new word
/// boundary for a later pattern). If that does not happen within `max_passes`,
/// fails closed with `[REDACTED:overflow]`.
fn redact_with_max_passes(input: &str, max_passes: usize) -> (Redacted, RedactionReport) {
    let mut report = RedactionReport::default();
    let mut text = input.to_string();
    for _ in 0..max_passes {
        let next = redact_pass(&text, &mut report);
        if next == text {
            return (Redacted(text), report);
        }
        text = next;
    }
    report.record("overflow", 1);
    (Redacted(placeholder("overflow")), report)
}

fn redact_pass(input: &str, report: &mut RedactionReport) -> String {
    let p = patterns();

    let s = replace_simple(input, &p.pem, "private_key", report);
    let s = replace_simple(&s, &p.jwt, "jwt", report);
    let s = replace_simple(&s, &p.api_key, "api_key", report);
    let s = replace_simple(&s, &p.bearer, "bearer", report);

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

    let s = redact_cards(&s, report);

    // After cards: a card inside a URL password becomes a placeholder first,
    // so the second pass sees the same text and the result is idempotent.
    let mut n = 0;
    let s = p
        .url_userinfo
        .replace_all(&s, |c: &Captures| {
            if is_placeholder(&c[2]) {
                c[0].to_string()
            } else {
                n += 1;
                format!("{}{}@", &c[1], placeholder("kv_secret"))
            }
        })
        .into_owned();
    report.record("kv_secret", n);

    let mut n = 0;
    let s =
        p.kv.replace_all(&s, |c: &Captures| {
            if suffix_denied(&c["suffix"]) {
                return c[0].to_string();
            }
            let pre = &c["pre"];
            let (open, value, close) = if let Some(v) = c.name("dq") {
                ("\"", v.as_str(), c.name("dqc").map_or("", |m| m.as_str()))
            } else if let Some(v) = c.name("sq") {
                ("'", v.as_str(), c.name("sqc").map_or("", |m| m.as_str()))
            } else {
                ("", &c["bare"], "")
            };
            let skip = value.is_empty()
                || is_placeholder(value)
                || (open.is_empty()
                    && !value.contains(PLACEHOLDER_PREFIX)
                    && bare_looks_like_code(value));
            if skip {
                c[0].to_string()
            } else {
                n += 1;
                format!("{pre}{open}{}{close}", placeholder("kv_secret"))
            }
        })
        .into_owned();
    report.record("kv_secret", n);

    s
}

/// Redact every string value and every object key, recursively. Under a
/// secret-named key (`password`, `token`, ...; plural names like `tokens`
/// when the value is an array or object) every string and number leaf is
/// replaced wholesale; booleans and null are kept. The result is always valid
/// JSON. If two keys redact to the same text, the later wins.
pub fn redact_json(value: &Value) -> (Value, RedactionReport) {
    let mut report = RedactionReport::default();
    let v = walk(value, false, &mut report);
    (v, report)
}

fn is_secret_key(key: &str, value: &Value) -> bool {
    let p = patterns();
    p.secret_key_name
        .captures(key)
        .is_some_and(|c| !suffix_denied(&c["suffix"]))
        || p.word_key_name.is_match(key)
        || (matches!(value, Value::Array(_) | Value::Object(_)) && p.plural_key_name.is_match(key))
}

fn walk(value: &Value, secret: bool, report: &mut RedactionReport) -> Value {
    match value {
        Value::String(s) if secret && !s.is_empty() && !is_placeholder(s) => {
            report.record("kv_secret", 1);
            Value::String(placeholder("kv_secret"))
        }
        Value::Number(_) if secret => {
            report.record("kv_secret", 1);
            Value::String(placeholder("kv_secret"))
        }
        Value::String(s) => {
            let (r, rep) = redact(s);
            report.merge(rep);
            Value::String(r.into_string())
        }
        Value::Array(a) => Value::Array(a.iter().map(|v| walk(v, secret, report)).collect()),
        Value::Object(o) => {
            let mut m = Map::new();
            for (k, v) in o {
                let (rk, rep) = redact(k);
                report.merge(rep);
                let nv = walk(v, secret || is_secret_key(k, v), report);
                m.insert(rk.into_string(), nv);
            }
            Value::Object(m)
        }
        other => other.clone(),
    }
}
