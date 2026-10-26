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
//! - secret formats it has no pattern for, or bare auth-header values
//!   without a scheme (`X-Api-Auth: abcd1234` with no `Bearer`/`Basic`);
//! - secret names without one of the keywords in text: `ENCRYPTION_KEY=`,
//!   `MASTER_KEY=`, `SIGNING_KEY=`, `DB_PASS=` (`pass` is a secret key only
//!   in JSON);
//! - plural secret names in text (`SECRETS=...`, `API_KEYS=...`): the glued
//!   `s` suffix is on the deny list because `tokens`/`secrets` collections
//!   and counts are common;
//! - secrets that were base64- or otherwise obfuscated;
//! - secrets split across tokens or lines (for example a key broken by a
//!   newline), or an unquoted value with spaces (`password: correct horse`
//!   redacts only `correct`; quote the value and the whole value is caught);
//! - escaped-quote JSON inside a string (`{\"password\":\"x\"}` from doubly
//!   serialized text), because the key is followed by `\"`, not `"`;
//! - card numbers embedded in a longer digit run (a 25-digit order number).
//!   A spaced or hyphenated card must have a real shape (4-4-4-4, 4-4-4-4-3,
//!   4-6-5, 4-6-4, 4-4-4-3, one separator kind throughout) and a plausible
//!   issuer prefix (4; any 5x, which covers Mastercard 51-55 and Maestro
//!   50/56-58; Mir 2200-2204; Mastercard 2221-2720; 30/34-39; any 6x); an
//!   unspaced one is 13-19 digits starting 2-6. All need a valid Luhn
//!   checksum. Other layouts are not caught: `4111-111111-111111`, a spaced
//!   13-digit Visa as 4-4-4-1, and mixed separators (`4111 1111-1111 1111`);
//! - bare numbers under a secret key in text (`password = 1234 5678` redacts
//!   only the first group; valid card numbers are caught by the card rule).
//!
//! Remaining false positives (over-redaction costs model context but leaks
//! nothing): key/value redaction fires on code that assigns to a secret-named
//! identifier (`token = request.headers["x"]`, `self.token = token`,
//! `const token: string = ...`, `pub token: String`). A secret keyword may
//! carry any identifier prefix and any suffix (`DB_PASSWORD`,
//! `SECRET_KEY_BASE`, `OPENAI_API_KEY_2`, `password1`), except a deny list
//! of known non-secrets. Glued suffixes match exactly: `s`,
//! `izer`/`ize`/`ized`/`izing`, `ary`, `hash`, `count` (so `tokens`,
//! `tokenizer`, `secretary` are left alone; `tokens_used: 12345` is not).
//! Delimited words match as a prefix, so more `_word` parts may follow:
//! `_hash`, `_count`, `_path`, `_file`, `_id(s)`, `_type`, `_length`,
//! `_len`, `_limit`, `_expiry`, `_confirmation`, `_policy`, `_ttl`, `_url`,
//! `_name`, `_budget`, `_usage`, `_lifetime`, `_endpoint`, `_arn`,
//! `_header`, `_ref`, `_version`, `_strength`, `_required`, `_position`,
//! `_index`, `_field`, `_min(_length)`, `_max(_length)` (so `token_budget`,
//! `token_budget_total`, `password_min_length`, `api_key_header` are left
//! alone, while `SECRET_KEY_FILE`, `secret_value`, `PASSWORD_SALT` are
//! secret: the deny word must come right after the keyword). To keep source
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
//! Token prefixes: fixed-length or distinctive ones (`AKIA`, `ASIA`,
//! `gh[pousr]_`, `AIza`, `sk-ant-`) match anywhere, even mid-word, so chains
//! of keys are caught. The variable-length ones that also occur inside
//! ordinary words (`sk-`, `sk_/rk_live_/test_`, `hf_`, `glpat-`, `xapp-`,
//! `xox?-`, `github_pat_`) need a left boundary: start of text or a char that
//! is not a letter or digit (`_`, `-`, quotes, `=`, `(` all count), so
//! `risk-assessment-for-the-quarter` and `network_test_connectivitycheck`
//! are left alone. A bounded key glued to an unbounded one
//! (`AKIA...EXAMPLEsk-...`) is caught on the next pass, after the first
//! key's placeholder gives it a boundary. A word that itself starts with
//! `sk-` and runs 20+ chars (`sk-learn-...`) is still over-redacted.
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

use regex::{CaptureLocations, Regex};
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
        // Variable-length prefixes that also occur inside ordinary words
        // (`risk-assessment`, `network_test_...`) need a left boundary: start
        // of text or a char that is not a letter or digit. It is consumed as
        // group `lb` (the regex crate has no look-behind) and written back.
        // Fixed-length or distinctive prefixes match anywhere, so key chains
        // are caught; a bounded key glued to one of them is caught on the next
        // fixpoint pass, once the placeholder's `]` precedes it.
        api_key: Regex::new(concat!(
            r"(?P<lb>^|[^\p{L}\p{N}])(?:",
            r"sk-[A-Za-z0-9_-]{20,}",
            r"|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}",
            r"|hf_[A-Za-z0-9]{30,}",
            r"|glpat-[A-Za-z0-9_-]{20,}",
            r"|xapp-[A-Za-z0-9-]{10,}",
            r"|xox[abprs]-[A-Za-z0-9-]{10,}",
            r"|github_pat_[A-Za-z0-9_]{22,}",
            r")",
            r"|sk-ant-[A-Za-z0-9_-]{17,}",
            r"|gh[pousr]_[A-Za-z0-9]{36}",
            r"|(?:AKIA|ASIA)[0-9A-Z]{16}",
            r"|AIza[0-9A-Za-z_-]{35}",
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

fn push_placeholder(out: &mut String, kind: &str) {
    out.push_str(PLACEHOLDER_PREFIX);
    out.push_str(kind);
    out.push(']');
}

/// Span text of capture group `i`, or "" when it did not participate.
fn cap<'t>(text: &'t str, locs: &CaptureLocations, i: usize) -> &'t str {
    locs.get(i).map_or("", |(s, e)| &text[s..e])
}

/// Walks every match of `re` with one reused capture buffer and one output
/// buffer (no allocation per match). `f` gets the text and the match's
/// capture locations, appends a replacement to `out` and returns true, or
/// returns false (writing nothing) to keep the match as is.
fn rewrite(
    text: &str,
    re: &Regex,
    kind: &'static str,
    report: &mut RedactionReport,
    mut f: impl FnMut(&str, &CaptureLocations, &mut String) -> bool,
) -> String {
    let mut locs = re.capture_locations();
    let mut out = String::with_capacity(text.len() + text.len() / 8);
    let (mut last, mut at, mut n) = (0, 0, 0);
    while at <= text.len() {
        let Some(m) = re.captures_read_at(&mut locs, text, at) else {
            break;
        };
        out.push_str(&text[last..m.start()]);
        if f(text, &locs, &mut out) {
            n += 1;
        } else {
            out.push_str(m.as_str());
        }
        last = m.end();
        at = if m.is_empty() {
            // No pattern here matches empty; step one char to stay safe.
            m.end() + text[m.end()..].chars().next().map_or(1, char::len_utf8)
        } else {
            m.end()
        };
    }
    out.push_str(&text[last..]);
    report.record(kind, n);
    out
}

/// Like [`rewrite`], but `f` gets only the matched text. Uses `find` (no
/// capture engine), which is several times cheaper per match; used for the
/// patterns that can match very often (api keys, key/value pairs).
fn rewrite_found(
    text: &str,
    re: &Regex,
    kind: &'static str,
    report: &mut RedactionReport,
    mut f: impl FnMut(&str, &mut String) -> bool,
) -> String {
    let mut out = String::with_capacity(text.len() + text.len() / 8);
    let (mut last, mut n) = (0, 0);
    for m in re.find_iter(text) {
        out.push_str(&text[last..m.start()]);
        if f(m.as_str(), &mut out) {
            n += 1;
        } else {
            out.push_str(m.as_str());
        }
        last = m.end();
    }
    out.push_str(&text[last..]);
    report.record(kind, n);
    out
}

fn replace_simple(
    text: &str,
    re: &Regex,
    kind: &'static str,
    report: &mut RedactionReport,
) -> String {
    rewrite_found(text, re, kind, report, |_, out| {
        push_placeholder(out, kind);
        true
    })
}

/// The keyword alternatives of [`KEYWORDS`], expanded, in the regex's
/// preference order (`credentials` before `credential`).
const KEYWORD_FORMS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "api-key",
    "apikey",
    "access_key",
    "access-key",
    "accesskey",
    "private_key",
    "private-key",
    "privatekey",
    "credentials",
    "credential",
];

/// The parts of one `kv` match, split without the capture engine.
#[derive(Debug, PartialEq, Eq)]
struct KvParts<'a> {
    /// Keyword, suffix, optional quote, separator and blanks.
    pre: &'a str,
    suffix: &'a str,
    /// `"`, `'` or "" (bare value).
    open: &'static str,
    value: &'a str,
    /// The closing quote when present, else "".
    close: &'a str,
}

/// Splits text matched by `patterns().kv` into its parts. This mirrors the
/// regex exactly (checked against the capture groups in a unit test): the
/// keyword is the first form in [`KEYWORD_FORMS`] that prefixes the match,
/// the suffix is the following run of `[A-Za-z0-9_-]`, then an optional
/// quote, blanks, `=` or `:`, blanks, and the value. A quoted value runs to
/// the first unescaped quote or the end of the match.
fn split_kv(m: &str) -> KvParts<'_> {
    let b = m.as_bytes();
    let kw = KEYWORD_FORMS
        .iter()
        .find(|k| b.len() >= k.len() && b[..k.len()].eq_ignore_ascii_case(k.as_bytes()))
        .map_or(0, |k| k.len());
    let mut i = kw;
    while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'-') {
        i += 1;
    }
    let suffix = &m[kw..i];
    if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
        i += 1;
    }
    while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
        i += 1;
    }
    i += 1; // the `=` or `:`
    while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
        i += 1;
    }
    let pre = &m[..i];
    let rest = &m[i..];
    let quote = match rest.as_bytes().first() {
        Some(b'"') => ("\"", b'"'),
        Some(b'\'') => ("'", b'\''),
        _ => {
            return KvParts {
                pre,
                suffix,
                open: "",
                value: rest,
                close: "",
            };
        }
    };
    let body = &rest[1..];
    // Content: any char but the quote, `\` or newline, or `\` + a non-newline
    // char. Escapes are ASCII `\`, so stepping by bytes and skipping one whole
    // char after `\` keeps us on char boundaries.
    let bb = body.as_bytes();
    let mut j = 0;
    while j < bb.len() {
        match bb[j] {
            c if c == quote.1 => break,
            b'\n' => break,
            b'\\' => match body[j + 1..].chars().next() {
                Some(c) if c != '\n' => j += 1 + c.len_utf8(),
                _ => break,
            },
            _ => j += 1,
        }
    }
    KvParts {
        pre,
        suffix,
        open: quote.0,
        value: &body[..j],
        close: &body[j..],
    }
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
            // Mir 2200-2204, Mastercard 2221-2720.
            (2200..=2204).contains(&n) || (2221..=2720).contains(&n)
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
            push_placeholder(&mut out, "card");
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

/// Whole suffixes glued to the keyword that mark a non-secret (`tokens`,
/// `tokenizer`, `secretary`, `passwordhash`). Matched exactly: `tokens_used`
/// is still treated as a secret name.
const DENY_GLUED: &[&str] = &["s", "izer", "ize", "ized", "izing", "ary", "hash", "count"];

/// Delimited words after the keyword that mark a non-secret
/// (`password_hash`, `token_budget`). Matched as a prefix of the suffix, so
/// more `_word` parts may follow (`token_budget_total`, `password_min_length`).
const DENY_WORDS: &[&str] = &[
    "hash",
    "count",
    "path",
    "file",
    "id",
    "ids",
    "type",
    "length",
    "len",
    "limit",
    "expiry",
    "confirmation",
    "policy",
    "ttl",
    "url",
    "name",
    "budget",
    "usage",
    "lifetime",
    "endpoint",
    "arn",
    "header",
    "ref",
    "version",
    "strength",
    "required",
    "position",
    "index",
    "field",
    "min_length",
    "max_length",
    "min",
    "max",
];

/// ASCII case-insensitive equality that treats `-` and `_` as the same.
fn word_eq(a: &[u8], b: &[u8]) -> bool {
    let norm = |c: u8| {
        if c == b'-' {
            b'_'
        } else {
            c.to_ascii_lowercase()
        }
    };
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| norm(*x) == norm(*y))
}

/// True when the suffix after a secret keyword marks a known non-secret:
/// `suffix == entry` for [`DENY_GLUED`], or `suffix == "_" + entry` or
/// `suffix.starts_with("_" + entry + "_")` for [`DENY_WORDS`] (`-` = `_`).
/// No allocation.
fn suffix_denied(suffix: &str) -> bool {
    let s = suffix.as_bytes();
    if DENY_GLUED.iter().any(|e| word_eq(s, e.as_bytes())) {
        return true;
    }
    let Some(rest) = s.strip_prefix(b"_").or_else(|| s.strip_prefix(b"-")) else {
        return false;
    };
    DENY_WORDS.iter().any(|e| {
        let e = e.as_bytes();
        rest.len() >= e.len()
            && word_eq(&rest[..e.len()], e)
            && (rest.len() == e.len() || matches!(rest[e.len()], b'_' | b'-'))
    })
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
    // Every key starts with an ASCII letter and the boundary char `lb` never
    // is one, so a match that starts with anything else carries `lb` first.
    let s = rewrite_found(&s, &p.api_key, "api_key", report, |m, out| {
        if let Some(c) = m.chars().next().filter(|c| !c.is_ascii_alphabetic()) {
            out.push(c);
        }
        push_placeholder(out, "api_key");
        true
    });
    let s = replace_simple(&s, &p.bearer, "bearer", report);

    let s = rewrite(&s, &p.basic, "bearer", report, |t, l, out| {
        let prefix = cap(t, l, 1);
        if prefix.is_empty() && !looks_like_base64_credential(cap(t, l, 2)) {
            return false;
        }
        out.push_str(prefix);
        push_placeholder(out, "bearer");
        true
    });

    let s = redact_cards(&s, report);

    // After cards: a card inside a URL password becomes a placeholder first,
    // so the second pass sees the same text and the result is idempotent.
    let s = rewrite(&s, &p.url_userinfo, "kv_secret", report, |t, l, out| {
        if is_placeholder(cap(t, l, 2)) {
            return false;
        }
        out.push_str(cap(t, l, 1));
        push_placeholder(out, "kv_secret");
        out.push('@');
        true
    });

    rewrite_found(&s, &p.kv, "kv_secret", report, |m, out| {
        let k = split_kv(m);
        if suffix_denied(k.suffix) {
            return false;
        }
        let skip = k.value.is_empty()
            || is_placeholder(k.value)
            || (k.open.is_empty()
                && !k.value.contains(PLACEHOLDER_PREFIX)
                && bare_looks_like_code(k.value));
        if skip {
            return false;
        }
        out.push_str(k.pre);
        out.push_str(k.open);
        push_placeholder(out, "kv_secret");
        out.push_str(k.close);
        true
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonconvergence_fails_closed_with_overflow() {
        // One pass changes the text and no pass is left to confirm a fixed point.
        let (r, rep) = redact_with_max_passes("key AKIAIOSFODNN7EXAMPLE", 1);
        assert_eq!(r.as_str(), "[REDACTED:overflow]");
        assert!(rep.kinds.contains(&"overflow"));
        assert!(rep.count >= 1);
        // The overflow output is itself stable.
        assert_eq!(redact(r.as_str()).0.as_str(), "[REDACTED:overflow]");
        // With one more pass it converges normally.
        let (r, _) = redact_with_max_passes("key AKIAIOSFODNN7EXAMPLE", 2);
        assert_eq!(r.as_str(), "key [REDACTED:api_key]");
    }

    /// `split_kv` must agree with the regex's own capture groups.
    #[test]
    fn split_kv_matches_regex_captures() {
        let frags = [
            "password",
            "PASSWD",
            "pwd",
            "Secret",
            "token",
            "api_key",
            "Api-Key",
            "apikey",
            "access_key",
            "privatekey",
            "credentials",
            "credential",
            "_x",
            "s",
            "-2",
            "\"",
            "'",
            " ",
            "\t",
            "=",
            ":",
            "\\",
            "\\\"",
            "\\'",
            "é",
            "日本",
            "\n",
            "abc",
            ",",
            ";",
            "x y",
            "[REDACTED:kv_secret]",
            "🚀",
        ];
        let kv = &patterns().kv;
        let mut seed: u64 = 42;
        let mut checked = 0;
        for _ in 0..20_000 {
            let mut s = String::new();
            for _ in 0..10 {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                s.push_str(frags[(seed >> 33) as usize % frags.len()]);
            }
            for c in kv.captures_iter(&s) {
                let g = |n: &str| c.name(n).map_or("", |m| m.as_str());
                let (open, value, close) = if c.name("dq").is_some() {
                    ("\"", g("dq"), g("dqc"))
                } else if c.name("sq").is_some() {
                    ("'", g("sq"), g("sqc"))
                } else {
                    ("", g("bare"), "")
                };
                let want = KvParts {
                    pre: g("pre"),
                    suffix: g("suffix"),
                    open,
                    value,
                    close,
                };
                assert_eq!(split_kv(&c[0]), want, "{s:?}");
                checked += 1;
            }
        }
        assert!(checked > 3_000, "{checked}");
    }

    #[test]
    fn suffix_deny_list_rules() {
        for s in [
            "s",
            "IZER",
            "_budget",
            "-budget",
            "_budget_total",
            "_min_length",
            "_MAX",
            "_id",
        ] {
            assert!(suffix_denied(s), "{s}");
        }
        for s in [
            "",
            "_2",
            "_prod",
            "s_used",
            "_key_file",
            "_identity",
            "_value",
            "_budgets",
            "1",
        ] {
            assert!(!suffix_denied(s), "{s}");
        }
    }
}
