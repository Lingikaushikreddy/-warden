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
//!   only the first group; valid card numbers are caught by the card rule);
//! - keywords spelled with other look-alike chars: only the two Unicode case
//!   folds of ASCII letters are matched (`ſ` U+017F for `s`, the Kelvin sign
//!   U+212A for `k`, so `ſecret=` and `to\u{212A}en=` are redacted);
//!   homoglyphs such as Cyrillic `а`/`е`/`о` or fullwidth letters are not;
//! - a compound name whose secret word sits before the keyword match only
//!   (`DB_KEY_TOKEN_ID` is read as `TOKEN` + `_ID`, a non-secret).
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
//! secret: the deny word must come right after the keyword). A deny word
//! only counts when no word of the suffix is `secret`, `token`, `password`,
//! `passwd`, `pwd`, `key`, `value`, `contents`, `content`, `data` or `salt`
//! (words split at `_`, `-` and camelCase), so `TOKEN_HASH_SECRET`,
//! `PASSWORD_FIELD_VALUE`, `TOKEN_URL_WITH_KEY` are secret while
//! `API_KEY_ID`, `PASSWORD_FILE`, `token_budget` are not. To keep source
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
//! `gh[pousr]_`, `AIza`, and `sk-ant-` only in its real layout
//! `sk-ant-<letters><2 digits>-...`) match anywhere, even mid-word, so chains
//! of keys are caught. The variable-length ones that also occur inside
//! ordinary words (`sk-`, `sk_/rk_live_/test_`, `hf_`, `glpat-`, `xapp-`,
//! `xox?-`, `github_pat_`) need a left boundary: start of text or a char that
//! is not a letter or digit (`_`, `-`, quotes, `=`, `(` all count), so
//! `risk-assessment-for-the-quarter` and `network_test_connectivitycheck`
//! are left alone. A bounded key glued to an unbounded one
//! (`AKIA...EXAMPLEsk-...`) is caught on the next pass, after the first
//! key's placeholder gives it a boundary. Because `-` is a boundary, a
//! kebab name with an `sk-` word followed by 20+ chars is still
//! over-redacted (`use-sk-learn-pipeline-configuration-v2` becomes
//! `use-[REDACTED:api_key]`); it is not special-cased.
//!
//! Fail closed: `redact` repeats its passes until the text stops changing
//! (a placeholder can create a new boundary for a later pattern). If it has
//! not converged after 8 passes, it returns the single string
//! `[REDACTED:overflow]` (kind `overflow`) instead of partially redacted text.
//!
//! All matching uses the `regex` crate (finite automata, linear time in the
//! input). Inputs are never logged, and no code path in `redact` or
//! `redact_json` can panic with a message built from input: keyword regexes
//! fold case explicitly (no `(?i)`), the key/value splitter steps over whole
//! chars and slices only with `str::get` (falling back to the regex's own
//! capture groups if it ever declines), and a failed internal slice makes
//! `redact` fail closed with `[REDACTED:overflow]` instead of panicking.
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

/// Regex for `word` that matches ASCII letters case-insensitively, plus the
/// only two non-ASCII chars that Unicode simple case folding maps to ASCII
/// letters: `ſ` (U+017F, folds to `s`) and the Kelvin sign (U+212A, folds to
/// `k`). Keyword regexes are built with this instead of `(?i)`, so the set of
/// chars they can match is explicit and [`split_kv`] can mirror it.
fn ascii_ci(word: &str) -> String {
    let mut p = String::new();
    for c in word.chars() {
        match c.to_ascii_lowercase() {
            's' => p.push_str("[sS\u{17F}]"),
            'k' => p.push_str("[kK\u{212A}]"),
            l if l.is_ascii_alphabetic() => {
                p.push('[');
                p.push(l);
                p.push(l.to_ascii_uppercase());
                p.push(']');
            }
            '-' => p.push_str(r"\-"),
            other => p.push(other),
        }
    }
    p
}

/// `[A-Za-z0-9_-]` plus the two non-ASCII case folds of ASCII letters.
const SUFFIX_CLASS: &str = "[A-Za-z0-9_\\-\u{17F}\u{212A}]";

/// The keyword alternation, in [`KEYWORD_FORMS`] preference order.
fn keywords_re() -> String {
    KEYWORD_FORMS
        .iter()
        .map(|f| ascii_ci(f))
        .collect::<Vec<_>>()
        .join("|")
}

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

/// Compiles a built-in pattern. The patterns are constants, so a failure is a
/// bug in this file (caught by every test), never something an input causes.
fn re(p: &str) -> Regex {
    Regex::new(p).expect("built-in redaction pattern")
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(build_patterns)
}

fn build_patterns() -> Patterns {
    let kw = keywords_re();
    let key_suffix = format!(
        "(?:[_-]?(?:{}|{}|{}|{}))?",
        ascii_ci("key"),
        ascii_ci("token"),
        ascii_ci("secret"),
        ascii_ci("password")
    );
    let word_keys = format!(
        "{}|{}|{}",
        ascii_ci("auth"),
        ascii_ci("passphrase"),
        ascii_ci("pass")
    );
    Patterns {
        pem: re(
            r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|\z)",
        ),
        jwt: re(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        // Variable-length prefixes that also occur inside ordinary words
        // (`risk-assessment`, `network_test_...`) need a left boundary: start
        // of text or a char that is not a letter or digit. It is consumed as
        // group `lb` (the regex crate has no look-behind) and written back.
        // Fixed-length or distinctive prefixes match anywhere, so key chains
        // are caught; a bounded key glued to one of them is caught on the next
        // fixpoint pass, once the placeholder's `]` precedes it.
        // `sk-ant-` is boundary-free only in its real layout
        // (`sk-ant-api03-...`), so `risk-ant-colony-...` is left alone.
        api_key: re(concat!(
            r"(?P<lb>^|[^\p{L}\p{N}])(?:",
            r"sk-[A-Za-z0-9_-]{20,}",
            r"|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}",
            r"|hf_[A-Za-z0-9]{30,}",
            r"|glpat-[A-Za-z0-9_-]{20,}",
            r"|xapp-[A-Za-z0-9-]{10,}",
            r"|xox[abprs]-[A-Za-z0-9-]{10,}",
            r"|github_pat_[A-Za-z0-9_]{22,}",
            r")",
            r"|sk-ant-[a-z]+[0-9]{2}-[A-Za-z0-9_-]{16,}",
            r"|gh[pousr]_[A-Za-z0-9]{36}",
            r"|(?:AKIA|ASIA)[0-9A-Z]{16}",
            r"|AIza[0-9A-Za-z_-]{35}",
        )),
        url_userinfo: re(r#"([A-Za-z][A-Za-z0-9+.-]*://[^\s/:@"'<>]*:)([^\s/@"'<>]+)@"#),
        bearer: re(&format!(
            r"\b{}\s+[A-Za-z0-9._~+/=-]{{16,}}",
            ascii_ci("bearer")
        )),
        basic: re(&format!(
            r"({}[ \t]*:[ \t]*)?\b{}[ \t]+([A-Za-z0-9+/]{{8,}}={{0,2}})",
            ascii_ci("authorization"),
            ascii_ci("basic")
        )),
        kv: re(&format!(
            r#"(?P<pre>(?:{kw})(?P<suffix>{SUFFIX_CLASS}*)["']?[ \t]*[=:][ \t]*)(?:"(?P<dq>(?:[^"\\\n]|\\[^\n])*)(?P<dqc>"?)|'(?P<sq>(?:[^'\\\n]|\\[^\n])*)(?P<sqc>'?)|(?P<bare>[^\s"',;]+))"#
        )),
        // Maximal runs of digit groups joined by single spaces or hyphens;
        // card windows are searched inside each run.
        card: re(r"\b[0-9]+(?:[ -][0-9]+)*\b"),
        secret_key_name: re(&format!("(?:{kw})(?P<suffix>{SUFFIX_CLASS}*)$")),
        word_key_name: re(&format!("(?:^|[_-])(?:{word_keys}){key_suffix}$")),
        plural_key_name: re(&format!("(?:{kw}){}$", ascii_ci("s"))),
    }
}

fn push_placeholder(out: &mut String, kind: &str) {
    out.push_str(PLACEHOLDER_PREFIX);
    out.push_str(kind);
    out.push(']');
}

/// Span text of capture group `i`, or "" when it did not participate.
fn cap<'t>(text: &'t str, locs: &CaptureLocations, i: usize) -> &'t str {
    locs.get(i).and_then(|(s, e)| text.get(s..e)).unwrap_or("")
}

// Panic policy: nothing on the `redact`/`redact_json` path indexes or slices
// with a bare `[..]` on input-derived positions. Text slices use `str::get`;
// a failed `get` (impossible for regex-reported match bounds, kept as a
// guard) makes the pass return `None`, and `redact` then fails closed with
// `[REDACTED:overflow]`. So no panic message can ever carry input text.

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
) -> Option<String> {
    let mut locs = re.capture_locations();
    let mut out = String::with_capacity(text.len() + text.len() / 8);
    let (mut last, mut at, mut n) = (0, 0, 0);
    while at <= text.len() {
        let Some(m) = re.captures_read_at(&mut locs, text, at) else {
            break;
        };
        out.push_str(text.get(last..m.start())?);
        if f(text, &locs, &mut out) {
            n += 1;
        } else {
            out.push_str(m.as_str());
        }
        last = m.end();
        at = if m.is_empty() {
            // No pattern here matches empty; step one char to stay safe.
            let step = text
                .get(m.end()..)?
                .chars()
                .next()
                .map_or(1, char::len_utf8);
            m.end() + step
        } else {
            m.end()
        };
    }
    out.push_str(text.get(last..)?);
    report.record(kind, n);
    Some(out)
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
) -> Option<String> {
    let mut out = String::with_capacity(text.len() + text.len() / 8);
    let (mut last, mut n) = (0, 0);
    for m in re.find_iter(text) {
        out.push_str(text.get(last..m.start())?);
        if f(m.as_str(), &mut out) {
            n += 1;
        } else {
            out.push_str(m.as_str());
        }
        last = m.end();
    }
    out.push_str(text.get(last..)?);
    report.record(kind, n);
    Some(out)
}

fn replace_simple(
    text: &str,
    re: &Regex,
    kind: &'static str,
    report: &mut RedactionReport,
) -> Option<String> {
    rewrite_found(text, re, kind, report, |_, out| {
        push_placeholder(out, kind);
        true
    })
}

/// The keyword alternatives, in the regex's preference order (`credentials`
/// before `credential`). The `kv`/key-name regexes are built from this list.
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

/// The parts of one `kv` match.
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

/// The char at byte `i` of `b`, folded the way [`ascii_ci`] folds it: an
/// ASCII byte as its lowercase form, `ſ` (C5 BF) as `s`, the Kelvin sign
/// (E2 84 AA) as `k`, with its length in bytes. `None` for any other char or
/// past the end. `i` must be on a char boundary; the result keeps it there.
fn folded_at(b: &[u8], i: usize) -> Option<(u8, usize)> {
    match *b.get(i)? {
        c if c.is_ascii() => Some((c.to_ascii_lowercase(), 1)),
        0xC5 if b.get(i + 1) == Some(&0xBF) => Some((b's', 2)),
        0xE2 if b.get(i + 1..i + 3) == Some(&[0x84, 0xAA][..]) => Some((b'k', 3)),
        _ => None,
    }
}

/// Splits text matched by `patterns().kv` into its parts without the capture
/// engine (several times faster). It mirrors the regex (checked against the
/// capture groups in a unit test): the keyword is the first form in
/// [`KEYWORD_FORMS`] that prefixes the match (folded per [`folded_at`]), the
/// suffix is the following run of ASCII letters, digits, `_`, `-`, `ſ` and
/// the Kelvin sign, then an optional quote, blanks, `=` or `:`, blanks, and
/// the value. A quoted value runs to the first unescaped quote or the end of
/// the match. It only steps over whole chars and slices only with `str::get`,
/// so it cannot panic; `None` means "use the capture engine instead" (see
/// [`kv_parts`]).
fn split_kv(m: &str) -> Option<KvParts<'_>> {
    let b = m.as_bytes();
    let kw = KEYWORD_FORMS.iter().find_map(|f| {
        let mut i = 0;
        for &p in f.as_bytes() {
            match folded_at(b, i) {
                Some((c, n)) if c == p => i += n,
                _ => return None,
            }
        }
        Some(i)
    })?;
    let mut i = kw;
    while let Some((c, n)) = folded_at(b, i) {
        if !(c.is_ascii_alphanumeric() || c == b'_' || c == b'-') {
            break;
        }
        i += n;
    }
    let suffix = m.get(kw..i)?;
    // Everything from here to the value is ASCII: quote, blanks, separator.
    if matches!(b.get(i), Some(b'"' | b'\'')) {
        i += 1;
    }
    while matches!(b.get(i), Some(b' ' | b'\t')) {
        i += 1;
    }
    if !matches!(b.get(i), Some(b'=' | b':')) {
        return None;
    }
    i += 1;
    while matches!(b.get(i), Some(b' ' | b'\t')) {
        i += 1;
    }
    let pre = m.get(..i)?;
    let rest = m.get(i..)?;
    let (open, q) = match rest.as_bytes().first() {
        Some(b'"') => ("\"", b'"'),
        Some(b'\'') => ("'", b'\''),
        _ => {
            return Some(KvParts {
                pre,
                suffix,
                open: "",
                value: rest,
                close: "",
            })
        }
    };
    let body = rest.get(1..)?;
    // Content: any char but the quote, `\` or newline, or `\` + a non-newline
    // char. Those three are ASCII, so scanning bytes for them only ever stops
    // on a char boundary; after `\` the whole next char is skipped.
    let bb = body.as_bytes();
    let mut end = body.len();
    let mut j = 0;
    while let Some(&c) = bb.get(j) {
        if c == q || c == b'\n' {
            end = j;
            break;
        }
        if c == b'\\' {
            match body.get(j + 1..).and_then(|r| r.chars().next()) {
                Some(e) if e != '\n' => j += 1 + e.len_utf8(),
                _ => {
                    end = j;
                    break;
                }
            }
        } else {
            j += 1;
        }
    }
    Some(KvParts {
        pre,
        suffix,
        open,
        value: body.get(..end)?,
        close: body.get(end..)?,
    })
}

/// Parts of a `kv` match: the fast splitter, or the regex's own capture
/// groups when the splitter declines. `None` only if both fail.
fn kv_parts(m: &str) -> Option<KvParts<'_>> {
    split_kv(m).or_else(|| {
        let c = patterns().kv.captures(m)?;
        let g = |n: &str| c.name(n).map_or("", |x| x.as_str());
        let (open, value, close) = if c.name("dq").is_some() {
            ("\"", g("dq"), g("dqc"))
        } else if c.name("sq").is_some() {
            ("'", g("sq"), g("sqc"))
        } else {
            ("", g("bare"), "")
        };
        Some(KvParts {
            pre: g("pre"),
            suffix: g("suffix"),
            open,
            value,
            close,
        })
    })
}

/// Digit value of an ASCII digit byte (other bytes give a value > 9, never a
/// panic; callers only pass digits).
fn digit(b: u8) -> u32 {
    u32::from(b.wrapping_sub(b'0'))
}

/// True when the digits of `groups[i..=j]` (read right to left) pass Luhn.
/// No allocation: walks the bytes in place.
fn window_luhn(bytes: &[u8], groups: &[(usize, usize)]) -> bool {
    let mut sum = 0u32;
    let mut idx = 0usize;
    for g in groups.iter().rev() {
        for b in bytes.get(g.0..g.1).unwrap_or(&[]).iter().rev() {
            let mut d = digit(*b);
            if idx % 2 == 1 {
                d *= 2;
                if d > 9 {
                    d -= 9;
                }
            }
            sum = sum.wrapping_add(d);
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
    let &[b0, b1, b2, b3, ..] = b else {
        return false;
    };
    match b0 {
        b'4' | b'5' | b'6' => true,
        b'2' => {
            let n = digit(b0) * 1000 + digit(b1) * 100 + digit(b2) * 10 + digit(b3);
            // Mir 2200-2204, Mastercard 2221-2720.
            (2200..=2204).contains(&n) || (2221..=2720).contains(&n)
        }
        b'3' => matches!(b1, b'0' | b'4'..=b'9'),
        _ => false,
    }
}

fn window_shape_ok(bytes: &[u8], groups: &[(usize, usize)]) -> bool {
    let (Some(first), Some(second)) = (groups.first(), groups.get(1)) else {
        return groups.first().is_some_and(|g| {
            (13..=19).contains(&(g.1.saturating_sub(g.0)))
                && bytes.get(g.0).is_some_and(|b| (b'2'..=b'6').contains(b))
        });
    };
    let shape_ok = CARD_SHAPES.iter().any(|s| {
        s.len() == groups.len()
            && s.iter()
                .zip(groups)
                .all(|(l, g)| g.1.saturating_sub(g.0) == *l)
    });
    let sep_before = |g: &(usize, usize)| g.0.checked_sub(1).and_then(|i| bytes.get(i));
    let sep = sep_before(second);
    shape_ok
        && sep.is_some()
        && groups.iter().skip(1).all(|g| sep_before(g) == sep)
        && iin_plausible(bytes.get(first.0..).unwrap_or(&[]))
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
    while let Some(gi) = groups.get(i) {
        let last = (i + 4).min(groups.len() - 1);
        let found = (i..=last)
            .rev()
            .find(|&j| {
                let w = groups.get(i..=j).unwrap_or(&[]);
                window_shape_ok(bytes, w) && window_luhn(bytes, w)
            })
            .and_then(|j| groups.get(j).map(|gj| (j, gj.1)));
        match found {
            Some((j, end)) => {
                spans.push((base + gi.0, base + end));
                i = j + 1;
            }
            None => i += 1,
        }
    }
    spans
}

fn redact_cards(text: &str, report: &mut RedactionReport) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    let mut n = 0;
    for m in patterns().card.find_iter(text) {
        for (s, e) in card_spans(m.as_str(), m.start()) {
            out.push_str(text.get(last..s)?);
            push_placeholder(&mut out, "card");
            last = e;
            n += 1;
        }
    }
    out.push_str(text.get(last..)?);
    report.record("card", n);
    Some(out)
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
/// more `_word` parts may follow (`token_budget_total`, `password_min_length`),
/// unless one of those words is in [`SECRET_WORDS`].
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

/// Words that make a suffix secret again even after a deny word
/// (`TOKEN_HASH_SECRET`, `PASSWORD_FIELD_VALUE`, `TOKEN_URL_WITH_KEY`).
const SECRET_WORDS: &[&str] = &[
    "secret",
    "token",
    "password",
    "passwd",
    "pwd",
    "key",
    "value",
    "contents",
    "content",
    "data",
    "salt",
    "credential",
    "credentials",
    "private",
    "pass",
    "passphrase",
    "auth",
    "pepper",
    "hmac",
    "signing",
    "pin",
    "cert",
    "jwt",
    "clear",
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

/// True when any word of `s` is in [`SECRET_WORDS`]. Words are split at `_`,
/// `-` and camelCase boundaries (`hashSecret`, `IDValue`).
fn has_secret_word(s: &[u8]) -> bool {
    let is_secret = |w: &[u8]| {
        SECRET_WORDS
            .iter()
            .any(|e| w.eq_ignore_ascii_case(e.as_bytes()))
    };
    let mut start = 0;
    for i in 0..=s.len() {
        let c = s.get(i).copied();
        let sep = matches!(c, None | Some(b'_' | b'-'));
        let prev = i.checked_sub(1).and_then(|p| s.get(p)).copied();
        let next = s.get(i + 1).copied();
        let camel = c.is_some_and(|c| c.is_ascii_uppercase())
            && i > start
            && (prev.is_some_and(|p| p.is_ascii_lowercase() || p.is_ascii_digit())
                || (prev.is_some_and(|p| p.is_ascii_uppercase())
                    && next.is_some_and(|n| n.is_ascii_lowercase())));
        if sep || camel {
            if s.get(start..i).is_some_and(is_secret) {
                return true;
            }
            start = if sep { i + 1 } else { i };
        }
    }
    false
}

/// True when the suffix after a secret keyword marks a known non-secret:
/// `suffix == entry` for [`DENY_GLUED`], or, for [`DENY_WORDS`],
/// `suffix == "_" + entry` or `suffix.starts_with("_" + entry + "_")`
/// (`-` = `_`) with no [`SECRET_WORDS`] word anywhere in the suffix.
/// No allocation.
fn suffix_denied(suffix: &str) -> bool {
    let s = suffix.as_bytes();
    if DENY_GLUED.iter().any(|e| word_eq(s, e.as_bytes())) {
        return true;
    }
    let Some(rest) = s.strip_prefix(b"_").or_else(|| s.strip_prefix(b"-")) else {
        return false;
    };
    let deny = DENY_WORDS.iter().any(|e| {
        let e = e.as_bytes();
        rest.get(..e.len()).is_some_and(|h| word_eq(h, e))
            && matches!(rest.get(e.len()), None | Some(b'_' | b'-'))
    });
    deny && !has_secret_word(s)
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
/// or a pass hits an internal guard, fails closed with `[REDACTED:overflow]`.
fn redact_with_max_passes(input: &str, max_passes: usize) -> (Redacted, RedactionReport) {
    let mut report = RedactionReport::default();
    let mut text = input.to_string();
    for _ in 0..max_passes {
        let Some(next) = redact_pass(&text, &mut report) else {
            break;
        };
        if next == text {
            return (Redacted(text), report);
        }
        text = next;
    }
    report.record("overflow", 1);
    (Redacted(placeholder("overflow")), report)
}

fn redact_pass(input: &str, report: &mut RedactionReport) -> Option<String> {
    let p = patterns();

    let s = replace_simple(input, &p.pem, "private_key", report)?;
    let s = replace_simple(&s, &p.jwt, "jwt", report)?;
    // Every key starts with an ASCII letter and the boundary char `lb` never
    // is one, so a match that starts with anything else carries `lb` first.
    let s = rewrite_found(&s, &p.api_key, "api_key", report, |m, out| {
        if let Some(c) = m.chars().next().filter(|c| !c.is_ascii_alphabetic()) {
            out.push(c);
        }
        push_placeholder(out, "api_key");
        true
    })?;
    let s = replace_simple(&s, &p.bearer, "bearer", report)?;

    let s = rewrite(&s, &p.basic, "bearer", report, |t, l, out| {
        let prefix = cap(t, l, 1);
        if prefix.is_empty() && !looks_like_base64_credential(cap(t, l, 2)) {
            return false;
        }
        out.push_str(prefix);
        push_placeholder(out, "bearer");
        true
    })?;

    let s = redact_cards(&s, report)?;

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
    })?;

    rewrite_found(&s, &p.kv, "kv_secret", report, |m, out| {
        let Some(k) = kv_parts(m) else {
            // Cannot happen (the regex matched `m`); fail closed anyway.
            push_placeholder(out, "kv_secret");
            return true;
        };
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
        .is_some_and(|c| !suffix_denied(c.name("suffix").map_or("", |m| m.as_str())))
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
            "\u{17F}",
            "\u{212A}",
            "\u{17F}ecret",
            "to\u{212A}en",
            "pa\u{17F}\u{17F}word",
            "api_\u{212A}ey",
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
                assert_eq!(split_kv(&c[0]), Some(want), "{s:?}");
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
            "_ID",
            "_file",
            "_name_display",
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
            "_hash_secret",
            "_url_with_key",
            "_field_value",
            "_id_Value",
            "_name_password",
            "_min_dataSalt",
            "_ref_myToken",
        ] {
            assert!(!suffix_denied(s), "{s}");
        }
    }
}
