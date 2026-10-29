# Warden WhatsApp Cloud API Channel Implementation Plan (Plan 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `warden daemon` also serves the owner over the official WhatsApp Business Cloud API: signed webhooks arrive on a loopback-only HTTP listener (exposed by the owner's own tunnel), owner text reaches the existing engine, and replies and `yes <code>` approvals go back through the Graph API. It runs alongside Telegram or alone.

**Architecture:** A `warden_agent::whatsapp` module mirrors `telegram`: a Graph API client over the shared reqwest setup (`api`), pure webhook verification and payload parsing (`webhook`), a persisted seen-message set (`seen`), a small hyper 1 HTTP/1 server bound to loopback (`listener`), and `WhatsAppChannel` (`channel`). The listener checks the HMAC over the raw body before any parsing and hands parsed batches to the channel through a bounded `tokio::sync::mpsc` queue. The channel deduplicates, records the batch's message ids on disk, then acts, so delivery is at most once as with the Telegram offset. The daemon composes channels with `Pair` and a new `impl Channel for Option<C>`, so the same types cover any mix of Telegram, WhatsApp and `--console`. The engine is unchanged: it stays the only gate.

**Tech Stack:** Rust 1.89+, tokio 1 (warden-agent adds `net`), reqwest 0.12 (already a dependency), hyper 1 (`server`, `http1`) + hyper-util 0.1 (`tokio`) + http-body-util 0.1, hmac 0.12 + sha2 0.10 (already a dependency) + subtle 2, serde_json, zeroize, wiremock 0.6 (dev), tempfile, assert_cmd.

**Spec:** `docs/superpowers/specs/2026-10-25-warden-design.md` (Goal 2: "the official WhatsApp Business Cloud API"; channel order CLI, Telegram, then WhatsApp Cloud API). Plan 3: `docs/superpowers/plans/2026-10-28-warden-telegram-daemon.md`. Inputs: `docs/SECURITY-NOTES.md` ("Channel", "Engine", "Telegram channel", "Daemon") and `README.md`.

## Global Constraints

- Everything in Plan 2's and Plan 3's Global Constraints still holds: `classify` computes the four tiers; `Blocked` never runs; `warden-core` has no network, async or HTTP code; nothing reaches a planner unless it is `Redacted`; the planner is untrusted; `approved` is audited before acting; no conversation memory between messages; at-most-once delivery; Unix only; Apache-2.0, no JIMMY text; tests never contact a real service; release binaries contain no test-only code (`scripts/check-release-strings.sh` still passes).
- **Decision: inbound by webhook only, on a loopback-only listener.** `[whatsapp] listen` defaults to `127.0.0.1:8097`. Any address whose IP is not loopback (`0.0.0.0`, `[::]`, a LAN IP, a host name) is refused at config load, and `WebhookListener::bind` refuses it again. The owner exposes it with their own tunnel (for example `cloudflared tunnel --url http://127.0.0.1:8097`). Warden never opens a public port. Why: the Cloud API has no polling, and binding loopback keeps the exposure decision with the owner.
- **Decision: hyper 1 + hyper-util + http-body-util, not axum.** Why: hyper 1 and hyper-util are already compiled in through reqwest, so this adds only the `server` feature and http-body-util. axum would add tower, matchit and more crates to serve two routes. Exact entries: `hyper = { version = "1", default-features = false, features = ["server", "http1"] }`, `hyper-util = { version = "0.1", default-features = false, features = ["tokio"] }`, `http-body-util = "0.1"`. The listener speaks HTTP/1.1 only.
- **Decision: the signature is checked before anything is parsed.** A POST is read raw (at most 1 MiB, with header and body timeouts and at most 16 connections at once), then `X-Hub-Signature-256` (`sha256=<hex>`, HMAC-SHA256 with the app secret over the raw body) is checked with `hmac::Mac::verify_slice`, which compares in constant time. A missing signature or a bad one gets 401 and is counted. That body is never parsed. Why: unauthenticated bytes from the public tunnel must not reach serde.
- **Decision: GET handshake.** 200 with the challenge as the body only when `hub.mode` is `subscribe`, `hub.verify_token` matches, and `hub.challenge` is 1-64 ASCII digits. The token match is a `subtle::ConstantTimeEq` comparison of the SHA-256 of each value, so the length is not leaked either. Every other GET gets 403. Why: Meta's subscription check, and nothing from the request is echoed except digits.
- **Decision: reply 200 fast.** After a valid signature the listener parses, puts the batch on the channel queue and answers 200 without waiting for the engine. Signed but malformed JSON, or a payload for another `phone_number_id`, also gets 200, is counted and is dropped, so Meta does not retry it forever. A full queue gets 503, so Meta retries later. Why: Meta retries any webhook that is not answered quickly with a 2xx.
- **Decision: deduplicate by `wamid`, persisted, before acting.** `<home>/whatsapp-seen` holds the SHA-256 of the last 1024 message ids (32 bytes each, oldest dropped first, 0600, written with `state::write_atomic`). The channel records a batch's new ids BEFORE it queues any of them. If that write fails, the channel is fatal. A crash between the 200 and the write loses the batch instead of replaying it. Why: Meta retries, so duplicates happen; this is at most once, like the Telegram offset. The set is bounded because the age rule below drops anything older than an hour anyway.
- **Decision: stale messages are never acted on.** An owner text whose WhatsApp `timestamp` (Unix seconds) is more than `max_message_age_secs` (default 120, range 10-3600) before the local clock is dropped. It reaches the engine as `wa-stale:<number>` with empty text, and the owner gets one notice per batch. The age is checked again when a queued text is popped (Plan 3's final fix).
- **Decision: secrets come only from the environment.** `access_token_env` (default `WARDEN_WHATSAPP_TOKEN`), `app_secret_env` (default `WARDEN_WHATSAPP_APP_SECRET`) and `verify_token_env` (default `WARDEN_WHATSAPP_VERIFY_TOKEN`) are env NAMES. They must differ from each other, from `api_key_env` and from `[telegram] bot_token_env`. Config keys `access_token`, `app_secret`, `verify_token` and `whatsapp_token` (at any depth) are refused like `api_key`. The daemon also refuses to start when any two secret values are equal (the three WhatsApp secrets, the bot token, the API key). Secrets are never logged, audited, printed, or shown in `Debug` or in errors. The access token travels only in an `Authorization: Bearer` header marked sensitive, never in a URL. The redactor gains a Meta access token pattern. Why: the same rule as Plan 3's bot token. The equal-value check matters because the verify token travels in a URL query, and tunnel request logs can record that.
- **Decision: owners are WhatsApp numbers.** `[whatsapp] owner_numbers` lists 1-8 numbers, each 7-15 digits in E.164 form. One leading `+` is accepted and stripped. Spaces and dashes are refused. They are served as sender `wa:<digits>`. Only `type == "text"` from an owner is acted on. Statuses, reactions, media, interactive, button, system, unsupported, and forwarded messages (`context.forwarded` or `context.frequently_forwarded` true) reach the engine as non-owner senders `wa-<tag>:<number or 0>` with empty text, so they are audited as in Telegram. A webhook change whose `metadata.phone_number_id` is not `[whatsapp] phone_number_id` is ignored. Why: the owner's decision; the audit entry also tells an owner their own `wa:` id.
- **Decision: approvals keep the challenge code.** `yes <code>` must come from the number the request came from. A reply whose `context.id` names a message other than the prompt is No. Why: the same chat-bound rule as Telegram.
- **Decision: no PIN over WhatsApp, ever.** `WhatsAppChannel::accepts_pin` is always `false`, with no config option. The engine therefore refuses PIN-tier actions with no prompt and tells the owner to do them at the computer. `retract_last` is the default no-op. Why: the Cloud API cannot delete a user's message, so a PIN typed into WhatsApp stays in the chat and at Meta. The docs say so plainly. The engine's existing rule (PIN-like owner text never reaches the planner) is unchanged.
- **Decision: 24-hour customer-service window, free-form text only, no templates.** The channel keeps the latest inbound `timestamp` per owner number (any verified message from that number, capped at the local clock) in memory. A send is allowed only while `now + 5 min < last_inbound + 24 h`. Otherwise it is dropped and counted (`window_drops`), and an approval prompt returns `ApprovalReply::Undelivered`, which the engine audits as `refused: prompt not delivered`. A Graph error 131047 counts the same way. The map is not persisted, so after a restart Warden cannot message an owner until that owner writes. Why: Meta rejects free-form messages outside the window. The 5-minute margin keeps a send near the edge from failing at Meta, and a channel counter fits the code (channels have no audit sink).
- **Decision: outbound text.** `POST {api_base}/{graph_version}/{phone_number_id}/messages` with body `{"messaging_product":"whatsapp","recipient_type":"individual","to":<digits>,"type":"text","text":{"preview_url":false,"body":<text>}}`. Every text goes through redaction, then sanitizing, then a cut to 4096 UTF-16 units ending in `…`. UTF-16 units are never fewer than characters, so this stays within WhatsApp's 4096-character body limit. `graph_version` defaults to `v26.0` and must be bumped as Meta retires versions. `api_base` defaults to `https://graph.facebook.com` and is validated by `http::check_base_url`. Auth errors (HTTP 401, Graph code 190) are a fatal `TokenRejected`. Rate limits (HTTP 429, codes 4, 80007, 130429, 131048, 131056) get one retry after `rate_limit_backoff`, unless shutdown has started.
- **Decision: startup verifies the token.** `warden daemon` calls `GET /{graph_version}/{phone_number_id}?fields=display_phone_number,verified_name` before opening any state, as Plan 3 does with `getMe`. Why: a wrong token or `phone_number_id` fails at start instead of at the first reply. The display number goes in the banner.
- **Decision: one daemon, any mix of channels.** The daemon runs whichever of `[telegram]` and `[whatsapp]` is present (at least one) as `Pair::new(Pair::new(Option<telegram>, Option<whatsapp>), Option<stdio>)`. A fatal error from either channel stops the daemon with exit 1 (`Watched<C>`, `FatalSlot` over `ChannelFatal`). `print-service` writes `REPLACE_ME` for every configured secret env name.
- **Decision: counters, not logs.** The listener counts refused requests (unsigned, bad signature, too large, malformed, foreign, queue full, busy). The channel counts window drops. At exit the daemon prints non-zero counts as one stderr line. No per-request line is ever printed, and no logger is installed.
- Tests never contact Meta. Agent tests use wiremock for the Graph API and a real loopback HTTP client (reqwest, or a raw `TcpStream` for slow and oversized requests) against the listener. CLI end-to-end tests use the `test-hooks` mock planner as `tests/daemon.rs` does, set `listen = "127.0.0.1:0"`, and read the bound address from the banner.
- Commits: conventional style (`feat(agent): ...`, `feat(cli): ...`, `docs: ...`) under the user's own git identity, with NO AI attribution or `Co-Authored-By` lines.

## Review Focus

1. A forged or replayed POST from the internet through the tunnel: no signature, a signature from another app's secret, a valid signature over a different body, or a valid signature for another `phone_number_id`. None may reach the engine or the planner, and none may be echoed back (Task 4: `unsigned_post_is_401_and_not_forwarded`, `bad_signature_is_401_and_not_forwarded`, `foreign_phone_number_id_is_200_and_not_forwarded`; Task 8: `whatsapp_forged_webhooks_are_401_and_never_acted_on`).
2. Meta delivers the same message twice: a retry after a slow 200, the same id twice in one batch, or a redelivery after a restart. It must be acted on once at most, including an old `yes <code>` or `delete x` (Task 5: `duplicate_wamid_is_delivered_once`, `restart_does_not_redeliver_seen_wamid`; Task 8: `whatsapp_redelivery_after_restart_is_not_replayed`).
3. The owner types the PIN into WhatsApp, with or without a pending PIN-tier request. It must never reach the planner, no PIN prompt may ever be sent, and the docs must say the message stays in the chat (Task 5: `accepts_pin_is_always_false`, `yespin_prompt_is_no_without_send`; Task 8: `whatsapp_refuses_pin_tier_without_a_prompt`, `whatsapp_pin_like_message_never_reaches_the_planner`; Task 9 docs).
4. The access token, app secret or verify token must never be printed, appear in stderr, the audit log or any data-dir file, or show up in an error, whatever the failure: connection refused, a 401 at startup or mid-run, a missing or reused variable, a bad handshake (Task 2: `errors_and_debug_never_contain_the_token`; Task 3: `debug_hides_secrets`; Task 8: `daemon_never_prints_or_audits_whatsapp_secrets`).
5. The public endpoint under abuse: slow headers, a slow body, a body over 1 MiB (declared or chunked), many idle connections, a listen address that is not loopback. Each must be bounded and refused without parsing, and the daemon must keep serving the owner (Task 1: `whatsapp_listen_must_be_loopback`; Task 4: `oversized_body_is_413_and_never_parsed`, `slow_headers_are_cut_off`, `slow_body_is_cut_off`, `connection_limit_holds`, `bind_refuses_non_loopback`).

Also pinned by tests: the 24 h window (Task 5), stale messages (Tasks 5 and 8), Telegram and WhatsApp in one daemon (Task 8), a token rejected mid-run (Tasks 5 and 8), and the listener stopping on SIGTERM (Task 8).

## Parallel lanes

Dependency order (an arrow means "needs"):

```
Wave 1 (start together):  T1 config+redact   T2 Graph client   T3 webhook+seen   T6 daemon groundwork
Wave 2:                   T4 listener -> T3
                          T5 channel  -> T2, T3
                          T7 print-service -> T1
Wave 3:                   T8 daemon on WhatsApp -> T1, T2, T4, T5, T6
Wave 4:                   T9 docs -> T7, T8
```

| Task | Can run in parallel with | Must wait for |
|---|---|---|
| 1 | 2, 3, 6 | - |
| 2 | 1, 3, 6, 4 | - |
| 3 | 1, 2, 6, 7 | - |
| 4 | 5, 7 (and 1, 2, 6 if still running) | 3 |
| 5 | 4, 7 (and 1, 6 if still running) | 2, 3 |
| 6 | 1, 2, 3, 4, 5, 7 | - |
| 7 | 2, 3, 4, 5, 6 | 1 |
| 8 | - | 1, 2, 4, 5, 6 |
| 9 | - | 7, 8 |

Shared-file notes for parallel agents (each in its own worktree):
- `crates/warden-agent/src/lib.rs` gets `pub mod whatsapp;`, and `crates/warden-agent/src/whatsapp/mod.rs` gets one `pub mod` and one `pub use` line per task (2, 3, 4, 5). Whichever of Tasks 2 and 3 lands first creates `mod.rs` (doc comment as in Task 2). The other merges by union.
- `crates/warden-agent/Cargo.toml`: Task 3 adds `hmac`, `subtle`; Task 4 adds `hyper`, `hyper-util`, `http-body-util` and tokio `net`. Merge by union, then let `cargo build` rewrite `Cargo.lock`. Never hand-merge the lock file.
- `crates/warden-agent/src/channel.rs`: Task 5 adds `cap_utf16` near `sanitize_for_display`, and Task 6 adds the `Option<C>` impl after `Pair`. These are different regions.
- `crates/warden-cli/src/daemon.rs`: only Tasks 6, 7 and 8 touch it, and Task 8 starts after 6 and 7 have merged.

## File Structure

```
crates/warden-agent/src/config.rs              modify: [whatsapp] table, secret keys, env-name uniqueness across tables
crates/warden-agent/src/redact.rs              modify: Meta access token pattern
crates/warden-agent/src/channel.rs             modify: pub(crate) cap_utf16 (moved from telegram), impl Channel for Option<C>
crates/warden-agent/src/telegram/channel.rs    modify: use channel::cap_utf16 (behavior unchanged)
crates/warden-agent/src/whatsapp/mod.rs        create: re-exports
crates/warden-agent/src/whatsapp/api.rs        create: AccessToken, GraphApi, PhoneInfo, WhatsAppError, ErrorClass
crates/warden-agent/src/whatsapp/webhook.rs    create: AppSecret, VerifyToken, check_signature, handshake, parse_notification, WaEvent, WebhookBatch
crates/warden-agent/src/whatsapp/seen.rs       create: SeenStore
crates/warden-agent/src/whatsapp/listener.rs   create: WebhookListener, ListenerConfig, WebhookStats
crates/warden-agent/src/whatsapp/channel.rs    create: WhatsAppChannel, WhatsAppOptions, WhatsAppFatal, sender_id
crates/warden-agent/src/lib.rs, Cargo.toml     modify
crates/warden-cli/src/daemon.rs                modify: Option channels, Watched<C>, ChannelFatal, WhatsApp startup, print-service names
crates/warden-cli/Cargo.toml                   modify: dev hmac, sha2
crates/warden-agent/tests/{config,redact,channel}.rs                  modify
crates/warden-agent/tests/{whatsapp_api,whatsapp_webhook,whatsapp_listener,whatsapp_channel}.rs  create
crates/warden-cli/tests/daemon.rs              modify
README.md, docs/SECURITY-NOTES.md              modify
```

---

### Task 1: `[whatsapp]` config table and Meta token redaction

**Files:**
- Modify: `crates/warden-agent/src/config.rs`, `crates/warden-agent/src/redact.rs` (pattern and module doc list)
- Test: `crates/warden-agent/tests/config.rs`, `crates/warden-agent/tests/redact.rs` (and `--test redact_differential` must pass unchanged)

**Interfaces:**
- Consumes: `check_env_name`, `shown_key`, `ConfigError::{Invalid, WrongType, WrongKind, UnknownField, SecretInFile}`, the `telegram()` parser pattern.
- Produces:
  - `pub const DEFAULT_WHATSAPP_TOKEN_ENV: &str = "WARDEN_WHATSAPP_TOKEN"`, `DEFAULT_WHATSAPP_APP_SECRET_ENV = "WARDEN_WHATSAPP_APP_SECRET"`, `DEFAULT_WHATSAPP_VERIFY_TOKEN_ENV = "WARDEN_WHATSAPP_VERIFY_TOKEN"`, `DEFAULT_WHATSAPP_LISTEN = "127.0.0.1:8097"`, `DEFAULT_GRAPH_VERSION = "v26.0"`, `DEFAULT_GRAPH_API_BASE = "https://graph.facebook.com"`
  - `pub struct WhatsAppConfig { pub owner_numbers: Vec<String> /* digits only */, pub phone_number_id: String, pub access_token_env: String, pub app_secret_env: String, pub verify_token_env: String, pub listen: std::net::SocketAddr, pub max_message_age_secs: u64, pub graph_version: String, pub api_base: Option<String> }`; `Config` gains `pub whatsapp: Option<WhatsAppConfig>`
  - Parsing: `[whatsapp]` becomes the second allowed nested table, parsed after `[telegram]`. Field names in errors are `whatsapp.<name>`. Rules:
    - `owner_numbers` is required: 1-8 strings, each one optional `+` then 7-15 ASCII digits (`Invalid("whatsapp.owner_numbers", ..)`); the stored value has no `+`.
    - `phone_number_id` is required: 1-32 ASCII digits, as a string.
    - The three `*_env` fields use `check_env_name`. The five names (the three, `api_key_env`, and the Telegram `bot_token_env` if present) must all differ: `Invalid(<field>, "must name a different environment variable than <other>")`.
    - `listen` is a string parsed as `SocketAddr` (so no host names) whose `ip().is_loopback()`. Otherwise `Invalid("whatsapp.listen", "must be a loopback address such as 127.0.0.1:8097; expose it through your own tunnel")`. Port 0 is allowed (tests).
    - `max_message_age_secs` is an integer in `10..=3600`, default 120.
    - `graph_version` matches `^v[0-9]{1,3}\.[0-9]{1,2}$`.
    - `api_base` is a string, checked later by `GraphApi::new`.
    - Wrong kinds use `WrongKind` / `WrongType` as in `[telegram]`.
  - `SECRET_KEYS` becomes 12 entries, adding `accesstoken`, `appsecret`, `verifytoken`, `whatsapptoken`. The `SecretInFile` message also names `[whatsapp] access_token_env`, `app_secret_env` and `verify_token_env`.
  - Redactor: inside the existing left-boundary group, `EAA[A-Za-z0-9]{40,}` is redacted as kind `api_key`.

- [ ] **Step 1: Write the failing tests.**
  - config:
    - `whatsapp_table_parses_with_defaults`: the three env defaults, `listen == "127.0.0.1:8097".parse()`, age 120, `graph_version == "v26.0"`, `api_base == None`.
    - `whatsapp_owner_numbers_rules`: `[]`, 9 entries, `"+1 555 123 4567"`, `"abc"`, 6 digits and 16 digits are refused; `"+15551234567"` is stored as `"15551234567"`.
    - `whatsapp_phone_number_id_required_digits`.
    - `whatsapp_listen_must_be_loopback`: `0.0.0.0:8097`, `[::]:8097`, `192.168.1.5:8097`, `localhost:8097` and `[::ffff:127.0.0.1]:8097` are refused; `127.0.0.1:0` and `[::1]:8097` are accepted.
    - `whatsapp_secret_fields_in_file_are_rejected`: `access_token`, `app_secret`, `verify_token`, `whatsapp_token` give `SecretInFile`; the message names `access_token_env` and not the value.
    - `whatsapp_env_names_must_all_differ`: every pair among the three, each against `api_key_env`, and each against `[telegram] bot_token_env`.
    - `whatsapp_graph_version_shape`: `"23.0"`, `"v23"` and `"v26.0/../x"` are refused.
    - `unknown_whatsapp_field_is_rejected`; `both_channel_tables_parse_together`; `third_nested_table_still_rejected`; `whatsapp_max_message_age_out_of_range_is_invalid` (9 and 3601); `whatsapp_wrong_kinds_are_named` (`owner_numbers = "155"`, `listen = 8097`).
    - Unit test `secret_key_names` gains the 4 new keys, and `access_token_env`, `app_secret_env`, `verify_token_env`, `phone_number_id`, `owner_numbers` as not secret.
  - redact:
    - `meta_access_token_is_redacted`: `"EAAG"` plus 150 alphanumerics gives `[REDACTED:api_key]`; the same after `token=` and in JSON.
    - `eaa_prefix_words_are_not_redacted`: `EAAS`, `EAA` plus 39 chars, and `xEAA` plus 60 chars (no left boundary) are left alone.
- [ ] **Step 2: Run** `cargo test -p warden-agent --test config --test redact`. Expected: FAIL.
- [ ] **Step 3: Implement** `fn whatsapp(t: &toml::Table, taken: &[(&'static str, &str)]) -> Result<WhatsAppConfig, ConfigError>`, where `taken` holds `api_key_env` and, if present, `telegram.bot_token_env`. Then add the redactor alternative.
- [ ] **Step 4: Run** `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): whatsapp config table and meta token redaction`

---

### Task 2: Graph API client

**Files:**
- Create: `crates/warden-agent/src/whatsapp/mod.rs` (module doc: webhook inbound on loopback, Graph API outbound, secrets from the environment, nothing in `Debug` or errors), `crates/warden-agent/src/whatsapp/api.rs`
- Modify: `crates/warden-agent/src/lib.rs`
- Test: `crates/warden-agent/tests/whatsapp_api.rs` (wiremock)

**Interfaces:**
- Consumes: `http::client`, `http::check_base_url`.
- Produces:
  - `pub struct AccessToken(Zeroizing<String>)`. `AccessToken::new(s: String) -> Result<AccessToken, WhatsAppError>` accepts 32-2048 chars of `[A-Za-z0-9._-]` and otherwise returns `Config("invalid access token")`. The input is zeroized either way. `Debug` is `AccessToken(<redacted>)`, and there is no `Display`.
  - `pub struct GraphApi`. `GraphApi::new(token: AccessToken, api_base: &str, graph_version: &str, phone_number_id: &str) -> Result<GraphApi, WhatsAppError>` re-checks the version shape and the digits of the id, since both go into the URL path. `with_timeout(self, Duration) -> Self` (default 30 s). `Debug` shows the base, the version and the id only.
    - `pub async fn phone_number(&self) -> Result<PhoneInfo, WhatsAppError>`: `GET {base}/{version}/{id}?fields=display_phone_number,verified_name`. `pub struct PhoneInfo { pub display_phone_number: String, pub verified_name: Option<String> }`.
    - `pub async fn send_text(&self, to: &str, body: &str) -> Result<String, WhatsAppError>`: the POST body is exactly the one in Global Constraints, and it returns `messages[0].id` (the wamid). The caller has already redacted, sanitized and capped `body`.
    - Every request sets `Authorization: Bearer <token>` through a `HeaderValue` built in a zeroizing buffer and marked `set_sensitive(true)`. Responses are read in chunks capped at 64 KiB (`TooLarge`).
  - `pub enum WhatsAppError { Config(&'static str), Transport(&'static str /* timeout|connect|other */), Status(u16), Graph { status: u16, code: i64, subcode: Option<i64> }, Malformed(&'static str), TooLarge }`, with a fixed-text `Display`. The Graph `error.message`, `error_user_msg` and `fbtrace_id` are never kept.
  - `pub enum ErrorClass { AuthRejected, RateLimited, OutsideWindow, Other }` and `impl WhatsAppError { pub fn class(&self) -> ErrorClass }`:
    - status 401, or code 190: `AuthRejected`;
    - status 429, or code 4, 80007, 130429, 131048 or 131056: `RateLimited`;
    - code 131047: `OutsideWindow`;
    - anything else: `Other`.

- [ ] **Step 1: Write the failing tests:**
  - `send_text_body_is_exact`: wiremock `body_json` equality. The path is `/v26.0/<id>/messages`, the header is `authorization: Bearer <token>`, the URL has no query and does not contain the token, and the text `[x](https://evil.example/?d=1) <b>` is sent byte for byte.
  - `send_text_returns_wamid`, `phone_number_uses_get_bearer_and_fields`.
  - `graph_error_keeps_code_and_subcode_only`: a 400 with `code` 100, `error_subcode` 33 and a `message` containing `LEAKME`; `format!("{e} {e:?}")` lacks `LEAKME`.
  - `auth_errors_are_auth_rejected`: a 401, and a 400 with code 190.
  - `rate_limits_are_rate_limited`: a 429, and codes 130429 and 131056.
  - `code_131047_is_outside_window`, `oversized_body_is_too_large`, `garbage_json_is_malformed`.
  - `redirect_is_not_followed`: a 302 gives `Status(302)`.
  - `errors_and_debug_never_contain_the_token`: a closed port, a 401, a timeout; `format!("{e} {e:?} {api:?}")` lacks the token.
  - `token_shape_is_validated`: 31 chars, a token containing a space or `\n`, and 2049 chars are refused.
  - `api_base_must_be_https_or_loopback`; `version_and_phone_number_id_are_validated`.
- [ ] **Step 2: Run** `cargo test -p warden-agent --test whatsapp_api`. Expected: FAIL.
- [ ] **Step 3: Implement** it on the model of `telegram/api.rs`: the same `transport()` kind words, the same chunked read, the same backstop `tokio::time::timeout`.
- [ ] **Step 4: Run** the same command and clippy. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): whatsapp graph api client`

---

### Task 3: Webhook verification, payload parser, seen-message store

**Files:**
- Create: `crates/warden-agent/src/whatsapp/webhook.rs`, `crates/warden-agent/src/whatsapp/seen.rs`
- Modify: `crates/warden-agent/src/whatsapp/mod.rs` (create it as in Task 2 if Task 2 has not landed), `crates/warden-agent/src/lib.rs`, `crates/warden-agent/Cargo.toml` (`hmac = "0.12"`, `subtle = "2"`)
- Test: `crates/warden-agent/tests/whatsapp_webhook.rs` (pure functions and JSON fixtures), unit tests in `seen.rs`

**Interfaces:**
- Consumes: `state::read_private`, `state::write_atomic`, `sha2::Sha256`.
- Produces:
  - `pub struct AppSecret(Zeroizing<Vec<u8>>)`. `AppSecret::new(s: String) -> Result<AppSecret, &'static str>` accepts 16-128 ASCII alphanumerics and otherwise returns `"invalid app secret"`.
  - `pub struct VerifyToken(Zeroizing<String>)`. `VerifyToken::new(s: String) -> Result<VerifyToken, &'static str>` accepts 16-128 chars of `[A-Za-z0-9._~-]` and otherwise returns `"invalid verify token"`.
  - Both have a redacted `Debug` and no `Display`.
  - `pub enum SignatureCheck { Valid, Missing, Invalid }` and `pub fn check_signature(secret: &AppSecret, header: Option<&[u8]>, body: &[u8]) -> SignatureCheck`. The header must be `sha256=` followed by 64 hex digits (either case); anything else is `Invalid`. The comparison uses `Mac::verify_slice`.
  - `pub fn handshake(query: Option<&str>, token: &VerifyToken) -> Option<String>`: parsed with `reqwest::Url::parse("http://h/?…").query_pairs()` (no new crate). A duplicate `hub.*` key gives `None`. The rules are in Global Constraints.
  - `pub enum RefuseReason { NotText, Forwarded, Reaction, Status, System, Unsupported, Malformed }`, with `pub fn tag(self) -> &'static str` returning `non-text`, `forward`, `reaction`, `status`, `system`, `unsupported`, `malformed`.
  - `pub enum WaEvent { Text { wamid: String, from: String, timestamp_s: i64, body: String, reply_to: Option<String> }, Refused { wamid: Option<String>, from: Option<String>, timestamp_s: Option<i64>, reason: RefuseReason } }`.
  - `pub struct Notification { pub events: Vec<WaEvent>, pub foreign: usize }`, `pub enum NotificationError { NotJson, NotWhatsApp }`.
  - `pub fn parse_notification(body: &[u8], phone_number_id: &str) -> Result<Notification, NotificationError>`:
    - `object` must be `"whatsapp_business_account"`, else `NotWhatsApp`.
    - For each `entry[].changes[]` with `field == "messages"`: a `value.metadata.phone_number_id` other than the configured one adds 1 to `foreign` and is skipped.
    - Each `value.statuses[]` becomes `Refused { reason: Status, .. }` with every field `None`.
    - Each `value.messages[]` is checked in this order:
      1. `id` (1-256 printable ASCII, no whitespace), `from` (1-20 digits) and `timestamp` (a decimal string or an integer) must be present and valid, else `Malformed` (with whichever of them were valid);
      2. `context.forwarded` or `context.frequently_forwarded` true gives `Forwarded`;
      3. an `errors` field gives `Unsupported`;
      4. `type` `"text"` with a string `text.body` gives `Text` (`reply_to` = `context.id`);
      5. `"reaction"` gives `Reaction`, `"system"` gives `System`, `"unsupported"` gives `Unsupported`;
      6. anything else gives `NotText`.
    - At most 256 events are kept per notification. Unknown fields are ignored.
  - `pub struct WebhookBatch { pub events: Vec<WaEvent> }`: what the listener sends to the channel.
  - `seen.rs`:
    - `pub const SEEN_FILE: &str = "whatsapp-seen"` and `pub const MAX_SEEN: usize = 1024`.
    - `pub struct SeenStore`. `SeenStore::open(home: &Path) -> io::Result<SeenStore>`: a missing file is empty. A length that is not a multiple of 32, or above `32 * MAX_SEEN`, is `InvalidData`. Insecure files follow the `read_private` rules.
    - `pub fn contains(&self, wamid: &str) -> bool`.
    - `pub fn record(&mut self, wamids: &[&str]) -> io::Result<()>`: appends the SHA-256 of each, drops the oldest beyond `MAX_SEEN`, then writes the whole file with `write_atomic`. Memory is updated only after the write succeeds.

- [ ] **Step 1: Write the failing tests:**
  - Signature:
    - `valid_signature_is_valid` (the test computes the HMAC with `hmac`/`sha2`/`hex`);
    - `missing_header_is_missing`;
    - `signature_of_other_body_or_secret_is_invalid`;
    - `sha1_prefix_non_hex_and_short_hex_are_invalid`;
    - `uppercase_hex_is_accepted`.
  - Handshake:
    - `handshake_returns_digit_challenge`;
    - `handshake_refuses_wrong_token_mode_or_challenge`: a wrong token, `unsubscribe`, `abc`, 65 digits, an empty challenge, missing keys, a duplicated `hub.verify_token`, and `None`.
  - Secrets:
    - `secret_shapes_are_validated`;
    - `debug_hides_secrets`: the `{:?}` of both types lacks the value.
  - Parsing:
    - `text_from_metadata_matching_number_is_text`, `reply_context_id_is_reply_to`;
    - `forwarded_and_frequently_forwarded_are_refused`;
    - `image_audio_document_sticker_location_contacts_interactive_button_are_not_text`;
    - `reaction_system_unsupported_are_tagged`, `message_with_errors_is_unsupported`;
    - `statuses_become_status_events`;
    - `foreign_phone_number_id_is_ignored`: `foreign == 1` and no events;
    - `missing_id_from_or_timestamp_is_malformed`, `non_digit_from_is_malformed`;
    - `wrong_object_is_not_whatsapp`, `garbage_is_not_json`;
    - `events_are_capped_at_256`.
  - Seen store:
    - `seen_roundtrip_and_0600`;
    - `seen_keeps_the_newest_1024`;
    - `seen_file_with_bad_length_is_invalid_data`;
    - `seen_file_holds_no_wamid_text`: the file bytes do not contain the wamid;
    - `failed_record_leaves_memory_unchanged`: make the home 0500.
- [ ] **Step 2: Run** `cargo test -p warden-agent --test whatsapp_webhook` and `cargo test -p warden-agent --lib seen`. Expected: FAIL.
- [ ] **Step 3: Implement** both files. Parse with `serde_json::Value` and `get` chains, as `telegram/update.rs` does.
- [ ] **Step 4: Run** the same commands and clippy. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): whatsapp webhook verification, payload parser and seen store`

---

### Task 4: Loopback webhook listener

**Files:**
- Create: `crates/warden-agent/src/whatsapp/listener.rs`
- Modify: `crates/warden-agent/src/whatsapp/mod.rs`, `crates/warden-agent/Cargo.toml` (hyper, hyper-util and http-body-util as in Global Constraints; tokio adds `net`)
- Test: `crates/warden-agent/tests/whatsapp_listener.rs` (a real loopback client: reqwest for well-formed requests, a raw `tokio::net::TcpStream` for slow, partial and oversized ones)

**Interfaces:**
- Consumes: Task 3 `AppSecret`, `VerifyToken`, `check_signature`, `SignatureCheck`, `handshake`, `parse_notification`, `WebhookBatch`.
- Produces:
  - `pub const WEBHOOK_PATH: &str = "/webhook"`.
  - `pub struct ListenerConfig { pub app_secret: AppSecret, pub verify_token: VerifyToken, pub phone_number_id: String, pub max_body_bytes: usize, pub header_timeout: Duration, pub body_timeout: Duration, pub max_connections: usize }`. `ListenerConfig::new(app_secret, verify_token, phone_number_id: String) -> ListenerConfig` sets the defaults: 1 MiB, 10 s, 10 s, 16.
  - `pub struct WebhookStats` (`AtomicU64` fields): `unsigned`, `bad_signature`, `too_large`, `timed_out`, `malformed`, `foreign`, `queue_full`, `busy`, `handshake_refused`. It also has `pub fn snapshot(&self) -> StatsSnapshot`. `pub struct StatsSnapshot` holds the same fields as `u64` (`Debug`, `PartialEq`, `Default`) plus `pub fn is_zero(&self) -> bool`.
  - `pub struct WebhookListener`:
    - `pub async fn bind(addr: SocketAddr) -> io::Result<WebhookListener>`: `InvalidInput` unless `addr.ip().is_loopback()`.
    - `pub fn local_addr(&self) -> io::Result<SocketAddr>`.
    - `pub async fn serve(self, cfg: ListenerConfig, tx: mpsc::Sender<WebhookBatch>, stats: Arc<WebhookStats>, shutdown: watch::Receiver<bool>)`: returns once shutdown is `true` (it stops accepting; connections in progress get at most 2 s more).

Request handling, in order (every response body is a fixed short ASCII string or the digit challenge, `content-type: text/plain`, `connection: close`):
1. Path other than `WEBHOOK_PATH`: 404. Method other than GET/POST: 405.
2. GET: `handshake(uri.query(), ..)` returns 200 with the challenge, or 403 (`handshake_refused`).
3. POST: a declared `Content-Length` above the cap gets 413 before any read. The body is read with `http_body_util::Limited` inside `tokio::time::timeout(body_timeout)`. Over the cap gives 413 (`too_large`). A timeout gives 408 (`timed_out`).
4. `check_signature` on the raw bytes: `Missing` gives 401 (`unsigned`), `Invalid` gives 401 (`bad_signature`). Nothing is parsed in either case.
5. `parse_notification`: `Err` gives 200 (`malformed`). `foreign` is added to the stat. No events gives 200.
6. `tx.try_send(WebhookBatch { events })`: `Ok` gives 200. `Full` or `Closed` gives 503 (`queue_full`).

Connections are served with `hyper::server::conn::http1::Builder` with `timer(TokioTimer)`, `header_read_timeout(header_timeout)`, `keep_alive(false)` and `max_buf_size(16 * 1024)`. Each connection also has an overall `header_timeout + body_timeout + 5 s` cap. Connections are limited by a `tokio::sync::Semaphore`: when no permit is free, the accepted socket is closed at once (`busy`). An accept error sleeps 100 ms and continues. Nothing is printed.

- [ ] **Step 1: Write the failing tests:**
  - Handshake:
    - `handshake_echoes_digit_challenge_with_the_right_token`;
    - `handshake_wrong_token_or_mode_is_403`: a 403 with no part of the query in the body.
  - Signed and unsigned POSTs:
    - `signed_post_is_200_and_forwarded`: the receiver gets one batch with the text event;
    - `unsigned_post_is_401_and_not_forwarded`: `try_recv` is empty and `unsigned == 1`;
    - `bad_signature_is_401_and_not_forwarded`: another secret, another body, `sha1=`; `bad_signature == 3`;
    - `foreign_phone_number_id_is_200_and_not_forwarded`;
    - `malformed_signed_json_is_200_and_not_forwarded`.
  - Abuse limits:
    - `oversized_body_is_413_and_never_parsed`: a declared `Content-Length: 1048577`, and a chunked body exceeding the cap (raw TCP);
    - `slow_headers_are_cut_off`: `header_timeout` 200 ms; send half a request line; the connection closes within 2 s;
    - `slow_body_is_cut_off`: `body_timeout` 200 ms; 408 or close;
    - `connection_limit_holds`: `max_connections` 2; two idle raw sockets; a third connection reads EOF at once and `busy >= 1`; after the idle ones time out, a signed POST succeeds;
    - `full_queue_is_503`: channel capacity 1, no consumer, the second POST is 503.
  - Routing and lifecycle:
    - `other_paths_404_and_methods_405`;
    - `bind_refuses_non_loopback`: `0.0.0.0:0` gives `InvalidInput`;
    - `shutdown_stops_accepting`: after `serve` returns, connecting is refused.
- [ ] **Step 2: Run** `cargo test -p warden-agent --test whatsapp_listener`. Expected: FAIL.
- [ ] **Step 3: Implement** the listener as specified.
- [ ] **Step 4: Run** `cargo test -p warden-agent --test whatsapp_listener` five times in a row (timing tests must not flake), then `cargo test --workspace` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): loopback whatsapp webhook listener with signature check before parsing`

---

### Task 5: `WhatsAppChannel`

**Files:**
- Create: `crates/warden-agent/src/whatsapp/channel.rs`
- Modify: `crates/warden-agent/src/whatsapp/mod.rs`, `crates/warden-agent/src/channel.rs` (move `cap_utf16` here as `pub(crate) fn cap_utf16(s: String, max_units: usize) -> String`, behavior unchanged), `crates/warden-agent/src/telegram/channel.rs` (call it with 4096)
- Test: `crates/warden-agent/tests/whatsapp_channel.rs`. Wiremock serves the Graph API. The test holds the `mpsc::Sender<WebhookBatch>` and feeds batches directly; no listener is involved. `crates/warden-agent/tests/telegram_channel.rs` must pass unchanged.

**Interfaces:**
- Consumes: Task 2 `GraphApi`, `WhatsAppError::class`, `ErrorClass`; Task 3 `WaEvent`, `RefuseReason`, `WebhookBatch`, `SeenStore`; `Channel`, `render_prompt`, `parse_reply`, `sanitize_for_display`, `redact`.
- Produces:
  - `pub struct WhatsAppOptions { pub max_message_age: Duration /* 120 s */, pub rate_limit_backoff: Duration /* 2 s */, pub shutdown_request_timeout: Duration /* 5 s */ }` with `Default`.
  - `WhatsAppChannel::new(api: GraphApi, inbound: mpsc::Receiver<WebhookBatch>, owners: Vec<String>, seen: SeenStore, opts: WhatsAppOptions) -> WhatsAppChannel`. Also `with_clock(self, Box<dyn Fn() -> u64 + Send + Sync>) -> Self` (Unix ms) and `with_shutdown(self, watch::Receiver<bool>) -> Self` (the same bounded-request rule as Telegram).
  - Accessors: `fatal(&self) -> Option<WhatsAppFatal>`, `dropped_count(&self) -> u64`, and `window_drops(&self) -> Arc<AtomicU64>`. The last is a handle shared with the channel; the daemon takes it before wrapping the channel in `Watched`/`Pair`, which have no accessors.
  - `pub fn sender_id(number: &str) -> SenderId` returns `wa:<number>`. Refused and stale events become `wa-<tag>:<from or 0>` (`wa-stale:<n>` for stale ones).
  - `pub enum WhatsAppFatal { TokenRejected, SeenUnwritable, ListenerStopped }`. `Display`: `WhatsApp rejected the access token`, `cannot save the WhatsApp seen-message list`, `the WhatsApp webhook listener stopped`.
  - `pub const WINDOW_MS: u64 = 86_400_000`, `const WINDOW_MARGIN_MS: u64 = 300_000`.

Behavior:
- **Ingest** (synchronous, so cancel-safe; used by `recv`, `ask_approval` and `discard_pending_input`):
  1. Drop events whose wamid `SeenStore::contains`, or that repeat a wamid earlier in the batch.
  2. `SeenStore::record` the remaining wamids. On failure: `fatal = SeenUnwritable`, drop the batch.
  3. Every event from an owner number with a timestamp sets `last_inbound[from] = max(old, min(ts * 1000, now))`.
  4. Owner `Text`: stale (the Telegram formula) becomes a `wa-stale` item plus one notice per batch `ignored <n> message(s) older than <s> s (Warden was not running or was busy)`. Otherwise it becomes an owner item with origin `(from, wamid, timestamp_s)`.
  5. Non-owner `Text`: `wa:<from>` with empty text.
  6. `Refused`: `wa-<tag>:<from or 0>` with empty text. An owner's `NotText` also queues the notice `only text messages are supported`.
- **`recv`:** flush notices; re-expire queued owner items (`expire_queued`, as Telegram); pop. Otherwise `inbound.recv().await` (cancel-safe) and ingest. `None` from the receiver while not shutting down sets `fatal = ListenerStopped`. `recv` returns `None` once `fatal` is set or the receiver is closed.
- **Queue:** at most 64 items, with Telegram's eviction rule: items with no content go first.
- **`send(to, text)`:**
  - Only to an owner; otherwise dropped.
  - Outside the window: dropped, `window_drops += 1`.
  - The text is `cap_utf16(sanitize_for_display(redact(text)), 4096)`.
  - `AuthRejected` sets `TokenRejected`. `RateLimited` sleeps `rate_limit_backoff` and retries once, unless shutting down. `OutsideWindow` counts as a window drop. Anything else is dropped.
- **`ask_approval(to, prompt)`:**
  - `No` if `to` is not an owner or the tier is `YesPin`, with nothing sent.
  - `Undelivered` if outside the window.
  - The summary and note are redacted, then rendered with `render_prompt`. A prompt over 4096 UTF-16 units sends `request too long to approve safely; refused` and returns `No`.
  - A failed send returns `Undelivered` (`TokenRejected` also sets fatal).
  - Then ingest batches until an owner `Text` from `to` arrives. A `reply_to` that is set and is not the prompt's wamid gives `No`; otherwise `parse_reply(text, false, code)`. A `NotText` from `to` gives `No`.
  - Everything else is queued. The reply text is held in `Zeroizing`.
- **`discard_pending_input(to)`:** drop queued items from `to`, drain the receiver with `try_recv` and ingest, drop `to`'s new items, keep the rest. It returns the bytes dropped (at least 1 per message).
- **The rest:** `accepts_pin` is always `false`. `retract_last` and `flush_pending` keep the trait defaults. `serves(who)` is `who.0.starts_with("wa:")`.

- [ ] **Step 1: Write the failing tests:**
  - Inbound and queueing:
    - `owner_text_becomes_inbound_with_wa_sender`;
    - `non_owner_text_is_non_owner_with_empty_text`;
    - `forwarded_reaction_media_and_status_reach_engine_as_tagged_non_owners`;
    - `owner_non_text_gets_notice_and_is_tagged`;
    - `stale_messages_are_dropped_and_owner_is_told_once`;
    - `queued_message_that_goes_stale_is_not_delivered`: the clock moves past the age while it sits in the queue;
    - `queue_overflow_drops_beyond_64`;
    - `discard_drops_pending_owner_messages_and_keeps_others`;
    - `recv_is_cancel_safe`: a `recv` dropped by a timeout; the batch sent next is returned exactly once.
  - Deduplication and fatal conditions:
    - `duplicate_wamid_is_delivered_once`: the same batch twice, and a wamid repeated within one batch;
    - `seen_is_persisted_before_the_message_is_returned`: `SeenStore::open` on the home `contains` it when `recv` returns;
    - `restart_does_not_redeliver_seen_wamid`: a new channel on the same home;
    - `seen_write_failure_is_fatal_and_nothing_is_delivered`;
    - `listener_gone_is_fatal_listener_stopped`: drop the sender; `recv` is `None` and `fatal == Some(ListenerStopped)`;
    - `listener_gone_during_shutdown_is_not_fatal`;
    - `token_rejected_on_send_is_fatal_and_ends_recv`: a 401 with code 190.
  - Outbound:
    - `send_goes_only_to_owners`;
    - `send_redacts_sanitizes_and_caps_at_4096`: a fake `sk-ant-` key becomes `[REDACTED:api_key]`, `\x1b[31m` becomes `\u{1b}`, and 3000 emoji fit within 4096 UTF-16 units ending in `…`;
    - `send_outside_24h_window_is_dropped_and_counted`: inbound at T; a send at T+23 h is sent; a send at T+24 h−4 min is dropped; `window_drops().load(Relaxed) == 1`; an inbound timestamp in the future does not extend the window past now+24 h;
    - `graph_131047_counts_as_outside_window`;
    - `rate_limited_send_retries_once`: `rate_limit_backoff` 10 ms; exactly 2 requests.
  - Approvals:
    - `ask_approval_outside_window_is_undelivered`: no request is made;
    - `ask_approval_accepts_yes_code_from_the_sender`;
    - `ask_approval_ignores_and_queues_other_senders`: a stranger's `yes <code>` first, then the owner's; the result is `Yes`, and the next `recv` is the stranger as a non-owner;
    - `reply_from_another_owner_is_queued_not_used`;
    - `reply_quoting_another_message_is_no`, `reply_quoting_the_prompt_is_accepted`;
    - `yespin_prompt_is_no_without_send`: wiremock expects 0 POSTs;
    - `accepts_pin_is_always_false`;
    - `retract_last_sends_nothing`.
  - Routing: `serves_only_wa_senders`.
- [ ] **Step 2: Run** `cargo test -p warden-agent --test whatsapp_channel`. Expected: FAIL.
- [ ] **Step 3: Implement** the channel. Move `cap_utf16` first, then confirm `cargo test -p warden-agent --test telegram_channel` still passes.
- [ ] **Step 4: Run** `cargo test --workspace` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): whatsapp channel with window-aware replies and chat-bound approvals`

---

### Task 6: Daemon groundwork for several channels

**Files:**
- Modify: `crates/warden-agent/src/channel.rs` (`impl Channel for Option<C>`), `crates/warden-cli/src/daemon.rs`
- Test: `crates/warden-agent/tests/channel.rs`, `crates/warden-cli/tests/daemon.rs` (all existing tests pass unchanged)

**Interfaces:**
- Consumes: `Channel`, `Pair`, `TelegramChannel::fatal`, `TelegramFatal`.
- Produces:
  - `impl<C: Channel + Send> Channel for Option<C>`. `Some` delegates every method. `None` behaves as follows: `recv` returns `None`, `send` and `retract_last` do nothing, `ask_approval` returns `No`, `discard_pending_input` returns 0, `accepts_pin` and `serves` return `false`, and `flush_pending` does nothing.
  - daemon.rs:
    - `enum ChannelFatal { Telegram(TelegramFatal) }`, whose `Display` delegates;
    - `trait FatalSource { fn fatal(&self) -> Option<ChannelFatal>; }`, implemented for `TelegramChannel`;
    - `struct Watched<C>` (generic; `note()` uses `FatalSource`);
    - `FatalSlot` stores `Option<ChannelFatal>`;
    - the channel is built as `Pair::new(Some(telegram), console.then(|| stdio))` in place of today's `if console` branches, so `run` is instantiated once.

- [ ] **Step 1: Write the failing tests:**
  - `option_none_is_a_closed_channel_that_serves_nobody`;
  - `option_some_delegates_every_call`: a `TestChannel` records the calls;
  - `pair_with_a_none_side_behaves_like_the_other_side`: `Pair::new(None::<TestChannel>, Some(stdio))` reads stdio lines and routes `local`.
- [ ] **Step 2: Run** `cargo test -p warden-agent --test channel`. Expected: FAIL.
- [ ] **Step 3: Implement** the impl, then the daemon refactor (no behavior or message changes).
- [ ] **Step 4: Run** `cargo test --workspace`, clippy and `cargo fmt --check`. Expected: PASS, including every existing `tests/daemon.rs` test.
- [ ] **Step 5: Commit** `refactor(cli): optional channels and a generic fatal watcher in the daemon`

---

### Task 7: `print-service` names every configured secret

**Files:**
- Modify: `crates/warden-cli/src/daemon.rs` (`service_file`, `launchd_plist`, `systemd_unit`)
- Test: `crates/warden-cli/tests/daemon.rs`

**Interfaces:**
- Consumes: Task 1 `Config::whatsapp`, `WhatsAppConfig::{access_token_env, app_secret_env, verify_token_env}`.
- Produces:
  - `launchd_plist` and `systemd_unit` take `env: &[&str]` in place of `[&str; 2]`. The order is `api_key_env`, then `bot_token_env` if `[telegram]` is present, then the three WhatsApp names if `[whatsapp]` is present.
  - With neither table: `error: no channel configured: add a [telegram] or [whatsapp] table`, exit 1.
  - Copy changes:
    - the plist comment says `the API key and the channel secrets`;
    - the systemd comment lists one `<NAME>=REPLACE_ME` line per name;
    - `Description=Warden agent daemon`.

- [ ] **Step 1: Write the failing tests:**
  - `print_service_lists_whatsapp_env_names`: a `[whatsapp]`-only config. Both formats contain `WARDEN_WHATSAPP_TOKEN`, `WARDEN_WHATSAPP_APP_SECRET`, `WARDEN_WHATSAPP_VERIFY_TOKEN` and `REPLACE_ME`, and not `WARDEN_TELEGRAM_TOKEN`. With both tables, all five names appear. With the three variables set to fake values in the environment, none of the values appears.
  - `print_service_without_any_channel_exits_1`.
- [ ] **Step 2: Run** `cargo test -p warden-cli --test daemon print_service`. Expected: FAIL.
- [ ] **Step 3: Implement** it. The existing `print_service_*` tests keep passing.
- [ ] **Step 4: Run** `cargo test --workspace` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** `feat(cli): service files carry the whatsapp secret placeholders`

---

### Task 8: `warden daemon` on WhatsApp

**Files:**
- Modify: `crates/warden-cli/src/daemon.rs` (module doc: the new startup order), `crates/warden-cli/Cargo.toml` (dev: `hmac = "0.12"`, `sha2 = "0.10"`)
- Test: `crates/warden-cli/tests/daemon.rs`

**Interfaces:**
- Consumes: Tasks 1-6: `WhatsAppConfig`, `AccessToken`, `GraphApi::{new, phone_number}`, `ErrorClass`, `AppSecret`, `VerifyToken`, `WebhookListener::{bind, local_addr, serve}`, `ListenerConfig::new`, `WebhookStats`, `SeenStore::open`, `SEEN_FILE`, `WhatsAppChannel`, `WhatsAppOptions`, `WhatsAppFatal`, `whatsapp::sender_id`, `ChannelFatal`, `FatalSource`, `Watched<C>`, `impl Channel for Option<C>`.
- Produces:
  - `ChannelFatal::WhatsApp(WhatsAppFatal)` and `impl FatalSource for WhatsAppChannel`.
  - The channel `Pair::new(Pair::new(Option<Watched<TelegramChannel>>, Option<Watched<WhatsAppChannel>>), Option<StdioChannel<..>>)`.
  - The mpsc queue between the listener and the channel holds 16 batches.

Startup, fail closed with exit 1, in this order:
1. data dir;
2. `daemon.lock`;
3. config, which needs `[telegram]` or `[whatsapp]` (`no channel configured: add a [telegram] or [whatsapp] table`); with `--console`, `owner` must be `local`;
4. root;
5. planner key;
6. if `[telegram]`: the bot token;
7. if `[whatsapp]`: the three variables. A missing or empty variable is named under `showable_env_name`. A bad shape gives `the WhatsApp access token variable does not hold a valid token` (or `app secret`, `verify token`). Then the values: `the WhatsApp secrets, the bot token and the API key must all be different values`;
8. if `[telegram]`: `getMe`;
9. if `[whatsapp]`: `GraphApi::new`, then `phone_number()`:
   - `AuthRejected`: `WhatsApp rejected the access token`;
   - a `Graph` code 100, or `Status(404)`: `the access token cannot see phone_number_id <id>`;
   - anything else: `cannot reach the WhatsApp Cloud API (<kind>)`;
10. if `[whatsapp]`: `WebhookListener::bind(listen)`. `AddrInUse` gives `<addr> is already in use`; anything else gives `cannot listen on <addr> (<io kind>)`;
11. `open_parts` with owners `tg:<id>…`, `wa:<number>…` and `local` with `--console`. Then `OffsetStore::open` (if Telegram) and `SeenStore::open` (if WhatsApp). The latter's error says `make whatsapp-seen a regular file with mode 0600, or remove it while Warden is stopped (removing it may act on a redelivered message newer than max_message_age_secs)`;
12. `Engine::try_new`.

Steps 1-10 leave no files except the data dir and `daemon.lock`.

Run:
- The listener is spawned with the shutdown receiver.
- Banner: `warden daemon:` followed by `telegram @<bot>` and/or `whatsapp <display_phone_number, sanitized> listen=<bound addr>`, then `owners=<total> root=<root>`. The Telegram-only banner is byte-identical to today's.
- After `run` returns: set shutdown, then await the listener task (at most 5 s). The final flush is unchanged. If any listener or window counter is non-zero, print one line: `whatsapp: refused <unsigned> unsigned, <bad_signature> bad-signature, <too_large> oversized, <timed_out> slow webhook requests; <window_drops> replies not sent outside the 24 h window`.
- Exit 1 if either channel reported a fatal error, else 0.

- [ ] **Step 1: Write the failing tests.**
  - Helpers:
    - `Wa::start()`: wiremock on a test-owned runtime. It serves `GET /v26.0/<PNID>`, records `POST /v26.0/<PNID>/messages` bodies and answers with increasing `wamid.test<n>` ids.
    - `Env::mock_wa(api_base, script, telegram: Option<&str>)` writes `[whatsapp] owner_numbers = ["15550000042"], phone_number_id = "<PNID>", listen = "127.0.0.1:0", api_base = …`.
    - `listen_addr(&Daemon) -> SocketAddr` parses `listen=` from stderr.
    - `post_webhook(addr, body: &Value, secret: Option<&str>) -> u16` uses a raw `std::net::TcpStream` (HTTP/1.1, `Connection: close`) and computes `sha256=` with `hmac`/`sha2`.
    - `wa_text(wamid, from, text, ts) -> Value`.
    - Fake secrets: `WARDEN_WHATSAPP_TOKEN` = `"EAA"` + 60 alphanumerics, the app secret = 32 hex characters, the verify token = 24 characters.
  - Tests:
    - `whatsapp_daemon_answers_an_owner_text`: a Graph POST `to == "15550000042"` whose body contains `model: `.
    - `whatsapp_forged_webhooks_are_401_and_never_acted_on`: unsigned, and signed with another secret, both give 401. The script is empty, so a planner call would fail. There is no Graph POST, and no `ignored` audit entry for them.
    - `whatsapp_handshake_needs_the_verify_token`: GET with the right token gives 200 and the challenge; with a wrong token, 403.
    - `whatsapp_write_needs_yes_code`: read the code from the captured prompt, post `yes <code>`; the file is written and `done:` is sent.
    - `whatsapp_refuses_pin_tier_without_a_prompt`: `delete_file` with a PIN set as `daemon_refuses_pin_tier_over_telegram_by_default` does. No prompt is POSTed, the owner is told the PIN is not accepted, and the file still exists.
    - `whatsapp_pin_like_message_never_reaches_the_planner`: post the PIN as text. The script is empty. The owner gets `looks like your PIN`, and the audit has `ignored: pin-like message`.
    - `whatsapp_duplicate_delivery_is_acted_on_once`: the same wamid posted twice gives exactly one `model:` send.
    - `whatsapp_redelivery_after_restart_is_not_replayed`: SIGTERM, start again, post the same wamid. There is no second `model:` send.
    - `whatsapp_drops_messages_older_than_max_age`: `ts` = now − 3600; there is no `model:` send, and the owner is told `ignored 1 message`.
    - `daemon_serves_telegram_and_whatsapp_together`: both tables. One message from each gets its reply on its own channel, and the banner names both.
    - `whatsapp_token_rejected_at_startup_exits_1`: GET 401 with code 190 gives `WhatsApp rejected the access token`, and the data dir holds only `daemon.lock`.
    - `whatsapp_token_rejected_mid_run_exits_1`: the messages POST answers 401 with code 190. Exit 1 with the same text, and `daemon session ended` is audited.
    - `whatsapp_missing_or_equal_secrets_exit_1_without_side_effects`: each variable unset in turn, and the app secret equal to the verify token.
    - `whatsapp_listen_port_in_use_exits_1`: the test holds a `TcpListener` on a port and configures it.
    - `daemon_never_prints_or_audits_whatsapp_secrets`: across a run with a forged POST, a handshake and a reply, stdout, stderr and every file under the home lack all three secret values.
    - `sigterm_stops_the_whatsapp_listener`: exit 0, then connecting to the address is refused.
    - `daemon_without_any_channel_exits_1`: renamed from `daemon_without_telegram_table_exits_1`, asserting the new message.
- [ ] **Step 2: Run** `cargo test -p warden-cli --test daemon`. Expected: FAIL.
- [ ] **Step 3: Implement** the startup steps and the run changes.
- [ ] **Step 4: Run** `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`, `scripts/check-release-strings.sh`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(cli): warden daemon on the whatsapp cloud api`

---

### Task 9: README and security notes

**Files:**
- Modify: `README.md`, `docs/SECURITY-NOTES.md`
- Test: none new. Every claim must match a test or code path from Tasks 1-8.

**Interfaces:**
- Consumes: the behavior and messages fixed in Tasks 1-8.
- Produces:
  - **README "WhatsApp" section** (after "Telegram daemon"), covering:
    1. Meta setup at a high level: a Meta developer app with the WhatsApp product; the test number or a registered business number; the `phone_number_id`; the app secret (App settings, Basic); a permanent token from a system user (the 24-hour test token is for trying it only);
    2. the tunnel: `cloudflared tunnel --url http://127.0.0.1:8097`, then the callback URL `https://<tunnel host>/webhook`, the verify token you chose, and a subscription to the `messages` field;
    3. finding your number: start with any placeholder, message the business number, and read `ignored: non-owner` with `wa:<digits>` in the audit log, as with Telegram;
    4. the `[whatsapp]` config with every field and default;
    5. the three `export` lines and `warden daemon`;
    6. using it: `yes <code>`; PIN actions only at the computer; replies only within 24 h of your last message; nothing is sent after a restart until you write.
  - **README "Honest limits" additions:**
    - WhatsApp Business chats are not end-to-end encrypted to Warden: the Cloud API decrypts at Meta, and Meta sees every request, reply and prompt;
    - a PIN typed into WhatsApp cannot be deleted by Warden and stays in the chat and at Meta;
    - the tunnel is a public endpoint protected only by the HMAC signature (and the verify token for the handshake), and its provider (for example Cloudflare) terminates TLS and sees the webhook bodies;
    - whoever controls an owner's WhatsApp account is the owner;
    - the 24 h window and the in-memory window state.
  - **README other edits:** "Not built" drops WhatsApp and adds WhatsApp message templates. "What exists today" mentions the channel.
  - **SECURITY-NOTES "WhatsApp channel"** (after "Telegram channel"):
    - the trust model and owner rule;
    - the listener: loopback only (refused twice), `/webhook` only, limits, the response codes table, counters, no logging;
    - signature before parse;
    - the handshake;
    - secrets: env only, distinct names and values, Bearer header marked sensitive, redacted `Debug`, the `EAA…` redactor pattern, no redactor pattern for the app secret (32 hex digits look like ordinary hashes), the verify token in tunnel logs;
    - refused kinds and tags;
    - dedup: `whatsapp-seen` holds hashes, 1024 entries, written before acting, at most once;
    - stale rule;
    - 24 h window and counters;
    - no PIN and no deletion;
    - outbound body, `preview_url: false`, 4096 cap;
    - errors, retries and fatal conditions;
    - shutdown bounds.
  - **SECURITY-NOTES "Daemon" edits:** the 12-step startup order, the two fatal sources, the banner, the listener shutdown and the counters line. "Recovery" adds `whatsapp-seen` and `.whatsapp-seen.warden-tmp`.

- [ ] **Step 1: Write** the README changes.
- [ ] **Step 2: Write** the SECURITY-NOTES changes.
- [ ] **Step 3: Check** each new claim against the code. Run `grep -n "8097\|WARDEN_WHATSAPP\|v26.0\|whatsapp-seen\|/webhook" README.md docs/SECURITY-NOTES.md crates -r` and confirm every value matches the constants. Run `cargo test --workspace` (no code changed). Expected: PASS.
- [ ] **Step 4: Commit** `docs: whatsapp channel setup, limits and security notes`

---

## Self-review notes

- **Spec coverage:** the WhatsApp Cloud API is the third channel in the spec's channel order (goal 2: official API, not WhatsApp Web linking). Owner-only control and safety in code: the engine is unchanged and is still the only gate, and the PIN tier is never offered over WhatsApp. No silent data leaving the machine: outbound redaction, previews off, and Meta's and the tunnel's exposure documented. Not here by design: message templates, media, Signal, Matrix, tray, remote undo, mesh/relay, skills, website.
- **Types defined once and reused:** `WhatsAppConfig` (1); `AccessToken`, `GraphApi`, `PhoneInfo`, `WhatsAppError`, `ErrorClass` (2); `AppSecret`, `VerifyToken`, `SignatureCheck`, `WaEvent`, `RefuseReason`, `Notification`, `WebhookBatch`, `SeenStore` (3); `WebhookListener`, `ListenerConfig`, `WebhookStats`, `StatsSnapshot` (4); `WhatsAppChannel`, `WhatsAppOptions`, `WhatsAppFatal`, `cap_utf16` (5); `impl Channel for Option<C>`, `ChannelFatal`, `FatalSource`, `Watched<C>` (6).
- **Known simplifications to check in review:**
  - Statuses reach the engine as `wa-status:0` non-owners, as the owner decided. Each reply produces several statuses, and they share the 60 s non-owner audit slot with strangers.
  - The window map is in memory only.
  - `discard_pending_input` returns approximate bytes, as in Telegram.
  - The Graph error codes in `ErrorClass` come from Meta's documentation as remembered when this plan was written. Check them against the current error-code page before Task 2 is merged.
