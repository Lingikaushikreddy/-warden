# Warden Telegram Channel and Daemon Implementation Plan (Plan 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `warden daemon` command that runs the existing agent engine unattended on a Telegram bot (owner-only, private chats, challenge-code approvals), survives restarts without replaying old messages or forgetting PIN lockouts, shuts down cleanly on SIGINT/SIGTERM, and lets the owner run `warden undo` locally while it is idle.

**Architecture:** The engine stays the only gate. Plan 2's `Channel` trait gains a recipient on every outbound call, so one engine can serve several owners and several channels; `TelegramChannel` implements it over a small hand-written Bot API client (`getUpdates` long polling, `sendMessage`, `deleteMessage`) on the existing reqwest setup. State that must survive a restart (Telegram update offset, PIN lockout, clock high-water mark) lives in small fixed-size files in the data dir, written before anything is acted on. The audit log is opened per message instead of for the process lifetime, so the local CLI can write to it between messages.

**Tech Stack:** Rust 1.89+, tokio 1 (`warden-cli` adds the `signal` feature), reqwest 0.12 (rustls, no default features, already a dependency), serde_json, zeroize, wiremock 0.6 (dev, added to `warden-cli` too), tempfile, assert_cmd, warden-core.

**Spec:** `docs/superpowers/specs/2026-10-25-warden-design.md`. Plan 2: `docs/superpowers/plans/2026-10-26-warden-agent-engine.md`. Inputs: the Plan 2 ledger `.superpowers/sdd/2026-10-26-warden-agent-engine/progress.md` ("FINAL REVIEW" Plan 3 blockers and "minor (deferred)" lines) and `docs/SECURITY-NOTES.md`.

**Renumbering:** Plan 2 put Telegram, daemon/tray and the WhatsApp Cloud API in Plan 3. This plan is Telegram and the daemon only; there is no tray, and WhatsApp becomes Plan 4 (then WASM skills + MCP, mesh + relay, website).

## Global Constraints

- Everything in Plan 2's Global Constraints still holds: four tiers computed by `classify`; `Blocked` never runs; `warden-core` has no network, async or HTTP code; nothing reaches a planner unless it is `Redacted`; the planner is untrusted; API keys only from the environment; `approved` is audited before acting; Apache-2.0, no JIMMY text.
- **Decision: Telegram through the Bot API over reqwest, not teloxide.** This departs from the spec's library list. Why: a much smaller dependency tree, and we control every error string, which matters because the bot token sits in the URL path. Client settings are the same as `AnthropicPlanner`: rustls, `no_proxy()`, `redirect(Policy::none())`, 10 s connect timeout.
- **Decision: long polling (`getUpdates`) only, no webhooks.** Why: Warden stays local-first and opens no inbound port.
- **Decision: bot token from an environment variable only.** The config field `bot_token_env` names the variable (default `WARDEN_TELEGRAM_TOKEN`). The token is never in the config file (a `bot_token`/`telegram_token` field is refused like `api_key`), never logged, audited, printed, in `Debug`, or in any error. Every reqwest error is reduced to a fixed kind word; reqwest's `Display` is never used, and `without_url()` is not relied on alone.
- **Decision: owners are allowlisted numeric Telegram user ids** (`[telegram] owner_ids`, 1-8 positive integers). Only a private chat with `chat.type == "private"` and `chat.id == from.id` is accepted. Groups, channels, edited messages, forwards (any `forward_*` field or `external_reply`), messages from bots or `via_bot`, and `sender_chat` messages are refused. They reach the engine as a non-owner sender with empty text, so the existing rate-limited `ignored: non-owner` audit records them.
- **Decision: approvals over Telegram keep the challenge code** (`yes <code>`, `yes <code> <PIN>`). The reply must come from the same chat the request came from. A reply that may contain a PIN (3+ tokens) is deleted with `deleteMessage` (best effort); Telegram's servers have still seen it.
- **Decision: PIN-tier approvals over Telegram are off by default** (`[telegram] allow_pin_approvals = false`). With it off, a `YesPin` action asked for over Telegram is refused without a prompt, and the owner is told to do it at the computer. Why: a PIN typed into Telegram is stored on Telegram's servers.
- **Decision: delivery is at most once.** The update offset is persisted before any update in a batch is acted on. A crash mid-message loses that message rather than replaying it. Messages whose Telegram `date` is older than `max_message_age_secs` (default 120) are never acted on.
- **Decision: no conversation memory between messages** (unchanged from Plan 2).
- **Decision: everything sent to Telegram is redacted and display-sanitized,** sent as plain text (no `parse_mode`) with link previews disabled and `protect_content: true`. Why: no Markdown injection, and no previews (a preview would make Telegram's servers fetch a model-chosen URL).
- **Decision: the daemon holds a single-instance lock** (`<home>/daemon.lock`) and the approver store lock for its lifetime. It holds the audit log only while a message is being handled.
- Tests never contact the real Telegram API: agent tests use wiremock, as `tests/anthropic.rs` does; CLI end-to-end tests point `[telegram] api_base` at a loopback wiremock server and use the `test-hooks` mock planner. Shipped binaries contain no test-only code (`scripts/check-release-strings.sh` still passes).
- Unix only (macOS and Linux), as in Plan 2.
- Commits: conventional style (`feat(agent): ...`, `fix(cli): ...`) under the user's own git identity, with NO AI attribution or `Co-Authored-By` lines.

## Review Focus

1. A stranger who finds the bot sends `yes 4821` (or a flood of messages) while an approval prompt is open. It must not approve, must not make the prompt fail, and must still be audited as a non-owner afterwards (Task 8: `ask_approval_ignores_and_queues_other_senders`, `queue_overflow_drops_beyond_64`).
2. A restart after a crash or SIGTERM must not act on old messages, including an old `delete x` request or an old `yes <code>` (Task 8: `restart_does_not_replay`; Task 9: `daemon_restart_does_not_replay_messages`, `daemon_drops_messages_older_than_max_age`).
3. The bot token must never be printed, in stderr, the audit log or any data-dir file, whatever the failure: connection refused, timeout, a 404 for a revoked token, or a bad config (Task 7: `errors_and_debug_never_contain_the_token`; Task 9: `daemon_never_prints_or_audits_the_token`).
4. Model text with a URL that carries data (`https://evil.example/?d=...`) or with Markdown/HTML must reach the owner as inert plain text, and Telegram must not fetch the link (Task 7: `send_message_disables_previews_and_uses_no_parse_mode`; Task 8: `send_redacts_sanitizes_and_caps_at_4096_utf16`).
5. The owner types the PIN on the phone when PIN approvals are off, or sends it late after a timeout. It must never reach the planner, and the chat copy must be deleted (Task 1: `pin_like_message_is_retracted`, `approval_shaped_message_with_three_tokens_is_retracted`; Task 8: `pin_reply_is_deleted_after_reading`; Task 9: `daemon_refuses_pin_tier_over_telegram_by_default`).

Also pinned by tests: clock rollback replay (Task 2), PIN lockout across restarts (Task 3), `warden undo` while the agent/daemon is idle (Tasks 4 and 9), SIGTERM at a prompt (Tasks 5 and 9), two daemons on one data dir (Task 9).

## Plan 2 carry-over

Plan 3 blockers from the Plan 2 final review:

| Blocker | Task |
|---|---|
| Undo vs lock (agent holds the audit log for its lifetime) | 4 (per-message audit lease), 9 (daemon e2e) |
| Persisted PinGuard | 3 (plus escalating lockout) |
| Multi-user `ask_approval` (replies from anyone in a shared channel) | 1 (owners list, approval asked of the sender), 8 (chat-bound replies) |
| `Channel::send` has no recipient | 1 |
| Approval filter on a remote channel (late `yes <code> <PIN>` stays in the chat history) | 1 (`retract_last`), 8 (delete PIN replies) |

Deferred minors pulled into this plan, because a remote, unattended channel makes them worse: clock-rollback high-water mark (Task 2); PIN not zeroized in `ApprovalReply` (Task 1); the remaining default-ignorable code points (Task 1, because phone clients render invisibles silently); the `[reply truncated]` marker lost past 4096 characters (Task 1, because Telegram also caps at 4096); recovery from a torn `spent-nonces` file or stale `.warden-tmp` files is undocumented (Task 10 docs, because an unattended daemon that cannot start needs a written way out).

Stay deferred (unchanged by a remote channel): look-alike letters and keyword-less secret names in the redactor; card false positives; regex debug-time margin; refusing a home not owned by euid inside `ApproverStore` (the CLI already checks the data dir); `O_NONBLOCK` left on regular-file handles; weak test asserts and the `compile_fail` without an error code; case-variant recreation of a deleted protected file; hard-link reads; the parent-swap TOCTOU (needs `openat`/cap-std, later plan); `ToolId` redactor check and Vertex model ids; backslash not escaped on display; `set_pin` charset vs channel; `cargo test --release` overwriting the release binary; terminal soft-wrap of model text (a Telegram bubble per message makes this weaker, not worse).

## File Structure

```
crates/warden-agent/src/channel.rs        modify: recipient on outbound calls, accepts_pin, retract_last, serves, Pair, render_prompt, zeroized PIN
crates/warden-agent/src/tools.rs          modify: more default-ignorable code points
crates/warden-agent/src/engine.rs         modify: owners list, PIN-channel gate, retract, persisted PinGuard, release lease, shutdown
crates/warden-agent/src/authorize.rs      modify: clock high-water mark
crates/warden-agent/src/state.rs          create: private state-file read and atomic write helpers
crates/warden-agent/src/lease.rs          create: LeasedAuditLog
crates/warden-agent/src/http.rs           create: shared reqwest client and base-URL check (moved from anthropic.rs)
crates/warden-agent/src/config.rs         modify: [telegram] table
crates/warden-agent/src/redact.rs         modify: Telegram bot token pattern
crates/warden-agent/src/telegram/mod.rs   create: re-exports
crates/warden-agent/src/telegram/api.rs   create: BotToken, TelegramApi, TelegramError
crates/warden-agent/src/telegram/update.rs create: Update, UpdateKind, RefuseReason, classify_update
crates/warden-agent/src/telegram/offset.rs create: OffsetStore
crates/warden-agent/src/telegram/channel.rs create: TelegramChannel
crates/warden-cli/src/startup.rs          create: shared startup steps (moved out of agent.rs)
crates/warden-cli/src/agent.rs            modify: use startup.rs and LeasedAuditLog
crates/warden-cli/src/daemon.rs           create: warden daemon, print-service
crates/warden-cli/src/cli.rs, commands.rs modify: Daemon subcommand
crates/warden-agent/tests/{channel,engine,authorize,config,redact}.rs  modify
crates/warden-agent/tests/{lease,telegram_api,telegram_update,telegram_channel}.rs  create
crates/warden-cli/tests/{agent,daemon}.rs  modify / create
README.md, docs/SECURITY-NOTES.md
```

---

### Task 1: Channel API for remote, multi-owner channels

**Files:**
- Modify: `crates/warden-agent/src/channel.rs`, `crates/warden-agent/src/tools.rs` (`is_forbidden_path_char`), `crates/warden-agent/src/engine.rs`, `crates/warden-cli/src/agent.rs` (constructor call only), `docs/SECURITY-NOTES.md` ("Channel", "Engine")
- Test: `crates/warden-agent/tests/channel.rs`, `crates/warden-agent/tests/engine.rs` (its `TestChannel` records `(SenderId, String)` pairs), `crates/warden-agent/tests/tools.rs`

**Interfaces:**
- Consumes: Plan 2 `Channel`, `ApprovalPrompt`, `ApprovalReply`, `EngineConfig`, `Engine::handle`, `is_approval_shaped`.
- Produces:
  - `Channel` becomes (the doc-comment contracts stay; `recv` additionally documents "must be cancel-safe"):
    - `fn recv(&mut self) -> impl Future<Output = Option<Inbound>> + Send`
    - `fn send(&mut self, to: &SenderId, text: &str) -> impl Future<Output = ()> + Send`
    - `fn ask_approval(&mut self, to: &SenderId, prompt: &ApprovalPrompt) -> impl Future<Output = ApprovalReply> + Send`, which must only return a reply from `to`
    - `fn discard_pending_input(&mut self, to: &SenderId) -> impl Future<Output = usize> + Send` (default `0`)
    - `fn accepts_pin(&self, to: &SenderId) -> bool` (default `true`)
    - `fn retract_last(&mut self, to: &SenderId) -> impl Future<Output = ()> + Send` (default no-op): best-effort removal of the most recent message received from `to`
  - `ApprovalReply::YesPin(Zeroizing<String>)` (Debug still `YesPin(<redacted>)`)
  - `pub(crate) fn render_prompt(prompt: &ApprovalPrompt) -> Option<String>` (the text `StdioChannel` prints today, byte-identical; `None` when the summary or note would be truncated or the challenge is invalid) and `pub(crate) fn parse_reply(text: &str, needs_pin: bool, code: &str) -> ApprovalReply` (made `pub(crate)`, unchanged)
  - `EngineConfig.owner: SenderId` is replaced by `pub owners: Vec<SenderId>`; `EngineConfig::new(owner: SenderId, root: PathBuf, cwd: PathBuf)` keeps its signature and sets `owners: vec![owner]`
  - Engine audit decision `refused: pin not accepted on this channel` and tool-result text `pin not accepted on this channel`

Engine behavior: every outbound call made while handling a message goes to `inbound.sender`. Before a `YesPin` prompt, and before the PIN-lock check, `!channel.accepts_pin(&sender)` refuses the action with no prompt, no challenge drawn and no PIN file read. The owner is told `this needs your PIN, which this channel does not accept; do it at the computer`. After a message is dropped as PIN-like, or as approval-shaped with 3 or more whitespace tokens, the engine calls `retract_last(&sender)`. A model reply is cut so that it fits in 4096 displayed characters together with `\n[reply truncated]` before the marker is appended, so the marker always survives.

New forbidden path/display characters (escaped on display, rejected in paths): U+180F, U+1BCA0–U+1BCA3, U+13430–U+1343F, U+E0080–U+E00FF, U+E01F0–U+E0FFF, U+FFF0–U+FFF8. U+1680 (Ogham space mark) joins the blank-looking set (escaped on display, legal in paths).

- [ ] **Step 1: Write failing tests:** channel: `default_ignorables_are_escaped` (each new code point → `\u{..}`), `ogham_space_is_escaped_for_display`, `render_prompt_matches_stdio_output` (the stdio prompt bytes equal `render_prompt` + nothing else), `debug_of_yes_pin_hides_the_pin` (updated to `Zeroizing`); tools: `new_default_ignorables_are_rejected_in_paths`; engine: `second_owner_is_served_and_replies_go_to_the_sender` (owners `a`,`b`; a message from `b`; every recorded send has recipient `b`), `approval_is_asked_of_the_sender_only`, `yespin_on_a_channel_without_pin_support_is_refused_without_prompt` (no prompt recorded, audit `refused: pin not accepted on this channel`, file still exists), `pin_like_message_is_retracted`, `approval_shaped_message_with_three_tokens_is_retracted`, `two_token_yes_is_not_retracted`, `truncated_marker_survives_a_long_reply` (10 000-char text with `truncated: true`; the sent text ends with `[reply truncated]`). Update every existing `TestChannel` and channel test to the new signatures.
- [ ] **Step 2: Run** `cargo test -p warden-agent --test channel --test engine --test tools`. Expected: FAIL (signatures, new behavior).
- [ ] **Step 3: Implement** the trait change, `render_prompt`/`parse_reply` extraction, `owners`, the engine rules above and the new code points; `StdioChannel` ignores `to` (its only sender is `local`).
- [ ] **Step 4: Run** `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`. Expected: PASS.
- [ ] **Step 5: Update `docs/SECURITY-NOTES.md`:** recipients and the multi-owner rule (approval only from the requester), the PIN-channel gate, retraction, the zeroized PIN, the new code points.
- [ ] **Step 6: Commit** `feat(agent): channel recipients, multiple owners and per-channel PIN gate`

---

### Task 2: Clock high-water mark in the approver store

**Files:**
- Modify: `crates/warden-agent/src/authorize.rs`, `crates/warden-cli/src/agent.rs`, `docs/SECURITY-NOTES.md` ("Agent approver store": replace the "Deferred (Plan 3)" paragraph)
- Test: `crates/warden-agent/tests/authorize.rs`, `crates/warden-cli/tests/agent.rs`

**Interfaces:**
- Consumes: `ApproverStore::open(home: &Path, now_ms: u64)`, `authorize(&mut self, action, cfg, tier, now_ms, ttl_ms)`, the existing `check_private_file` and open flags, `MAX_SKEW_MS`.
- Produces:
  - File `<home>/clock-mark`: 8 bytes, `u64` big-endian, mode 0600, opened and checked like the other store files; created when missing (also for existing stores); any other size → `InvalidData`
  - `ApproverStore::open`: `mark = max(stored, now_ms)` is written and `sync_data`'d BEFORE pruning, and pruning uses `mark`, not `now_ms`
  - `authorize`: the effective time is `max(now_ms, mark)`, used for grant, redeem and the token's `expires_at_ms`. When `now_ms > mark` the new mark is written and synced first; a failure returns `AuthorizeError::Persist(kind)` with no token, no nonce spent and no poisoning
  - `pub fn clock_mark_ms(&self) -> u64` and `pub fn clock_behind_ms(&self) -> u64` (how far `now_ms` was behind the stored mark at open; 0 if not)
  - `redeem_for_test` uses the same effective time
  - CLI: when `clock_behind_ms() > 30_000`, `warden agent` prints `warning: the system clock is <n> s behind the last time Warden ran; approvals use the later time` and audits `clock behind high-water mark` (action id `session`)

Decision: a clock that is behind is clamped up to the mark, not refused. Why: refusing would brick the agent until the clock is fixed, and clamping already closes the replay (an approval pruned under a forward jump is still `Expired` after the clock goes back).

- [ ] **Step 1: Write failing tests:** `clock_mark_is_created_0600_and_holds_open_time`, `rolled_back_clock_cannot_replay_a_pruned_approval` (authorize at T; reopen at T+1 h so the record is pruned; reopen at T; replaying the stored `Approval` via `redeem_for_test(.., T)` is `Expired`), `mark_never_decreases`, `wrong_size_mark_is_invalid_data`, `clock_behind_reports_the_gap`, `authorize_persists_a_newer_mark`, `token_expiry_uses_the_mark_when_clock_is_behind`, `mark_write_failure_issues_no_token_and_spends_no_nonce`; CLI `agent_warns_when_the_clock_is_behind_the_mark` (write a mark 1 h in the future before starting).
- [ ] **Step 2: Run** `cargo test -p warden-agent --test authorize` and `cargo test -p warden-cli --test agent`. Expected: FAIL.
- [ ] **Step 3: Implement** with `FileExt::write_all_at(&bytes, 0)` + `sync_data`.
- [ ] **Step 4: Run** `cargo test --workspace` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): clock high-water mark for approvals and pruning`

---

### Task 3: Persisted, escalating PIN lockout

**Files:**
- Create: `crates/warden-agent/src/state.rs`
- Modify: `crates/warden-agent/src/engine.rs` (`PinGuard`, `Engine::try_new`, `verify_pin`), `crates/warden-agent/src/lib.rs`, `docs/SECURITY-NOTES.md` ("Engine": the "PIN lockout is in memory only" bullet)
- Test: `crates/warden-agent/tests/engine.rs`, in-crate unit tests in `engine.rs` and `state.rs`

**Interfaces:**
- Produces:
  - `state.rs`: `pub(crate) fn read_private(path: &Path, max_len: usize) -> io::Result<Option<Vec<u8>>>`. `None` if missing. Opened `O_NOFOLLOW | O_NONBLOCK`; it must be a regular file with no group/other bits, at most `max_len` bytes, else `InvalidData`/`PermissionDenied`. Also `pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()>`: temp file 0600 in the same dir named `.<name>.warden-tmp`, write, `sync_all`, rename, fsync the dir.
  - `pub const PIN_GUARD_FILE: &str = "pin-guard"` (in the PIN home)
  - `PinGuard` gains a lock level. A lock lasts `60_000 << level` ms, capped at `PIN_LOCK_MAX_MS = 86_400_000`. `level` rises by 1 on each lock and resets to 0 with `failures` on a correct PIN. `new`, `state` and `record` keep their signatures. The first lock is still 60 s, so the existing tests hold.
  - `pub fn to_bytes(&self) -> [u8; 16]` (`failures u32 BE || level u32 BE || locked_until_ms u64 BE`, 0 = not locked) and `pub fn from_bytes(b: &[u8]) -> Option<PinGuard>` (wrong length → `None`)
  - `Engine::try_new` loads `<home>/pin-guard` (missing → fresh) and fails with the new `EngineConfigError::PinGuardState(io::ErrorKind)` on a malformed or insecure file
  - After every `PinGuard::record`, the engine writes the file on a blocking thread. If writing fails, PIN-tier approvals are refused (`refused: pin unavailable`) until restart, and the owner is told `warning: cannot save the PIN lockout; PIN approvals are disabled until restart`

- [ ] **Step 1: Write failing tests:** unit `pin_guard_bytes_roundtrip`, `lock_doubles_on_each_consecutive_lockout_and_caps_at_a_day` (locks of 60 s, 120 s, 240 s …, never above 86 400 000 ms), `correct_pin_resets_level`; `state.rs` unit `write_atomic_replaces_and_is_0600`, `read_private_refuses_group_writable_and_symlink`; engine `pin_lockout_survives_an_engine_restart` (3 bad PINs, rebuild the engine on the same home, a `YesPin` action is refused `pin locked` with no prompt), `corrupt_pin_guard_file_refuses_engine_start`, `group_writable_pin_guard_file_is_refused`, `unwritable_pin_guard_disables_pin_approvals` (make the home 0500 after start; the next bad PIN, then a correct PIN, are both refused).
- [ ] **Step 2: Run** `cargo test -p warden-agent --lib` and `cargo test -p warden-agent --test engine`. Expected: FAIL.
- [ ] **Step 3: Implement** `state.rs`, the level, the encoding, load in `try_new` (blocking file I/O is fine there; it is sync), and persist after `record`.
- [ ] **Step 4: Run** `cargo test --workspace` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): persist the PIN lockout and escalate repeated lockouts`

---

### Task 4: Per-message audit lease (undo while the agent is idle)

**Files:**
- Create: `crates/warden-agent/src/lease.rs`
- Modify: `crates/warden-agent/src/engine.rs` (`AuditSink`, `handle`), `crates/warden-agent/src/lib.rs`, `crates/warden-cli/src/agent.rs` (replace `SharedAudit(Arc<Mutex<AuditLog>>)`), `README.md` ("One process at a time"), `docs/SECURITY-NOTES.md` ("Agent engine (overview)")
- Test: `crates/warden-agent/tests/lease.rs`, `crates/warden-cli/tests/agent.rs`

**Interfaces:**
- Consumes: `AuditLog::open(path) -> io::Result<AuditLog>` (try-lock, verifies the chain), `AuditSink`.
- Produces:
  - `AuditSink` gains `fn release(&mut self) {}` (default no-op; existing test sinks unchanged)
  - `pub struct LeasedAuditLog`: `LeasedAuditLog::new(path: PathBuf) -> LeasedAuditLog`, `with_wait(self, d: Duration) -> Self` (default 2 s), `pub fn open_now(&mut self) -> io::Result<()>` (startup check: a broken or locked log is still refused). `impl AuditSink`: `append` opens the log if it is not open; on `WouldBlock` it retries every 100 ms until the wait runs out, then returns the error. `release` drops the open log.
  - The engine calls `release` (on a blocking thread, through the same mutex as appends) when `handle` returns, on every path including non-owner and dropped messages
  - `warden agent` uses `Arc<Mutex<LeasedAuditLog>>` for the engine and the session entries, and releases it after each session entry

Decision: reopen the log per message instead of adding a control socket for `undo`. Why: the CLI already serializes writers with the log's lock. The cost is a chain verification per message (linear in log size, documented). Undo over Telegram is not in this plan (see the report at the end).

- [ ] **Step 1: Write failing tests:** lease: `lease_is_released_after_each_message` (after `handle`, `AuditLog::open` from the test succeeds), `append_while_another_writer_holds_the_log_fails_closed` (`with_wait(200 ms)`; the test holds the log; a write action is refused `audit unavailable` and the file is unchanged), `appends_by_another_writer_between_messages_keep_the_chain_valid` (engine message, external append, engine message, `AuditLog::verify` is ok with all entries); CLI: `undo_works_while_the_agent_is_idle` (scripted write approved with `yes <code>`; while `warden agent` is still running with stdin open, `warden undo <id> --root .. --yes` with `WARDEN_PIN` exits 0 and restores the file; then stdin closes and the agent exits 0).
- [ ] **Step 2: Run** `cargo test -p warden-agent --test lease` and `cargo test -p warden-cli --test agent`. Expected: FAIL.
- [ ] **Step 3: Implement** the lease, the trait default and the release point; update the CLI.
- [ ] **Step 4: Run** `cargo test --workspace` and clippy. Expected: PASS.
- [ ] **Step 5: Update** README "One process at a time" (writing commands work while the agent is idle; they fail fast with a lock error while it is handling a message) and SECURITY-NOTES.
- [ ] **Step 6: Commit** `feat(agent): hold the audit log only while handling a message`

---

### Task 5: Engine shutdown and the `Pair` channel

**Files:**
- Modify: `crates/warden-agent/src/engine.rs`, `crates/warden-agent/src/channel.rs`, `docs/SECURITY-NOTES.md` ("Engine": timeouts section)
- Test: `crates/warden-agent/tests/engine.rs`, `crates/warden-agent/tests/channel.rs`

**Interfaces:**
- Consumes: Task 1 `Channel`.
- Produces:
  - `Engine::with_shutdown(self, shutdown: tokio::sync::watch::Receiver<bool>) -> Self`. `run` returns when the channel closes or the value becomes `true`; `recv` is raced against it, so an idle engine stops at once.
  - In `handle`, a planner call is raced against shutdown. Losing it ends the message: the owner is told `Warden is shutting down`, audited `failed: shutdown`. An owner prompt is raced against shutdown too. Losing it refuses the action (`refused: shutting down`, tool result `owner declined`) and ends the message with the same owner text and `failed: shutdown`. `Executor::run` and audit appends are never raced: a started tool finishes and is audited, then the message ends.
  - `Channel` gains `fn serves(&self, who: &SenderId) -> bool` (default `true`); `StdioChannel::serves` is `who.0 == "local"`
  - `pub struct Pair<A, B>` with `Pair::new(a: A, b: B)`, `impl<A: Channel + Send, B: Channel + Send> Channel for Pair<A, B>`. Outbound calls go to `a` if `a.serves(to)`, else to `b` if `b.serves(to)`. Otherwise `send`/`retract_last` do nothing, `ask_approval` returns `No`, `discard_pending_input` returns 0 and `accepts_pin` is false. `recv` races both sides with `tokio::select!`, keeps polling the other side after one returns `None`, returns `None` when both have, and alternates which side is polled first.

- [ ] **Step 1: Write failing tests:** engine: `run_returns_when_shutdown_is_set_while_idle`, `shutdown_during_prompt_refuses_and_ends_the_message` (`ask_approval` never returns; the test sets shutdown; audit has `refused: shutting down` then `failed: shutdown`; the file is unchanged; `run` returns), `shutdown_during_planner_call_fails_the_message`, `shutdown_while_a_tool_runs_lets_it_finish_and_audits_it` (`before_rename_hook_for_test` sleeps 200 ms while the test sets shutdown; audit has `executed snapshot=`; the file is written); channel: `pair_routes_by_sender`, `pair_unknown_recipient_gets_no_and_nothing_sent`, `pair_recv_keeps_going_after_one_side_closes` (stdio side at EOF, the other side still delivers), `pair_recv_is_cancel_safe` (a `recv` cancelled by a timeout loses no line).
- [ ] **Step 2: Run** `cargo test -p warden-agent --test engine --test channel`. Expected: FAIL.
- [ ] **Step 3: Implement** with `watch::Receiver::wait_for(|v| *v)` in `select!` arms.
- [ ] **Step 4: Run** `cargo test --workspace` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): graceful engine shutdown and a two-channel Pair`

---

### Task 6: Telegram config, token redaction, shared HTTP client

**Files:**
- Create: `crates/warden-agent/src/http.rs`
- Modify: `crates/warden-agent/src/anthropic.rs` (use `http.rs`; behavior unchanged), `crates/warden-agent/src/config.rs`, `crates/warden-agent/src/redact.rs`, `crates/warden-agent/src/lib.rs`
- Test: `crates/warden-agent/tests/config.rs`, `crates/warden-agent/tests/redact.rs` (existing `tests/anthropic.rs` must pass unchanged)

**Interfaces:**
- Produces:
  - `http.rs`: `pub(crate) fn client() -> Result<reqwest::Client, ()>` (rustls, `no_proxy`, no redirects, 10 s connect timeout, the existing user agent) and `pub(crate) fn check_base_url(base: &str) -> Result<Url, &'static str>` (the rules moved verbatim from `anthropic.rs`: https, or http only to `127.0.0.1`/`localhost`/`[::1]`, no credentials, query or fragment)
  - `pub const DEFAULT_TELEGRAM_TOKEN_ENV: &str = "WARDEN_TELEGRAM_TOKEN"`, `pub const DEFAULT_TELEGRAM_API_BASE: &str = "https://api.telegram.org"`
  - `pub struct TelegramConfig { pub owner_ids: Vec<i64>, pub bot_token_env: String, pub allow_pin_approvals: bool, pub max_message_age_secs: u64, pub api_base: Option<String> }`; `Config` gains `pub telegram: Option<TelegramConfig>`
  - Parsing: exactly one nested table, `[telegram]`, is allowed. Other tables are still refused. Top-level fields stay strings. Inside `[telegram]`: `owner_ids` is required, 1-8 integers each in `1..=2^52` (`ConfigError::Invalid("telegram.owner_ids", ..)`); `bot_token_env` is an env NAME, validated like `api_key_env`; `allow_pin_approvals` is a bool, default `false`; `max_message_age_secs` is an integer in `10..=3600`, default `120`; `api_base` is a string. Unknown fields inside → `UnknownField("telegram.<name>")`. Wrong types → new `ConfigError::WrongKind(&'static str /*field*/, &'static str /*"an integer" | "a boolean" | "a list of integers"*/)`.
  - `SECRET_KEYS` adds `bottoken`, `telegramtoken`, `telegrambottoken`. The `SecretInFile` message names both `api_key_env` and `[telegram] bot_token_env`.
  - Redactor: Telegram bot tokens (`[0-9]{8,10}:[A-Za-z0-9_-]{35}`, with the existing left-boundary group) are redacted as kind `api_key`

- [ ] **Step 1: Write failing tests:** config: `telegram_table_parses_with_defaults` (`bot_token_env == "WARDEN_TELEGRAM_TOKEN"`, `allow_pin_approvals == false`, `max_message_age_secs == 120`), `telegram_owner_ids_required_nonempty_positive_and_at_most_8`, `bot_token_in_file_is_rejected_with_message` (`[telegram] bot_token = "..."` → `SecretInFile`; the message contains `bot_token_env` and not the value), `unknown_telegram_field_is_rejected`, `other_nested_tables_still_rejected`, `max_message_age_out_of_range_is_invalid` (9 and 3601), `wrong_kinds_are_named` (`owner_ids = "42"`, `allow_pin_approvals = "yes"`); redact: `telegram_bot_token_is_redacted` (fake `123456789:` + 35 chars → `[REDACTED:api_key]`), `ratios_and_times_are_not_redacted` (`10:30`, `12345678:abc`, `123456789:` + 34 chars).
- [ ] **Step 2: Run** `cargo test -p warden-agent --test config --test redact`. Expected: FAIL.
- [ ] **Step 3: Implement**; move the client builder and URL check into `http.rs` and call them from `AnthropicPlanner::new`.
- [ ] **Step 4: Run** `cargo test --workspace` (including `--test anthropic --test redact_differential`) and clippy. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): telegram config table, bot token redaction, shared HTTP client`

---

### Task 7: Telegram Bot API client, update filter, offset store

**Files:**
- Create: `crates/warden-agent/src/telegram/{mod.rs,api.rs,update.rs,offset.rs}`
- Modify: `crates/warden-agent/src/lib.rs`
- Test: `crates/warden-agent/tests/telegram_api.rs` (wiremock), `crates/warden-agent/tests/telegram_update.rs` (JSON fixtures)

**Interfaces:**
- Consumes: Task 6 `http::client`, `http::check_base_url`; Task 3 `state::read_private`, `state::write_atomic`.
- Produces:
  - `pub struct BotToken(Zeroizing<String>)`: `BotToken::new(s: String) -> Result<BotToken, TelegramError>` accepts only `^[0-9]{5,16}:[A-Za-z0-9_-]{30,64}$` (`Config("invalid bot token")`; the input is zeroized either way). `Debug` prints `BotToken(<redacted>)`; there is no `Display`.
  - `pub struct TelegramApi`: `TelegramApi::new(token: BotToken, api_base: &str) -> Result<TelegramApi, TelegramError>`; `Debug` shows the base only. Request URL `{base}/bot{token}/{method}`, built per request in a `Zeroizing<String>`. Bodies are POST JSON. Responses are read in chunks and capped at 1 MiB (`TooLarge`). Telegram's `{"ok":false,"error_code":n,"parameters":{"retry_after":s}}` → `Api { code, retry_after }`; any other non-2xx → `Status(code)` (redirects are not followed, so a 3xx is `Status`).
    - `pub async fn get_me(&self) -> Result<BotInfo, TelegramError>`; `pub struct BotInfo { pub id: i64, pub username: Option<String> }`; `is_bot != true` → `Malformed("not a bot")`
    - `pub async fn get_updates(&self, offset: i64, timeout_secs: u32, limit: u8) -> Result<Vec<serde_json::Value>, TelegramError>`: body `{"offset", "timeout", "limit", "allowed_updates": ["message"]}`; HTTP timeout = `timeout_secs + 15` s
    - `pub async fn send_message(&self, chat_id: i64, text: &str) -> Result<i64, TelegramError>` (returns `message_id`): body exactly `chat_id`, `text`, `link_preview_options: {"is_disabled": true}`, `protect_content: true`, and no `parse_mode`
    - `pub async fn delete_message(&self, chat_id: i64, message_id: i64) -> Result<(), TelegramError>`
  - `pub enum TelegramError { Config(&'static str), Transport(&'static str /* "timeout" | "connect" | "other" */), Status(u16), Api { code: u16, retry_after: Option<u64> }, Malformed(&'static str), TooLarge }` with a fixed-text `Display`. No variant holds text from reqwest or the server.
  - `update.rs`: `pub struct Update { pub update_id: i64, pub kind: UpdateKind }`; `pub enum UpdateKind { Text { chat_id: i64, from_id: i64, message_id: i64, date_s: i64, text: String, reply_to: Option<i64> }, Refused { from_id: Option<i64>, message_id: Option<i64>, chat_id: Option<i64>, reason: RefuseReason } }`; `pub enum RefuseReason { NotPrivate, Forwarded, FromBot, ViaBot, SenderChat, Edited, NotText, Other, Malformed }` with `pub fn tag(self) -> &'static str` (`group`, `forward`, `bot`, `via-bot`, `sender-chat`, `edited`, `non-text`, `other`, `malformed`)
  - `pub fn classify_update(v: &serde_json::Value) -> Option<Update>`: `None` only without an integer `update_id`. Rules are checked in this order: `edited_message` → `Edited`; no `message` → `Other`; `from` missing → `SenderChat`; `from.is_bot` → `FromBot`; `sender_chat` → `SenderChat`; `via_bot` → `ViaBot`; any of `forward_origin`, `forward_from`, `forward_from_chat`, `forward_date`, `forward_sender_name`, `is_automatic_forward`, `external_reply` → `Forwarded`; `chat.type != "private"` or `chat.id != from.id` → `NotPrivate`; no string `text` → `NotText`; otherwise `Text` (`reply_to` = `reply_to_message.message_id`). Unknown fields are ignored.
  - `offset.rs`: `pub struct OffsetStore`; `OffsetStore::open(home: &Path) -> io::Result<(OffsetStore, i64)>` reads `<home>/telegram-offset` (8 bytes, i64 BE; missing → 0; other size → `InvalidData`); `pub fn save(&mut self, next: i64) -> io::Result<()>` via `write_atomic`

- [ ] **Step 1: Write failing tests:** api: `get_me_requires_is_bot`, `get_updates_posts_offset_timeout_limit_and_allowed_updates`, `send_message_disables_previews_and_uses_no_parse_mode` (the body has no `parse_mode`, has `link_preview_options.is_disabled == true` and `protect_content == true`; the text `[x](https://evil.example/?d=1) <b>` is sent byte-for-byte), `delete_message_posts_ids`, `api_error_maps_code_and_retry_after` (429, `retry_after` 7), `oversized_body_is_too_large`, `garbage_json_is_malformed`, `redirect_is_not_followed` (302 → `Status(302)`, the target receives nothing), `errors_and_debug_never_contain_the_token` (connect to a closed loopback port, a 404, a timeout; `format!("{e} {e:?} {api:?}")` contains neither the token nor its secret half), `token_shape_is_validated` (`abc`, `123:short`, a token with `\n`, a 65-char secret), `api_base_must_be_https_or_loopback`; update: one test per rule (`private_text_from_owner_is_text`, `chat_id_differs_from_from_id_is_not_private`, `group_chat_is_not_private`, `edited_message_is_refused`, `forward_origin_is_refused`, `legacy_forward_from_is_refused`, `external_reply_is_refused`, `bot_sender_is_refused`, `via_bot_is_refused`, `sender_chat_is_refused`, `photo_with_caption_is_not_text`, `missing_update_id_is_none`, `reply_to_is_extracted`); offset: `offset_roundtrip_and_0600`, `wrong_size_offset_is_invalid_data`, `missing_offset_is_zero`.
- [ ] **Step 2: Run** `cargo test -p warden-agent --test telegram_api --test telegram_update`. Expected: FAIL.
- [ ] **Step 3: Implement**. Map reqwest errors with `is_timeout()`/`is_connect()` into the three kind words and never format them. Read the body with `chunk()` as `anthropic.rs` does.
- [ ] **Step 4: Run** the same command and clippy. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): telegram bot API client, update filter and offset store`

---

### Task 8: `TelegramChannel`

**Files:**
- Create: `crates/warden-agent/src/telegram/channel.rs`
- Modify: `crates/warden-agent/src/telegram/mod.rs`
- Test: `crates/warden-agent/tests/telegram_channel.rs` (wiremock; a scripted `Respond` that serves queued `getUpdates` batches, then `{"ok":true,"result":[]}` after a 100 ms delay)

**Interfaces:**
- Consumes: Task 1 `Channel` (with `render_prompt`, `parse_reply`), Task 5 `serves`, Task 7 everything, `redact`, `sanitize_for_display`, `is_approval_shaped`.
- Produces:
  - `pub struct TelegramOptions { pub allow_pin_approvals: bool, pub max_message_age: Duration, pub poll_timeout_secs: u32 /* 30 */, pub backoff_base: Duration /* 1 s */ }`
  - `TelegramChannel::new(api: TelegramApi, owners: Vec<i64>, offset: OffsetStore, start_offset: i64, opts: TelegramOptions) -> TelegramChannel`; `with_clock(self, clock: Box<dyn Fn() -> u64 + Send + Sync>) -> Self` (unix ms, used for message age)
  - `pub fn sender_id(user_id: i64) -> SenderId` → `tg:<id>`. Refused and stale updates become `Inbound { sender: SenderId("tg-<tag>:<from_id or 0>"), text: String::new() }` (`tg-stale:<id>` for stale). Those never equal an owner id, so the engine audits them as non-owners.
  - `pub enum TelegramFatal { TokenRejected, Conflict, OffsetUnwritable }` (fixed `Display`) and `pub fn fatal(&self) -> Option<TelegramFatal>`

Behavior:
- `recv` returns queued items first. Otherwise it calls `get_updates(offset, poll_timeout_secs, 20)` and ignores updates with `update_id < offset`. It saves `max(update_id) + 1` with `OffsetStore::save` BEFORE queuing any of them, then queues them in order. Cancel safety: nothing after the await can be lost (a dropped poll is simply re-fetched).
- `TooLarge` → refetch with `limit` 1; a single update still too large is skipped (offset advanced, queued as `tg-malformed:0`).
- Errors: `Api`/`Status` 401, 404 → `TokenRejected`; 409 → `Conflict`; a failed offset save → `OffsetUnwritable`. All three set `fatal` and make `recv` return `None`. Anything else backs off (`backoff_base` doubling to 60 s) and retries.
- Owner text whose `date_s * 1000 + max_message_age < now` is stale. Each poll batch with stale owner messages sends the owner one notice: `ignored <n> message(s) older than <s> s (sent while Warden was not running)`.
- Owner non-text messages get the reply `only text messages are supported` and are not passed on. Owner text starting with `/` gets a fixed help line and is not passed on.
- The queue holds at most 64 items; extra items are dropped and counted.
- `send(to, text)`: only to owner `tg:<id>`; anything else is dropped. The text goes through `redact`, then `sanitize_for_display`, then a cut to at most 4096 UTF-16 code units ending in `…`. A 429 with `retry_after <= 30` sleeps and retries once; any other failure is dropped (best effort).
- `ask_approval(to, prompt)`:
  - `No` when `to` is not an owner, or when the tier is `YesPin` and `allow_pin_approvals` is false. The prompt text is `render_prompt` with the summary and note redacted first, plus, for `YesPin`, the line `Your PIN will pass through Telegram's servers; Warden deletes your reply after reading it (best effort).`
  - A failed send → `No`.
  - The next `Text` update from chat `to` is the reply. If `reply_to` is set to a message other than the prompt's → `No`. Otherwise `parse_reply`. A reply of 3 or more tokens is deleted (`delete_message`, best effort) before returning. A non-text update from `to` → `No`.
  - Every other update (other owners, non-owners, refused) is queued for `recv`. The reply text is held in `Zeroizing`.
- `discard_pending_input(to)`: drops queued items from `to`, polls once with `timeout 0` (saving the offset as in `recv`), drops `to`'s new items and queues the rest. Returns the dropped text bytes (at least 1 per dropped message).
- `retract_last(to)`: deletes the last message received from `to`. `accepts_pin(_)` returns `allow_pin_approvals`. `serves(to)` is `to.0.starts_with("tg:")`.

- [ ] **Step 1: Write failing tests:** `owner_private_text_becomes_inbound_with_tg_sender`, `non_owner_text_becomes_non_owner_inbound_with_empty_text`, `group_message_from_owner_is_not_owner`, `forwarded_message_from_owner_is_not_owner`, `stale_messages_are_dropped_and_owner_is_told_once`, `offset_is_persisted_before_the_message_is_returned`, `restart_does_not_replay` (a new channel on the same home polls with offset N+1), `send_goes_only_to_owner_chats`, `send_redacts_sanitizes_and_caps_at_4096_utf16` (a fake `sk-ant-` key → `[REDACTED:api_key]`; `\x1b[31m` → `\u{1b}`; 3000 emoji → at most 4096 UTF-16 units), `ask_approval_accepts_yes_code_from_the_sender_chat`, `ask_approval_ignores_and_queues_other_senders` (a stranger's `yes <code>` arrives first, then the owner's: the result is `Yes`, and the next `recv` returns the stranger as non-owner), `reply_from_another_owner_is_queued_not_used`, `wrong_code_or_chat_text_is_no`, `reply_to_a_different_message_is_no`, `pin_reply_is_deleted_after_reading` (wiremock expects `deleteMessage` with that `message_id`), `yespin_prompt_refused_when_pin_approvals_disabled` (`No`, no `sendMessage`), `discard_drops_pending_owner_messages_and_keeps_others`, `slash_commands_get_help_and_are_not_passed_on`, `unauthorized_token_ends_recv_with_fatal` (401 → `None`, `fatal() == Some(TokenRejected)`), `conflict_409_ends_recv_with_fatal`, `transient_500_backs_off_and_recovers` (`backoff_base` 10 ms), `recv_is_cancel_safe` (a `recv` dropped by a timeout while the server delays; the next `recv` returns the message exactly once), `queue_overflow_drops_beyond_64`.
- [ ] **Step 2: Run** `cargo test -p warden-agent --test telegram_channel`. Expected: FAIL.
- [ ] **Step 3: Implement** the channel as specified.
- [ ] **Step 4: Run** `cargo test --workspace` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): telegram channel with chat-bound approvals`

---

### Task 9: `warden daemon`

**Files:**
- Create: `crates/warden-cli/src/startup.rs`, `crates/warden-cli/src/daemon.rs`
- Modify: `crates/warden-cli/src/agent.rs` (steps 1-6 move to `startup.rs`; behavior and messages unchanged), `crates/warden-cli/src/cli.rs`, `crates/warden-cli/src/commands.rs`, `crates/warden-cli/src/lib.rs`, `crates/warden-cli/Cargo.toml` (tokio `signal`; dev: `wiremock`, `tokio` with `macros`)
- Test: `crates/warden-cli/tests/daemon.rs` (`required-features = ["test-hooks"]`), `crates/warden-cli/tests/agent.rs` (must pass unchanged)

**Interfaces:**
- Consumes: Tasks 1-8; `AnthropicPlanner`, `MockPlanner::from_script_file` (test-hooks), `Engine::try_new`, `with_shutdown`, `Pair`, `StdioChannel`, `LeasedAuditLog`, `ApproverStore::clock_behind_ms`.
- Produces:
  - `startup.rs`: `pub(crate) struct Prepared { cfg: Config, config_path: PathBuf, root: PathBuf }`; `pub(crate) fn prepare(home: &Path, config: Option<PathBuf>, allow_home_root: bool) -> Result<Prepared, u8>` (steps 1-3); `pub(crate) fn api_key(cfg: &Config) -> Result<String, u8>`; `pub(crate) fn open_parts(home: &Path, prepared: &Prepared, owners: Vec<SenderId>) -> Result<Parts, u8>` (audit lease check, approver store with the clock warning from Task 2, snapshots, executor)
  - CLI: `warden daemon [--config <path>] [--console]` (plus the hidden `--allow-home-root`) → `pub fn cmd_daemon(home: &Path, config: Option<PathBuf>, console: bool, allow_home_root: bool) -> u8`

Startup, fail closed with exit 1, in this order:
1. data dir check;
2. `<home>/daemon.lock` (0600, `try_lock`; held for life): `another warden daemon is using <home>`;
3. config, which must have a `[telegram]` table (`no channel configured: add a [telegram] table`); with `--console`, `owner` must be `local`;
4. root;
5. planner key;
6. the bot token from the variable named by `bot_token_env` (missing/empty: the variable is named only under the existing `showable_env_name` rule; bad shape: `the Telegram bot token variable does not hold a valid bot token`);
7. `TelegramApi::new`, then `get_me` (401/404: `Telegram rejected the bot token`; other: `cannot reach Telegram (<kind>)`);
8. `open_parts` with owners `tg:<id>…` (+ `local` with `--console`), then `OffsetStore::open`;
9. `Engine::try_new(..).with_shutdown(rx)`.

Steps 1-7 leave no files except the data dir and `daemon.lock`.

Run:
- Audit `daemon session started` (action id `session`, summary `daemon session`).
- stderr banner `warden daemon: telegram @<username> owners=<n> root=<root>`.
- Channel `TelegramChannel`, or `Pair::new(telegram, stdio)` with `--console`.
- First SIGINT/SIGTERM: set the watch to `true` and print `shutting down after the current step`. Later signals print `still shutting down` (no force; a running tool always finishes).
- After `run` returns, audit `daemon session ended` (best effort). If the channel reported `fatal()`, print its text and exit 1; otherwise exit 0.
- stderr never carries message text, tokens or keys.

- [ ] **Step 1: Write failing tests** (a helper starts a wiremock server on a tokio runtime owned by the test; it serves `getMe`, a shared queue of `getUpdates` batches, and records `sendMessage`/`deleteMessage`. The daemon is spawned with `std::process::Command` from `assert_cmd::cargo::cargo_bin("warden")` and stopped with `kill -TERM <pid>`. The config has `provider = "mock"`, `[telegram] owner_ids = [42], api_base = "http://127.0.0.1:<port>"`, and `WARDEN_TELEGRAM_TOKEN` holds a fake valid token): `daemon_answers_an_owner_message_over_telegram` (a `sendMessage` to chat 42 contains `model: `), `daemon_ignores_non_owner_and_group_messages` (no `sendMessage` to them; the audit has `ignored: non-owner`), `daemon_write_needs_yes_code_over_telegram` (read the code from the captured prompt, queue `yes <code>`, the file is written, `done:` is sent), `daemon_refuses_pin_tier_over_telegram_by_default` (`delete_file`: no prompt, the owner is told PIN is not accepted, the file exists), `daemon_restart_does_not_replay_messages` (the second run's first `getUpdates` body has `offset` = first id + 1), `daemon_drops_messages_older_than_max_age` (`date` = now − 3600; the script is empty, so a planner call would fail; no `model:` send; the owner is told `ignored 1 message`), `second_daemon_on_same_home_exits_1`, `sigterm_exits_0_and_audits_session_end`, `sigterm_during_prompt_refuses_the_action` (file unchanged, audit `refused: shutting down`, exit 0), `daemon_without_telegram_table_exits_1`, `daemon_without_token_env_exits_1_without_side_effects` (the data dir holds only `daemon.lock`), `token_rejected_by_telegram_exits_1` (`getMe` 401), `daemon_never_prints_or_audits_the_token` (stdout, stderr and every file under the home lack the token and its secret half), `warden_undo_works_while_the_daemon_is_idle`.
- [ ] **Step 2: Run** `cargo test -p warden-cli --test daemon`. Expected: FAIL.
- [ ] **Step 3: Implement** `startup.rs` (moving code, then confirming `cargo test -p warden-cli --test agent` still passes), then `daemon.rs`.
- [ ] **Step 4: Run** `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(cli): warden daemon on telegram with graceful shutdown`

---

### Task 10: `warden daemon print-service`, README, security notes

**Files:**
- Modify: `crates/warden-cli/src/daemon.rs`, `crates/warden-cli/src/cli.rs`, `README.md`, `docs/SECURITY-NOTES.md`
- Test: `crates/warden-cli/tests/daemon.rs`

**Interfaces:**
- Produces: `warden daemon print-service (--launchd | --systemd) [--config <path>]` (clap `ArgGroup`, exactly one format required) → `pub fn cmd_print_service(home: &Path, config: Option<PathBuf>, format: ServiceFormat) -> u8` with `pub enum ServiceFormat { Launchd, Systemd }`. It loads the config only to read the two env var NAMES, writes nothing, and prints to stdout.
  - Paths: the canonical `current_exe()`, the absolute home and the config path. Any path containing a control character or one of `" \ % $ ' & < >` and backtick is refused (exit 1, `path not supported in a service file`), so no escaping is needed beyond quoting.
  - launchd: plist with label `local.warden.daemon`; `ProgramArguments` [exe, `--home`, home, `daemon`, (`--config`, path)]; `RunAtLoad` true; `KeepAlive` `{SuccessfulExit: false}`; `ThrottleInterval` 60; `ExitTimeOut` 60; `StandardErrorPath` `<home>/daemon.log`; `EnvironmentVariables` with the two configured names set to `REPLACE_ME`. A leading XML comment says the file will hold secrets and must be `chmod 600`.
  - systemd user unit: `ExecStart="<exe>" --home "<home>" daemon [--config "<path>"]`, `EnvironmentFile=%h/.config/warden/daemon.env`, `Restart=on-failure`, `RestartSec=60`, `TimeoutStopSec=60`, `KillSignal=SIGTERM`, `NoNewPrivileges=yes`, `UMask=0077`, `WantedBy=default.target`. Leading comments explain how to create `daemon.env` (0600) with the two names.
- Docs:
  - README gains a "Telegram daemon" section: creating a bot with BotFather; finding your numeric id (message the bot once; the audit log records `ignored: non-owner` with sender `tg:<id>`); the `[telegram]` config; `export WARDEN_TELEGRAM_TOKEN=...`; `warden daemon`; approvals by `yes <code>`; PIN actions at the computer; undo locally while idle; installing with `print-service`. "Not built" is updated (WhatsApp, Signal, Matrix, tray, remote undo). "Honest limits" adds: Telegram bot chats are not end-to-end encrypted, and Telegram sees every request, reply, prompt and, if enabled, the PIN; whoever controls the owner's Telegram account is the owner; deletion is best effort; at-most-once delivery; service files hold secrets.
  - SECURITY-NOTES gains "Telegram channel" (trust model, the refused update kinds, the token in the URL and the error scrubbing, outbound redaction, previews off, `protect_content`, offset and stale semantics, queue bound, fatal errors) and "Daemon" (locks, the audit lease, shutdown semantics, clock mark, persisted escalating PIN lockout). It also documents recovery for an unattended daemon that will not start: a `spent-nonces` file whose length is not a multiple of 24 can be truncated to the last whole record, because a torn record's token was never issued; stray `.*.warden-tmp` files can be deleted while Warden is stopped. The overview section is updated.

- [ ] **Step 1: Write failing tests:** `print_service_launchd_has_absolute_paths_and_placeholders` (contains the exe path, `--home`, `daemon`, `REPLACE_ME`, `local.warden.daemon`; with `WARDEN_TELEGRAM_TOKEN=<fake>` set in the environment, the output does not contain it), `print_service_systemd_has_execstart_and_environment_file`, `print_service_requires_exactly_one_format`, `print_service_refuses_paths_with_quotes_or_percent`, `print_service_writes_nothing_to_disk` (the home listing is unchanged).
- [ ] **Step 2: Run** `cargo test -p warden-cli --test daemon print_service`. Expected: FAIL.
- [ ] **Step 3: Implement** the subcommand.
- [ ] **Step 4: Write the README and SECURITY-NOTES changes** listed above; every claim must match a test or code path in this plan.
- [ ] **Step 5: Run** `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`, `scripts/check-release-strings.sh`. Expected: PASS.
- [ ] **Step 6: Commit** `feat(cli): print launchd and systemd service files; document telegram daemon`

---

## Self-review notes

- Spec coverage: Telegram is the second channel in the spec's channel order; owner-only control, safety in code (the engine stays the only gate, and the PIN tier is off on Telegram by default), no silent data leaving the machine (outbound redaction, previews off, documented Telegram exposure), real undo (local undo while idle), local-first (no inbound port). Not here by design: WhatsApp, Signal, Matrix, tray, remote undo, mesh/relay, skills, website.
- Types are defined once and reused: `Channel` (Tasks 1 and 5), `Pair`, `LeasedAuditLog`, `PinGuard`, `BotToken`, `TelegramApi`, `TelegramError`, `Update`/`UpdateKind`/`RefuseReason`, `OffsetStore`, `TelegramChannel`/`TelegramOptions`/`TelegramFatal`, `TelegramConfig`.
- Known simplifications to check in review: `discard_pending_input` returns bytes for stdio and approximate bytes for Telegram (the engine only tests `> 0`); the audit lease re-verifies the whole chain per message, which grows linearly with the log.
