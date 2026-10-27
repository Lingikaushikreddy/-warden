# Security notes

## Auto reads and symlinks

`classify` is pure and lexical: it never touches the filesystem and does not
resolve symlinks. A `ReadPath("/root/link/id_rsa")` where `link -> ~/.ssh` is
therefore classified `Auto` because it lies lexically inside an allowed root.
Roots containing `..` are likewise normalized lexically.

The agent executor (`warden_agent::exec`, see "Agent executor" below) closes
the lexical gap for reads: before any read or listing it canonicalizes the
deepest existing ancestor of the path and re-checks it against its canonical
root, refuses any existing symlink component below the root, and opens the
file with `O_NOFOLLOW | O_NONBLOCK` and checks through the handle that it is a
regular file. What remains is the parent-swap window: a process that can write
inside the root can replace a parent directory with a symlink between the
checks and the open. Closing it needs an `openat`-style walk (`rustix` or
`cap-std`), a later item.

## Agent executor

`warden_agent::exec::Executor::run(action, tool, auth, now_ms)` is the only
agent code that touches the disk. It takes the `Authorized` token by value
(one token, one run) and checks, before any filesystem write: the token has
not expired (`TokenExpired`); the token's action hash matches the action and
the tool maps to exactly that action (`TokenMismatch`); then the path rules.

- **Root.** The path must be lexically under the root (as given or
  canonical) and, after canonicalizing its deepest existing ancestor, under
  the canonical root (`OutsideRoot`). The root itself is never written or
  deleted (`Protected`).
- **Symlinks.** Any existing component below the root that is a symlink is
  refused (`Symlink`), even when it points inside the root. `list_dir` shows
  symlinks with a trailing `@` and never follows them.
- **Protected paths.** Paths equal to or inside a `protected` directory are
  refused (`Protected`). Every protected path must exist when the executor
  is built (`Executor::new` fails `NotFound` otherwise), so create the
  approver home and the snapshot directory first. Protected paths are
  resolved again on every call and compared with both the lexical and the
  canonical form of the tool path, so case or Unicode-normalization
  variants (case- and normalization-insensitive filesystems such as APFS),
  `/tmp` vs `/private/tmp` spellings, and a protected directory that was
  removed and re-created are all still refused. The snapshot store and the
  approver home MUST live outside the root or be listed in `protected`;
  otherwise an authorized write could edit the approver key, the
  spent-nonce log or snapshot manifests.
- **Writes and deletes** require a regular file with link count 1 (`NotAFile`,
  `HardLink`), and an existing parent (parents are never created). The
  snapshot is taken first (a new file is recorded as absent), then the write
  goes through a temp file with an unpredictable name (8 random bytes from
  the OS RNG), created `0o600` with `O_NOFOLLOW`, given its final mode (an
  existing file's mode masked to `0o777`, else `0o600`), synced and renamed
  over the target; then `record_after`, then the directory is fsynced. A
  failed directory fsync is reported in the output (`wrote <n> bytes
  (directory sync failed)`) rather than failing the run, since the change is
  already visible and recorded. A failure after the snapshot and before the
  rename completes returns the snapshot id (`ExecFailure::snapshot`) and
  removes the temp file.
- **Reads** are capped at `max_bytes` through the opened handle and converted
  lossily to UTF-8; a FIFO or device is `NotAFile` and does not block.
  Reads do NOT check link counts: a file inside the root that is hard-linked
  to a file elsewhere is readable (an inode shared with an outside file is
  exposed through the inside name).
- **Listings** escape control and invisible characters, a name's trailing
  `@` and leading `[`, so names cannot imitate the symlink marker or the
  overflow line.
- Error messages never contain file contents.

Remaining: the parent-swap TOCTOU window described under "Auto reads and
symlinks" applies to reads, writes and deletes alike (only the final
component of a read and the temp file use `O_NOFOLLOW`; rename and unlink are
path-based). A hard link created concurrently between the link-count check
and the operation is not caught. Fix: walk from a root directory handle with
`openat`/`renameat`/`unlinkat` (`rustix` or `cap-std`).

## Approvals: expiry and persisted nonces

`Approver::redeem(action, cfg, approval, now_ms)` computes the required tier
itself with `classify(action, cfg)`; callers cannot pass a tier. A caller
holding a stale or lower view of an action therefore cannot downgrade it: a
`YesPin` action is never redeemed with a `Yes` approval, and a `Blocked` action
is refused whatever the approval says. Check order: `Blocked` → action hash →
signature (`verify_strict`) → window checks (`BadTtl`, `NotYetValid`,
`Expired`) → tier floor → nonce insert. The nonce is
inserted last, so a failed redeem never burns it. The caller must pass the same
`PolicyConfig` the executor will act under.

**Expiry.** The signed message uses the v2 domain:

```text
b"warden/approval/v2\0" || action_hash (32) || tier byte (1)
    || issued_at_ms (u64 BE) || expires_at_ms (u64 BE) || nonce (16)
```

`Approver::grant(action, tier, issued_at_ms, ttl_ms)` sets
`expires_at_ms = issued_at_ms + ttl_ms` and refuses (`BadTtl`) a TTL of 0,
above `MAX_TTL_MS` (600 000 ms, 10 minutes), or one that overflows. Both
times are inside the signature, so changing either is `BadSignature`. After the
signature verifies, `redeem` checks the signed window again and refuses:

- `BadTtl` if `expires_at_ms <= issued_at_ms` or
  `expires_at_ms - issued_at_ms > MAX_TTL_MS` (defense in depth: only the key
  holder can sign such a window, but `redeem` does not trust `grant` to have
  been the signer);
- `NotYetValid` if `issued_at_ms > now_ms + MAX_SKEW_MS` (`MAX_SKEW_MS` =
  30 000 ms, saturating add). This also catches a caller that passed
  microseconds or another unit to `grant`;
- `Expired` if `now_ms >= expires_at_ms`.

Together these bound how long an approval is redeemable to at most
`MAX_SKEW_MS + MAX_TTL_MS` (10.5 minutes) of the redeemer's clock. **The bound
holds only if `now_ms` is milliseconds since the Unix epoch from a sane
clock.** `warden-core` does not read the clock; a caller that passes a wrong
`now_ms` (wrong unit, frozen or rolled-back clock) defeats expiry. v1
approvals do not verify under v2.

**Persisted nonces.** `Approver::spent()` exports the spent-nonce set (sorted,
so output is deterministic) and `Approver::from_signing_key_with_spent(key,
spent)` restores it. `warden-core` itself does not write the set anywhere;
persisting it next to the signing key, and loading it before any redeem, is
done by `warden_agent::authorize::ApproverStore` (see "Agent approver store"
below). `Approver::from_signing_key` still
starts with an empty set: reloading a key that way lets an already redeemed,
unexpired approval be redeemed once more, so the replay window after a restart
is bounded by `MAX_SKEW_MS + MAX_TTL_MS` but is not zero.
`from_signing_key_with_spent` protects only as well as the persisted set is
complete: a redeemed nonce missing from it can be replayed while unexpired.

**Contract for the agent crate** (the caller that persists the set):

1. Load the persisted spent set and build the `Approver` with
   `from_signing_key_with_spent` before any `redeem`. If the set cannot be
   loaded, do not redeem (fail closed).
2. After a successful `redeem`, persist the new nonce durably (append and
   sync, e.g. `fsync`) BEFORE executing the action. If persisting fails, do
   not execute the action.
3. A crash between persist and execute therefore burns that approval (the
   user must approve again) rather than allowing a replay. This is the
   intended fail-closed behavior.

Remaining items:

- `Approver::spent()` exports bare nonces, so the in-memory set inside one
  `Approver` grows with every legitimate redemption (rejected approvals never
  add to it). Pruning happens in `ApproverStore`, which records each nonce's
  expiry next to it and drops expired records when it is opened.
- **The standalone CLI still uses flags.** `warden run`/`undo` approve with
  `--yes` and the PIN (see "CLI PIN"); they do not create or redeem signed
  approvals. Signed approvals are used by the agent engine only.

## Planner boundary

`warden_agent::planner` is the only path to a model. What is sent: the
system prompt, the conversation turns and the tool specs (name,
description, JSON schema). Text and tool results are `Redacted` (built only
by `redact`); tool-call arguments echoed back into history are
`RedactedJson`, built only by `Block::tool_use`, which runs `redact_json`
(a raw `Value` in `Block::ToolUse` does not compile). Redaction is
pattern-based, so its known limits (see `redact.rs`) apply to everything
sent: unknown secret formats, obfuscated or split secrets and so on still
leave the machine.

The other fields are validated, not redacted, so arbitrary text cannot
ride along in them: tool-use ids and names (`ToolUse`, `ToolResult`) are
`ToolId`s, built only by `ToolId::new`, which allows `[A-Za-z0-9_-]{1,64}`;
`ToolSpec` fields are private and specs come only from `tools::tool_specs`;
the model id must match `[A-Za-z0-9._:-]{1,100}` and is refused if the
redactor would change it (an `AKIA...` or `sk-ant-...` string passed as the
model is an error, not a request).

Message assembly: empty turns are dropped, consecutive same-role turns are
merged, and in each user message `tool_result` blocks are moved (stably)
before other blocks, as the API requires. Pairing every `tool_use` with
its `tool_result` is the engine's job; the provider does not check it.

- **Responses are untrusted.** Text is truncated at 64 KiB. Tool calls go
  through `parse_call`, `classify` and approval like any other model output.
  Tool-use ids and names must match `[A-Za-z0-9_-]{1,64}` (they are echoed
  into later requests), and at most 64 calls are accepted per response;
  otherwise the whole response is `Malformed`. Unknown block types
  (thinking, server tools) are ignored. Response text is passed through
  unchanged: NUL, ANSI escapes, bidi controls and other terminal control
  sequences are NOT stripped here and must be sanitized by whatever
  displays it (the channel, Task 8).
- **Bounded reads.** The body is read chunk by chunk and abandoned past
  1 MiB (`TooLarge`); Content-Length is not consulted. A non-2xx status is
  returned as `Status(code)` without reading the body. Parse errors use
  fixed messages and never quote the body.
- **Transport.** HTTPS only (rustls), except `http://` to `127.0.0.1`,
  `localhost` or `[::1]` for tests and local proxies; base URLs with
  credentials, a query or a fragment are refused. Redirects are not
  followed (a 3xx is a `Status` error). Proxies are disabled
  (`no_proxy()`): `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` are ignored, so the
  key cannot be routed through a proxy from the environment (with an http
  loopback base it would otherwise travel in cleartext). Corporate-proxy
  support is a later, explicit opt-in config. Timeouts: 10 s connect, 60 s for the
  whole request by default (`with_timeout`). Transport errors are a short
  category plus reqwest's message with the URL removed (`without_url`);
  the source chain is dropped.
- **No retries.** One POST per `plan` call; a 429 or 5xx is returned to the
  caller.
- **API key.** Passed in by the caller (the CLI reads it from an
  environment variable); never written to disk, the audit log or logs. It
  is held only as a `HeaderValue` marked sensitive, and the `String` it
  came from is zeroized (the header's own buffer is not). `Debug` of the
  planner shows the model, base URL and timeout, never the key; no error
  carries it. Constructor problems are `PlannerError::Config` with fixed
  messages.

## Agent approver store

`warden_agent::authorize::ApproverStore` implements the contract above. It is
Unix-only (the crate fails to compile elsewhere) and its `home` directory must
be on a local filesystem, because the single-owner guarantee is an advisory
`flock` on `approver.lock`, which network filesystems may not honour.

- **`authorize` does NOT verify consent.** It classifies the action, grants
  and redeems an approval at that tier, persists the nonce and returns an
  `Authorized` token. The caller must collect consent matching the tier first:
  a yes for `Yes`, a yes plus the PIN for `YesPin`. `Blocked` is always
  refused; `authorize_auto` issues tokens only for `Auto` actions.
- **Tokens are time-limited, not policy-bound.** `Authorized` carries the
  action hash, the tier and `expires_at_ms` (`now_ms + ttl_ms`, same TTL rules
  as `grant`); the executor checks the expiry. A token is not bound to the
  `PolicyConfig`: the executor must act under the same policy the caller
  passed to `authorize`.
- **Files.** `approver.key` (32 bytes, 0600, created atomically via temp file
  + `hard_link`), `spent-nonces` (24-byte records `nonce || expires_at_ms BE`,
  0600), `approver.lock` (0600). All are opened with `O_NOFOLLOW |
  O_NONBLOCK` and checked through the handle: regular file, no group/other
  bits. A wrong-size key or a log whose length is not a multiple of 24 is
  `InvalidData` and is never repaired.
- **A missing log is fatal.** `spent-nonces` is created only together with a
  new key. If the key exists and the log does not, `open` fails `NotFound`:
  silently starting an empty log would re-enable replays.
- **Persist before execute, poison on failure.** After `redeem`, the record is
  appended and `sync_data`'d before the token is returned. If the append or
  sync fails, no token is issued, the nonce stays spent in memory, the log is
  truncated back to its previous length (best effort) and the store is
  poisoned: `authorize` returns `Poisoned` until the store is reopened, which
  re-validates the log.
- **Pruning.** On open, a record is dropped only when
  `expires_at_ms + MAX_SKEW_MS <= now_ms`, so the pruning tolerance matches
  `redeem`'s. Pruning trusts `now_ms`: a clock that jumps forward on open
  prunes early, and if it then goes back those approvals could be replayed
  within their window.
- **Locks and child processes.** The `flock` belongs to the open file
  description. A child forked by any thread while a store is open shares
  it until the child execs (the descriptor is close-on-exec), so the lock
  can briefly outlive dropping the store and an immediate reopen sees
  `WouldBlock`. This made tests that spawned `mkfifo`/`id` flaky; they now
  call `libc::mkfifo` in-process (the only `unsafe` in the workspace, in
  test files only). A long-running engine that spawns processes should not
  rely on drop-then-reopen being instant.

Deferred (Plan 3): persist a high-water mark of the largest `now_ms` seen
(next to the log) and refuse to open or prune with an earlier clock, closing
the clock-rollback replay above.

## Snapshots and restore

`restore` and `record_after` take the allowed root from the caller. Its
canonical form must equal the root recorded in the manifest, or the call fails
with `OutsideRoot`. The manifest on disk is treated as untrusted: every path is
re-checked against that root (absolute, no `..`, no symlinked parent or
target). Blob names and snapshot ids are validated before they are used as file
names. Every blob is re-hashed, and all checks run before anything is written.
The store directories are `0o700`. Blobs, manifests and restore temp files are
created `0o600`. Recorded and restored modes are masked to `0o777`, so
setuid/setgid/sticky bits are never restored.

Residual risks (see the module docs in `crates/warden-core/src/snapshot.rs`):

- Symlink checks are `symlink_metadata` followed by use. This gap remains by
  design choice in Plan 1, not because of `forbid(unsafe_code)`: safe std can
  pass `O_NOFOLLOW` through `OpenOptionsExt::custom_flags`. A process that can
  write inside the root can swap a parent directory for a symlink between the
  check and the write, and so redirect one write outside the root.
  **Plan 2:** open with `O_NOFOLLOW` and walk parents with `openat`-style
  directory handles (for example `rustix` or `cap-std`).
- Manifests are unauthenticated. Anyone who can write the store directory can
  choose which bytes land on which regular files under the caller's root. Keep
  the store writable only by Warden.
- Apply is not transactional: an I/O error partway through restore can leave
  some files restored and others not.
- Undoing a file recorded as `existed: false` removes only that file. Parent
  directories the agent created around it are left in place.
- If `record_after` was never called for a snapshot, restore has no
  changed-since protection and overwrites whatever is on disk.

## CLI PIN

`warden init-pin` stores a random 16-byte salt and `sha256(salt || pin)` in
`<home>/pin` (mode `0o600`; the data dir is created `0o700` if the CLI creates
it). The PIN is compared in constant time and is never written to the audit
log, stdout or stderr. Known weaknesses of this version:

- **Offline guessing.** Salted sha256 is fast. Anyone who can read the `pin`
  file can brute-force a short PIN offline in seconds. The 6-character
  minimum does not change that. argon2 (or similar) was out of scope here.
- **`--pin` is visible in process lists.** Command-line arguments can be read
  by other local users (`ps`). This applies equally to the positional
  `warden init-pin <pin>` argument. Prefer the `WARDEN_PIN` environment
  variable for both `run` and `init-pin`. If both are given, the argument wins.
- **Replacing the PIN needs the current one.** `init-pin --force` is refused
  (exit 2, audited `refused: missing current pin` or `refused: bad pin`)
  unless `--current-pin <pin>` or `WARDEN_CURRENT_PIN` matches the stored PIN;
  the old PIN keeps working after a refused reset. With no PIN set, `--force`
  is unnecessary and behaves like a plain init. Anyone who can write `<home>`
  can still delete the `pin` file and set a new one; the file is not a
  defence against the owning user.
- **No attempt rate-limit.** Wrong PINs are audited as `refused: bad pin`, but
  nothing slows or locks out repeated guesses.
- **Approvals are flags, not signed approvals.** `--yes` and the PIN are
  checked by the CLI process itself; the signed, single-use `Approver`
  approvals from `warden-core` are not used yet. Anyone who can run `warden`
  with the PIN can approve.

The standalone CLI commands keep these flags; signed approvals are used by
the agent engine (see "Approvals: expiry and persisted nonces"). Moving the
secret to keychain-backed storage is still open.

## CLI audit and execution

Every command that writes (`run`, `undo`, `prune`, `init-pin`) opens the audit
log first and refuses with exit code 1 if it cannot (including a broken hash
chain or a log held by another process). Each one appends an entry before it
changes anything (`run`: `approved`; `undo`: `requested`; `prune`: `prune
requested`; `init-pin`: `init-pin requested`)
and stops if that append fails, so no change is made without a prior audit
record. What is **not** guaranteed is the outcome record: if the append after
the change fails (disk full, I/O error), the change has happened but its final
entry (`executed snapshot=<id>`, `restored files=N`, `pruned N`, `pin set`) is
missing. That gap is reported on stderr and the command exits 1. Refusals are
audited as `refused: <reason>` before the command exits; if that append fails,
the command exits 1 and nothing was changed.

`run` appends `approved` before taking the snapshot and acting, then
`executed snapshot=<id>` or `failed: <reason>`. The audit summary names the
kind and target only, never write content. Once a write/delete has been
attempted, `run` prints `snapshot <id>` before the final audit append, so the
id is never lost and the change can still be undone if that append fails.

`undo` is treated as a `YesPin` action, because restore can overwrite and
delete files: it needs `--yes` and the PIN (same `--pin` / `WARDEN_PIN` rules
and fail-closed behaviour as `run`, exit 2 on refusal). It is audited at tier
`YesPin` as `refused: <reason>`, or `requested` and then its outcome.

`prune` and `init-pin` are not tiered actions. Their audit entries carry
`Tier::Auto` only because `AuditEntry` requires a tier; the decision text uses
a non-tier label (`prune requested`, `init-pin requested`, `pruned N`,
`pin set`) rather than implying an Auto approval.

The audit log is created `0o600` by `warden-core` (`AuditLog::open`); an
existing log keeps its mode. `warden audit verify` prints `no audit log`
(exit 0) when the home has no log yet.

During `run`, a target that is (or passes through) a symlink, or is not a
regular file, is a refusal: exit 2, audited `refused: symlink` or
`refused: not a file`. These are detected by the snapshot step, which runs
after `approved` is appended, so such an entry reads `approved` then
`refused: <reason>`, and nothing is changed.

Fault injection for tests (`WARDEN_TEST_FAIL_AUDIT_APPEND=<n>`, fail the n-th
append of the process) exists only when `warden-cli` is built with the
`test-hooks` Cargo feature, which is off by default; a default or release
build contains no reference to the variable. The tests enable it through a
self dev-dependency. The hook never lets a refused action through, but failing
the append that follows an executed action leaves that action without its
final audit record, which is the audit gap described above.

The CLI `write`/`delete` executor relies on the snapshot module's symlink
checks; it inherits the same TOCTOU gap described under "Snapshots and
restore". The agent executor has its own checks (see "Agent executor").

### Hard links

A hard link is a second name for the same inode, and nothing stops a name
inside `--root` from pointing at an inode that is also reachable from outside
it. `write` opens an existing file with `O_TRUNC`, so writing through such a
link would change the outside file, and the snapshot would not show it. `run`
therefore refuses `write` to an existing file and `delete` when the target's
link count is greater than 1 (exit 2, audited `refused: hard-linked file`),
before anything is approved or snapshotted. Limits: the check is
`symlink_metadata` followed by use, so a link created concurrently between the
check and the open is not caught (the same TOCTOU class as symlinks), and
link counts are only checked on Unix. A link count of 1 for a file inside the
root does not prove the file was never shared: it only proves no other name
exists at the time of the check.

## Plan 2 API notes

- All `warden-core` I/O is blocking and fsyncs (audit appends, snapshot blobs
  and manifests, restore). From async code, call it via
  `tokio::task::spawn_blocking` (or a dedicated thread), never on the runtime.
- `Approver::redeem` and `AuditLog::append` take `&mut self`. A shared
  `Approver` or `AuditLog` needs a `Mutex` (one per instance), and the
  spent-nonce check-and-mark relies on that exclusivity.
- Every `SnapshotStore` operation (`snapshot`, `record_after`, `restore`,
  `prune`) takes the store lock via the private `SnapshotStore::lock`, a
  blocking `File::lock` that waits indefinitely, whereas `AuditLog::open` uses `try_lock` and fails at once if another
  process holds the log. A long-running service must not hold a store lock
  across slow work, and should expect `AuditLog::open` to fail rather than
  wait.

## Channel

- Display sanitization is visible-escaping, not deletion: control, C1, DEL,
  `\r`, bidi, zero-width and other format characters are shown as `\u{hex}`
  so an injected ANSI/OSC sequence is visible and cannot hide or rewrite the
  screen. `\n` and `\t` are kept; output is capped at 4096 characters.
- Multi-line summaries and model notes in an approval prompt have every line
  after the first prefixed with `  | `, so model or file-name text cannot
  forge a `Reply "yes"...` line.
- `Channel::ask_approval` must only return a reply that came from the owner;
  the engine does not re-check. Any doubt must yield `No`.
- Input lines are capped at 65,536 bytes read with a bounded buffer; an
  over-long line is discarded up to its newline with a notice. Over-long or
  missing approval replies are `No`.
- `StdioChannel` is local-only: whoever controls the process's stdin is the
  owner. It is not suitable for any network-exposed transport.
- **Per-prompt challenge code.** Every `ApprovalPrompt` carries a
  `challenge`: a fresh 4-digit code the ENGINE draws from the OS RNG for
  that prompt (never derived from the action, and different from the last
  100 codes), shown in the prompt as `Reply "yes <code>" or "no":` or
  `Reply "yes <code> <PIN>" or "no":`. Why: a reply typed before the prompt
  was displayed cannot contain its code, so stale, typed-ahead or
  in-transit input, and a reply meant for an earlier prompt, can never
  approve. The code is not secret (it is on screen); it is exact-matched,
  and a wrong guess fails closed (1 in 10 000 for a blind guess).
- Approval replies fail closed. For tiers other than `YesPin` only
  `yes <code>` approves (`yes` in any case, trimmed, exactly one token
  after it, equal to the code). For `YesPin`, `yes <code> <pin>` (the PIN
  is the rest of the line, 1-128 chars) is required. A bare `yes`,
  `yes <wrong or previous code>`, `yes <pin>` without the code, over-long
  replies, and a truncated summary or note or an invalid challenge (the
  prompt is refused without asking) are all No. EOF before a complete
  reply line is `ApprovalReply::Closed`, which the engine treats as a
  refusal audited `refused: no reply` that also ends the message (the
  owner is told `input closed`, the message is audited `failed: input
  closed`, and the planner is not called again).
- Freshness: stdin is one stream. The challenge code is what makes an
  approval fresh: only a reply typed after the prompt appeared can carry
  it. On top of that the engine calls `discard_pending_input` before every
  prompt (it returns the bytes dropped, and the owner is told `earlier
  unsent input was discarded`), ends the message on a prompt timeout, and
  never treats approval-shaped text as chat.
- The PIN comes back as a plain `String` (not zeroized); the engine must
  compare it in constant time.
- Display also escapes blank-looking spaces (NBSP, U+2000-200A, U+202F,
  U+205F, U+3000), which stay legal in paths. A literal backslash is not
  escaped, so literal `\u{1b}` text looks like an escaped ESC (noise only).
  Confusables and tab alignment are not solvable by filtering.

## Agent engine (overview)

`warden agent` (in `warden-cli`, `crates/warden-cli/src/agent.rs`) runs the
agent engine on stdin/stdout. The pieces, each with its own section here:

- **Config** (`warden_agent::config`): `<home>/config.toml`, `root`
  required (no default), unknown fields refused, refused if group/other
  writable, and refused if it contains a key-like field (`api_key`,
  `token`, `secret`, `password`, ...): the API key comes only from the
  environment variable named by `api_key_env`. Errors never quote values.
  `provider = "mock"` (a scripted planner) exists only in builds with the
  `test-hooks` feature; a default or release build has no reference to it.
- **Startup fails closed** (exit 1, nothing runs), in this order: data
  dir not creatable, a symlink, not owned by the current user (learned from
  the owner of a freshly created probe file, no `geteuid`), or
  group/other-writable; config missing or invalid (the config is opened
  `O_NONBLOCK` and checked through the handle, so a FIFO is refused, not
  waited on); `owner` other than `local` (the stdio channel's only
  sender); `root` missing, not a directory, `/`, or `$HOME` or an ANCESTOR
  of it (unless the hidden `--allow-home-root`; an unset or unresolvable
  `HOME` also needs the flag); key variable unset or empty (named only
  when it is the default or a conventional `UPPER_SNAKE` name of at most
  40 characters); planner config invalid. Only then are the audit log
  (broken or locked: refused), the approver store, the snapshot store and
  the executor opened, so the earlier failures leave no files but the data
  dir. Last, `Engine::try_new` refuses an unprotected state dir. The CLI
  always protects the data dir and `<home>/snapshots` (inside the data
  dir, so protecting it separately is defense in depth), so a root that
  contains the data dir starts, and every tool call into it is refused
  `Protected`. Sessions are audited (`agent session started` / `agent
  session ended`, action id `session`, tier `Auto`; the end entry is best
  effort). While the agent runs it holds the audit log lock, so other
  writing `warden` commands fail until it exits. The API key stays in the
  process environment (the planner zeroizes its own copy).
- **Owner values are never echoed raw**: `owner` must be
  `[A-Za-z0-9._@:-]{1,64}` and unchanged by the redactor.
- **Planner trust model**: see "Planner boundary" (what is sent, transport,
  the API key) and "Engine" (the planner is untrusted; tiers come from
  `classify`).
- **Redaction limits**: pattern-based (see "Planner boundary" and
  `redact.rs` "Known limits"); it will miss unknown secret formats, and the
  remote planner sees whatever it misses.
- **Consent and the PIN**: see "Channel" (per-prompt challenge code) and
  "Engine" (PIN lockout in memory, late replies, PIN-like chat).
- **Approvals and execution**: see "Agent approver store" and "Agent
  executor".

## Engine

`warden_agent::engine::Engine` is the gated tool loop: the only place where
owner consent, the policy tier, the signed approval, the audit log, the
planner and the executor are wired together.

**Trust model.**

- **The planner is untrusted.** Its text, tool names, ids and arguments are
  model output. Ids and names must be valid `ToolId`s (and unique within a
  message), otherwise the whole response is treated as a `malformed` planner
  error and nothing in it runs. Arguments go through `parse_call`; the
  action and its summary are built only from validated fields; the tier is
  computed by `classify` from capabilities in one place (`Engine::decide`).
  `Blocked` never runs. The system prompt tells the model that tool results
  are untrusted data, but no safety property depends on it.
- **The owner prompt is the only consent.** `Yes` actions need the reply
  `Yes`; `YesPin` actions need `YesPin(pin)` and a PIN that matches
  `<home>/pin` (`warden_core::pin`, constant-time). The wrong kind of reply
  (a PIN reply at a Yes prompt, a bare yes at a PIN prompt) is refused
  (`refused: bad reply`), even though the channel already guarantees it. A
  missing, unreadable or malformed PIN file fails closed (`refused: pin
  unavailable`). The PIN is held in `Zeroizing<String>` and dropped right
  after the check; it never appears in the audit log, tool results,
  channel messages or error text.
- **PIN lockout is in memory only.** Three consecutive bad PINs lock
  PIN-tier approvals for 60 s of the injected wall clock. The lock is
  checked BEFORE prompting: while locked, a `YesPin` action is refused
  without a prompt (`refused: pin locked`, owner told `PIN approvals locked
  for <n> s`) and the PIN file is not read; a correct PIN resets the
  count. A restart clears the lockout, so it limits online guessing
  through one running engine, not offline guessing of the PIN file (see
  "CLI PIN").
- **Consent only for runnable actions.** Before any prompt, an action
  with a path capability the executor would refuse as outside the root is
  refused. The engine asks the executor itself
  (`Executor::accepts_spelling`, the same spelling rule `run` uses): the
  path must be spelled, component by component, under the canonical root
  or the root as given (`..` removed lexically), and its deepest existing
  ancestor must resolve inside the canonical root. So a symlink alias the
  executor was built with works, while a case variant (`/.../ROOT/a.txt` on
  a case-insensitive filesystem), an unknown alias, a path too long to
  canonicalize, or a symlinked parent pointing out is
  refused (`refused: outside root`, tool result `outside the allowed
  folder`) without asking: the owner is never asked to approve something
  that cannot run. A summary longer than 3000 characters after display
  sanitizing (checked first, for actions that would prompt) is refused
  unprompted (`refused: prompt too long`, tool result
  `request too long`), and the model note is cut by the engine to 500
  characters with `…`, so the channel never has to refuse a truncated
  prompt. A write approval shows only the quoted path and the byte count,
  never the content to be written.
- **Late replies and the PIN.** Each owner prompt has its own timeout
  (`approval_timeout`, default 120 s), independent of the message deadline.
  Two hazards follow from a prompt that times out while the owner is still
  typing: the late `yes` (or `yes <PIN>`) could answer the NEXT prompt of
  the same message, approving an action the owner never saw; or it could
  arrive as the next chat message and send the PIN to the remote planner.
  Mitigations:
  0. **Per-prompt challenge code** (see "Channel"): an approval must
     contain the code shown in THAT prompt, so no reply typed before the
     prompt existed, and no reply carrying an earlier prompt's code, can
     approve it. This is the primary defence; the rest is depth.
  1. **A prompt timeout ends the message.** The owner is told `timed out`,
     the action is audited `refused: approval timed out`, then the message
     `failed: timeout`; no further call of that message is processed or
     prompted, and the planner is not called again. A late reply can
     therefore only arrive as a new message. A closed input stream at a
     prompt (`ApprovalReply::Closed`) ends the message the same way: the
     owner is told `input closed`, the audit reads `refused: no reply` then
     `failed: input closed`.
  2. **Approval-shaped messages never reach the planner.** An owner
     message that, after trimming and ignoring ASCII case, is exactly
     `yes`, `no`, or `yes` followed by whitespace and anything is dropped
     unlogged with the reply `no approval pending`, at any time. Cost: chat
     such as `yes please do it` is dropped too.
  3. **Stale input is discarded before every prompt.**
     `Channel::discard_pending_input` (default: no-op) runs right before
     each `ask_approval`. `StdioChannel` drops its partial line and every
     chunk the reader has ready right now (polled once per chunk, never
     waiting, at most 1 MiB); if the dropped input ended mid-line, the rest
     of that line is skipped when it arrives, so `ye` (dropped) + `s\n`
     (typed after the prompt appears) is not read as a reply.
  4. **Cancel-safe reads.** `StdioChannel` keeps a partially read line in
     the channel, not in the read future, so a prompt cancelled by its
     timeout mid-line does not split `yes 1234` into a lost `yes 12` and a
     chat message `34`; the whole line arrives as one (dropped) message.
  5. **PIN-like chat is dropped.** An owner message of at most 8
     whitespace-separated tokens is checked token by token (tokens of
     1-128 characters; each token as typed, with punctuation trimmed from
     its ends, and each piece between punctuation, so `4815162342.`,
     `(4815162342)`, `"4815162342"`, `4815162342。` and `pin=4815162342`
     match) against the stored PIN with `check_pin` (constant
     time, on a blocking thread). "Punctuation" here is any character that
     is neither alphanumeric nor whitespace (so full-width `。，！？、` count).
     At most 64 distinct candidates are checked per message (whole and
     trimmed tokens first, then pieces), each once, so a long message with
     many separators costs at most 64 PIN-hash checks. On a match the message is dropped, the
     owner is told `that message looks like your PIN; it was not sent`, and
     `ignored: pin-like message` is audited with no content. The check is
     skipped silently when no PIN is set or the file cannot be read, and it
     never feeds the `PinGuard` lockout.

  Limits of discarding on a stream: `discard_pending_input` sees only bytes
  that have reached this process. Input still in a pipe, a terminal's line
  buffer or a network path when it runs arrives later and is read as the
  reply. A pure `AsyncBufRead` cannot tell "nothing typed" from "typed but
  not yet delivered". An owner who completes a dropped half line after the
  prompt appears must type the reply again.
- **Executor and audit state must be protected.** `Engine::try_new`
  refuses (`EngineConfigError::UnprotectedHome`) when the PIN home, the
  approver store's home or any state directory the caller passes (audit
  log, snapshot store) lies inside `cfg.root` and is not protected by the
  executor (`Executor::protects`, lexical and canonical). "Inside" is
  checked both lexically and canonically (either one counts), against the
  root as given and its canonical form. `try_new` stores the canonical
  `cfg.root` and `cfg.cwd`; the policy allows both the canonical root and
  the root as given, so either spelling classifies the same.
- **Non-owners get nothing.** A message whose sender is not
  `cfg.owner` causes no planner call and no reply. It is audited
  `ignored: non-owner` at most once per 60 s, with the sender id
  display-sanitized and cut to 64 characters. A wall clock that goes
  backwards resets the window (it cannot suppress entries until it catches
  up). The engine trusts the channel's `SenderId`.

**What is audited, and when.** Every audit append runs on a blocking
thread.

- `approved auto` (Auto) or `approved` (Yes/YesPin, after consent) is
  appended BEFORE the token is issued and the tool runs; if that append
  fails nothing runs and the model gets `audit unavailable`.
- `approved` is appended BEFORE `ApproverStore::authorize`, so a failed
  `approved` append spends no approval nonce.
- Then `executed snapshot=<id>` / `executed`, or `failed: <ExecError
  variant>`, or `failed: authorize` (token could not be issued; nothing
  ran), or `failed: executor` if the blocking executor task panicked. On a
  panic the snapshot id (if one was taken before the panic) is NOT known to
  the engine and is not shown to the owner; `warden` has no cheap
  "newest snapshot" lookup yet, so the owner must find it in the snapshot
  store. If the append AFTER a run fails, the change has happened: the owner
  is told `warning: audit append failed after the action` with the snapshot
  id, so it can still be undone, and the model still gets its result.
- Refusals: `refused: invalid call` (fixed summary, nothing from the
  arguments), `refused: blocked`, `refused: owner declined`, `refused: bad
  reply`, `refused: approval timed out`, `refused: pin locked`, `refused:
  bad pin`, `refused: pin unavailable`, `refused: outside root`,
  `refused: prompt too long`, and one aggregated `refused: too
  many calls` entry per planner response for calls beyond
  `max_calls_per_message`.
- Per message: `failed: planner`, `failed: timeout`, `failed: input
  closed`, `failed: step limit`.
- Summaries are the validated action summaries (kind, quoted path, sizes);
  file content and write content never enter the audit log. A failed
  refusal append is reported to the owner (`warning: audit append failed`).

**What reaches the planner.** The system prompt, the owner text and every
tool result go through `redact`. Tool results for `read_file` and
`list_dir` start with `[untrusted file content]`, are redacted, cut to
`result_max_bytes` on a char boundary with `\n[truncated]`, and redacted
again (a cut can turn an unmatched longer digit run into a matchable one).
Error results use fixed texts (`invalid call: <kind>`, `blocked by policy`,
`owner declined`, `bad pin`, `pin locked`, `pin unavailable`, `audit
unavailable`, `approval unavailable`, `too many calls`, `error: <ExecError
Display>`), never argument values. Tool-call arguments echoed into history
go through `redact_json`; arguments over 64 KiB are replaced by a fixed
placeholder rather than echoed. Every `tool_use` gets exactly one
`tool_result` in the next user turn, in order, including refused calls.
Planner errors are shown as `planner unavailable (<kind>)` with a fixed
word per variant, never the error text.

**No memory between messages.** Each owner message starts a fresh
conversation; nothing from an earlier message, file or tool result is
carried into the next one.

**Timeouts never cancel a running tool.** `message_timeout` bounds the
whole message: each planner call runs under the time left, and the
deadline is checked between steps and before each call (a call reached
after the deadline gets `timed out` and no prompt). Each owner prompt runs
under `approval_timeout` instead; a prompt that times out is a refusal
(`refused: approval timed out`) and ends the message (see "Late replies"). `Executor::run` and the audit
appends run on blocking threads and are never wrapped in a timeout: a tool
that started finishes and its outcome is audited, after which the message
stops with `timed out`. Limits: `max_steps` planner calls (`step limit
reached`) and `max_calls_per_message` tool calls per message.

**Residual risks.**

- Redaction recall: redaction is pattern-based (see `redact.rs` "Known
  limits"); unknown or obfuscated secret formats in files the owner lets
  the agent read still reach the model. Auto reads inside the root need no
  prompt.
- Confusables: summaries are escaped for display, but visually confusable
  paths (Cyrillic lookalikes, mixed scripts) can still mislead the owner at
  an approval prompt.
- The model note in a prompt is model prose (labelled unverified); a
  persuasive note can still socially engineer the owner.
- Input that reaches the process after the discard can still answer a
  prompt only if it contains that prompt's code, that is, only if it was
  typed by someone who saw the prompt (or guessed the 4 digits).
- The PIN-like filter checks short messages only (at most 8 tokens, at most
  64 candidates): a PIN inside a longer message, glued to letters, past the
  64th candidate, or typed after the PIN file was changed is ordinary chat and goes to the planner after redaction, which
  does not recognize PINs.
- `AuditLog` appends and `ApproverStore` share the engine's lifetime; the
  engine holds both behind mutexes and processes one message at a time.
