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
  action hash, the tier and `expires_at_ms`: `max(now_ms, clock mark) +
  ttl_ms` from `authorize`, `now_ms + ttl_ms` from `authorize_auto` (which
  uses no store), with the same TTL rules as `grant`; the executor checks
  the expiry. A token is not bound to the
  `PolicyConfig`: the executor must act under the same policy the caller
  passed to `authorize`.
- **Files.** `approver.key` (32 bytes, 0600, created atomically via temp file
  + `hard_link`), `spent-nonces` (24-byte records `nonce || expires_at_ms BE`,
  0600), `approver.lock` (0600), `clock-mark` (8 bytes, 0600, see below).
  All are opened with `O_NOFOLLOW | O_NONBLOCK` and checked through the
  handle: regular file, no group/other bits. A wrong-size key or a log whose length is not a multiple of 24 is
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
  `expires_at_ms + MAX_SKEW_MS <= mark` (the clock high-water mark below), so
  the pruning tolerance matches `redeem`'s.
- **Locks and child processes.** The `flock` belongs to the open file
  description. A child forked by any thread while a store is open shares
  it until the child execs (the descriptor is close-on-exec), so the lock
  can briefly outlive dropping the store and an immediate reopen sees
  `WouldBlock`. This made tests that spawned `mkfifo`/`id` flaky; they now
  call `libc::mkfifo` in-process (the only `unsafe` in the workspace, in
  test files only). A long-running engine that spawns processes should not
  rely on drop-then-reopen being instant.

**Clock high-water mark.** `clock-mark` holds the largest `now_ms` the store
has seen: 8 bytes, `u64` big-endian, 0600, opened and checked like the other
files (any other size is `InvalidData`, never repaired). It is created when
missing, also for stores made before it existed, atomically via a temp file
and rename. `open` writes and `sync_data`s `mark = max(stored, now_ms)`
BEFORE pruning, and prunes with `mark`, not `now_ms`. `authorize` grants and
redeems at `max(now_ms, mark)` and sets the token's `expires_at_ms` from it;
when `now_ms` is newer, the mark is written and synced first, and if that
fails `authorize` returns `Persist` with no token, no nonce spent and no
poisoning. This closes the clock-rollback replay: a record pruned under a
forward jump stays `Expired` after the clock goes back, because redeem time
never goes below the mark.

Decision: a clock that is behind the mark is clamped up to it, not refused.
Refusing would brick the agent until the clock is fixed, and clamping already
closes the replay. The cost: while the clock is behind, approvals and tokens
expire relative to the later time (they live longer in wall-clock terms by up
to the gap, never shorter), and a mark pushed far into the future by a bad
clock stays there (delete `clock-mark` only with the agent stopped and the
clock fixed; that re-opens the rollback window for records already pruned).
`warden agent` warns on stderr and audits `clock behind high-water mark`
(action id `session`) when the clock is more than 30 s behind the mark at
open.

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
- **Recipients.** Every outbound `Channel` call names its recipient:
  `send(to, text)`, `ask_approval(to, prompt)`,
  `discard_pending_input(to)`, `retract_last(to)`, and `accepts_pin(to)`.
  The engine passes the sender of the message being handled to all of
  them. A remote channel must deliver to `to` and nobody else; a local
  channel with one sender (`StdioChannel`, whose only sender is `local`)
  ignores it. `recv` must be cancel-safe (a dropped `recv` future loses
  and splits no message).
- **Two channels as one (`Pair`).** `Channel::serves(who)` (default
  `true`; `StdioChannel`: only `local`) says whether a channel can reach a
  sender. `Pair::new(a, b)` routes every outbound call to `a` if it serves
  the recipient, else to `b` if it does; a recipient neither serves gets
  nothing (`send`/`retract_last` do nothing, `ask_approval` is `No`,
  `discard_pending_input` is 0, `accepts_pin` is `false`). Its `recv`
  races both sides, alternating which is polled first, keeps reading one
  side after the other closes, and is cancel-safe because each side's
  `recv` is.
- `Channel::ask_approval(to, ...)` must only return a reply that came from
  `to`; the engine does not re-check. With several owners, a reply from a
  different owner does not count either. Any doubt must yield `No`.
- **Per-channel PIN gate.** `Channel::accepts_pin(to)` (default `true`)
  says whether a PIN may be typed over this channel. When it is `false`
  the engine never prompts for a `YesPin` action (see "Engine").
- **Retraction.** `Channel::retract_last(to)` (default no-op) is a
  best-effort removal of the most recent message received from `to`. The
  engine calls it after dropping a message that may hold the PIN. On a
  remote service the text has still reached that service's servers.
- `render_prompt` (crate-private) is the approval prompt text exactly as
  `StdioChannel` prints it, or `None` when the prompt must be refused
  (truncated summary or note, invalid challenge), so other channels show
  the same sanitized, `  | `-indented text with the same refusal rule.
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
- The PIN comes back as `ApprovalReply::YesPin(Zeroizing<String>)`, wiped
  when dropped, and its `Debug` is `YesPin(<redacted>)`; the engine
  compares it in constant time.
- Display escapes, and paths reject, these default-ignorable or reserved
  format code points as well: U+180F, U+1BCA0-U+1BCA3 (shorthand format
  controls), U+13430-U+1343F (Egyptian hieroglyph format controls),
  U+E0080-U+E00FF and U+E01F0-U+E0FFF (unassigned tag-plane slots) and
  U+FFF0-U+FFF8 (unassigned specials). Why: a renderer may draw them as
  nothing, so two different paths could look identical in a prompt.
- Display also escapes blank-looking spaces (NBSP, U+1680 Ogham space
  mark, U+2000-200A, U+202F, U+205F, U+3000), which stay legal in paths. A literal backslash is not
  escaped, so literal `\u{1b}` text looks like an escaped ESC (noise only).
  Confusables and tab alignment are not solvable by filtering.

## Agent engine (overview)

`warden agent` (in `warden-cli`, `crates/warden-cli/src/agent.rs`) runs the
agent engine on stdin/stdout; `warden daemon`
(`crates/warden-cli/src/daemon.rs`) runs the same engine on Telegram
and/or WhatsApp, optionally paired with stdin/stdout (`--console`). Both share their startup
(`crates/warden-cli/src/startup.rs`). The daemon's own rules are in
"Telegram channel", "WhatsApp channel" and "Daemon" below. The pieces, each with its own
section here:

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
  sender; `warden daemon` checks it only with `--console`, and serves the
  `[telegram] owner_ids` as `tg:<id>`); `root` missing, not a directory, `/`, or `$HOME` or an ANCESTOR
  of it (unless the hidden `--allow-home-root`; an unset or unresolvable
  `HOME` also needs the flag); key variable unset or empty (named only
  when it is the default, or a conventional `UPPER_SNAKE` name of at most
  40 characters that the redactor leaves unchanged, with no segment over
  16 characters and at most 6 digits in all); planner config invalid. Only then are the audit log
  (broken or locked: refused), the approver store, the snapshot store and
  the executor opened, so the earlier failures leave no files but the data
  dir. Last, `Engine::try_new` refuses an unprotected state dir. The CLI
  always protects the data dir and `<home>/snapshots` (inside the data
  dir, so protecting it separately is defense in depth), so a root that
  contains the data dir starts, and every tool call into it is refused
  `Protected`. Sessions are audited (`agent session started` / `agent
  session ended`, action id `session`, tier `Auto`; the end entry is best
  effort). The audit log is leased (`warden_agent::lease::LeasedAuditLog`):
  opened (exclusive lock, full chain verification) on the first append
  of a message and released when `Engine::handle` returns, on every path
  (non-owner and dropped messages included), on a blocking thread through
  the same mutex as appends; each session entry also releases it. So
  `warden undo` and the other writing commands work while the agent is
  idle and fail fast with a lock error while it handles a message. An
  agent append that finds the log locked retries every 100 ms for up to
  2 s, then fails, and the action is refused `audit unavailable` (fail
  closed). Each reopen re-verifies the chain from the start, so every
  message pays a read of the whole log (linear in its size), and the chain
  continues from the log's real head, so entries other writers appended
  in between keep it valid. The startup open does not wait: a broken or
  locked log is refused. A failed append drops the open log, so the next
  one re-verifies the file before writing. If a `handle` future is
  dropped mid-message (cancellation), the release does not run and the
  log stays held until the next message finishes. The API key stays in the
  process environment (the planner zeroizes its own copy).
- **The HOME-ancestor guard trusts the `HOME` environment variable**; the
  passwd home is not consulted, so a process started with a different
  `HOME` can bypass it. `--allow-home-root` and the choice of root remain
  the user's responsibility.
- **Owner values are never echoed raw**: `owner` must be
  `[A-Za-z0-9._@:-]{1,64}` and unchanged by the redactor.
- **Planner trust model**: see "Planner boundary" (what is sent, transport,
  the API key) and "Engine" (the planner is untrusted; tiers come from
  `classify`).
- **Redaction limits**: pattern-based (see "Planner boundary" and
  `redact.rs` "Known limits"); it will miss unknown secret formats, and the
  remote planner sees whatever it misses.
- **Consent and the PIN**: see "Channel" (per-prompt challenge code) and
  "Engine" (persisted PIN lockout, late replies, PIN-like chat).
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
- **PIN lockout is persisted and escalates.** Three consecutive bad PINs
  lock PIN-tier approvals for `60_000 << level` ms of the injected wall
  clock, capped at a day (`PIN_LOCK_MAX_MS = 86_400_000`); `level` rises by 1
  on each lock, so repeated lockouts last 60 s, 120 s, 240 s and so on. A
  correct PIN resets the count and the level. The lock is checked BEFORE
  prompting: while locked, a `YesPin` action is refused without a prompt
  (`refused: pin locked`, owner told `PIN approvals locked for <n> s`) and
  the PIN file is not read. The state (`failures`, `level`,
  `locked_until_ms`, 16 bytes) lives in `<home>/pin-guard`; `Engine::try_new`
  loads it (missing means no lockout) and refuses to start
  (`EngineConfigError::PinGuardState`) if it is malformed, a symlink, not a
  regular file or has group/other permission bits. It is rewritten
  atomically (0600 temp file, `sync_all`, rename, directory fsync) after
  every PIN check, so a restart does not clear a lockout. If the write
  fails, PIN-tier approvals are refused (`refused: pin unavailable`, no
  prompt) until restart and the owner is told `warning: cannot save the PIN
  lockout; PIN approvals are disabled until restart`. If saving keeps
  failing, the bad PIN that failed to save was counted in memory only, so
  each restart gives one uncounted guess. Limits: it limits
  online guessing through the engine, not offline guessing of the PIN file
  (see "CLI PIN"); anyone who can write the PIN home can reset it, and the
  lock follows the wall clock, so a clock moved forward ends it early.
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
- **Relative paths resolve against the root.** `warden agent` sets the
  engine's `cwd` to the canonical root, never the process's working
  directory (which used to make `notes.txt` resolve outside the root and be
  refused when the agent was started elsewhere). `EngineConfig::new` builds
  the system prompt with `default_system_prompt(root, cwd)`, which names
  the folder (quoted) and what relative paths resolve against; the whole
  prompt is redacted before it is sent. `..` is still resolved lexically
  and anything that leaves the root is refused before any prompt.
- **Several owners, each served alone.** `EngineConfig.owners` lists the
  senders whose messages are acted on (`EngineConfig::new` sets one).
  Everything said while handling a message, approval prompts and the
  discard notice included, goes to that message's sender only, and an
  approval is asked of (and may only be answered by) the requester, never
  another owner. Owners share one PIN, one PIN lockout and one approver
  store. Accepted cost: wrong PINs from one owner lock PIN approvals for
  every owner (a cross-owner denial of service; every owner is trusted).
  So a compromised owner account (a stolen Telegram session, say) can lock
  PIN approvals for every owner for up to 24 h.
- **Per-channel PIN gate.** Before a `YesPin` prompt, and before the PIN
  lockout check, an action whose requester's channel answers
  `accepts_pin(sender) == false` is refused with no prompt, no challenge
  drawn and no PIN file read: audited `refused: pin not accepted on this
  channel`, tool result `pin not accepted on this channel`, and the owner
  is told `this needs your PIN, which this channel does not accept; do it
  at the computer`. Why: a PIN typed into a remote chat service is stored
  on its servers.
- **Retraction of messages that may hold the PIN.** After a message is
  dropped as PIN-like, or as approval-shaped with 3 or more whitespace
  tokens (`yes <code> <PIN>`), the engine calls `retract_last(sender)`.
  A two-token approval-shaped message (`yes <x>`, any whitespace) is also
  checked with the PIN-like check (same bounds, constant time); if it holds
  the PIN (an owner who forgot the code), it is handled as a PIN-like
  message: retracted, `ignored: pin-like message` audited, never sent to
  the planner. Best effort only; a bare `yes`/`no` or `yes <code>` that is
  not the PIN is not retracted.
- **The truncation marker always survives.** A model reply the provider
  cut off is first cut so that, together with `\n[reply truncated]`, it
  fits in the 4096 characters a channel displays (counting display
  escapes), and the marker is appended after that, so the channel's own
  cap never removes it.
- **Non-owners get nothing.** A message whose sender is not in
  `cfg.owners` causes no planner call and no reply. It is audited
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
  `refused: prompt too long`, `refused: shutting down`, `refused: prompt not
  delivered` (a remote channel could not send the prompt, so nobody was
  asked), and one aggregated `refused: too
  many calls` entry per planner response for calls beyond
  `max_calls_per_message`.
- Per message: `failed: planner`, `failed: timeout`, `failed: input
  closed`, `failed: shutdown`, `failed: step limit`.
- Summaries are the validated action summaries (kind, quoted path, sizes);
  file content and write content never enter the audit log. A failed
  refusal append is reported to the owner (`warning: audit append failed`).

**What reaches the planner.** The system prompt, the owner text and every
tool result go through `redact`. For `read_file`, the order is fixed and no
cut ever applies to unredacted text:

1. the executor reads up to `MAX_READ_BYTES + 4096` bytes (1 MiB + 4 KiB)
   whatever `max_bytes` the model asked for, and flags a file longer than
   that;
2. the engine redacts that whole text;
3. the engine cuts the REDACTED text to the model's `max_bytes` on a char
   boundary, appending `\n[truncated at <max_bytes> bytes]` when it cut or
   when the file was longer than the buffer (the count is of redacted
   bytes);
4. like every tool result, it is prefixed with `[untrusted file content]`,
   redacted, cut to `result_max_bytes` on a char boundary with
   `\n[truncated]`, and redacted again (a cut can turn an unmatched longer
   digit run into a matchable one).

Why: `read_file` is an `Auto` action, and with the cut made BEFORE
redaction the model could read a file once to see `[REDACTED:card]` at byte
6, then ask for `max_bytes: 21` and receive the first 15 digits (Luhn gives
the 16th), or 35 of 36 characters of a `ghp_` token, 19 of 20 of an AKIA
id. Redacting first means every cut the model can choose is a prefix of
text that no longer contains the secret. Residual limit: a secret that
starts before byte 1,048,576 and runs past the 4096-byte overlap, and whose
pattern needs its end to match (for example an unterminated quoted value
longer than 4 KiB), is cut by the buffer before redaction and may be partly
visible; fixed-length tokens, cards and key prefixes are far shorter than
the overlap. `list_dir` output is already bounded (500 names) and is
redacted as a whole.
Error results use fixed texts (`invalid call: <kind>`, `blocked by policy`,
`owner declined`, `prompt not delivered`, `bad pin`, `pin locked`, `pin unavailable`, `audit
unavailable`, `approval unavailable`, `too many calls`, `error: <ExecError
Display>`), never argument values. Tool-call arguments echoed into history
go through `redact_json`; arguments over 64 KiB are replaced by a fixed
placeholder rather than echoed. Every `tool_use` gets exactly one
`tool_result` in the next user turn, in order, including refused calls.
Planner errors are shown as `planner unavailable (<kind>)` with a fixed
word per variant, never the error text.

**Output limit.** Requests ask for `max_tokens` 4096. A response with
`stop_reason: "max_tokens"` was cut off: if it contains any `tool_use`
block the Anthropic planner returns `Malformed("response truncated")` (and
the engine independently refuses a `truncated` response with calls as
`malformed`), so a possibly partial `write_file` is never offered for
approval. A cut-off text-only reply is shown with `[reply truncated]`
appended. Other and unknown stop reasons are ignored. Consequence:
`write_file` content larger than the model's output budget (about 16 KB of
text) cannot be produced in one call, and the approval prompt for any write
shows only the path and byte count, never the content.

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

**Shutdown never cancels a running tool either.** `Engine::with_shutdown`
takes a `tokio::sync::watch::Receiver<bool>`; when it becomes `true`:

- an idle engine stops at once: `run` races the channel's `recv` (which
  every channel must make cancel-safe) against the signal and returns;
- a planner call in progress loses the race: the message ends, the owner is
  told `Warden is shutting down`, audited `failed: shutdown`;
- an owner prompt in progress loses too: the action is refused (`refused:
  shutting down`, tool result `owner declined`) and the message ends the
  same way. The prompt is dropped like a timed-out one, so no reply can
  approve anything afterwards;
- `Executor::run` and audit appends are never raced: a started tool
  finishes and its outcome is audited, then the message ends with
  `failed: shutdown` before any further call or planner request.

The race happens inside `Engine::handle`, never by cancelling `handle` from
outside, so the audit sink is released (`AuditSink::release`) on every
shutdown path. A signal already `true` wins every race at once; a dropped
sender without `true` is not a shutdown request.

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

## Telegram channel

`warden_agent::telegram` (`api.rs`, `update.rs`, `offset.rs`,
`channel.rs`): the `Channel` trait over the Telegram Bot API, with long
polling (`getUpdates`) only. Warden opens no inbound port and sets no
webhook.

**Trust model.**

- **Telegram authenticates the owner.** Owners are the allowlisted numeric
  user ids in `[telegram] owner_ids` (1-8, each in `1..=2^52`), served as
  sender `tg:<id>`. Whoever controls one of those Telegram accounts (a
  stolen phone, a hijacked session) is an owner and can approve `Yes`
  actions. Telegram's servers see, and could forge, everything: bot chats
  are cloud chats, not end-to-end encrypted. Every request, reply, prompt
  and (with `allow_pin_approvals`) PIN is stored there.
- **Only a person's private chat counts.** `classify_update` accepts only
  a new text `message` whose `chat.type` is `"private"` and whose `chat.id`
  equals `from.id`. Refused, in this order: `edited_message` (`edited`);
  updates with no `message`, such as channel posts or callback queries
  (`other`); a message with no `from` or with `sender_chat`
  (`sender-chat`); `from.is_bot` (`bot`); `via_bot` (`via-bot`); any of
  `forward_origin`, `forward_from`, `forward_from_chat`, `forward_date`,
  `forward_sender_name`, `is_automatic_forward`, `external_reply`
  (`forward`); a group, supergroup, channel or any chat whose id is not the
  sender's (`group`); non-text (`non-text`); a wrong-typed id field
  (`malformed`). Each refused update reaches the engine as the non-owner
  sender `tg-<tag>:<id>` with empty text, so the only effect is the
  rate-limited `ignored: non-owner` audit entry (at most one per 60 s for
  all non-owners together). A stranger's private message is `tg:<id>`
  with empty text: the same entry, which is also how an owner finds their
  own id. Non-owners never get a reply. An owner's non-text message gets
  `only text messages are supported`; an owner text starting with `/`
  gets a fixed help line; neither reaches the engine.
- **Approvals stay in the requester's chat.** `ask_approval` sends the
  prompt to the requester's chat only, and the reply is the next text
  polled from THAT chat after the prompt was sent; updates from anyone else
  are queued for later. A non-text reply, or a Telegram reply to a message
  other than the prompt, is No. The text is judged by the same
  `parse_reply` as the terminal, so it must carry the prompt's challenge
  code (`yes <code>`, or `yes <code> <PIN>`). A prompt is never cut: one
  over Telegram's 4096 UTF-16 unit limit is not sent (the owner gets
  `request too long to approve safely; refused`) and is No. A prompt whose
  `sendMessage` fails is `Undelivered` (audited `refused: prompt not
  delivered`), never mistaken for the owner declining.
- **The PIN is off by default.** `allow_pin_approvals = false` makes
  `accepts_pin` false, so the engine refuses a `YesPin` action requested
  over Telegram before any prompt (see "Engine", "Per-channel PIN gate");
  `ask_approval` also answers No to a `YesPin` prompt by itself. With it
  on, the prompt adds a warning that the PIN passes through Telegram's
  servers.
- **Deleting replies that may hold the PIN (best effort).** The reply is
  consumed by the channel, so the engine's PIN-like check never sees it;
  the channel deletes it with `deleteMessage` right after reading it. At a
  `YesPin` prompt every text reply is deleted, whatever it parsed to (a
  bare `482193`, `yes 482193` without the code, `<code> <PIN>`). At a
  `Yes` prompt a reply of 2 or more tokens that did not approve is deleted
  (it may be `yes <PIN>`); `yes <code>` that approved, or a bare `no`, is
  not. Owner text dropped unread (as stale, by `discard_pending_input`, or
  by queue overflow) is deleted when it is approval-shaped with 2 or more
  tokens, or has at most 8 tokens and contains a run of 4 or more digits
  (a bare PIN; ordinary text such as `call at 1530` is deleted too). The
  engine retracts PIN-like messages it is handed (see "Engine",
  "Retraction"). Deletion removes the message from the chat; Telegram's
  servers have still seen it.

**The token.**

- It comes only from the environment variable named by `bot_token_env`
  (default `WARDEN_TELEGRAM_TOKEN`; it must differ from `api_key_env`, so
  the planner key can never be put into a Telegram URL). A config field
  named `bot_token`, `telegram_token` or `telegram_bot_token` is refused
  like `api_key`. `BotToken` accepts only
  `^[0-9]{5,16}:[A-Za-z0-9_-]{30,64}$`, is zeroized on drop, has no
  `Display`, and its `Debug` is `BotToken(<redacted>)`.
- It sits in the URL path (`{base}/bot{token}/{method}`), so the URL is
  built per request in a zeroizing buffer and is never shown. Every
  reqwest error is reduced to a fixed kind word (`timeout`, `connect`,
  `other`); reqwest's `Display` is never used (it includes the URL), and
  `without_url()` is not relied on. Telegram's `description` text is never
  kept: `TelegramError` holds only fixed text, status codes and
  `retry_after`. The redactor also matches a bot token after the letters
  `bot` in a Bot API URL, as a second line of defence.
- **No logger is ever installed.** reqwest can log request URLs at debug
  level, and the URL holds the token. Neither `warden agent` nor `warden
  daemon` sets up `log` or `tracing` output.
- Startup errors name the variable only under the same rule as the API
  key variable (the default, or a conventional `UPPER_SNAKE` name); a
  value is never shown. The token stays in the process environment for the
  daemon's life.

**Transport.** The shared client (`warden_agent::http`): rustls, proxy
environment variables ignored (`no_proxy()`), redirects not followed (a
3xx is an error), 10 s connect timeout. `[telegram] api_base` must be
`https://`, or `http://` to a loopback host only (used by the tests), with
no credentials, query or fragment. Responses are read in chunks and capped
at 1 MiB. Each request has a 30 s timeout, except `getUpdates` (the 30 s
long poll plus 15 s). No request is retried, except one `sendMessage`
retry after a 429 whose `retry_after` is at most 30 s. Once shutdown has
started (`TelegramChannel::with_shutdown`, wired by the daemon), there is
no retry (a 429 wait in progress ends at once) and each request, one
already in flight included, gets at most 5 s more, so the last messages
fit a service manager's 60 s stop timeout.

**Outbound.** `send` delivers only to an owner's chat (`tg:<owner id>`;
anything else is dropped), after `redact` and display sanitizing, cut to
4096 UTF-16 units with `…`. Prompts have their summary and model note
redacted, then are rendered and sanitized by the same `render_prompt` as
the terminal. Every message is plain text (no `parse_mode`, so no Markdown
or HTML injection), with link previews off (`link_preview_options:
{is_disabled: true}`: a preview would make Telegram's servers fetch a
model-chosen URL) and `protect_content: true` (clients disable forwarding
and saving; a screenshot still works, so it is not a confidentiality
boundary). Sends are best effort: a failed send is dropped.

**Offset and stale messages.** Delivery is at most once. `getUpdates`
fetches up to 20 updates from the saved offset; the offset past the whole
batch is written to `<home>/telegram-offset` (8 bytes, big-endian `i64`,
0600, no symlinks, atomic replace through a `.telegram-offset.warden-tmp`
file) BEFORE any update in the batch is acted on. A crash or kill
mid-batch therefore loses the rest of that batch instead of replaying it;
a restart never replays a handled message. If the offset cannot be saved,
the channel stops (fatal, below). An owner text whose Telegram `date` is
more than `max_message_age_secs` (default 120, 10-3600) before the local
clock is never acted on: it reaches the engine as `tg-stale:<id>` with
empty text, and the owner is told `ignored <n> message(s) older than <s> s
(Warden was not running or was busy)`. The age is checked when a batch is
polled and again when a queued owner text is handed to the engine, so a
message that waited in the queue (while the engine spent a long time on
an earlier one) is not acted on late either; the dropped text gets the
deletion rule above. The age check uses the local wall
clock, so a clock that is wrong by more than that misjudges it. A batch
over the 1 MiB cap is fetched again one update at a time, and a single
update over the cap is skipped by advancing the offset by one.

**Queue bound.** At most 64 items wait for the engine, and at most 64
notices wait to be sent. When the queue is full, items without content
(non-owner, refused and stale ones, which the engine only audits) go
first: an owner message evicts the newest of them, and is itself dropped
only when none is left. So a stranger flood cannot push owner messages out
of the queue. Every drop is counted; a dropped owner message that may hold
a PIN (the rule in "Deleting replies that may hold the PIN") is deleted,
best effort.

**Errors.** Transient failures (network, 5xx, 429 on `getUpdates`, a
malformed response) back off from 1 s, doubling to 60 s. Fatal, and final
for the channel (`recv` returns `None`, a prompt in progress is
`Closed`): 401 or 404 (the token was rejected or revoked), 409 (something
else is polling this bot, or a webhook is set), and an offset that cannot
be saved. `warden daemon` turns any of them into exit 1 (see "Daemon").

## WhatsApp channel

`warden_agent::whatsapp` (`api.rs`, `webhook.rs`, `listener.rs`,
`seen.rs`, `channel.rs`): the `Channel` trait over Meta's WhatsApp Cloud
API. Inbound messages arrive only by webhook, on a loopback listener the
owner exposes with their own tunnel; outbound text goes to the Graph API.
There is no polling (the Cloud API has none), no message template and no
media.

**Trust model.**

- **Meta authenticates the owner, and sees everything.** Owners are the
  numbers in `[whatsapp] owner_numbers` (1-8, each an optional `+` then
  7-15 digits, the first not 0; spaces and dashes are refused), served as
  sender `wa:<digits>`. The digits must be Meta's WhatsApp id for the
  account, which for some countries (for example Mexico, `521…`, or
  Brazil's ninth digit) differs from the dialled number; the owner copies
  it from the `ignored: non-owner` audit entry (`wa:<digits>`). Whoever controls one of those WhatsApp accounts is an
  owner and can approve `Yes` actions. Business-number chats are not
  end-to-end encrypted to Warden: the Cloud API decrypts at Meta, which
  sees, and could forge, every request, reply and prompt. Meta signs each
  webhook with the app secret; nothing else authenticates a request.
- **Only a fresh, non-forwarded text from an owner is acted on.**
  `parse_notification` reads only changes with `field == "messages"`
  whose `value.metadata.phone_number_id` equals `[whatsapp]
  phone_number_id` (others, and a missing one, are counted as `foreign`
  and skipped), and at most 256 items per notification: the messages of
  every change first, then the statuses, so statuses never push a message
  out; items past the cap are dropped and counted (`truncated`). A message becomes text only when its `type` is
  `"text"` with a `text.body`, its `id`, `from` (1-20 digits) and
  `timestamp` are valid, it carries no `errors`, and neither
  `context.forwarded` nor `context.frequently_forwarded` is set (a flag of
  any value but `false` or `null` counts as set). Refused, with their
  tags: forwarded (`forward`), carrying `errors` or `type: "unsupported"`
  (`unsupported`), `reaction`, `system`, any other type such as media,
  location, contacts, interactive or button (`non-text`), and a missing or
  invalid `id`, `from` or `timestamp` (`malformed`). Each refused message
  reaches the engine as the non-owner sender `wa-<tag>:<number or 0>` with
  empty text, so its only effect is the rate-limited `ignored: non-owner`
  audit entry (at most one per 60 s for all non-owners together). A
  stranger's text is `wa:<number>` with empty text: the same entry, which
  is also how an owner finds their own number. Non-owners never get a
  reply. An owner's `non-text` message also gets `only text messages are
  supported`.
- **Statuses are counted and dropped.** Delivery statuses (sent,
  delivered, read, failed) for messages Warden sent are counted
  (`WhatsAppChannel::status_count`) and never reach the engine or the
  audit log: each reply produces several, and they would crowd the single
  non-owner audit slot.
- **Approvals stay with the requesting number.** `ask_approval` sends the
  prompt to the requester's number only. The reply is the next text from
  THAT number; messages from anyone else, other owners included, are
  queued for later. A text that is `yes <code>` for this prompt is
  accepted whatever its timestamp (the code is drawn fresh per prompt, so
  it cannot predate it, and clock skew between Meta and the local clock
  must not lock the owner out). Any other text, and any non-text message,
  counts as the reply only if it is stamped no earlier than 5 s before the
  prompt was sent; earlier ones were typed before the prompt existed and
  are queued for `recv`. A non-text reply is No, and so is a reply whose
  `context.id` quotes a message other than the prompt. The text is judged
  by the same `parse_reply` as the terminal. A prompt is never cut: one
  over 4096 UTF-16 units is not sent (the owner gets `request too long to
  approve safely; refused`) and is No. A prompt that cannot be sent
  (outside the window, a failed send) is `Undelivered`, audited `refused:
  prompt not delivered`.

**The listener** (`WebhookListener`).

- **Loopback only, refused twice.** `[whatsapp] listen` (default
  `127.0.0.1:8097`) must parse as an IP and port whose IP is loopback
  (`127.0.0.0/8` or `::1`); `0.0.0.0`, `[::]`, a LAN address,
  `::ffff:127.0.0.1` and any host name are refused at config load, and
  `WebhookListener::bind` refuses a non-loopback address again before it
  opens a socket. Warden never opens a public port; the owner chooses the
  tunnel.
- **Limits.** HTTP/1.1 only, one request per connection (keep-alive off,
  every response `connection: close`), at most 16 connections at once (a
  socket accepted beyond that is closed at once and counted `busy`), the
  request head within 10 s and at most 16 KiB of buffer, the body within
  10 s, at most 1 MiB of body (a larger declared `Content-Length` is
  refused before reading; a streamed body is cut at the cap), and every
  connection ends after 25 s (the two timeouts plus 5 s) whatever it is
  doing.
- **One path.** Only `/webhook` is served. Every response is `text/plain`
  with a fixed short ASCII body, or the digits of a valid handshake
  challenge; nothing from a request is echoed otherwise.

| Request | Response | Counter |
|---|---|---|
| any path but `/webhook` | 404 | none |
| a method other than GET or POST | 405 | none |
| GET, valid handshake | 200, the challenge | none |
| GET, anything else | 403 | `handshake_refused` |
| POST, declared body over 1 MiB | 413 | `too_large` |
| POST, no `X-Hub-Signature-256` | 401, body not read | `unsigned` |
| POST, body over 1 MiB while streaming | 413 | `too_large` |
| POST, body not complete within 10 s | 408 | `timed_out` |
| POST, body broken off or badly framed | 400 | `bad_request` |
| POST, signature malformed, wrong, or sent twice | 401, never parsed | `bad_signature` |
| POST, signed but not a WhatsApp notification | 200, dropped | `malformed` |
| POST, signed, items past the 256 cap | 200, those items dropped | `truncated` (per item) |
| POST, signed, changes for another `phone_number_id` | 200, those changes dropped | `foreign` (per change) |
| POST, signed, channel queue full or closed | 503 (Meta retries) | `queue_full` |
| POST, signed, otherwise | 200, batch queued | none |
| POST, once shutdown has started (checked before the body is read and again after the signature check) | 503 (Meta redelivers after the restart) | none |
| connection over the slot limit | closed at once | `busy` |
| request head or connection over its time limit | connection closed | `timed_out` |

Signed but unusable bodies get 200 so Meta does not retry them forever.
hyper's own replies to a request head it cannot parse or that overflows
the buffer are not counted. The counters (`WebhookStats`, read as a
`StatsSnapshot`) are the only record: nothing is printed per request and
no logger is installed (see "Telegram channel", "The token").

- **Signature before parse.** A POST with no `X-Hub-Signature-256` header
  is refused before its body is read. Otherwise the body is read raw, and
  the header must be exactly `sha256=` plus 64 hex digits (either case):
  two signature headers, or one with comma-joined values, are refused,
  not resolved. The HMAC-SHA256 of the raw bytes with the app secret is
  compared with `hmac::Mac::verify_slice`, in constant time. Only a body
  whose signature matches reaches `serde_json`; unauthenticated bytes from
  the tunnel are never parsed.
- **Handshake.** Meta's subscription check is a GET. It gets 200 with the
  challenge as the body only when `hub.mode`, `hub.verify_token` and
  `hub.challenge` each appear exactly once, `hub.mode` is `subscribe`,
  the token matches, and the challenge is 1-64 ASCII digits. The token is
  compared as the SHA-256 of each value with `subtle::ConstantTimeEq`, so
  neither its content nor its length is leaked by timing. Every other GET
  gets 403.
- **Reply fast.** After a valid signature the listener parses, puts the
  batch on the channel's queue with `try_send` and answers without waiting
  for the engine. The daemon's queue holds 16 batches (`WEBHOOK_QUEUE`);
  when it is full the answer is 503 and Meta retries later.
- **Shutdown.** Once asked to stop, the listener closes its listening
  socket at once and gives connections in progress at most 2 s more. From
  the moment shutdown starts, every POST gets 503 (not counted), so Meta
  redelivers it after the restart instead of it being answered 200 and
  then lost; the seen store drops what was already taken.

**Secrets.**

- All three come only from the environment, from the variables named by
  `access_token_env` (default `WARDEN_WHATSAPP_TOKEN`), `app_secret_env`
  (default `WARDEN_WHATSAPP_APP_SECRET`) and `verify_token_env` (default
  `WARDEN_WHATSAPP_VERIFY_TOKEN`). The names must differ from each other,
  from `api_key_env` and from `[telegram] bot_token_env`. A config field
  named `access_token`, `app_secret`, `verify_token` or `whatsapp_token`
  (at any depth) is refused like `api_key`. At startup `warden daemon`
  also refuses (exit 1, `the WhatsApp secrets, the bot token and the API
  key must all be different values`) when any two of the secret values it
  holds are equal: the three WhatsApp secrets, the bot token and the API
  key, with any mix of channels (so a Telegram-only config whose bot token
  equals the API key is refused too). Distinct values matter because the verify token travels in a URL query
  (Meta's handshake GET), and tunnel request logs can record it.
- Shapes: the access token is 32-2048 characters of `[A-Za-z0-9._-]`, the
  app secret 16-128 ASCII letters and digits, the verify token 16-128
  characters of `[A-Za-z0-9._~-]`. Each is zeroized on drop, has no
  `Display`, and its `Debug` is `AccessToken(<redacted>)`,
  `AppSecret(<redacted>)` or `VerifyToken(<redacted>)`.
- The access token travels only in an `Authorization: Bearer` header,
  built per request in a zeroizing buffer and marked sensitive (the
  `HeaderValue`'s own copy, which reqwest owns until the request is sent,
  is not zeroized). It never goes in a URL. `GraphApi`'s `Debug` shows only
  the base URL, the Graph version and the phone number id.
- **Redaction.** The redactor gains a Meta access token pattern: `EAA`
  followed by 40 or more letters and digits, with a left boundary (start of
  text or a character that is not a letter or digit; see `redact.rs`). It may over-redact a long identifier that happens
  to start with `EAA`. A Meta or Telegram token right after a percent
  escape (`access_token%3DEAA…`, as in a URL-encoded query) is redacted
  too; the escape is kept. There is no pattern for the app secret: 32 hex
  digits look like ordinary hashes, and redacting every hash would make
  file contents useless to the model. The verify token is chosen by the
  owner and has no fixed shape either.

**Deduplication: at most once.** Meta retries webhooks, so the same message
can arrive twice. `<home>/whatsapp-seen` records the message ids
(`wamid`s) of OWNER numbers only: the 8-byte magic `WDNSEEN2`, then one
40-byte entry per id (its SHA-256 and the message's time in Unix ms,
capped at the local clock, big-endian), oldest first; never the ids
themselves. It follows the private state file rules (0600, no symlinks,
atomic replace through `.whatsapp-seen.warden-tmp`). When a batch arrives,
ids already recorded or repeated in the batch are dropped, and the
remaining owner ids are recorded BEFORE any message in the batch is
queued; the in-memory set changes only after the write succeeds. A failed
write is fatal and the batch is dropped. A crash between the listener's
200 and that write loses the batch instead of replaying it.

Eviction is by age. Past 1024 entries, only entries older than
`max_message_age_secs` are dropped (oldest first): a redelivery of those
would be stale and never acted on anyway. Younger entries are kept up to
a hard cap of 4096; past that the oldest go whatever their age, so more
than 4096 owner messages within `max_message_age_secs` could let an old
one be acted on twice. Strangers' ids are not recorded, so a stranger
flood cannot push an owner's id out; a redelivered stranger message only
reaches the engine again as a non-owner with empty text (an audit entry
at most). A message with no valid `wamid` (a `malformed` one) cannot be
deduplicated, but it is only ever audited.

**Stale messages.** An owner text whose WhatsApp `timestamp` is more than
`max_message_age_secs` (default 120, 10-3600) before the local clock is
never acted on: it reaches the engine as `wa-stale:<number>` with empty
text, and the owner is told `ignored <n> message(s) older than <s> s
(Warden was not running or was busy)` once per batch. The age is checked
when a batch arrives and again when a queued owner text is handed to the
engine. Meta's timestamps are capped at the local clock, so a sender clock
running ahead cannot keep a message fresh (or extend the window below).
The check uses the local wall clock, so a clock that is wrong by more than
the limit misjudges it.

**The 24-hour window.** Meta accepts free-form messages to a user only
within 24 hours of that user's last message. The channel keeps, per owner
number, the latest inbound `timestamp` (from any verified message from
that number, capped at the local clock) and sends only while `now + 5 min
< last inbound + 24 h`. Anything else is not sent and is counted in
`window_drops`; an approval prompt returns `Undelivered`. A Graph error
131047 (outside the window) on a send counts the same way. The map is in
memory only: after a restart Warden cannot message an owner until that
owner writes. Meta may instead report 131047 only later, in a `failed`
status webhook; statuses are dropped, so such a prompt counts as
delivered, the approval waits for the engine's timeout and ends as a
refusal (fail-closed), and `window_drops` undercounts.

**No PIN, and no deletion.** `accepts_pin` is always `false`, with no
config option, so the engine refuses a `YesPin` action requested over
WhatsApp before any prompt and tells the owner to do it at the computer
(see "Engine", "Per-channel PIN gate"); `ask_approval` also answers No to
a `YesPin` prompt without sending anything. Why: the Cloud API cannot
delete a user's message, so a PIN typed into WhatsApp would stay in the
chat and at Meta. The engine's PIN-like check still applies to every owner
message (it is sender-agnostic): a message that looks like the PIN is never
sent to the planner. `retract_last` cannot delete it; instead it sends the
owner `Warden cannot delete WhatsApp messages; delete that message
yourself.` The channel sends the same notice for owner text it consumes
itself and that may hold the PIN: a text dropped as stale (at arrival or
in the queue) or by `discard_pending_input` that is approval-shaped with 2
or more tokens, or has at most 8 tokens and a run of 4 or more digits; and
any approval reply that did not approve, except a bare `no` (so `yes
<code> <PIN>`, but also a wrong code or any other text). At most one notice per owner per batch
handled; best effort, and only inside the window (outside it the notice is
skipped and not counted).

**Outbound.** `send` delivers only to an owner (`wa:<owner number>`;
anything else is dropped), after `redact` and display sanitizing, cut to
4096 UTF-16 units ending in `…` (UTF-16 units are never fewer than
characters, so this stays within WhatsApp's 4096-character body limit).
Prompts have their summary and model note redacted, then are rendered by
the same `render_prompt` as the terminal. Each message is `POST
{api_base}/{graph_version}/{phone_number_id}/messages` with exactly
`{"messaging_product":"whatsapp","recipient_type":"individual","to":<digits>,"type":"text","text":{"preview_url":false,"body":<text>}}`:
plain text, and `preview_url: false` so Meta does not fetch a
model-chosen URL. Sends are best effort. At most 64 of Warden's own
notices wait to be sent; more are dropped.

**Transport.** The shared client (see "Telegram channel", "Transport"):
rustls, proxy variables ignored, redirects not followed (a 3xx is an
error). `api_base` (default `https://graph.facebook.com`) must be
`https://`, or `http://` to a loopback host (used by the tests), with no
credentials, query or fragment. `graph_version` (default `v26.0`, checked
2026-10-29; it must be raised as Meta retires versions) must look like
`v<1-3 digits>.<1-2 digits>` and `phone_number_id` must be 1-32 digits,
since both go into the URL path. Each request has a 30 s timeout, and
responses are read in chunks capped at 64 KiB. Of a Graph error only the
HTTP status, `code` and `error_subcode` are kept; `message`,
`error_user_msg` and `fbtrace_id` are dropped, and every reqwest error is
reduced to a kind word (`timeout`, `connect`, `other`).

**Errors.** Graph errors are classified, in this order: HTTP 401 or code
190 is an auth failure; HTTP 429 or code 4, 80007, 130429, 131048 or
131056 is a rate limit; code 131047 is outside the window; anything else
is other. A rate-limited send is retried once after 2 s, unless shutdown
has started. Fatal, and final for the channel (`recv` returns `None`, a
prompt in progress is `Closed`): the access token rejected on any send
(`WhatsApp rejected the access token`), `whatsapp-seen` that cannot be
written (`cannot save the WhatsApp seen-message list`), and the listener
going away while not shutting down (`the WhatsApp webhook listener
stopped`). Once fatal, the channel makes no more requests. Other failed
sends are dropped.

**Queue bound.** At most 64 items wait for the engine. When the queue is
full, items without content (non-owner, refused and stale ones) go first,
as in "Telegram channel", "Queue bound", so a stranger flood cannot push
owner messages out. `discard_pending_input` drops the owner's queued
messages and takes only the batches already waiting when it is called.

**Shutdown bounds.** Once shutdown has started (`with_shutdown`, wired by
the daemon), a rate-limit wait in progress ends at once with no retry,
and each request, one already in flight included, gets at most 5 s more.
After the engine stops, `flush_pending` sends the notices still waiting
(stale, non-text, delete-it-yourself), inside the window only, within 5 s
in all; whatever is left then is dropped. The listener stops as above.

## Daemon

`warden daemon` (`crates/warden-cli/src/daemon.rs`) runs the engine on
Telegram and/or WhatsApp, in the foreground, unattended. The channel is
`Pair(Pair(telegram, whatsapp), console)`, each side present only when
configured (with `--console` for the console).

- **Startup fails closed** (exit 1, nothing runs), in this order:
  1. the data dir (as for `warden agent`);
  2. `<home>/daemon.lock`;
  3. the config, which must have a `[telegram]` or a `[whatsapp]` table,
     or both (`no channel configured: add a [telegram] or [whatsapp]
     table`); with `--console`, `owner` must be `local`;
  4. the root;
  5. the planner key;
  6. with `[telegram]`: the bot token variable (unset, empty or not
     token-shaped);
  7. with `[whatsapp]`: the access token, app secret and verify token
     variables (unset, empty or not the right shape); then, with any mix
     of channels, every secret value held (those three, the bot token, the
     API key) must differ (`the WhatsApp secrets, the bot token and the
     API key must all be different values`);
  8. with `[telegram]`: `getMe` (a 401 or 404 is `Telegram rejected the
     bot token`; anything else is `cannot reach Telegram (<kind>)`);
  9. with `[whatsapp]`: the Graph phone number lookup (`GET
     /{graph_version}/{phone_number_id}?fields=display_phone_number,verified_name`):
     HTTP 401 or code 190 is `WhatsApp rejected the access token`; code 100
     or HTTP 404 is `the access token cannot see phone_number_id <id>`;
     anything else is `cannot reach the WhatsApp Cloud API (<kind>)`, where
     the kind holds only fixed words and numbers;
  10. with `[whatsapp]`: the webhook listener is bound (not yet serving):
      `<address> is already in use`, or `cannot listen on <address>
      (<kind>)`;
  11. the audit log, approver store, snapshot store and executor (as for
      `warden agent`), with owners `tg:<id>`, `wa:<number>` (and `local`
      with `--console`), then the Telegram offset store and the WhatsApp
      seen store;
  12. `Engine::try_new`.

  Steps 1-10 leave no file but the data dir and `daemon.lock`. Variables
  are named in errors only under the API key variable's rule; values
  never are.
- **Locks.** `daemon.lock` (0600, `O_NOFOLLOW`, refused unless a private
  regular file, `try_lock`) is held for the process's life: a second daemon
  on the same data dir exits 1 at once. The approver store lock is also
  held for the daemon's life, so `warden agent` cannot run on the same data
  dir meanwhile. Two daemons on different data dirs with the same bot get
  409 conflicts.
- **The audit lease.** The audit log is held only while a message is
  handled (see "Agent engine (overview)"), INCLUDING while an approval
  prompt waits for the owner, which can be up to `approval_timeout`
  (120 s). During that time `warden undo`, `warden run` and the other
  writing commands fail fast with a lock error; while the daemon is idle
  they work. An engine append that finds the log held by one of them
  waits up to 2 s, then the action is refused `audit unavailable`.
- **Shutdown.** The SIGINT and SIGTERM handlers are installed after
  `Engine::try_new` and before the `daemon session started` entry. The
  webhook listener starts serving after that entry and before the
  banner. A signal
  that arrives before then (during startup) kills the process the default
  way; no message has been fetched or handled at that point. The first
  signal afterwards asks the engine to stop (see "Engine", "Shutdown never
  cancels a running tool"): an idle daemon stops at once, a running tool
  finishes and is audited, a pending prompt is refused (`refused: shutting
  down`). Later signals only print `still shutting down`. From the first
  signal on, Telegram and Graph requests are bounded (see "Telegram
  channel", "Transport", and "WhatsApp channel", "Shutdown bounds"), and
  the webhook listener closes its listening socket and answers 503 to
  any POST still in progress (connections get at most 2 s more). After
  the engine stops, the daemon waits at most 5 s for the listener to
  finish, then aborts it. Then the daemon performs once more any deletion
  still owed (a reply that may hold the PIN whose `deleteMessage` was cut
  off) and sends the WhatsApp notices still waiting, best effort and
  bounded to 10 s in total. Messages already
  fetched but not yet handled are dropped, not replayed on the next start
  (delivery is at most once). Then `daemon session ended` is audited (best
  effort) and the exit code is 0.
- **Fatal channel errors** come from two sources, Telegram (token
  rejected, 409 conflict, offset unwritable) and WhatsApp (`WhatsApp
  rejected the access token`, `cannot save the WhatsApp seen-message
  list`, `the WhatsApp webhook listener stopped`). Each channel is wrapped
  so that its first fatal condition is recorded and wakes the run loop,
  even inside a `Pair`. That sets the shutdown signal at once, which also
  closes the webhook listener (so Meta is not answered 200 for batches
  nobody will read), stops the engine the same way as a signal, and exits
  1 with the reason on stderr (`error: <reason>`), also with `--console`.
- **`--console`** pairs the terminal (sender `local`) with the configured
  remote channels (`Pair`). Each owner is served on their own side; the
  terminal accepts the PIN, Telegram only with `allow_pin_approvals`,
  WhatsApp never. Closing stdin does not stop the daemon: `Pair` keeps
  reading the other side.
- **stderr** carries the banner, warnings and errors: never message text,
  tokens, secrets or the API key. The banner is `warden daemon:`, then
  `telegram @<bot>` with Telegram, then `whatsapp <display number>
  listen=<address>` with WhatsApp, then `owners=<n> root=<dir>` (`n`
  counts the remote owners). The display number comes from Meta, so it is
  display-sanitized (newlines and tabs escaped too) and cut to 64
  characters. Nothing is printed per request, and no logger is installed
  (see "Telegram channel").
- **Exit counters.** With WhatsApp, after `daemon session ended`, one
  stderr line is printed when any listener counter, the window counter or
  the channel's queue-drop counter is non-zero: `whatsapp: refused <n>
  unsigned, <n> bad-signature, <n> oversized, <n> slow webhook requests;
  <n> replies not sent outside the 24 h window`, followed by `; other: `
  and the non-zero ones of `malformed`, `bad-request`, `foreign`,
  `truncated`, `queue-full`, `busy`, `handshake-refused` and
  `queue-dropped` (`<n> <name>`, comma-separated). Delivery statuses are
  normal traffic and are not reported.
- **Clock.** The approver store's high-water mark (`<home>/clock-mark`,
  see "Agent approver store") clamps a clock that went backwards: approvals
  and tokens then expire relative to the later time, so they can outlive
  their real-time TTL by up to the gap. Startup warns on stderr and audits
  `clock behind high-water mark` when the clock is more than 30 s behind.
- **PIN lockout persists** in `<home>/pin-guard` (see "Engine"): three bad
  PINs lock PIN approvals for 60 s, doubling with each further lockout to
  at most 24 h, across restarts and for every owner at once: a compromised
  owner account can lock PIN approvals for every owner for up to 24 h.

**Service files.** `warden daemon print-service --launchd | --systemd
[--config <path>]` prints a launchd agent plist (label
`local.warden.daemon`) or a systemd user unit. It loads the config only to
read the two variable names (`api_key_env`, `bot_token_env`), never their
values, writes nothing (not even the data dir) and prints to stdout. The
paths are the canonical binary (`current_exe`), the absolute data dir and
the canonical config (only when `--config` is given). A path that is not
UTF-8 or contains a control character, `"`, `\`, `%`, `$`, `'`, `&`, `<`,
`>` or a backtick is refused (exit 1, `path not supported in a service
file`), so no XML entity, systemd specifier, variable or shell expansion
can appear and plain quoting is enough. The secrets are `REPLACE_ME`
placeholders: in the plist's `EnvironmentVariables` (the file then holds
secrets; its leading comment says to `chmod 600` it), and for systemd in
`EnvironmentFile=%h/.config/warden/daemon.env`, which the unit's comments
say to create with mode 0600. Both restart only after a failed exit
(launchd `KeepAlive` `{SuccessfulExit: false}` with `ThrottleInterval` 60;
systemd `Restart=on-failure`, `RestartSec=60`), so a fatal Telegram error
is retried once a minute and a clean stop stays stopped. Both allow 60 s
for a graceful stop (`ExitTimeOut`, `TimeoutStopSec`) and stop with
SIGTERM. The unit also sets `NoNewPrivileges=yes` and `UMask=0077`.
launchd writes stderr to `<home>/daemon.log`, which it creates with its
default umask (typically mode 0644, inside the 0700 data dir). It holds no
secrets: stderr never carries message text, the token or the API key.

**Recovery when an unattended daemon will not start.** Stop anything using
the data dir first.

- **`spent-nonces` length not a multiple of 24** (`InvalidData` from the
  approver store). A crash in the middle of an append leaves a torn last
  record. Truncate the file to its last whole record (the largest multiple
  of 24 bytes not above its size). This is safe: an approval token is
  returned only after its record has been appended and synced, so the
  approval of a torn record was never issued and nothing ran under it. Do
  not truncate further: whole records are spent nonces.
- **Stray `.*.warden-tmp` files** (`.pin-guard.warden-tmp`,
  `.telegram-offset.warden-tmp`, `.whatsapp-seen.warden-tmp`) are
  leftovers of an interrupted atomic write and are never read as state.
  The next write removes one itself; any can be deleted while Warden is
  stopped.
- **`daemon.lock` not a private regular file**: remove it (it holds no
  data) and start again.
- **`pin-guard` malformed or insecure** (`cannot load the PIN lockout
  state`): if it only has the wrong mode, `chmod 600` it. Otherwise
  remove it while Warden is stopped. Removing it resets the PIN lockout
  (bad-PIN count and escalation level), so do it only if you know why it
  broke.
- **`clock-mark` malformed or insecure** (from the approver store): fix its
  mode to 0600, or remove it while Warden is stopped. Removing it drops the
  rollback protection until the next run: the mark is recreated at the
  current clock, so a clock that was set back before then is not detected.
- **`telegram-offset` malformed or insecure** (`cannot open the Telegram
  update offset`): fix its mode to 0600, or remove it while Warden is
  stopped. Removing it restarts polling from Telegram's oldest unconfirmed
  update, so messages newer than `max_message_age_secs` may be replayed
  (older ones are still dropped as stale).
- **`whatsapp-seen` malformed or insecure** (`cannot open the WhatsApp
  seen-message list`: it does not start with the `WDNSEEN2` magic, as a
  file in an older format does not; its entries are not whole 40-byte
  records; it holds more than 4096 entries; it is a symlink or not a
  regular file; or group or others have access): if it only has the wrong
  mode, `chmod 600` it. Otherwise remove it while Warden is stopped
  (an older-format file is never migrated). Removing it forgets which
  messages were already taken, so a message Meta delivers again may be
  acted on again if it is newer than `max_message_age_secs` (older ones
  are still dropped as stale).

Each of these startup errors repeats the short form of this advice.
