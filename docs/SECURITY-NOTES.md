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
  refused (`Protected`), checked on the lexical and the canonical form. The
  snapshot store and the approver home MUST live outside the root or be
  listed in `protected`; otherwise an authorized write could edit the
  approver key, the spent-nonce log or snapshot manifests.
- **Writes and deletes** require a regular file with link count 1 (`NotAFile`,
  `HardLink`), and an existing parent (parents are never created). The
  snapshot is taken first (a new file is recorded as absent), then the write
  goes through a temp file with an unpredictable name (8 random bytes from
  the OS RNG), created `0o600` with `O_NOFOLLOW`, given its final mode (an
  existing file's mode masked to `0o777`, else `0o600`), synced, renamed over
  the target, and the directory is fsynced; then `record_after`. A failure
  after the snapshot still returns the snapshot id (`ExecFailure::snapshot`)
  and removes the temp file.
- **Reads** are capped at `max_bytes` through the opened handle and converted
  lossily to UTF-8; a FIFO or device is `NotAFile` and does not block.
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
