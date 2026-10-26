# Security notes

## Auto reads and symlinks

`classify` is pure and lexical: it never touches the filesystem and does not
resolve symlinks. A `ReadPath("/root/link/id_rsa")` where `link -> ~/.ssh` is
therefore classified `Auto` because it lies lexically inside an allowed root.
Roots containing `..` are likewise normalized lexically.

Requirement for the Plan 2 executor: before acting on an `Auto` read, it MUST
either canonicalize the path and re-check it against the allowed roots, or open
it with no-follow semantics. The snapshot module does not cover reads, so this
check belongs to the executor.

## Approvals: expiry and persisted nonces

`Approver::redeem(action, cfg, approval)` computes the required tier itself
with `classify(action, cfg)`; callers cannot pass a tier. A caller holding a
stale or lower view of an action therefore cannot downgrade it: a `YesPin`
action is never redeemed with a `Yes` approval, and a `Blocked` action is
refused whatever the approval says. Check order: `Blocked` → action hash →
signature → tier floor → nonce insert. The caller must pass the same
`PolicyConfig` the executor will act under.

`Approver` keeps its spent-nonce set in memory only, and an `Approval` is valid
for as long as the key that signed it. `Approver::from_signing_key` starts with
an empty spent set, so reloading a key after a restart lets every approval that
key ever signed be redeemed again (cross-restart replay).

Open items for Plan 2:

- Approvals carry no expiry or epoch. Add one to the signed message (for
  example an issued-at time plus a TTL, or a key epoch) so old approvals stop
  verifying.
- The spent-nonce set must be persisted together with the signing key, and
  loaded before any redeem, so a restart cannot reset it.
- The spent-nonce set grows with every legitimate redemption (rejected
  approvals never add to it). With an expiry in place, nonces older than the
  expiry window can be pruned.

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

Plan 2 wires the signed `Approver` into the CLI and moves the secret to
keychain-backed storage.

## CLI audit and execution

Every command that writes (`run`, `undo`, `prune`, `init-pin`) opens the audit
log first and refuses with exit code 1 if it cannot (including a broken hash
chain or a log held by another process). Each one appends an entry before it
changes anything (`run`: `approved`; `undo`, `prune`, `init-pin`: `requested`)
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
`Tier::Auto` only because `AuditEntry` requires a tier; the decision text says
what happened.

Fault injection for tests (`WARDEN_TEST_FAIL_AUDIT_APPEND=<n>`, fail the n-th
append of the process) exists only when `warden-cli` is built with the
`test-hooks` Cargo feature, which is off by default; a default or release
build contains no reference to the variable. The tests enable it through a
self dev-dependency. The hook never lets a refused action through, but failing
the append that follows an executed action leaves that action without its
final audit record, which is the audit gap described above.

The `write`/`delete` executor relies on the snapshot module's symlink checks;
it inherits the same TOCTOU gap described under "Snapshots and restore".

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
