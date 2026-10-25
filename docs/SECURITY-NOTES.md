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
