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

`restore` treats the manifest on disk as untrusted: it re-checks every path
against the recorded canonical root (absolute, no `..`, no symlinked parent or
target), validates blob names and snapshot ids before using them as file names,
re-hashes every blob, and runs all checks before writing anything.

Residual risks (see the module docs in `crates/warden-core/src/snapshot.rs`):

- Symlink checks are `symlink_metadata` followed by use (no `O_NOFOLLOW` or
  `openat`, since the crate forbids `unsafe` and has no `libc`). A process that
  can write inside the root can swap a parent directory for a symlink between
  the check and the write and redirect one write outside the root.
- Manifests are unauthenticated. Anyone who can write the store directory can
  point restore at any regular-file path the process can write. Keep the store
  writable only by Warden.
- Apply is not transactional: an I/O error partway through restore can leave
  some files restored and others not.
