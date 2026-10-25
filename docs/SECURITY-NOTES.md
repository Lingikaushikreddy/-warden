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
