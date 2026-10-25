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
