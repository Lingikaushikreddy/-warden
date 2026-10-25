# Warden Safety Core Implementation Plan (Plan 1 of 5)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Rust workspace whose `warden-core` crate classifies actions into policy tiers, records every decision in a tamper-evident audit log, snapshots files before changes so they can be restored, and exposes all three through a `warden` CLI.

**Architecture:** `warden-core` is a pure library with no network and no model code. An `Action` is a list of `Capability` values; the tier is computed from capabilities only (never from model text). Approvals are signed with ed25519 and bound to one exact action. The audit log is an append-only JSONL file where each entry hashes the previous entry. Snapshots are content-addressed blobs plus a manifest.

**Tech Stack:** Rust 1.94 (edition 2021), serde/serde_json, sha2, ed25519-dalek 2, rand_core/rand, thiserror, tempfile (dev), clap 4 (CLI), assert_cmd (dev).

**Spec:** `docs/superpowers/specs/2026-10-25-warden-design.md`

**Later plans (not in this plan):** 2 agent daemon + CLI/Telegram channels + planner; 3 WASM skills; 4 device mesh + relay; 5 website.

## Global Constraints

- Four tiers exactly: `Auto`, `Yes`, `YesPin`, `Blocked` (spec: "auto; YES; YES + PIN; blocked").
- Tier is computed from capabilities, never from model output.
- Blocked actions can never be approved, even with a valid signature.
- Snapshots are kept 30 days by default (configurable).
- `warden-core` has no network dependency.
- Licence Apache-2.0; no code, text, or assets copied from JIMMY.
- Commits under the user's own git identity, no AI attribution lines (user rule).

## Review Focus

1. Approval signed for action A is replayed for action B with a different path: must be rejected.
2. An approval is replayed twice (same nonce): the second use must be rejected.
3. Audit log file is edited, truncated, or has a line deleted in the middle: `verify` must report the first bad index.
4. Snapshotting a path that does not exist, a symlink, or a directory: must not follow symlinks out of the allowed root and must not panic.
5. Restoring when the file was changed again since the snapshot: must refuse unless `--force`.

## File Structure

```
Cargo.toml                       workspace
crates/warden-core/Cargo.toml
crates/warden-core/src/lib.rs            re-exports
crates/warden-core/src/action.rs         Capability, Action
crates/warden-core/src/policy.rs         Tier, classify()
crates/warden-core/src/approval.rs       Approver, Approval, ApprovalError
crates/warden-core/src/audit.rs          AuditLog, AuditEntry, VerifyReport
crates/warden-core/src/snapshot.rs       SnapshotStore, SnapshotId
crates/warden-cli/Cargo.toml
crates/warden-cli/src/main.rs            clap commands
crates/warden-core/tests/*.rs            integration tests
```

---

### Task 1: Workspace and `Action`/`Capability` types

**Files:**
- Create: `Cargo.toml`, `crates/warden-core/Cargo.toml`, `crates/warden-core/src/lib.rs`, `crates/warden-core/src/action.rs`, `.gitignore`, `LICENSE`
- Test: `crates/warden-core/src/action.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Produces:
  - `enum Capability { ReadPath(PathBuf), WritePath(PathBuf), DeletePath(PathBuf), RunNewScript(String), OpenApp(String), MessagePerson(String), SendEmail(String), InstallSoftware(String), NetworkSend(String), FormatDisk, EditRegistry, DisableSecurityTool, ReadSavedPasswords }` (derives `Debug, Clone, PartialEq, Eq, Serialize, Deserialize`)
  - `struct Action { pub id: String, pub summary: String, pub capabilities: Vec<Capability> }`
  - `impl Action { pub fn canonical_bytes(&self) -> Vec<u8> }` — deterministic JSON of `id`, `summary`, `capabilities` (fixed field order), used for hashing and signing.

- [ ] **Step 1: `git init` in the project root, add `.gitignore` (`target/`, `.superpowers/`), Apache-2.0 `LICENSE`, workspace `Cargo.toml` listing `crates/*`, and the `warden-core` crate manifest with the dependencies above.**
- [ ] **Step 2: Write failing tests** `canonical_bytes_is_stable_across_calls` (same action twice gives equal bytes) and `canonical_bytes_differs_when_a_path_differs` (`WritePath("/a")` vs `WritePath("/b")` differ).
- [ ] **Step 3: Run** `cargo test -p warden-core action` — Expected: FAIL (types not defined).
- [ ] **Step 4: Implement the types and `canonical_bytes` in `action.rs`; re-export from `lib.rs`.** Use `serde_json::to_vec` on a private struct with fixed field order.
- [ ] **Step 5: Run** `cargo test -p warden-core action` — Expected: PASS.
- [ ] **Step 6: Commit** `git add -A && git commit -m "feat(core): workspace, Action and Capability types"`

---

### Task 2: Policy engine (`classify`)

**Files:**
- Create: `crates/warden-core/src/policy.rs`
- Test: `crates/warden-core/tests/policy.rs`

**Interfaces:**
- Consumes: `Action`, `Capability` (Task 1).
- Produces:
  - `enum Tier { Auto, Yes, YesPin, Blocked }` (derives `Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize`, ordered `Auto < Yes < YesPin < Blocked`)
  - `struct PolicyConfig { pub allowed_roots: Vec<PathBuf> }`
  - `pub fn classify(action: &Action, cfg: &PolicyConfig) -> Tier` — returns the highest tier over all capabilities; an empty capability list is `Auto`.

Rules (from spec): `ReadPath` inside an allowed root → `Auto`; `ReadPath` outside → `Yes`. `WritePath` inside an allowed root → `Yes`; outside → `Yes`. `RunNewScript`, `OpenApp` → `Yes`. `MessagePerson`, `SendEmail`, `InstallSoftware`, `NetworkSend`, `DeletePath` → `YesPin`. `FormatDisk`, `EditRegistry`, `DisableSecurityTool`, `ReadSavedPasswords` → `Blocked`.

- [ ] **Step 1: Write failing tests** in `tests/policy.rs`: `read_inside_root_is_auto`, `read_outside_root_needs_yes`, `delete_needs_pin`, `message_person_needs_pin`, `format_disk_is_blocked`, `highest_tier_wins` (read + delete → `YesPin`), `empty_action_is_auto`, `path_traversal_does_not_count_as_inside` (`/root/../etc/passwd` with root `/root` → `Yes`), `blocked_beats_everything` (read + format → `Blocked`).
- [ ] **Step 2: Run** `cargo test -p warden-core --test policy` — Expected: FAIL.
- [ ] **Step 3: Implement `classify`.** Normalize paths lexically (resolve `.` and `..` without touching the filesystem) before the "inside root" check.
- [ ] **Step 4: Run** `cargo test -p warden-core --test policy` — Expected: PASS (9 tests).
- [ ] **Step 5: Commit** `feat(core): tier classification from capabilities`

---

### Task 3: Signed, single-use approvals

**Files:**
- Create: `crates/warden-core/src/approval.rs`
- Test: `crates/warden-core/tests/approval.rs`

**Interfaces:**
- Consumes: `Action::canonical_bytes`, `Tier`.
- Produces:
  - `struct Approver` — holds an ed25519 `SigningKey` and a `HashSet<[u8;16]>` of spent nonces; `Approver::generate() -> Approver`, `Approver::verifying_key(&self) -> VerifyingKey`.
  - `struct Approval { pub action_hash: [u8;32], pub tier: Tier, pub nonce: [u8;16], pub signature: Signature }`
  - `impl Approver { pub fn grant(&self, action: &Action, tier: Tier) -> Approval; pub fn redeem(&mut self, action: &Action, tier: Tier, approval: &Approval) -> Result<(), ApprovalError> }`
  - `enum ApprovalError { Blocked, WrongAction, BadSignature, AlreadyUsed, InsufficientTier }`

`grant` on a `Blocked` tier must not be possible: `grant` returns the approval only for non-blocked tiers, so signature is `Result<Approval, ApprovalError>` — final signature `grant(&self, action: &Action, tier: Tier) -> Result<Approval, ApprovalError>`. `redeem` checks, in order: tier not `Blocked`; hash of `canonical_bytes` equals `action_hash`; signature valid; approval tier ≥ required tier; nonce unspent; then marks the nonce spent.

- [ ] **Step 1: Write failing tests:** `valid_approval_redeems_once`, `second_redeem_is_already_used`, `approval_for_other_action_is_wrong_action` (Review Focus 1), `tampered_signature_is_bad_signature`, `blocked_tier_cannot_be_granted`, `yes_approval_cannot_cover_yespin_action` (`InsufficientTier`).
- [ ] **Step 2: Run** `cargo test -p warden-core --test approval` — Expected: FAIL.
- [ ] **Step 3: Implement** in `approval.rs` with sha2 for the action hash and `ed25519_dalek` for signing over `action_hash || tier byte || nonce`.
- [ ] **Step 4: Run** the same command — Expected: PASS (6 tests).
- [ ] **Step 5: Commit** `feat(core): signed single-use approvals`

---

### Task 4: Hash-chained audit log

**Files:**
- Create: `crates/warden-core/src/audit.rs`
- Test: `crates/warden-core/tests/audit.rs`

**Interfaces:**
- Consumes: `Tier`.
- Produces:
  - `struct AuditEntry { pub index: u64, pub timestamp_ms: u64, pub action_id: String, pub summary: String, pub tier: Tier, pub decision: String, pub prev_hash: String, pub hash: String }`
  - `struct AuditLog` with `AuditLog::open(path: &Path) -> io::Result<AuditLog>`
  - `fn append(&mut self, action_id: &str, summary: &str, tier: Tier, decision: &str) -> io::Result<AuditEntry>`
  - `fn verify(path: &Path) -> io::Result<VerifyReport>` (associated function; works without opening for write)
  - `enum VerifyReport { Ok { entries: u64 }, Broken { first_bad_index: u64, reason: String } }`

Format: one JSON object per line; `hash = sha256(prev_hash || index || timestamp_ms || action_id || summary || tier || decision)` hex; first entry's `prev_hash` is 64 zeros. `open` on an existing log restores the last hash and index (and fails with `InvalidData` if the existing log does not verify).

- [ ] **Step 1: Write failing tests:** `append_then_verify_ok`, `reopen_continues_chain`, `edited_summary_reports_that_index` (Review Focus 3), `deleted_middle_line_reports_first_bad_index`, `truncated_last_line_reports_broken`, `open_refuses_a_broken_log`.
- [ ] **Step 2: Run** `cargo test -p warden-core --test audit` — Expected: FAIL.
- [ ] **Step 3: Implement** with `OpenOptions::append`, flushing and `sync_data` after every append.
- [ ] **Step 4: Run** same — Expected: PASS (6 tests).
- [ ] **Step 5: Commit** `feat(core): tamper-evident audit log`

---

### Task 5: Content-addressed snapshots and restore

**Files:**
- Create: `crates/warden-core/src/snapshot.rs`
- Test: `crates/warden-core/tests/snapshot.rs`

**Interfaces:**
- Produces:
  - `struct SnapshotId(pub String)`
  - `struct SnapshotStore` with `SnapshotStore::open(dir: &Path) -> io::Result<Self>`
  - `fn snapshot(&self, paths: &[PathBuf], allowed_root: &Path) -> Result<SnapshotId, SnapshotError>` — stores each regular file's bytes under `blobs/<sha256>` and writes `manifests/<id>.json` listing `(path, sha256, existed)`; a path that does not exist is recorded with `existed: false`.
  - `fn restore(&self, id: &SnapshotId, force: bool) -> Result<Vec<PathBuf>, SnapshotError>`
  - `fn prune(&self, older_than: Duration) -> io::Result<usize>` — deletes manifests older than the cutoff, then blobs no manifest references.
  - `enum SnapshotError { OutsideRoot(PathBuf), Symlink(PathBuf), NotAFile(PathBuf), ChangedSinceSnapshot(PathBuf), Io(io::Error), UnknownSnapshot }`

Restore rules: files that existed are written back; files recorded `existed: false` are deleted if present. Unless `force`, restore returns `ChangedSinceSnapshot` if the file's current hash differs from the hash at the time of the *next* operation recorded in the manifest (`after_hash`, filled by `fn record_after(&self, id: &SnapshotId) -> Result<(), SnapshotError>`, which the caller invokes once the change is done).

- [ ] **Step 1: Write failing tests:** `snapshot_and_restore_roundtrip`, `identical_files_share_one_blob`, `missing_file_is_recorded_and_removed_on_restore`, `symlink_is_rejected` (Review Focus 4), `path_outside_root_is_rejected`, `directory_is_not_a_file`, `restore_refuses_if_changed_again_without_force` (Review Focus 5), `restore_with_force_overwrites`, `prune_removes_old_manifests_and_orphan_blobs`.
- [ ] **Step 2: Run** `cargo test -p warden-core --test snapshot` — Expected: FAIL.
- [ ] **Step 3: Implement.** Canonicalize `allowed_root` and each parent directory (not the final component) to enforce the root check; use `symlink_metadata` for the symlink check.
- [ ] **Step 4: Run** same — Expected: PASS (9 tests).
- [ ] **Step 5: Commit** `feat(core): content-addressed snapshots with safe restore`

---

### Task 6: `warden` CLI wiring everything together

**Files:**
- Create: `crates/warden-cli/Cargo.toml`, `crates/warden-cli/src/main.rs`
- Test: `crates/warden-cli/tests/cli.rs` (assert_cmd)

**Interfaces:**
- Consumes: all `warden-core` public items.
- Produces commands (data dir via `--home <dir>`, default `~/.warden`):
  - `warden classify --root <dir> <kind> <arg>` — prints the tier name; e.g. `warden classify --root /tmp/r delete /tmp/r/a.txt` prints `YesPin`.
  - `warden run --root <dir> --yes [--pin <pin>] <kind> <arg>` — classifies, refuses `Blocked` (exit code 3), requires `--yes` for `Yes` and additionally `--pin` for `YesPin` (exit code 2 when missing), snapshots affected paths first, appends an audit entry for every attempt including refusals, and prints the snapshot id when one was taken. The CLI performs write/delete itself for `write <path> <content>` and `delete <path>`; other kinds are classify-only in this plan.
  - `warden audit verify` — exit code 0 and `ok <n>` or exit code 1 and `broken <index>: <reason>`.
  - `warden undo <snapshot-id> [--force]`.
  - `warden prune [--days 30]`.

- [ ] **Step 1: Write failing tests:** `classify_prints_tier`, `blocked_exits_3_and_is_audited`, `delete_without_pin_exits_2_and_changes_nothing`, `delete_with_pin_snapshots_then_undo_restores`, `audit_verify_detects_tampering` (edit a line in `audit.jsonl`, expect exit 1 and the right index).
- [ ] **Step 2: Run** `cargo test -p warden-cli` — Expected: FAIL.
- [ ] **Step 3: Implement** the clap subcommands. PIN is compared against a hash stored by `warden init-pin <pin>` (add this command; argon2 is out of scope here, use salted sha256 and note the limitation in `docs/`).
- [ ] **Step 4: Run** `cargo test --workspace` — Expected: PASS, plus `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] **Step 5: Commit** `feat(cli): classify, run, undo, audit verify, prune`

---

## Self-review notes

- Spec coverage for this plan: four tiers, code-computed policy, blocked never approvable, signed approvals, snapshots with 30-day pruning, hash-chained audit log, Rust core with no network dependency. Not covered here by design: channels, planner, redaction, WASM skills, mesh, relay, website (Plans 2–5).
- Types used across tasks (`Action`, `Capability`, `Tier`, `Approval`, `SnapshotId`, `AuditEntry`) are defined once in Tasks 1–5.
- Known limitation recorded for follow-up: PIN uses salted sha256, to be replaced with a keychain-backed secret in Plan 2.
