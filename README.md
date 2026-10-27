# Warden

Warden is a safety layer for an AI assistant that works with files on your
computer. Every action the assistant proposes is classified by a fixed
policy, needs your consent when it changes anything, is recorded in a
hash-chained audit log before it runs, and is snapshotted so it can be
undone.

It is early software: Unix-only (macOS and Linux), local, single user, no
releases yet. Read [Honest limits](#honest-limits) before trusting it with
anything that matters.

## What exists today

- **The `warden` CLI**, a standalone safety core:
  - `warden classify --root <dir> <kind> <args>` prints the tier an action
    needs (`Auto`, `Yes`, `YesPin`, `Blocked`);
  - `warden run --root <dir> [--yes] <write|delete|...> <args>` checks the
    approval, snapshots, then performs a write or delete (other kinds are
    classify-only);
  - `warden undo <snapshot-id> --root <dir> --yes` (plus the PIN) restores
    a snapshot;
  - `warden audit verify` checks the audit log's hash chain;
  - `warden prune --days <n>` deletes old snapshots;
  - `warden init-pin` sets the PIN for `YesPin` actions.

  The standalone CLI approves with **flags** (`--yes` and the PIN from
  `WARDEN_PIN` or `--pin`), not with signed approvals.
- **`warden agent`**, the agent engine on stdin/stdout: you type a request,
  a model (Anthropic's Messages API is the only provider) proposes tool
  calls (`list_dir`, `read_file`, `write_file`, `delete_file`), and Warden
  gates every call. One line of input is one message.

## The safety model, in plain words

- **One folder.** The agent works inside the single `root` folder from its
  config. Reading inside it is `Auto` (no prompt); writing needs `Yes`;
  deleting needs `Yes` plus your PIN; anything outside the folder is
  refused before you are asked. The tier comes from a fixed policy applied
  to the action's capabilities, never from what the model says (the same
  policy marks actions such as formatting a disk as always `Blocked`).
- **Owner only.** Only messages from the configured owner are acted on. On
  stdio, whoever controls the process's stdin is the owner.
- **A fresh code per prompt.** Every approval prompt shows a new random
  4-digit code; only `yes <code>` (or `yes <code> <PIN>`) typed after the
  prompt appears approves it. Anything else, including a bare `yes`, is a
  no. A prompt that times out, or input that closes, ends the message.
- **PIN.** Deletes need the PIN set with `warden init-pin`. Three wrong PINs
  lock PIN approvals for 60 seconds (in memory only). A chat message that
  looks like your PIN is dropped instead of being sent to the model.
- **Signed, single-use approvals.** Inside the engine, each consent becomes
  a signed, expiring, single-use approval whose nonce is recorded on disk
  before the action runs.
- **Snapshots and undo.** Before a write or delete, the old file is
  snapshotted; `warden undo <id>` restores it.
- **Audit log.** Every decision is appended to `<home>/audit.jsonl`, a
  hash chain, before anything runs; if that append fails, nothing runs.
  File contents and PINs are never written to it.
- **Redaction.** Everything sent to the model (your messages, file
  contents, tool results) first goes through a pattern-based secret
  redactor.
- **Key handling.** The API key is read only from an environment variable.
  It is never stored in the config file (a config that contains a key-like
  field is refused), and never printed, logged or audited.

## Try it

```sh
cargo build --release
./target/release/warden init-pin            # reads WARDEN_PIN, or pass the PIN
mkdir -p ~/warden-folder
```

Create `~/.warden/config.toml` (the data directory is `~/.warden` unless
you pass `--home`; the file must not be writable by group or others):

```toml
# The one folder the agent may use. Required, absolute; no default.
root = "/Users/you/warden-folder"

# Optional, with their defaults:
# owner = "local"                  # the stdio channel's sender id
# provider = "anthropic"
# model = "claude-sonnet-5-5"
# base_url = "https://api.anthropic.com"
# api_key_env = "ANTHROPIC_API_KEY"   # the NAME of the variable, not the key
```

Then:

```sh
export ANTHROPIC_API_KEY=...       # never put the key in the config file
./target/release/warden agent      # or: warden agent --config <path>
```

Type a request, for example `list the files and summarize notes.txt`. When
the model wants to change something you see a prompt such as:

```text
Approval needed (Yes):
  write "/Users/you/warden-folder/notes.txt" (42 bytes)
Reply "yes 4821" or "no":
```

Press Ctrl-D (end of input) to stop; the agent exits 0.

Startup fails closed with exit code 1 and a one-line message if the config
is missing or invalid, the key variable is unset, the audit log is broken
or locked, or `root` is `/`, missing, or your home directory itself (the
last is allowed only with the deliberately unadvertised
`--allow-home-root` flag, because it exposes every dotfile to `Auto`
reads).

## Honest limits

These are summarized from [docs/SECURITY-NOTES.md](docs/SECURITY-NOTES.md),
which has the details.

- **No memory between messages.** Each line you type starts a fresh
  conversation with the model.
- **Unix-only.** The approver store relies on Unix file modes, `O_NOFOLLOW`
  and `flock`; the data directory must be on a local filesystem.
- **Redaction is pattern-based.** Secret formats it has no pattern for,
  obfuscated or split secrets, and anything else it does not recognize in
  files the agent reads still reach the model. Reads inside the root need
  no prompt.
- **The model is a remote service.** The planner runs at Anthropic and sees
  the redacted text of your messages and of every file the agent reads. Its
  output is treated as untrusted, but it can still word an approval note
  persuasively.
- **The audit log is tamper-evident, not tamper-proof.** The hash chain
  shows edits made by someone who cannot rewrite the whole file; anyone who
  can write `<home>` (including you, or malware running as you) can rewrite
  it consistently.
- **TOCTOU window.** A process that can write inside the root can swap a
  parent directory for a symlink between Warden's checks and the file
  operation and redirect one operation outside the root. Closing it needs
  an `openat`-style walk, not done yet.
- **PIN storage is weak against offline guessing.** The PIN file holds a
  salted SHA-256; anyone who can read it can brute-force a short PIN.
- **Stdio trust.** Whoever controls stdin is the owner, and input already
  in transit when a prompt appears can still answer it if it carries that
  prompt's code.
- The standalone CLI (`run`, `undo`) uses `--yes` and PIN flags, not signed
  approvals.

## Not built

Telegram or WhatsApp channels, WASM skills, MCP, a mesh or relay between
devices, a website, and a local routing model. None of these exist in this
repository.

## Docs

- [docs/SECURITY-NOTES.md](docs/SECURITY-NOTES.md): the security design,
  per component, with residual risks.

## License

Apache-2.0. See [LICENSE](LICENSE).
