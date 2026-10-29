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
- **`warden daemon`**, the same engine on Telegram, unattended: you message
  your own bot, and approvals come back as `yes <code>` in the same chat.
  See [Telegram daemon](#telegram-daemon).

## The safety model, in plain words

- **One folder.** The agent works inside the single `root` folder from its
  config. Reading inside it is `Auto` (no prompt); writing needs `Yes`;
  deleting needs `Yes` plus your PIN; anything outside the folder is
  refused before you are asked. The tier comes from a fixed policy applied
  to the action's capabilities, never from what the model says (the same
  policy marks actions such as formatting a disk as always `Blocked`).
- **Owner only.** Only messages from the configured owner are acted on. On
  stdio, whoever controls the process's stdin is the owner. On Telegram,
  the owners are the numeric user ids you list, each in a private chat
  with the bot.
- **A fresh code per prompt.** Every approval prompt shows a new random
  4-digit code; only `yes <code>` (or `yes <code> <PIN>`) typed after the
  prompt appears approves it. Anything else, including a bare `yes`, is a
  no. A prompt that times out, or input that closes, ends the message.
- **PIN.** Deletes need the PIN set with `warden init-pin`. Three wrong PINs
  lock PIN approvals for 60 seconds, doubling on each further lockout (at
  most a day); the lockout survives a restart. A chat message that
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
  redactor. A file read is redacted as a whole (up to 1 MiB + 4 KiB)
  before it is cut to the size the model asked for, so the model cannot
  choose a cut that ends inside a secret.
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
# owner = "local"                  # must be "local" with the stdio channel
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

Type a request, for example `list the files and summarize notes.txt`.
Relative paths are taken inside `root` (wherever you started `warden
agent`), and the model is told which folder that is. When
the model wants to change something you see a prompt such as:

```text
Approval needed (Yes):
  write "/Users/you/warden-folder/notes.txt" (42 bytes)
Reply "yes 4821" or "no":
```

Press Ctrl-D (end of input) to stop; the agent exits 0.

Startup fails closed with exit code 1 and a short message on stderr
(usually one line, sometimes two) if:

- the data dir is a symlink, not yours, or writable by group or others;
- the config is missing or invalid, or `owner` is anything but `local`
  (the stdio channel has only one sender, `local`; other values are kept
  in the schema for future channels);
- `root` is `/`, missing, not a directory, or your home directory or any
  folder that contains it (such as `/Users`), because that would expose
  `~/.ssh` and every dotfile to `Auto` reads. The deliberately unadvertised
  `--allow-home-root` flag overrides this, and is also required when
  `HOME` is not set or does not exist, since the check cannot be made then
  (the message is `HOME is not set or does not exist; pass
  --allow-home-root to continue`);
- the API key variable is unset or empty;
- the audit log is broken or locked.

Config, root and key problems are caught before the audit log, approver
key or snapshot store are created, so they leave nothing behind but the
data dir.

**One process at a time.** `warden agent` holds the audit log's lock only
while it handles a message. While it is idle (waiting for your next line),
`warden run`, `warden undo` and the other writing commands work from
another terminal; while it is handling a message they fail fast with a
lock error, so try again once it has answered. The agent waits up to 2
seconds for a command that holds the log; if the log is still busy, the
action it was about to take is refused (`audit unavailable`).

## Telegram daemon

`warden daemon` runs the engine on Telegram in the foreground. It uses long
polling (`getUpdates`), so it opens no inbound port.

**1. Create a bot.** In Telegram, message `@BotFather`, send `/newbot` and
follow the steps. It gives you a bot token (`123456:ABC...`). Keep it
secret: whoever has it can read what the bot receives.

**2. Configure.** Add a `[telegram]` table to the config:

```toml
root = "/Users/you/warden-folder"

[telegram]
owner_ids = [123456789]            # required: 1-8 numeric Telegram user ids
# bot_token_env = "WARDEN_TELEGRAM_TOKEN"   # the NAME of the variable
# allow_pin_approvals = false      # PIN-tier approvals over Telegram
# max_message_age_secs = 120       # older messages are never acted on (10-3600)
```

The token never goes in the file (a `bot_token` or `telegram_token` field
is refused like `api_key`).

**3. Find your numeric id.** It is not your @username. Start the daemon
with any placeholder id (say `owner_ids = [1]`), send your bot one message
in a private chat, stop the daemon, and look in the audit log: the message
was refused and recorded as `ignored: non-owner` with the summary
`tg:<your id>` (`grep non-owner ~/.warden/audit.jsonl`). Non-owner entries
are written at most once a minute, so check the entry's time. Put the id in
`owner_ids` and start again.

**4. Run.**

```sh
export ANTHROPIC_API_KEY=...
export WARDEN_TELEGRAM_TOKEN=...   # never put the token in the config file
./target/release/warden daemon     # or: warden daemon --config <path>
```

It prints `warden daemon: telegram @<bot> owners=<n> root=<dir>` on
stderr. Ctrl-C or SIGTERM stops it after the current step (exit 0). Startup
fails closed with exit 1 for the same reasons as `warden agent`, and also
when the `[telegram]` table is missing, the token variable is unset or not
token-shaped, Telegram rejects the token, or another `warden daemon` is
using the same data dir.

**Using it.** Message the bot in a private chat. Group messages, edited
messages, forwards, messages from other bots and messages older than
`max_message_age_secs` are never acted on (also when they waited that long
for the daemon to finish an earlier request); they are reported as
ignored. When an
action needs consent the bot sends the same prompt as the terminal; reply
`yes <code>` in the same chat (anything else is a no).

**PIN actions happen at the computer.** By default an action that needs the
PIN (a delete) is refused over Telegram without a prompt, and you are told
to do it at the computer: start the daemon with `--console` to also take
requests and approvals on its terminal (owner `local`), or use `warden run`
from another terminal while the daemon is idle. Setting
`allow_pin_approvals = true` allows `yes <code> <PIN>` over Telegram; the
bot warns that the PIN passes through Telegram's servers and deletes your
reply after reading it (best effort).

**Undo is local.** There is no undo over Telegram. The daemon holds the
audit log only while it handles a message, so `warden undo <id> --root
<dir> --yes` works from a terminal while it is idle (with a lock error
while it is busy: try again). The snapshot id is in the audit log, in the
action's `executed snapshot=<id>` entry.

**One engine per data dir.** The daemon holds `<home>/daemon.lock` and the
approver store lock for its whole life, so a second daemon, or `warden
agent`, on the same data dir is refused.

**Install as a service.** `warden daemon print-service --launchd` (macOS)
or `--systemd` (Linux, a user unit) prints a service file with the
absolute paths of the binary, the data dir and the config (if you pass
`--config`). It writes nothing. Secrets are `REPLACE_ME` placeholders:

```sh
warden daemon print-service --launchd > ~/Library/LaunchAgents/local.warden.daemon.plist
chmod 600 ~/Library/LaunchAgents/local.warden.daemon.plist   # then fill in REPLACE_ME
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.warden.daemon.plist
```

The systemd unit reads the secrets from `~/.config/warden/daemon.env`
(create it with mode 0600; the unit's comments show how). Both restart the
daemon only after a failed exit, at most once a minute, and stop it with
SIGTERM. Paths containing quotes, backslashes, `%`, `$`, `&`, `<`, `>`,
backticks or control characters are refused.

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
  no prompt. A file is redacted only up to 1 MiB + 4 KiB: a secret that
  starts before the 1 MiB mark, runs more than 4 KiB past it and needs its
  end to be recognized (such as a very long unterminated quoted value) may
  be partly visible.
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
- **The home-folder guard trusts the `HOME` environment variable.** The
  system's account database (passwd) is not consulted, so a process started
  with a different `HOME` can get past it. `--allow-home-root` and the
  choice of `root` remain your responsibility.
- **The API key stays in the process environment** for the life of the
  agent (Warden zeroizes its own copy, but cannot safely remove the
  variable), so anything that can read the process's environment can read
  it.
- The standalone CLI (`run`, `undo`) uses `--yes` and PIN flags, not signed
  approvals.
- **Telegram is not end-to-end encrypted.** Bot chats are cloud chats:
  Telegram's servers see every request, every reply and approval prompt,
  and, if you enable `allow_pin_approvals`, your PIN. Deleting the PIN
  reply is best effort and does not remove it from Telegram's servers.
- **Whoever controls your Telegram account is the owner.** A stolen phone
  or session can send requests and approve `Yes` actions. Every owner
  shares one PIN and one PIN lockout, so wrong PINs from one owner lock
  all of them (a compromised account can lock PIN approvals for everyone
  for up to 24 hours).
- **At-most-once delivery.** The daemon records that it has seen a batch
  of messages before acting on it, so a crash or kill mid-message loses
  that message rather than replaying it. Messages fetched but not yet
  handled when it stops (SIGTERM included) are dropped too.
- **Service files hold secrets** once you fill them in. Keep them `chmod
  600`. The token and API key also live in the daemon's environment.
- **Large writes.** The model's output is capped at 4096 tokens per step,
  so `write_file` content larger than about 16 KB cannot be produced in one
  call (a cut-off call is refused, never offered for approval). A write
  approval shows only the path and byte count, not the content. A cut-off
  text reply ends with `[reply truncated]`.

## Verifying a release build

```sh
scripts/check-release-strings.sh
```

It builds `cargo build --release -p warden-cli --locked` and fails if the
binary contains any test-only string (`mock`, `from_script`,
`WARDEN_TEST_FAIL`, `test-hooks`), or if a config with `provider = "mock"`
is not rejected. Test-only code (the scripted planner, audit fault
injection) is compiled only with the `test-hooks` Cargo feature, which
`cargo test` enables and release builds must not.

## Not built

WhatsApp, Signal or Matrix channels, a tray app, remote undo (undo over
Telegram), WASM skills, MCP, a mesh or relay between devices, a website,
and a local routing model. None of these exist in this repository.

## Docs

- [docs/SECURITY-NOTES.md](docs/SECURITY-NOTES.md): the security design,
  per component, with residual risks.

## License

Apache-2.0. See [LICENSE](LICENSE).
