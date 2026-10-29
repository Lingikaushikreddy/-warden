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
- **`warden daemon`**, the same engine on Telegram and/or WhatsApp,
  unattended: you message your own Telegram bot, or a WhatsApp business
  number (over Meta's official WhatsApp Cloud API), and approvals come
  back as `yes <code>` in the same chat. WhatsApp messages arrive by
  webhook on a loopback-only listener that you expose with your own
  tunnel. See [Telegram daemon](#telegram-daemon) and
  [WhatsApp](#whatsapp).

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
  with the bot. On WhatsApp, the owners are the phone numbers you list.
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
polling (`getUpdates`), so Telegram needs no inbound port (for WhatsApp,
see [WhatsApp](#whatsapp)).

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
when the config has neither a `[telegram]` nor a `[whatsapp]` table, the
token variable is unset or not token-shaped, Telegram rejects the token,
any two of the secrets it holds (the bot token, the API key and, with
WhatsApp, its three secrets) are the same value, or another `warden
daemon` is using the same data dir.

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

## WhatsApp

The WhatsApp channel uses Meta's WhatsApp Cloud API (the official API, not
WhatsApp Web linking). Meta delivers your messages to a webhook, so unlike
Telegram it needs an inbound HTTP endpoint. Warden listens on a loopback
address only (`127.0.0.1:8097` by default) and never opens a public port;
you put your own tunnel in front of it. Read the WhatsApp entries in
[Honest limits](#honest-limits) first: Meta sees every message, and the
tunnel is a public endpoint.

**1. Set up Meta.** At a high level (per Meta's developer docs as of
2026-10; Meta's dashboard changes, so the names may differ):

- create a Meta developer app and add the WhatsApp product to it;
- use the test number Meta gives you, or register a business number;
- note the number's **phone number id** (a string of digits shown in the
  app's WhatsApp API setup; it is not the phone number itself);
- note the **app secret** (App settings, Basic). Meta signs every webhook
  with it, and Warden refuses any request whose signature does not match;
- create an **access token**. The 24-hour test token is for trying it
  only; for real use, create a permanent token for a system user in your
  business settings.

**2. Expose the listener with a tunnel.** For example, with Cloudflare's
quick tunnel:

```sh
cloudflared tunnel --url http://127.0.0.1:8097
```

It prints a public `https://` host name. In the app's WhatsApp webhook
settings, set the callback URL to `https://<tunnel host>/webhook` (Warden
serves that one path only), set the verify token to a value you choose
(16-128 characters of letters, digits, `.`, `_`, `~` or `-`), and
subscribe to the `messages` field. Per Meta's docs, Meta checks the
callback by calling it when you save, so start the daemon (step 5) first.
In Cloudflare's current behaviour, a quick tunnel gets a new host name
each time it starts, so the callback URL must then be updated.

**3. Configure.** Add a `[whatsapp]` table to the config:

```toml
root = "/Users/you/warden-folder"

[whatsapp]
owner_numbers = ["+15551234567"]   # required: 1-8 numbers, E.164 (`+` optional, 7-15 digits, first not 0)
phone_number_id = "106540352242922" # required: the phone number id, as a string of digits
# access_token_env = "WARDEN_WHATSAPP_TOKEN"          # the NAMES of the variables
# app_secret_env = "WARDEN_WHATSAPP_APP_SECRET"
# verify_token_env = "WARDEN_WHATSAPP_VERIFY_TOKEN"
# listen = "127.0.0.1:8097"        # loopback only: 127.0.0.0/8 or [::1], IP and port
# max_message_age_secs = 120       # older messages are never acted on (10-3600)
# graph_version = "v26.0"          # Graph API version
# api_base = "https://graph.facebook.com"
```

No secret goes in the file: an `access_token`, `app_secret`,
`verify_token` or `whatsapp_token` field is refused like `api_key`, and
the variable names must all differ from each other, from `api_key_env`
and from `[telegram] bot_token_env`. A `listen` address that is not
loopback (`0.0.0.0`, `[::]`, a LAN address, a host name) is refused.
`graph_version` defaults to `v26.0`, the latest Graph version listed in
Meta's changelog on 2026-10-29; Meta retires old versions, so it must be
raised when Meta does.

A config may have a `[whatsapp]` table alone, or with a `[telegram]`
table: one daemon then serves both, each owner on their own channel.

**4. Find your number.** Use the number exactly as Meta reports it, which
is not always the number you dial: for some countries (for example Mexico,
`521…`, or Brazil, with or without the ninth digit) Meta's WhatsApp id
differs from the dialled number. So start with any placeholder (say
`owner_numbers = ["+10000000"]`), send the business number one text, stop
the daemon, and look in the audit log: the message was refused and
recorded as `ignored: non-owner` with the summary `wa:<digits>` (`grep
non-owner ~/.warden/audit.jsonl`). As with Telegram, non-owner entries are
written at most once a minute, so check the entry's time. Copy those
digits into `owner_numbers` and start again.

**5. Run.**

```sh
export ANTHROPIC_API_KEY=...
export WARDEN_WHATSAPP_TOKEN=...          # the access token
export WARDEN_WHATSAPP_APP_SECRET=...     # the app secret
export WARDEN_WHATSAPP_VERIFY_TOKEN=...   # the verify token you chose
./target/release/warden daemon            # or: warden daemon --config <path>
```

It prints `warden daemon: whatsapp <business number> listen=<address>
owners=<n> root=<dir>` on stderr (with Telegram too, `telegram @<bot>`
comes first). Start the tunnel and save the webhook settings once this
line appears. Besides the reasons above, startup fails closed with exit 1
when a WhatsApp variable is unset, empty or badly shaped; when any two
secrets are the same value (`the WhatsApp secrets, the bot token and the
API key must all be different values`: the verify token travels in a URL
that tunnel logs may record, so it must not equal a real key); when Meta
rejects the token (`WhatsApp rejected the access token`) or the token
cannot see the number (`the access token cannot see phone_number_id
<id>`); and when the listen address is taken (`<address> is already in
use`). `--console` works as with Telegram.

When it stops, it prints one line of counters if the listener refused or
dropped any request, items were cut from a notification (`truncated`)
or dropped from a full queue, a message was not sent because the 24-hour
window was closed, or messages were left unread at stop, for example
`whatsapp: refused 1 unsigned, 1 bad-signature, 0 oversized, 0 slow
webhook requests; 0 replies not sent outside the 24 h window`. Sends that
failed for another reason (a network error, a rate limit) are not
counted. Refused unsigned or badly-signed requests usually mean someone
other than Meta found the tunnel, or the app secret is wrong.

**Using it.** Message the business number from an owner number. Only text
is acted on: media, reactions, interactive and button replies, forwarded
messages and messages older than `max_message_age_secs` are never acted on
(they are audited as ignored, at most one such entry a minute), and an
owner's media or other non-text message (not a reaction or a forward)
gets `only text messages are supported`. When an action needs consent you
get the same prompt as the terminal; reply `yes <code>` from the same
number (anything else is a no, and so is a reply that quotes a different
message).

**One chat at a time.** With both Telegram and WhatsApp configured, while
an approval prompt is open on one of them (up to 120 s) the other is not
read: its messages may pass `max_message_age_secs` meanwhile and are then
dropped with a notice, and if the WhatsApp listener dies during that
time, the daemon notices only after the prompt ends.

- **PIN actions happen at the computer.** An action that needs the PIN (a
  delete) is always refused over WhatsApp without a prompt, and you are
  told to do it at the computer. There is no option to change this: Warden
  cannot delete a WhatsApp message, so a PIN typed there would stay in the
  chat and at Meta. If you send a message that looks like your PIN (or
  may hold it, such as `yes <code> <PIN>`), it is not sent to the model,
  and Warden answers `Warden cannot delete WhatsApp messages; delete that
  message yourself.` (only while your window is open).
- **Replies only within 24 hours of your last message.** Meta allows a
  business to send free-form messages only inside a 24-hour window that
  opens each time you write. Warden sends nothing when less than 5 minutes
  of your window is left: a reply is dropped and a prompt is refused
  (audited `refused: prompt not delivered`). Write to it again to reopen
  the window.
- **Nothing is sent after a restart until you write.** Warden keeps the
  window in memory only, so after a restart it cannot message you until
  you send it something.
- **Undo is local**, as with Telegram.

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
- **At-most-once delivery, so a stop can lose messages.** The daemon
  records that it has seen a batch of messages before acting on it, so a
  crash or kill mid-message loses that message rather than replaying it.
  Any stop, a clean Ctrl-C or SIGTERM included, also loses messages
  already received but not yet handled: they are never acted on, now or
  after the restart. On Telegram they are dropped silently. On WhatsApp,
  messages Meta was already told were received are recorded as seen and
  dropped, and each owner they came from gets one message, `Warden
  stopped before reading <n> message(s); send them again.`, but only
  inside that owner's 24-hour window: outside it, the owner is not told.
  This is done before the time-limited final send, so a slow Telegram
  cleanup cannot skip it. The exit line counts them (`<n> unread at
  stop`). Warden's notices are best effort and may occasionally arrive
  twice (a send cut off midway is retried). A crash or kill after
  Warden has answered Meta's webhook loses those messages with no notice
  at all. Webhooks that arrive once stopping has begun are answered 503,
  so Meta delivers them again after the restart (and messages older than
  `max_message_age_secs` by then are dropped as stale).
- **WhatsApp Business chats are not end-to-end encrypted to Warden.** The
  Cloud API decrypts messages at Meta, so Meta sees every request, every
  reply and every approval prompt.
- **A PIN typed into WhatsApp stays there.** Warden never asks for the PIN
  over WhatsApp, but if you type it anyway, Warden cannot delete it: it
  stays in the chat and at Meta. Warden can only ask you to delete it from
  the chat yourself.
- **The tunnel is a public endpoint.** Anyone who finds its host name can
  send requests to it. They are refused unless they carry a valid HMAC
  signature made with the app secret (and the subscription check needs the
  verify token), but that signature is the only protection. The tunnel's
  provider (for example Cloudflare, whose quick tunnels, in Cloudflare's
  current behaviour, end TLS at Cloudflare) sees every webhook body, and
  its request logs may record the verify token, which Meta sends in the
  URL.
- **Whoever controls an owner's WhatsApp account is the owner.** A stolen
  phone or a hijacked account can send requests and approve `Yes`
  actions.
- **The 24-hour window.** Warden cannot message you more than 24 hours
  (less 5 minutes) after your last message, and it keeps that window in
  memory only, so after a restart it cannot message you until you write.
  Meta can also report "outside the window" only later, in a delivery
  status; Warden does not read statuses, so such a prompt counts as
  delivered and the approval simply times out (a no).
- **Service files hold secrets** once you fill them in. Keep them `chmod
  600`. The tokens, the WhatsApp app secret and verify token, and the API
  key also live in the daemon's environment. A filled-in launchd plist
  holds the WhatsApp app secret and verify token as plain text that the
  redactor does not recognise, so a read of it would pass them to the
  model: never set `root` to `~/Library/LaunchAgents` or a folder that
  contains it (such as `~/Library`, or, with `--allow-home-root`, your
  home folder).
- **Some encoded tokens are not redacted.** A token that is
  percent-encoded twice (`%2520EAA…`), or a Telegram token whose colon is
  percent-encoded (`%3A`), does not match the redactor's patterns and
  reaches the model as is.
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

Signal or Matrix channels, WhatsApp message templates (so Warden cannot
message you outside the 24-hour window) and WhatsApp media, a tray app,
remote undo (undo over Telegram or WhatsApp), WASM skills, MCP, a mesh or
relay between devices, a website, and a local routing model. None of
these exist in this repository.

## Docs

- [docs/SECURITY-NOTES.md](docs/SECURITY-NOTES.md): the security design,
  per component, with residual risks.

## License

Apache-2.0. See [LICENSE](LICENSE).
