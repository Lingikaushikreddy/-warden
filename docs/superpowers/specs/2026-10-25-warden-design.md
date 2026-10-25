# Warden — design

Working name. Trademark and domain are unchecked; rename freely before launch.

## Intent and why

Kaushik studied JIMMY (jimmy.vedanshh.dev), a Windows-only agent that takes orders from your own WhatsApp chat, and wants a better, more advanced product in Rust that can win against it. He has not used JIMMY, so this design is built from JIMMY's public pages, not from his experience. Everything is original: no JIMMY copy, art, layout, or code.

Warden is a personal agent that runs on all of a user's computers and is controlled from any chat app. Core is open source and local-first.

## Goals

1. One small Rust binary for Windows, macOS and Linux (JIMMY: Windows only).
2. Safe channels first: Telegram, Signal, Matrix, a CLI, and the official WhatsApp Business Cloud API. Unofficial WhatsApp Web linking is an opt-in plugin with a ban-risk warning. (JIMMY depends on the unofficial route.)
3. A device mesh: several machines form one agent; each task routes to a machine that is on. A self-hostable relay keeps it reachable when a laptop sleeps.
4. Safety enforced in code, never by the model: a policy engine with four tiers (auto; YES; YES + PIN; blocked). Skills run as WebAssembly modules with declared capabilities, so a skill cannot touch anything it did not declare.
5. Real undo: content-addressed snapshots of files and settings, plus an append-only, hash-chained audit log the user can replay.
6. Local-first AI: a small local model routes requests and strips secrets; any cloud model (Anthropic, OpenAI, Gemini, Groq, OpenRouter, Ollama, LM Studio) only sees redacted text. Warden is an MCP client, so any MCP tool plugs in.
7. Free open-source core; paid add-ons (hosted relay, sync, teams).
8. A public website in the "light, editorial, calm control" style, with a live approval-card demo as its centrepiece.

## Non-goals

- Mobile app for v1 (the phone is just a chat app).
- Bulk or automated messaging of third parties.
- Replacing the user's judgment on tier-3 actions.

## Anti-goals (failure even if it works)

- Any action that bypasses the policy engine, including via prompt injection from email or web content.
- Silent data leaving the machine; secrets reaching a cloud model.
- Copying JIMMY's wording, imagery, or page structure.
- Claiming safety or privacy properties that are not enforced and tested.

## Decided by Kaushik

- Language: Rust.
- Scope: a better and more advanced product than JIMMY, aimed at beating it.
- Website: original, not a copy; he liked JIMMY's page and wants it bettered.
- Look: he clicked option B (light, editorial, "calm control") several times, then A (dark, live chat plus approval card) last.

## My calls (change any of these)

- Website look: B's warm off-white editorial style for the page, with A's live chat and approval card as the hero demo. A dark "terminal" theme is a toggle.
- Repo: `~/Desktop/Projects/warden`, Cargo workspace plus a Next.js site in `site/`.
- Crates: `warden-core` (policy engine, audit log, snapshots), `warden-agent` (daemon, tray, channels, planner), `warden-skills` (wasmtime host and capability model), `warden-mesh` (device pairing, routing, relay client), `warden-relay` (self-hostable server), `warden-cli`.
- Key libraries: tokio, wasmtime, rusqlite or redb, ed25519-dalek, age for key storage, axum for the relay, reqwest for model APIs, teloxide for Telegram.
- Channel order: CLI, then Telegram, then WhatsApp Cloud API, then Signal and Matrix.
- v1 target: macOS and Windows desktop first; Linux in the same build, tested later.
- Licence: Apache-2.0 for core; relay and sync are the paid parts.
- Build in vertical slices, starting with the policy engine and audit log, because they define the safety claim.
- The site is static Next.js with the live demo simulated in-browser (no backend call).

## Architecture

```
Chat app → channel adapter → owner check → router (local rules, then local model)
  → redactor → planner (chosen LLM) → plan
  → policy engine (tiers, signed approvals) → executor
       ├─ built-in tools (files, shell, screenshots, calendar, mail)
       ├─ WASM skills (declared capabilities only)
       └─ MCP servers
  → snapshot store + hash-chained audit log → reply in chat
Mesh: devices pair with ed25519 keys; tasks routed by capability and availability;
relay forwards encrypted envelopes when peers cannot connect directly.
```

Tiers: 0 auto (reads in allowed folders), 1 YES, 2 YES + PIN (messaging people, deleting, installing, sending data out), 3 blocked (formatting disks, registry edits, disabling security tools, reading saved passwords). The tier is computed from the action's capabilities, not from model output.

## Left to the builder

Exact crate layout, the capability schema, PIN storage (OS keychain), snapshot garbage collection, installer packaging and signing, relay protocol details, and the site copy, which must be written fresh.

## Defaults assumed on 2026-10-25 (Kaushik said "proceed" without answering)

1. Audience: everyday users first (light theme default), developers second.
2. Repo stays private until v1, then goes public.
3. Treated as a portfolio project that can become commercial later.
