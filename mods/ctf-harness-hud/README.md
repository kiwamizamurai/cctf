# ctf-harness-hud

A live **HUD pane** for the autonomous CTF harness. It reads the harness state
the solver writes via `ctf_state.py` and draws a dashboard beside the chat:

- **Progress**: solved / total with a bar and %, plus remaining / stuck / solving / todo.
- **By category**: solved/total per category (pwn, crypto, web, …).
- **In progress**: the challenge currently being solved.
- **Recent flags**: the last captured flags.
- **Stuck**: stuck challenges with their latest ledger note.
- **Activity**: the tail of the decision ledger.

It also shows a compact `⚑ CTF <solved>/<total>` status-line entry and a toast
when a new flag is captured. It is **read-only** — it never writes harness state.

## Data it reads
- `.claude/state/ctf/queue.json` — `{ challenges: { slug: {status, flag, category, …} } }`
- `.claude/state/ctf/ledger.ndjson` — one JSON decision record per line

Both are produced by `.claude/skills/ctf-autosolve/scripts/ctf_state.py` (see the
repo's `HARNESS.md`). The pane refreshes every ~2s.

## Use
- `/ctf-hud` opens (or re-opens) the pane. It also opens automatically when a
  session starts if the mod is enabled.

## Install (from this repo)
Load it as a plugin directory while developing:

```
claude --plugin-dir mods/ctf-harness-hud
```

Or, when writing mods in a session, drop it under the session's dev-mods folder
and accept the "turn on the mods" prompt.
