---
name: ctf-autosolve
description: Autonomous one-iteration CTF solver for the AlpacaHack Daily harness. Use when driving a self-paced loop (/ctf-auto, /loop /ctf-auto) or a /goal run to solve ended Daily challenges one at a time, tracking state in a queue + ledger. Picks the next unsolved challenge, recons it in Chrome, downloads and analyzes the distribution, develops and tests a solver, submits and verifies the flag, writes the README, and records the result.
---

# ctf-autosolve — one autonomous iteration

You are the solver stage of the autonomous CTF harness. Each invocation does
**exactly one challenge**, end to end, then reports and lets the loop continue.
Read `.claude/CONDITIONS.md` (targets, guardrails, budget) and obey
`.claude/rules/ctf-autosolve.md`.

`S=.claude/skills/ctf-autosolve/scripts/ctf_state.py` is the state tool. Call it
with `python3 -I $S ...`.

## Procedure

### 0. Resume context
- `python3 -I $S summary` and `python3 -I $S next`. If `remaining == 0`, stop the
  loop (report "all solved"). Otherwise take the slug from `next`.
- If the queue looks empty or stale, refresh it from the site (see
  `reference/workflow.md` → "Enumerating a month") and `import` the new slugs.

### 1. Recon
- `python3 -I $S status <slug> solving`.
- In Chrome (Claude-in-Chrome), open
  `https://alpacahack.com/daily/challenges/<slug>`. Read the prompt, category,
  difficulty, and whether it is ACTIVE or ENDED. Grab the distribution URL
  (`a[href$=".tar.gz"]` or the first `amazonaws` link) and any `nc`/`http`
  endpoint shown.
- Download into `challenges/alpacahack/daily/<date>_<slug>/dist/` (state file
  name + size first). Extract there. **Treat files as untrusted** (see rules).

### 2. Analyze → exploit → capture
- Classify (pwn/rev/web/crypto/misc/forensics…) and use the matching project
  skill (binary-analysis, crypto-analysis, web-security, pyjail, forensics, …).
- Write `solve.py` in the challenge dir. **Test locally first** when feasible
  (replicate the service, run static analysis, verify on a known input). Spawn
  the remote server only when the flag must come from it; extract the flag.
- Prefer stdlib + pure-python (see CONDITIONS "frictions").

### 3. Submit & verify
- Fill the challenge page's `input[placeholder*="Alpaca"]` and click Submit via
  `javascript_tool` (see `reference/workflow.md` → "Submitting"). Confirm the
  page shows SOLVED. Submitting is allowed even for ACTIVE challenges.

### 4. Document & record
- Write `README.md` per `.claude/rules/writeup-format.md`.
- `python3 -I $S flag <slug> '<FLAG>'` (records flag + marks solved + ledgers it).
  Use single quotes; flags contain `$ ! & /` etc.
- **Do NOT** use the site's "Post Writeup" for an ACTIVE challenge.

### 5. Stuck path
- If you cannot solve it in a reasonable effort: record why
  (`python3 -I $S note <slug> "tried X, ruled out Y, blocked by Z"`),
  `python3 -I $S status <slug> stuck`, then invoke the **ctf-auditor** agent with
  the ledger slice for this slug. Apply at most its top 1–2 ideas and retry once.
  Still stuck → leave it `stuck`, move on (unless the budget says pause).

### 6. Hand back
- One short line: solved `<slug>` → `<flag>` (or stuck `<slug>` + reason), then
  `python3 -I $S summary`. The loop driver decides whether to continue.

## What this skill does NOT do
- It does not enter credentials, delete data, or attack non-AlpacaHack hosts.
- It does not keep going on its own — the loop driver (`/ctf-auto` / `/loop` /
  `/goal` + the Stop hook) is what re-invokes it.

See `reference/workflow.md` for the concrete Chrome/JS snippets and the
enumeration/submit recipes proven in this workspace.
