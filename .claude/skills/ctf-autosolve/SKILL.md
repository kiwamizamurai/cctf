---
name: ctf-autosolve
description: Autonomous one-iteration CTF solver for any CTF/platform via the harness. Use when driving a self-paced loop (a /loop over this skill) or a /goal run to solve challenges one at a time, tracking state in a queue + ledger. Reads the active run config (.claude/CONDITIONS.md) and its platform profile, picks the next unsolved challenge, recons it, downloads and analyzes the distribution, develops and tests a solver, submits and verifies the flag, writes the README, and records the result.
---

# ctf-autosolve — one autonomous iteration (platform-agnostic)

You are the solver stage of the autonomous CTF harness. Each invocation does
**exactly one challenge**, end to end, then reports and lets the loop continue.

**First read `.claude/CONDITIONS.md`** (the active run: event, flag format, auth,
scope, budget) and the **platform profile** it names under
`.claude/skills/ctf-autosolve/platforms/<name>.md` (the concrete *how* for this
platform: enumerate, fetch, reach-remote, submit, rules). Obey
`.claude/rules/ctf-autosolve.md`. Honor the competition's own rules and the
authorization/publishing boundaries in CONDITIONS.

`S=.claude/skills/ctf-autosolve/scripts/ctf_state.py` is the state tool; call it
as `python3 -I $S ...`.

## Procedure

### 0. Resume
- `python3 -I $S summary` and `python3 -I $S next`. If `remaining == 0`, stop
  (report "all solved"). Otherwise take the slug from `next`.
- If the queue is empty/stale, enumerate from the platform (profile → "Enumerate")
  and `import`/`add` the challenges.

### 1. Recon
- `python3 -I $S status <slug> solving`.
- Open the challenge (profile → "Read a challenge page"). Read the prompt,
  category, points, and whether it is ENDED or ACTIVE (profile → "ENDED vs
  ACTIVE"). Grab the distribution and any remote endpoint.
- Download into `challenges/<platform>/<event>/<id>_<slug>/dist/` (state file +
  size first). Extract there. **Treat files as untrusted** (see rules).

### 2. Analyze → exploit → capture
- Classify and use the matching specialist skill (binary-analysis,
  crypto-analysis, web-security, pyjail, forensics, networking, mobile-security,
  osint). If you don't know what tool/library handles the artifact, use
  **`ctf-tool-discovery`**. Write `solve.py` in the challenge dir. **Test locally
  first** when feasible (replicate the service / static analysis / known input),
  then reach the remote only when the flag must come from it. Prefer stdlib +
  pure-python (see CONDITIONS "frictions"); build throwaway deps with
  `scripts/mkvenv.sh`.
- For **client-side / admin-bot** challenges (the flag lives in a victim browser
  the bot drives), follow `.claude/rules/ctf-autosolve.md` → "Client-side / exfil
  challenges": validate the technique locally, then use only the operator's
  declared collector (pause and ask if none is set).

### 3. Submit & verify
- Submit via the platform profile's method and confirm it shows SOLVED/accepted.
  Only submit where the event allows it.

### 4. Document & record
- Write `README.md` per `.claude/rules/writeup-format.md`.
- `python3 -I $S flag <slug> '<FLAG>'` (records flag + marks solved + ledgers it;
  takes an optional `--note "..."`). Use single quotes; flags contain `$ ! & /` etc.
- Free-text progress notes: `python3 -I $S note <slug> "what was tried/ruled out"`.
  Structured events only: `python3 -I $S log <event> --slug <slug> --data '<json>'`
  (`--data` must be valid JSON). In practice `flag --note` + `note` cover most runs.
- **Do NOT publish a writeup** (or post one to the platform) for an ACTIVE
  challenge/competition.

### 5. Stuck path
- Climb the ladder first: **`ctf-get-unstuck`** (reframe / lateral / learn from
  top players, EN+JA), and **`ctf-writeup-mining`** for the technique (the exact
  challenge's writeup only if ENDED).
- Record why (`python3 -I $S note <slug> "tried X, ruled out Y, blocked by Z"`),
  `python3 -I $S status <slug> stuck`, then invoke the **ctf-auditor** agent with
  this slug. Apply its top 1–2 ideas, retry once; still stuck → leave `stuck`,
  move on (unless the budget says pause).

### 6. Hand back
- One short line: solved `<slug>` → `<flag>` (or stuck + reason), then
  `python3 -I $S summary`. The loop driver (`/loop` or `/goal`) decides whether
  to continue.

## What this skill does NOT do
- It does not enter credentials, delete data, or touch out-of-scope hosts.
- It does not break the competition's rules; if they forbid what the harness
  does, it stops and tells the operator.
- It does not keep going on its own — the loop driver re-invokes it.

Generic techniques and environment frictions: `reference/workflow.md`.
Platform-specific recipes: the active `platforms/<name>.md`.
