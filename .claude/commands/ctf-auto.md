---
allowed-tools: Bash, Read, Write, Edit, Grep, Glob, Task, WebFetch, WebSearch
argument-hint: "[on|off|status|<empty = run one iteration>]"
description: Drive the autonomous CTF-solving harness (one iteration, or toggle autopilot)
---

## State

!`python3 -I .claude/skills/ctf-autosolve/scripts/ctf_state.py summary 2>/dev/null || echo '{"note":"queue not initialized"}'`

Next up:
!`python3 -I .claude/skills/ctf-autosolve/scripts/ctf_state.py next 2>/dev/null || echo '{}'`

Autopilot flag present?
!`test -f .claude/state/ctf/AUTOPILOT && cat .claude/state/ctf/AUTOPILOT || echo 'off'`

## Task

Argument: `$ARGUMENTS`

- **`on`** — turn on autopilot: write `.claude/state/ctf/AUTOPILOT` with a JSON
  budget `{"max_iterations": 20, "started": "<now>", "solved_at_start": <n>}`
  (so the Stop hook keeps the loop going until the queue is empty or the budget
  is spent), confirm in one line, then begin the first iteration.
- **`off`** — delete `.claude/state/ctf/AUTOPILOT`, confirm the loop will stop
  after the current turn.
- **`status`** — print the summary + the remaining `todo`/`stuck` list
  (`ctf_state list`) and stop.
- **empty / `run`** — run **one** iteration: invoke the **`ctf-autosolve`** skill
  and follow it to solve exactly one challenge (recon → solve → submit → verify
  → README → record), then report the result and the new summary.

Always read `.claude/CONDITIONS.md` and obey `.claude/rules/ctf-autosolve.md`.
Recommended drivers:
- `/loop /ctf-auto` — run iterations back-to-back, self-paced.
- `/ctf-auto on` then `/goal <the run's goal from CONDITIONS.md>` — autopilot
  with the Stop hook enforcing continuation (release early with `/goal clear`).
