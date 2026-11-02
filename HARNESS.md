# Autonomous CTF-solving harness

A self-driving loop for the AlpacaHack Daily track, built from this workspace's
own solving experience and the stall-audit / externalized-conditions patterns
from the ISUCON 2026 autonomous-agent writeup.

## Components (all created, no approval needed)

| File | Role |
|------|------|
| `.claude/CONDITIONS.md` | Externalized run conditions: target, guardrails, budget, known frictions. Edit this to retarget a run; the loop reads it first. |
| `.claude/rules/ctf-autosolve.md` | Operating rules for autonomous runs (one-at-a-time, local-first, ledger discipline, injection resistance, stall handling, publishing boundary). |
| `.claude/skills/ctf-autosolve/SKILL.md` | The **one-iteration** solver procedure (recon → solve → submit → verify → README → record). |
| `.claude/skills/ctf-autosolve/reference/workflow.md` | Proven Chrome/JS snippets: month enumeration, page reading, server spawn, download, submit, environment tactics. |
| `.claude/skills/ctf-autosolve/scripts/ctf_state.py` | State backbone: `queue.json` (status per challenge) + `ledger.ndjson` (append-only decision log). |
| `.claude/commands/ctf-auto.md` | `/ctf-auto [on\|off\|status\|run]` driver. |
| `.claude/agents/ctf-auditor.md` | Checklist-based stall-audit subagent for `stuck` challenges. |
| `.claude/state/ctf/` | Runtime state (git-ignored). Seeded with this session's 19 solves + the September queue. |

## How to run

- **Self-paced loop (recommended):** `/loop /ctf-auto` — runs iterations
  back-to-back; each solves one challenge and updates the queue. Stop with the
  loop's own control.
- **Single step:** `/ctf-auto` — solve exactly one challenge (the next `todo`).
- **Goal-driven autopilot:** `/ctf-auto on` then
  `/goal solve every ended AlpacaHack Daily challenge`. The `/goal` Stop hook
  keeps the turn going until the queue is empty (see optional Stop hook below
  for a budget-bounded variant).
- **Check progress:** `/ctf-auto status` or
  `python3 -I .claude/skills/ctf-autosolve/scripts/ctf_state.py summary`.

## State tool quick reference

```bash
S=.claude/skills/ctf-autosolve/scripts/ctf_state.py
python3 -I $S summary                      # counts + remaining
python3 -I $S next                         # next todo (oldest-first), JSON
python3 -I $S status <slug> solving        # mark in-progress
python3 -I $S flag <slug> 'Alpaca{...}'    # record flag + mark solved + ledger
python3 -I $S note <slug> "tried X, ruled out Y"
python3 -I $S status <slug> stuck
python3 -I $S list --status todo
```

---

## Optional hook changes (need operator approval)

Editing hook scripts and `settings.json` is gated by Claude Code's
self-modification guard, so these are **not applied automatically**. They make
the harness smoother but are not required — the loop works without them. Apply
by pasting these contents (or tell Claude "apply the HARNESS.md hook changes"
and approve the writes).

### 1. Fix `.claude/hooks/pre-bash.sh` (false-positive block)

The current hook uses bash `=~` with patterns like `rm -rf /*` and
`curl .* | bash`, which are read as regexes: `/*` blocks `rm -rf work`, and the
`|` makes any command containing ` bash` get blocked (this is why `curl`
downloads were refused mid-session). Replace its body with precise `grep -E`
checks:

```bash
#!/bin/bash
# Pre-bash hook: block genuinely destructive commands; allow CTF tooling.
INPUT=$(cat); COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
block(){ printf '{"decision":"block","reason":"%s"}\n' "$1"; exit 2; }
grep -Eq 'rm[[:space:]]+-[a-zA-Z]*r[a-zA-Z]*f?[a-zA-Z]*[[:space:]]+(-[a-zA-Z]+[[:space:]]+)*(/|/\*|~|\$HOME|\$\{HOME\})([[:space:]]|$|/\*)' <<<"$COMMAND" && block "refusing recursive delete of / ~ \$HOME"
grep -Eq 'mkfs(\.[a-z0-9]+)?[[:space:]]' <<<"$COMMAND" && block "mkfs"
grep -Eq 'dd[[:space:]].*of=/dev/(sd|nvme|disk|hd|rdisk)' <<<"$COMMAND" && block "dd to raw device"
grep -Eq '>[[:space:]]*/dev/(sd|nvme|disk|hd)' <<<"$COMMAND" && block "redirect to raw device"
grep -Eq 'chmod[[:space:]]+-[a-zA-Z]*R[a-zA-Z]*[[:space:]]+[0-7]{3,4}[[:space:]]+/([[:space:]]|$)' <<<"$COMMAND" && block "recursive chmod on /"
grep -Eq '(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(bash|sh|zsh|dash|python[0-9.]*|perl|ruby)\b' <<<"$COMMAND" && block "piping a download into an interpreter; download, inspect, then run"
grep -Eq ':\(\)[[:space:]]*\{[[:space:]]*:\|:' <<<"$COMMAND" && block "fork bomb"
exit 0
```

### 2. Enhance `.claude/hooks/post-bash.sh` (auto-log captured flags)

Append, after the existing flag-sound logic, a call that records any flag seen
in Bash stdout to the harness ledger (best-effort, never fails the tool):

```bash
# --- auto-log captured flags to the harness ledger ---
FLAG=$(printf '%s' "$STDOUT" | grep -oE '(Alpaca|TSGLIVE|flag|FLAG|picoCTF|HTB|THM)\{[^}]*\}' | head -1)
if [ -n "$FLAG" ] && [ -f "$CLAUDE_PROJECT_DIR/.claude/skills/ctf-autosolve/scripts/ctf_state.py" ]; then
  python3 -I "$CLAUDE_PROJECT_DIR/.claude/skills/ctf-autosolve/scripts/ctf_state.py" \
    log flag-seen --data "{\"flag\":\"$FLAG\"}" >/dev/null 2>&1 || true
fi
```

### 3. Add `.claude/hooks/ctf-stop.sh` (budget-bounded autopilot + stall audit)

Only engages when `.claude/state/ctf/AUTOPILOT` exists (so it is opt-in via
`/ctf-auto on`). It keeps the loop going until the queue is empty or the budget
is spent, and nudges a stall audit when progress stops.

```bash
#!/bin/bash
# Stop hook: continue the autopilot loop until the queue is empty / budget spent.
DIR="$CLAUDE_PROJECT_DIR/.claude/state/ctf"; AP="$DIR/AUTOPILOT"
[ -f "$AP" ] || exit 0                      # autopilot off -> allow stop
S="$CLAUDE_PROJECT_DIR/.claude/skills/ctf-autosolve/scripts/ctf_state.py"
REMAIN=$(python3 -I "$S" summary 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("remaining",0))' 2>/dev/null || echo 0)
MAXIT=$(python3 -c 'import json;print(json.load(open("'"$AP"'")).get("max_iterations",20))' 2>/dev/null || echo 20)
N=$(cat "$DIR/iter" 2>/dev/null || echo 0); N=$((N+1)); echo "$N" > "$DIR/iter"
if [ "$REMAIN" -le 0 ] || [ "$N" -gt "$MAXIT" ]; then
  rm -f "$AP" "$DIR/iter"
  exit 0                                     # done or out of budget -> allow stop
fi
printf '{"decision":"block","reason":"Autopilot: %s challenge(s) remain (iter %s/%s). Run the next /ctf-auto iteration via the ctf-autosolve skill. If the last one is stuck, invoke the ctf-auditor agent first."}\n' "$REMAIN" "$N" "$MAXIT"
exit 0
```

### 4. Wire the Stop hook in `.claude/settings.json`

Add to the `hooks` object:

```json
"Stop": [
  { "hooks": [ { "type": "command",
      "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/ctf-stop.sh", "timeout": 10 } ] }
]
```

`chmod +x` the two new/edited scripts after creating them.
