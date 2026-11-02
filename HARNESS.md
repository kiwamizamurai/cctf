# Autonomous CTF-solving harness

A self-driving loop that solves CTF challenges end-to-end — recon → solve →
submit → verify → writeup → record — one at a time, on **any CTF/platform**.
Built from this workspace's solving experience and the stall-audit /
externalized-conditions patterns from the ISUCON 2026 autonomous-agent writeup.

Per competition you edit **one file** (`.claude/CONDITIONS.md`) and point it at a
**platform profile** (`.claude/skills/ctf-autosolve/platforms/<name>.md`).
AlpacaHack ships as the first profile.

## Usage — how to run it

The core is the **`ctf-autosolve` skill** (one challenge per invocation) plus the
**`ctf_state.py`** state tool. Two built-in drivers re-invoke the skill — there is
no extra command to learn:

| You want | How |
|----------|-----|
| **Keep solving until done** (self-paced loop) | `/loop use the ctf-autosolve skill to solve the next challenge` |
| **Keep going until a goal is met** | `/goal <your goal>` — the Stop hook nudges until it reads as met; release early with `/goal clear` |
| **Solve one challenge** (single step) | invoke the `ctf-autosolve` skill directly |
| **Check progress** | `python3 -I .claude/skills/ctf-autosolve/scripts/ctf_state.py summary` |

- **`/loop …`** runs iterations back-to-back; each solves one challenge and
  updates the queue. It stops when the queue is empty (`remaining == 0`) or you
  stop the loop.
- **`/goal …`** persists across turns via the Stop hook; the model keeps invoking
  the skill until the goal reads as met. `/goal clear` releases it.

### Onboard a new CTF (do this once per event)

1. Copy `platforms/_template.md` → `platforms/<name>.md` and fill it (how to
   enumerate, fetch, reach the remote, submit, and the event's rules).
2. Edit `.claude/CONDITIONS.md`: set the event, flag format, auth, goal, scope,
   and point `Platform profile` at your new file.
3. Enumerate the challenges into the queue (profile → "Enumerate"), then drive
   with `/loop …` (or `/goal …`).

> **Rules first.** Every event differs — some forbid AI/automation, all forbid
> sharing solutions while a challenge is still running. The harness reads the
> competition's rules from the profile/CONDITIONS and stops if they forbid what
> it does. It only touches authorized, in-scope targets.

## Components (all created, no approval needed)

| File | Role |
|------|------|
| `.claude/CONDITIONS.md` | The **active run**: event, flag format, auth, scope, budget, and which platform profile to use. Edit this per competition; the loop reads it first. |
| `.claude/skills/ctf-autosolve/platforms/<name>.md` | **Platform profile** — the concrete *how* for one platform (enumerate, fetch, reach-remote, submit, rules). `alpacahack.md` ships; `_template.md` onboards a new one. |
| `.claude/rules/ctf-autosolve.md` | Operating rules for autonomous runs (one-at-a-time, local-first, ledger discipline, injection resistance, stall handling, publishing boundary). |
| `.claude/skills/ctf-autosolve/SKILL.md` | The platform-agnostic **one-iteration** solver procedure (recon → solve → submit → verify → README → record). |
| `.claude/skills/ctf-autosolve/reference/workflow.md` | Generic techniques & environment frictions (platform-specifics live in the profile). |
| `.claude/skills/ctf-autosolve/scripts/ctf_state.py` | State backbone: `queue.json` (status per challenge) + `ledger.ndjson` (append-only decision log). |
| `.claude/agents/ctf-auditor.md` | Checklist-based stall-audit subagent for `stuck` challenges. |
| `.claude/state/ctf/` | Runtime state (git-ignored): the queue + decision ledger. |

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

`chmod +x .claude/hooks/pre-bash.sh` after editing it. Both hooks are optional
conveniences; the loop (`/loop …`) and `/goal` work without them. (Driving the
loop uses the built-in `/loop` and `/goal` — there is no custom Stop hook.)
