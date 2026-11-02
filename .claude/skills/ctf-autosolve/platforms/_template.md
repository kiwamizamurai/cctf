# Platform profile: <NAME>

Copy this to `platforms/<name>.md`, fill every section, then point
`Platform profile` in `.claude/CONDITIONS.md` at it. The harness skill reads the
active profile to know *how* to do each step on this platform. Keep it concrete
(exact URLs, selectors, commands) — this is the platform's "driver".

## Basics
- Scoreboard / base URL:
- Challenge URL shape:
- Flag format(s):
- Auth: how the operator signs in (browser session / API token / team cookie).
  **Never enter credentials yourself** — the operator signs in; you reuse it.
- Rendering: server-rendered (fetch HTML) or SPA (read live DOM via the browser)?

## Enumerate challenges → queue
How to list challenges + metadata (category, points, state). CTF-style events
often expose a JSON API (e.g. CTFd `/api/v1/challenges`); classic scoreboards
need DOM scraping. Add each with `ctf_state add <slug> ...`.

## Tell ENDED vs ACTIVE
How to know a challenge/competition window is closed (so publishing is allowed)
vs still running (so it is not). For a single event, the whole CTF is "active"
until its end time — note that time here.

## Fetch distribution files
Exact way to download attachments into the challenge's `dist/` (direct URL,
authed download, `git`, etc.). Prefer `python3 -I -c "urllib...urlretrieve"`.

## Reach the remote target
Static files only, or a live service (`nc host port`, `http://host:port`), or an
on-demand instance you must spawn? Give the exact spawn/connect steps.

## Submit a flag + verify
Exact submit step (web form selector + click, or API POST), and how to read back
accepted / already-solved / wrong.

## Platform rules (READ — they gate what the harness may do)
Does this event allow AI / automation / multiple accounts? When may writeups be
shared? Any out-of-scope hosts, rate limits, or anti-automation measures? If the
rules forbid what the harness does, STOP and tell the operator.
