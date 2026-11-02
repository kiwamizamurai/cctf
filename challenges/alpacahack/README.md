# AlpacaHack

[AlpacaHack](https://alpacahack.com/) - A CTF platform from Japan

## Flag Format

```
Alpaca{...}
TSGLIVE{...}  # TSGLIVE (mirrored on AlpacaHack)
```

## Event Types

### Daily Challenges

New challenges released daily. Stored in `daily/YYYY-MM-DD_challenge-name/`.

### Contests

Regularly scheduled competitions. Stored in `contests/YYYY-MM_contest-name/challenge-name/`.

## Progress

Live progress is tracked by the autonomous harness, not a static table here:

```bash
python3 -I .claude/skills/ctf-autosolve/scripts/ctf_state.py summary
python3 -I .claude/skills/ctf-autosolve/scripts/ctf_state.py list --status solved
```

Each solved challenge keeps its own `README.md` + `solve.py` in its directory.

## Directory Structure

```
alpacahack/
├── daily/
│   └── YYYY-MM-DD_challenge-name/
│       ├── README.md    # Writeup (tracked)
│       ├── solve.py     # Solution (tracked)
│       ├── dist/        # Challenge files (ignored)
│       └── work/        # Working files (ignored)
└── contests/
    └── YYYY-MM_contest-name/
        └── challenge-name/
```
