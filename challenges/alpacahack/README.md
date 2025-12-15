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

| Event | Solved | Total |
|-------|--------|-------|
| Daily | 0 | - |
| Contests | 0 | - |

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
