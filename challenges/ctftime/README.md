# CTFtime Competitions

Scaffolds for upcoming CTFtime events we plan to play, highest CTFtime **rating
weight** first. Each competition gets its own `YYYY-MM_<slug>/` directory (by
event **start** month, UTC); per-challenge work lives in subdirectories created
during the event.

## Planned events (as of 2026-11-03)

| Weight | Event | Start (UTC) | Dir |
|-------:|-------|-------------|-----|
| 99.38 | ASIS CTF Finals 2026 | 2026-12-27 | [`2026-12_asis-finals/`](2026-12_asis-finals/) |
| 79.51 | bi0sCTF 2026 | 2026-12-05 | [`2026-12_bi0sctf/`](2026-12_bi0sctf/) |
| 77.38 | BackdoorCTF 2026 | 2026-12-19 | [`2026-12_backdoorctf/`](2026-12_backdoorctf/) |
| 73.17 | GlacierCTF 2026 | 2026-11-20 | [`2026-11_glacierctf/`](2026-11_glacierctf/) |
| 59.00 | niteCTF 2026 | 2026-12-11 | [`2026-12_nitectf/`](2026-12_nitectf/) |

All are online Jeopardy. Registration opens on each event's own site near its
date — **register yourself** (accounts/personal data are not entered by the
assistant).

## Per-challenge layout (created during the event)

```
YYYY-MM_<slug>/
├── README.md                 # event info (this scaffold)
└── <category>_<challenge>/   # one dir per challenge
    ├── README.md             # writeup
    ├── solve.py              # solver
    ├── dist/                 # distributed files (gitignored)
    └── work/                 # scratch (gitignored)
```
