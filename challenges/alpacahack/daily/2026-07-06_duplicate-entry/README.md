# [forensics] duplicate entry

> A ZIP with 100 entries all named `flag.txt` — extraction keeps the wrong one, but the real flag entry is still in the archive.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | forensics |
| Difficulty | ★☆☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{never_never_never_kyukei}` |

## Problem Statement

> You won't get the real flag.txt even after extraction! Probably.
>
> `duplicate-entry.tar.gz`

## TL;DR

- `make_zip.py` writes 100 entries, all named `flag.txt`; only the 51st (`i == 50`) contains the real FLAG, the other 99 say "No flag here. Try harder."
- Unzipping keeps only one `flag.txt` (the overwriting one), so the extracted file is a decoy. But every entry persists in the archive — the real one is the single entry whose `file_size`/`CRC` differ from the 99 identical decoys. Read it directly from the central directory.

## Background Knowledge

### Duplicate filenames in ZIP

A ZIP's central directory can list many entries with the same name. Extractors write them in order, so the last wins; standard tools surface only that one. `zipfile.infolist()` exposes **all** entries (each with its own `header_offset`, size, CRC), so you can open any specific one with `z.open(info)`.

## Solution

The decoys are 25 bytes each ("No flag here. Try harder."); the real entry is 32 bytes with a distinct CRC. Iterate `infolist()` and read the odd one out:

```python
for info in z.infolist():
    if info.filename == "flag.txt" and info.file_size != 25:
        print(z.open(info).read())   # Alpaca{never_never_never_kyukei}
```

See [`solve.py`](solve.py). Fully offline.

## Tools Used

| Tool | Purpose |
|------|---------|
| Python `zipfile` | Enumerate all duplicate entries, read the distinct one |

## Lessons Learned

- "After extraction" ≠ "in the archive": duplicate-named entries all live in the central directory; enumerate `infolist()` and pick by offset/size/CRC rather than trusting the extracted file.

## Tags

`forensics` `zip` `duplicate-entries` `central-directory`
