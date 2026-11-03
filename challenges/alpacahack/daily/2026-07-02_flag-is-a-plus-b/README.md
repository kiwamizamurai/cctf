# [crypto] Flag is A+B

> Given only `A|B` and `A^B`, recover `A+B` with the identity `A+B = (A&B)+(A|B)`.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | crypto |
| Difficulty | ★☆☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{m4thema7ics_i5_fun!!!}` |

## Problem Statement

> You only need to calculate A+B to get the flag! Wait, what were A and B...?
>
> `flag-is-a-plus-b.tar.gz`

## TL;DR

- `FLAG = A + B`, and the output gives `A | B` and `A ^ B`.
- `A + B = (A & B) + (A | B)` and `A & B = (A | B) - (A ^ B)`, so `FLAG = 2*(A|B) - (A^B)`.
- `long_to_bytes(FLAG)` → flag.

## Background Knowledge

### Bitwise identities for addition

For non-negative integers:
- `A + B = (A XOR B) + 2*(A AND B)` (XOR is add-without-carry; AND<<1 is the carries).
- `A OR B = (A XOR B) + (A AND B)` (the set bits split into "exactly one" and "both").

From the second, `A AND B = (A|B) - (A^B)`. Substituting:
`A + B = (A^B) + 2*((A|B) - (A^B)) = 2*(A|B) - (A^B)`.

## Solution

```python
FLAG = 2*A_or_B - A_xor_B
# long_to_bytes -> Alpaca{m4thema7ics_i5_fun!!!}
```

See [`solve.py`](solve.py). Fully offline from `output.txt`.

## Tools Used

| Tool | Purpose |
|------|---------|
| Python (big ints) | Arithmetic recovery |

## Lessons Learned

- `OR` and `XOR` together pin down `AND` (`AND = OR - XOR`), and `AND` + `OR` reconstruct the sum — no search needed.

## Tags

`crypto` `bitwise` `xor` `or` `addition-identity`
