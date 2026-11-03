# [crypto] Let's Poly1305! 2

> This time `s` is leaked — recover `r` from one tag by solving `c·r ≡ acc (mod 2¹³⁰−5)` and picking the clamp-valid root.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | crypto |
| Difficulty | ★★★☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{letsgooooooooo}` |

## Problem Statement

> you are given half of the Poly1305 key (here: `s`). Related: Let's Poly1305!
>
> `server.py`

## TL;DR

- Poly1305 tag = `(acc_r(m) + s) mod 2¹²⁸`; now `s` is known and `r` secret.
- Send a one-block message `m1`. Then `acc_r(m1) mod 2¹²⁸ = (tag1 − s) mod 2¹²⁸`, and `acc_r(m1) = c₁·r mod p` with `p = 2¹³⁰−5`, `c₁ = int(m1,'little') | 2¹²⁸`.
- The true `acc` is `acc₀ + k·2¹²⁸` for some `k ∈ {0,1,2,3}` (since `acc < p < 4·2¹²⁸`). For each, `r = acc·c₁⁻¹ mod p`; keep the one satisfying Poly1305's clamp (`r == r & CLAMP`, `r < 2¹²⁸`). Forge the TARGET tag with that `r` and `s`.

## Background Knowledge

### Recovering `r` from one block

For a single block, `acc = c₁·r mod p` is linear in `r`, so `r = acc·c₁⁻¹ mod p`. The only ambiguity is the top ~2 bits lost when the server reduces `acc` to 128 bits; enumerating the ≤4 lifts and testing the clamp pattern pins `r` uniquely. (Reusing `(r,s)` for two messages is the underlying flaw.)

## Solution

```python
acc0 = (int(tag1,'little') - int(s,'little')) % 2**128
for k in range(4):
    acc = acc0 + k*2**128
    if acc >= p: break
    r = acc * pow(c1 % p, -1, p) % p
    if r == r & CLAMP and r < 2**128:   # the real clamped r
        forged = (acc_r(r, b"admin=true") + int(s,'little')) % 2**128
```

See [`solve.py`](solve.py). Verified against PyCryptodome locally, then remote.

```bash
$ python3 solve.py 34.170.146.252 21311
Alpaca{letsgooooooooo}
```

## Tools Used

| Tool | Purpose |
|------|---------|
| Python stdlib `socket` | Interact, modular inverse, forge |
| PyCryptodome (venv) | Local correctness check |

## Lessons Learned

- Leaking either half of a one-time Poly1305 key is fatal: with `s` known, one single-block tag yields a linear equation for `r` modulo `2¹³⁰−5`, solvable by modular inverse + clamp test.

## Tags

`crypto` `poly1305` `key-recovery` `modular-inverse` `mac-forgery`
