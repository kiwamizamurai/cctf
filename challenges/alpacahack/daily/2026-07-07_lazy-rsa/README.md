# [crypto] Lazy RSA

> A linear leak `12345·p + 6789·q` plus `n = p·q` gives a quadratic in `p` — factor `n` instantly.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | crypto |
| Difficulty | ★☆☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{sugaku_tan0511}` |

## Problem Statement

> simple RSA challenge
>
> `lazy-rsa.tar.gz`

## TL;DR

- Standard RSA (`e = 65537`) but the output also leaks `hint = 12345·p + 6789·q`.
- With `q = n/p`, substitute: `12345·p² − hint·p + 6789·n = 0`. Solve the quadratic for `p` (integer discriminant is a perfect square), factor `n`, recover `d`, decrypt.

## Background Knowledge

Two independent relations in `p, q` determine them: `n = p·q` and a linear combination `hint = a·p + b·q`. Eliminating `q = n/p` yields `a·p² − hint·p + b·n = 0`, so `p = (hint ± √(hint² − 4ab·n)) / (2a)`. The discriminant is a perfect square, giving exact integer roots.

## Solution

```python
disc = hint*hint - 4*12345*6789*n
s = isqrt(disc)                 # exact
p = (hint + s)//(2*12345)       # (or hint - s) s.t. n % p == 0
q = n//p
d = pow(65537, -1, (p-1)*(q-1))
m = pow(c, d, n)                # Alpaca{sugaku_tan0511}
```

See [`solve.py`](solve.py). Fully offline.

## Tools Used

| Tool | Purpose |
|------|---------|
| Python `math.isqrt`, big ints | Quadratic solve + RSA decrypt |

## Lessons Learned

- Any extra linear equation in `p, q` collapses RSA: combine with `n = p·q` to get a solvable quadratic. Never leak a function of the primes.

## Tags

`crypto` `rsa` `factoring` `quadratic` `prime-leak`
