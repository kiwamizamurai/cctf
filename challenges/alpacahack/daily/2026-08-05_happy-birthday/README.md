# [crypto] Happy Birthday

> A 40-bit truncated hash is small enough that a birthday attack finds a `user=` / `admin=` collision in about a second.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | crypto |
| Difficulty | ★★☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{Happy_Birthday!Happy_BirthDay?Happy_Birthday_parabox:(())}` |

## Problem Statement

> Happy 2nd anniversary, AlpacaHack!
>
> `happy-birthday.tar.gz`

## TL;DR

- The server prints the flag iff you supply `a` and `b` with `a != b`, `a` starts with `user=`, `b` starts with `admin=`, and `H(a) == H(b)` where `H(m) = sha256(m)[:5]`.
- `H` is only **40 bits**. A birthday attack between the `user=…` family and the `admin=…` family finds a collision in ~2²⁰ hashes per side.
- `a = "user=390673"`, `b = "admin=492296"` collide; send both (hex) to get the flag. Fully offline — no server needed to find the pair.

## Background Knowledge

### Birthday attack on a truncated hash

For an n-bit output, a collision between two chosen sets is expected after about 2^(n/2) evaluations per set. Here n = 40, so ~2²⁰ ≈ 1,048,576 per side. Store `H(user=i)` in a dict, then enumerate `H(admin=j)` until one is already present. The differing prefixes guarantee `a != b`.

## Solution

### Step 1: Read `prob.py`

```python
def H(m): return sha256(m).digest()[:5]
ok = a != b and a.startswith(b"user=") and b.startswith(b"admin=") and H(a) == H(b)
```

### Step 2: Birthday collision (offline)

Build `{H(b"user="+i): …}` for ~2²⁰ values of `i`, then scan `b"admin="+j`:

```bash
$ python3 solve.py
a = 757365723d333930363733   # "user=390673"
b = 61646d696e3d343932323936 # "admin=492296"
```

Found in ~1.3 s.

### Step 3: Capture

```bash
$ python3 solve.py 34.170.146.252 38785
...
Alpaca{Happy_Birthday!Happy_BirthDay?Happy_Birthday_parabox:(())}
```

## Tools Used

| Tool | Purpose |
|------|---------|
| Python stdlib `hashlib`, `socket` | Collision search + submit |

## Lessons Learned

- Truncating a secure hash destroys its collision resistance in proportion to the output size; 40 bits collides in seconds.
- A "two prefix" collision is just a meet-in-the-middle birthday search: one family in a table, the other scanned against it.

## Tags

`crypto` `hash` `birthday-attack` `collision` `sha256`
