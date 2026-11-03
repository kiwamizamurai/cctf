# [crypto] Let's Poly1305!

> With the Poly1305 `r` key known, one (message, tag) pair reveals the secret `s`, forging any message's tag.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | crypto |
| Difficulty | ★★☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{lets-po-po-po-poly-poly-poly}` |

## Problem Statement

> you are given half of the Poly1305 key
>
> `server.py`

## TL;DR

- The server prints `r`, tags one chosen message, and gives the flag if you provide the tag of `TARGET=b"admin=true"` (which you can't send as the message).
- Poly1305 tag = `(acc_r(m) + s) mod 2^128` with `s` secret. Because `r` is known, the tag of any chosen `m` gives `s = (tag − acc_r(m)) mod 2^128`.
- With `s`, forge `TARGET`'s tag = `(acc_r(TARGET) + s) mod 2^128`.

## Background Knowledge

### Poly1305 structure

Poly1305 is a one-time MAC: `tag = (poly_r(m) + s) mod 2^128`, where `poly_r` evaluates the padded message blocks as a polynomial in the clamped `r` modulo `p = 2^130 − 5`. Security relies on **both** `r` and `s` being secret and one-time. Leaking `r` makes `poly_r(m)` computable, so a single valid tag leaks `s` additively — then every message is forgeable. (Reusing the key, as here across two messages, is itself fatal.)

```
acc_r(m): a = 0; for each 16-byte block b: a = (a + (int(b,'little') | 2^(8*len(b)))) * (r & CLAMP) % p
tag = (acc_r(m) + s) mod 2^128
```

## Solution

```python
# r from the banner; send any message m, read its tag
s = (int(tag, 'little') - acc_r(m)) % 2**128
forged = (acc_r(b"admin=true") + s) % 2**128   # little-endian hex
```

See [`solve.py`](solve.py). Logic verified locally against PyCryptodome's `Poly1305_MAC` before the remote run.

```bash
$ python3 solve.py 34.170.146.252 54320
Alpaca{lets-po-po-po-poly-poly-poly}
```

## Tools Used

| Tool | Purpose |
|------|---------|
| Python stdlib `socket` | Interact, recover `s`, forge tag |
| PyCryptodome (venv) | Local correctness check of the Poly1305 math |

## Lessons Learned

- Poly1305 is a **one-time** MAC; revealing `r` (or reusing the (r,s) key) lets `s` be solved from one tag, breaking all authenticity.

## Tags

`crypto` `poly1305` `mac-forgery` `one-time-mac` `key-recovery`
