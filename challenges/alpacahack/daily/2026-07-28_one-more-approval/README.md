# [crypto] One More Approval

> ECDSA signatures are malleable: `(r, s)` and `(r, n − s)` both verify, so a "one-time" signature check that only blacklists the exact bytes is trivially bypassed.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | crypto |
| Difficulty | ★★☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{same_transaction_different_signature}` |

## Problem Statement

> This approval has already been used.
>
> `server.py`

## TL;DR

- The server ECDSA-signs a fixed message (P-256, PyCryptodome `DSS.new(..., "fips-186-3")`), prints the signature, and gives the flag if you submit a *different* signature that still verifies for the same message.
- ECDSA is malleable: if `(r, s)` is valid, so is `(r, n − s)` where `n` is the group order. FIPS 186-3 mode does **not** enforce low-s, so the negated signature verifies.
- DSS encodes the signature as `r || s` (two 32-byte big-endian ints for P-256). Negate `s`, resubmit → different bytes, still valid → flag.

## Background Knowledge

### ECDSA signature malleability

An ECDSA signature is `(r, s)` with `s ≡ k⁻¹(H(m) + r·d) mod n`. Because verification uses `s⁻¹` and the curve is symmetric about the x-axis, `(r, −s mod n)` verifies for the same message and key. Systems that want uniqueness must canonicalize to low-s (`s ≤ n/2`, as Bitcoin does) — FIPS 186-3 does not, so both forms pass here.

The server's only replay defense is `candidate in used`, a blacklist of the *exact* signature bytes. The malleated signature has different bytes, so it isn't in the set.

## Solution

```python
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # P-256 order
r, s = given[:32], int.from_bytes(given[32:], "big")
forged = r + ((N - s) % N).to_bytes(32, "big")
```

Read the printed signature, negate `s`, send `forged.hex()`. See [`solve.py`](solve.py).

```bash
$ python3 solve.py 34.170.146.252 32124
Alpaca{same_transaction_different_signature}
```

Validated locally against `server.py` (PyCryptodome in a venv) before the remote run.

## Tools Used

| Tool | Purpose |
|------|---------|
| Python stdlib `socket` | Read signature, submit forgery (pure integer math) |
| PyCryptodome (venv) | Run `server.py` locally to confirm the malleation verifies |

## Lessons Learned

- Never use raw signature bytes as a uniqueness/nonce key; ECDSA malleability (`s ↔ n − s`, and DER re-encoding) yields a distinct-but-valid signature.
- Enforce low-s canonicalization (or sign a per-use nonce) to make "one approval" actually one.

## Tags

`crypto` `ecdsa` `signature-malleability` `p-256` `replay`
