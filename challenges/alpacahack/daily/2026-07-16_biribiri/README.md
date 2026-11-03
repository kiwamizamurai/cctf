# [crypto/misc] biribiri

> bcrypt hashes only the first 72 bytes, so a `SECRET + ticket` signature authenticates only a prefix of the ticket — forge the rest.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | crypto (bcrypt quirk) |
| Difficulty | ★★☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{bcrypt_truncates_passwords_after_72_bytes}` |

## Problem Statement

> I issued a certificate!
>
> `biribiri.tar.gz`

## TL;DR

- `signature = bcrypt.hashpw(SECRET(16) + ticket, salt)`; you get `ticket` and `signature`, then submit a ticket that must both verify against `signature` (as `SECRET + submitted`) and have `"admin": true`.
- **bcrypt only uses the first 72 bytes** of the password. So only `SECRET + ticket[:56]` is actually authenticated. If `submitted[:56] == ticket[:56]`, then `SECRET + submitted` has the same first 72 bytes → `checkpw` passes — no need to know `SECRET`.
- Byte 56 sits inside the memo's `A`s, so `submitted = ticket[:56] + b'","admin":true}'` is valid JSON with admin true and a matching prefix.

## Background Knowledge

### bcrypt's 72-byte limit

bcrypt (Blowfish-based) ignores everything past the first 72 password bytes. Concatenating a secret with attacker-influenced data and signing with bcrypt only binds the first `72 − len(secret)` bytes of that data; the tail is unauthenticated and freely malleable. Here `len(SECRET)=16`, so only `ticket[:56]` is covered.

## Solution

```python
submitted = ticket[:56] + b'","admin":true}'
# first 56 bytes == ticket[:56] → bcrypt(SECRET+submitted) matches signature
# json: {"user":"guest","memo":"AAterminated...","admin":true}
```

See [`solve.py`](solve.py). Verified locally with `bcrypt==4.3.0` (the pinned version silently truncates; newer bcrypt raises on >72 bytes).

```bash
$ python3 solve.py 34.170.146.252 30833
Alpaca{bcrypt_truncates_passwords_after_72_bytes}
```

## Tools Used

| Tool | Purpose |
|------|---------|
| Python stdlib `socket` | Read ticket, submit forged ticket |
| bcrypt 4.3.0 (venv) | Confirm 72-byte truncation locally |

## Lessons Learned

- Never use bcrypt as a MAC over `secret + long_message`: only the first 72 bytes are authenticated, leaving the remainder forgeable. Use HMAC for message authentication.

## Tags

`crypto` `bcrypt` `truncation` `mac-forgery` `72-bytes`
