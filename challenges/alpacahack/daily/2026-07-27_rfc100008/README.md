# [web] RFC100008

> A route bound to a secret HTTP method leaks that method in the `Allow` header of an OPTIONS / 405 response.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | web |
| Difficulty | ★☆☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{how_do_you_like_my_new_method}` |

## Problem Statement

> To celebrate the brand new HTTP method, we have a new challenge for you! Can you guess the method I made?
>
> `rfc100008.tar.gz`

## TL;DR

- `/rfc100008` is registered for one secret method `METHOD = secrets.token_hex(8).upper()` (16 hex chars, 2⁶⁴ — unguessable).
- Flask/Werkzeug answers `OPTIONS` (and any disallowed method → 405) with an `Allow` header enumerating the route's methods — which includes the secret `METHOD`.
- Send `OPTIONS /rfc100008`, read `Allow: <METHOD>, OPTIONS`, then send a request with `<METHOD>` to get the flag.

## Background Knowledge

### Werkzeug auto-OPTIONS and the `Allow` header

Flask/Werkzeug automatically handles `OPTIONS` for every route and returns an `Allow` header listing the methods the route accepts. The same header appears on a `405 Method Not Allowed`. Registering a route for an obscure/secret method does not hide it — it's advertised in `Allow`.

## Solution

```
OPTIONS /rfc100008  →  Allow: 93107EBBD24B6F52, OPTIONS
93107EBBD24B6F52 /rfc100008  →  Hello from ... Here is your flag: Alpaca{...}
```

Done with a raw socket (arbitrary method token). See [`solve.py`](solve.py).

```bash
$ python3 solve.py 34.170.146.252 27354
method=93107EBBD24B6F52
Alpaca{how_do_you_like_my_new_method}
```

Validated locally against `app.py` (Flask in a venv) first.

## Tools Used

| Tool | Purpose |
|------|---------|
| Python stdlib `socket` | Send OPTIONS + custom-method requests |
| Flask (venv) | Local reproduction of the `Allow`-header leak |

## Lessons Learned

- "Secret" HTTP methods aren't secret: the framework advertises allowed methods via `Allow` on OPTIONS/405. Don't treat a method name as an access-control secret.

## Tags

`web` `http` `options` `allow-header` `flask` `werkzeug`
