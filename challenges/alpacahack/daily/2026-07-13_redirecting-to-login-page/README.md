# [web] Redirecting to Login Page

> PHP `header("Location: ...")` without `exit` still sends the body — the redirect response leaks the flag.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | web |
| Difficulty | ★☆☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{redir3ct_to_y0ur_he4r7}` |

## Problem Statement

> The user ID is alpaca and the password is pacapaca.
>
> `redirecting-to-login-page.tar.gz`

## TL;DR

- `index.php` is `header("Location: login.php"); echo "Flag: " . getenv('FLAG');` — **no `exit()`** after the redirect header.
- PHP keeps executing and sends the flag in the 302 response body. Browsers follow the redirect and discard it, but fetching `index.php` without following the redirect reveals the flag. (The login form / content.php are red herrings — content.php holds nothing.)

## Background Knowledge

### `header("Location:")` is not a stop

`header()` only queues a response header; script execution continues. Without `exit;`/`die;`, everything echoed afterwards is still written to the response body. A client that doesn't auto-follow the 302 sees it.

## Solution

```bash
$ python3 solve.py 34.170.146.252 21928   # GET /index.php, don't follow 302
Alpaca{redir3ct_to_y0ur_he4r7}
```

(Equivalent: `curl -s http://host:port/index.php`.) See [`solve.py`](solve.py).

## Tools Used

| Tool | Purpose |
|------|---------|
| Python stdlib `http.client` | GET without following the redirect |

## Lessons Learned

- Always `exit` after an authorization redirect; otherwise protected output is still emitted in the redirect's body.

## Tags

`web` `php` `header-redirect` `missing-exit` `info-leak`
