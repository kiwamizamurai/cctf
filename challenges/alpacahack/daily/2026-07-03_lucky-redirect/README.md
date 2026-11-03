# [web] Lucky Redirect

> A per-prefix route whose "lucky" redirect targets `url_for(next-char route)` leaks the flag one character at a time via the `Location` header.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | web |
| Difficulty | ★★☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{Ill_never_gamble_again_I_bet_on_it}` |

## Problem Statement

> I've never used the "Search" button on Google Search; the "I'm Feeling Lucky" button is enough for me.
>
> `lucky-redirect.tar.gz`

## TL;DR

- The app registers a route for **every prefix** of the flag: `/A`, `/A/l`, `/A/l/p`, … (chars joined by `/`).
- Each route, with probability 1/5, `redirect(url_for("flag_{i+1}"))` — i.e. to the *next* prefix's route — otherwise to `/nope`. The final route returns the flag.
- `url_for` builds that next path, so the lucky redirect's `Location` header contains the prefix **plus one more character** — leaking the next flag char. Walk the chain (retry ~5× per step) to recover the whole flag; no guessing.

## Background Knowledge

### `url_for` leaks the route's path

The endpoints are named `flag_0..flag_{n}`, each bound to the static path `/`+`/`.join(FLAG[:i+1]). When route `i` is "lucky" it redirects to `url_for("flag_{i+1}")`, whose URL is the path for `FLAG[:i+2]`. Reading `Location` reveals `FLAG[i+1]` directly — the randomness only gates *whether* you advance, never *what* the next char is.

## Solution

Start from the known prefix `Alpaca{`, GET that prefix path with redirects disabled, and:
- `Location` → `/nope`: unlucky, retry.
- `Location` one segment longer: append the new last segment (the next char).
- Final route returns `Well done! The flag is: …`.

```bash
$ python3 solve.py 34.170.146.252 43962
Alpaca{Ill_never_gamble_again_I_bet_on_it}
```

See [`solve.py`](solve.py). Validated locally against `app.py` (dummy flag) first.

## Tools Used

| Tool | Purpose |
|------|---------|
| Python stdlib `http.client` | Follow redirects manually, read `Location` |
| Flask (venv) | Local reproduction |

## Lessons Learned

- Redirecting to `url_for(secret-dependent-endpoint)` echoes the secret into the `Location` header; probabilistic gating doesn't hide it — just retry.
- Prefix-per-route designs leak structure; never encode a secret into routable paths.

## Tags

`web` `flask` `url_for` `open-redirect` `info-leak` `location-header`
