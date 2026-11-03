# [misc] Password, Please

> An unquoted right-hand side in bash `[[ $x == $y ]]` is a glob pattern, so `*` matches any password.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | misc |
| Difficulty | ★☆☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{welcome_to_the_terminal}` |

## Problem Statement

> I wrote my first password checker in Bash. Please log in.
>
> `password-please.tar.gz`

## TL;DR

- `chal.sh` sets `secret="${RANDOM}${RANDOM}${RANDOM}${RANDOM}"` and checks `[[ $secret == $password ]]`.
- In `[[ ... ]]`, the right operand of `==` is a **glob pattern** when unquoted. Entering `*` matches any `secret`, so the comparison always succeeds and `/flag.txt` is printed.

## Background Knowledge

### Bash `[[ == ]]` pattern matching

Inside `[[ ... ]]`, `==` (and `!=`) does pattern matching, not string equality, unless the right side is quoted:

```bash
[[ $secret == $password ]]   # $password is an unquoted glob pattern
[[ $secret == "$password" ]] # quoted → literal string comparison (the fix)
```

So `password=*` is the pattern `*`, which matches everything. The random secret is irrelevant.

## Solution

Send `*` as the password:

```bash
$ python3 solve.py 34.170.146.252 45808
Alpaca{welcome_to_the_terminal}
```

Confirmed locally with a one-line bash reproduction before the remote run. See [`solve.py`](solve.py).

## Tools Used

| Tool | Purpose |
|------|---------|
| bash | Reproduce the glob-match bug locally |
| Python stdlib `socket` | Send `*` to the service |

## Lessons Learned

- Always quote variables in `[[ $a == "$b" ]]`; an unquoted RHS turns a comparison into glob matching — a classic auth bypass.

## Tags

`misc` `bash` `glob` `pattern-matching` `auth-bypass`
