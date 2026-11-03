# [misc] Not so Pyf**k

> `eval` limited to ASCII and at most 3 distinct letters — build any string with `'%c'%N` (letter `c` only) and run it with `exec` (letters e, x, c).

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | misc (pyjail) |
| Difficulty | ★★★☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{now_can_you_golf_this_challenge?my_best_is_36_characters}` |

## Problem Statement

> Only 3 kinds of alphabets, but there's no limit on other characters.
>
> `not-so-pyfk.tar.gz`

## TL;DR

- `jail.py` runs `eval(code)` with two filters: `code` must be ASCII, and the number of **distinct alphabetic characters** must be ≤ 3 (non-letters are unlimited).
- `'%c' % N` produces any character using only the letter `c`, so `('%c'*N) % (ords...)` builds an arbitrary string from just `c` + digits + operators.
- Feed that string to `exec(...)` (letters `e`, `x`, `c`). Total distinct letters = `{c, e, x}` = 3. The code *inside* the generated string never appears in the source, so it can freely use any identifiers.

## Background Knowledge

### Counting distinct letters, not characters

The filter is `len(set(c for c in code if c.isalpha())) > 3`. Reusing the same letter many times is free; only the *set* of letters is capped at 3. Digits, punctuation, operators, and whitespace don't count — so string-building via `%` formatting and arithmetic is unrestricted.

### `'%c'` as a letter-free `chr`

`'%c' % 110 == 'n'`. The only letter is the `c` in the format string. Repeating the format (`'%c'*N`) and supplying a tuple of code points yields any string with no new letters. This dodges `chr` (which would cost `c,h,r`).

### `exec` fits the budget

`exec` uses letters `{e, x, c}` — exactly 3, and shares `c` with `'%c'`. `exec` runs a *string* of statements, and that string, being built at runtime, contributes no letters to the source.

## Solution

### Payload

```python
inner = "import glob\nprint(open(glob.glob('/flag*')[0]).read())"
payload = "exec(('%c'*%d)%%(%s))" % ...   # -> exec(('%c'*54)%(105,109,112,...))
```

`payload` is ASCII and uses only `{c, e, x}`. `eval(payload)` calls `exec` on the reconstructed `inner`, which globs the randomized `/flag-<md5>.txt` and prints it. See [`solve.py`](solve.py).

### Capture

```bash
$ python3 solve.py 34.170.146.252 6943
Alpaca{now_can_you_golf_this_challenge?my_best_is_36_characters}
```

Validated locally against `jail.py` first (letters = `{c,e,x}`, read a seeded flag), then one connection to the remote.

## Tools Used

| Tool | Purpose |
|------|---------|
| Python stdlib `socket` | Send the one-line payload |
| Local `jail.py` | Validate the letter budget + exec mechanism offline |

## Lessons Learned

- "N distinct letters" jails fall to `'%c'%N` string-building plus a 3-letter runner like `exec`; the executed string's identifiers are invisible to the source filter.
- Pick the 3 letters to overlap: `c` serves both `'%c'` and `exec`, leaving room for `e`, `x`.
- The flag hints it golfs to 36 chars — a nice follow-up, but correctness first.

## Tags

`misc` `pyjail` `eval` `exec` `format-string` `%c` `sandbox-escape`
