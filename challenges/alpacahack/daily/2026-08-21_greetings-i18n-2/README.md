# [web] Greetings i18n 2

> A user-controlled `str.format` template turns into a read primitive over server-side globals — enough to leak a hidden function's bytecode and reverse the flag check.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | web (Python format-string injection) |
| Difficulty | ★★★★☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{7X5svMqHgZHRlZJR8ngLYZNILxHBxKCAk454qpGE1A}` |

## Problem Statement

> Hey, stop making black-box web challenges already!
>
> `greetings-i18n-2.tar.gz`

The distributed `check.py` is a stub (`return True # This function is different in the remote server`), so the real check lives only on the server — a deliberately black-box flag check.

## TL;DR

- The i18n helper `_(key)` returns `request.form["custom-<key>"]` when present, so the attacker controls the **template** given to `str.format`: `_("hello").format(username=...)` and, on error, `_("error").format(err=e)`.
- `str.format` permits `.attr` and `[idx]` traversal on its arguments. Force the error branch, then from the exception `err` walk `err.__traceback__.tb_frame.f_globals` → the server-only `check` function → its `__code__`.
- Leak `check.__code__.co_consts` / bytecode, reverse the algorithm with `dis`, and reconstruct the 50-char flag (two `[::3]`/`[::-3]` slice constants fix 2/3 of the chars; the rest fall out of a per-byte XOR that's invertible mod 256).

## Background Knowledge

### Python format-string injection

`"{0.x}".format(obj)` evaluates attribute/item access on the arguments. If the *template* is attacker-controlled, any object reachable from a passed argument is readable (not callable). The exception object passed as `err` is a gateway: `err.__traceback__.tb_frame.f_globals` exposes the module globals of the frame that raised.

### Reaching the flag check

`f_globals["check"]` is the function imported into `app.py`. Functions expose `__code__`, whose `co_consts`, `co_names`, `co_varnames`, `co_code`, etc. are all plain attributes — fully leakable through the format template, one field per request.

## Solution

### Step 1: Confirm the injection sink

`_(key)` prefers `request.form.get(f"custom-{key}")`. The `/` route is GET, but Werkzeug still parses a urlencoded **body** on a GET request, so sending `custom-hello` / `custom-error` in a GET body controls both templates.

### Step 2: Drive into the error branch and read globals

```
custom-hello = {missingkey}      # KeyError inside .format() → except branch
custom-error = {err.__traceback__.tb_frame.f_globals[check].__globals__}
```

The remote globals had no `FLAG`, so the flag is computed inside `check`.

### Step 3: Leak the code object and disassemble

Pull each field: `co_consts`, `co_names=('len','bytes','range','ord')`, `co_varnames=('input','i')`, `co_code`, plus the small ints needed to rebuild a `types.CodeType`. Reconstruct it under a matching CPython (the Docker image pins `python:3.14.6`; local `python3.14` disassembles identically):

```python
def check(input):
    if len(input) != 50: return False
    if input[::3]  != 'Aa{5MgRJnYIHKk4GA': return False   # positions 0,3,…,48
    if input[::-3] != '}Eq4CBLZgRlZqs7cl': return False    # positions 49,46,…,1
    if bytes(
        (7*ord(input[3*i])   % 256)
      ^ (5*ord(input[3*i+1]) % 256)
      ^ ((3*ord(input[3*i+2]) + 23) % 256) for i in range(16)
    ) != b'\xbcrQ5\xc1\xfc\x07#\xfa\xac\xfc\xcd\x98_>\x02':
        return False
    return True
```

### Step 4: Reconstruct the flag

- `input[::3]` fixes positions ≡ 0 (mod 3) = `'Aa{5MgRJnYIHKk4GA'`.
- `input[::-3]` fixes positions ≡ 1 (mod 3): `input[49-3k] = '}Eq4CBLZgRlZqs7cl'[k]`.
- Positions ≡ 2 (mod 3) are the only unknowns. For each `i`, `term1 = 7·ord(input[3i])%256` and `term2 = 5·ord(input[3i+1])%256` are known, so `term3 = target[i] ^ term1 ^ term2 = (3·x + 23) % 256`, and `x = (term3 − 23)·3⁻¹ mod 256` (3⁻¹ ≡ 171).

```bash
$ python3 solve.py 34.170.146.252 32318
Alpaca{7X5svMqHgZHRlZJR8ngLYZNILxHBxKCAk454qpGE1A}
```

Verified live against `POST /check` → "That's the correct flag!".

## Tools Used

| Tool | Purpose |
|------|---------|
| Python stdlib `socket` | Craft GET-with-body injection, drive `/check` |
| `dis` on `python3.14` | Disassemble the leaked `check` code object |
| Flask (venv) | Local harness to validate the injection mechanics |

## Lessons Learned

- Never hand user input (or user-controlled keys that *select* a template) to `str.format` — it is a read-anything primitive over every object reachable from the format arguments.
- An exception object is the juiciest argument: `__traceback__.tb_frame.f_globals` reaches module globals, and from a function there, `__code__.co_consts`/bytecode reaches "hidden" server logic.
- "Black-box" is only black-box until you can read the bytecode; matching the pinned interpreter (3.14.6 ↔ local 3.14) makes `dis` exact.

## References

- [Python format-string vulnerabilities](https://podalirius.net/en/articles/python-format-string-vulnerabilities/) — the attribute/item traversal gadget chains.

## Tags

`web` `python` `format-string` `str.format` `info-leak` `bytecode` `dis` `flask`
