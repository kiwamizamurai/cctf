# [misc] private method

> Python name-mangling turns `__flag` into the perfectly callable identifier `_Main__flag`.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | misc |
| Difficulty | ★☆☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{what_are_alpaca_doing_in_their_private_time?}` |

## Problem Statement

> The private method should not be callable...
>
> `private-method.tar.gz`

## TL;DR

- `app.py` reads input matching `\w+\(\)` and runs `eval(f"Main.{code}")`. `Main.__flag()` returns the flag but looks "private".
- Python name-mangles a `__name` inside a class to `_ClassName__name`. So the method is actually `Main._Main__flag`, and `_Main__flag` is a plain `\w+` identifier.
- Input `_Main__flag()` → passes the regex → `eval("Main._Main__flag()")` → flag.

## Background Knowledge

### Python name mangling

Any identifier of the form `__spam` (at most one trailing underscore) used in a class body is textually replaced with `_ClassName__spam`. It's a readability/collision convention, **not** access control — the attribute exists under the mangled name and is fully reachable from outside: `Main._Main__flag()`.

## Solution

```
>>> Main._Main__flag()
Alpaca{what_are_alpaca_doing_in_their_private_time?}
```

See [`solve.py`](solve.py). Verified locally (`echo "_Main__flag()" | python3 app.py`).

## Tools Used

| Tool | Purpose |
|------|---------|
| Python stdlib `socket` | Send the single payload |

## Lessons Learned

- `__`-prefixed members are not private; mangling just renames them. `eval` on even a tightly-regexed `\w+()` is exploitable when the mangled name is a valid identifier.

## Tags

`misc` `python` `name-mangling` `eval` `private`
