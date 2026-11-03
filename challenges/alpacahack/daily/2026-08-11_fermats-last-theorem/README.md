# [misc] Fermat's Last Theorem

> You can't find a counterexample to Fermat — but you can break the C macro that "cubes" your input.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | misc (C macro / injection) |
| Difficulty | ★★☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{Pierre_de_Fermat_is_one_of_the_greatest_mathematicians}` |

## Problem Statement

> According to Fermat's Last Theorem, for an integer N ≥ 3 there are no positive integers (A, B, C) satisfying Aᴺ + Bᴺ = Cᴺ.
>
> `fermats-last-theorem.tar.gz`

## TL;DR

- `server.py` keeps each of A, B, C to ≤3 characters of `[-0-9]`, then pastes them textually into C source that checks `A>0 && B>0 && C>0 && CUBE(A)+CUBE(B)==CUBE(C)`.
- The macro is `#define CUBE(x) (x * x * x)` — **no parentheses around `x`**. Injecting a `-` lets `*` bind tighter than `-`, so the "cube" is no longer a cube.
- `A=1, B=1, C=2-0`: `CUBE(2-0)` expands to `2-0 * 2-0 * 2-0 = 2 - 0*2 - 0*2 - 0 = 2`, raw `C = 2 > 0`, and `1 + 1 == 2`.

## Background Knowledge

### The classic unparenthesized-macro bug

`#define CUBE(x) (x * x * x)` expands `CUBE(2-0)` to `(2-0 * 2-0 * 2-0)`. With C precedence (`*` before binary `-`):

```
2 - (0 * 2) - (0 * 2) - 0  =  2 - 0 - 0 - 0  =  2
```

So `CUBE` returns the *first digit* here, not the cube. Meanwhile the guard `C <= 0` sees the raw string `2-0`, which evaluates to `2 > 0`, passing the positivity check. This is exactly why function-like macros must parenthesize every parameter use: `#define CUBE(x) ((x)*(x)*(x))`.

## Solution

### Step 1: Read `server.py`

Input sanitizer: `re.sub(r'[^-0-9]', '', txt)[:3]` → each value is ≤3 chars from digits and `-`. Values are substituted into the guard (raw) and into `CUBE(...)` (expanded `x*x*x`).

### Step 2: Search for a working triple

Enumerate all ≤3-char strings over `[-0-9]`, compute the raw value and the `x * x * x` expansion (rejecting leading-zero multi-digit tokens to avoid C octal), and look for `cube(A)+cube(B)==cube(C)` with all raws > 0. Solver finds `A=1, B=1, C=2-0`. See [`solve.py`](solve.py).

### Step 3: Verify locally, then capture

Compiled the exact generated C locally → reached the "Seriously? Flag" branch. Remote:

```bash
$ python3 solve.py 34.170.146.252 8875
Alpaca{Pierre_de_Fermat_is_one_of_the_greatest_mathematicians}
```

## Tools Used

| Tool | Purpose |
|------|---------|
| Python (search + socket client) | Enumerate triples, drive the service |
| `cc`/gcc | Local verification of the generated C |

## Lessons Learned

- Unparenthesized macro parameters are an injection primitive when attacker input is pasted into the macro argument.
- Separate the two evaluation contexts: the guard sees the *raw* token (`2-0`→2), the macro sees the *expanded* form (`2-0*2-0*2-0`→2). Making them disagree defeats the check.

## Tags

`misc` `c` `macro` `preprocessor` `operator-precedence` `injection`
