# [rev/misc] Compile time flag checker

> A C++ `static_assert` gates compilation on the flag convolved with a deterministic PRNG sequence — deconvolve it since the first coefficient is odd (invertible mod 256).

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | rev (constexpr C++) |
| Difficulty | ★★★☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{C++'s_template,_NTTP,_constexpr,_and_type_traits_are_too_powerful!}` |

## Problem Statement

> It can only be compiled with a correct flag.
>
> `compile-time-flag-checker.tar.gz` — compile with `g++ -std=c++20`.

## TL;DR

- `chal.cpp` computes, at compile time, the **convolution (mod 256)** of the flag bytes `input` with an `odd_random` sequence, and `static_assert`s it equals a fixed `expected_t`.
- `odd_random[i]` = the (i+1)-th output of a fixed-seed `xoshiro128++`, `& 0xFF | 1` → always odd ⇒ `odd[0]` is invertible mod 256.
- So the convolution is lower-triangular and **deconvolves** in order: `input[K] = (expected[K] − Σ_{i<K} input[i]·odd[K−i]) · odd[0]⁻¹ (mod 256)`.

## Background Knowledge

### Convolution as a triangular linear system

`expected[K] = Σ_{i=0..K} input[i]·odd[K−i]` (mod 256). For `K=0`: `expected[0] = input[0]·odd[0]`. Because `odd[0]` is odd (coprime to 256), invert it and solve forward; each new `input[K]` depends only on earlier, already-recovered bytes. `N = (len(expected)+1)/2` since full convolution length is `2N−1`.

### Reproducing `odd_random`

`make_odd_random_number(i)` re-seeds `xoshiro128++` with the fixed seed, advances `i` steps, then returns `next() & 0xFF | 1`. Reimplement the generator (seed `0x6c696144,0x6c412079,0x61636170,0x6b636148`) in Python and generate `odd[0..N-1]`.

## Solution

```python
od = [odd(i) for i in range(N)]
inv = pow(od[0], -1, 256)
for K in range(N):
    acc = expected[K]
    for i in range(K):
        acc = (acc - inp[i]*od[K-i]) % 256
    inp[K] = acc * inv % 256
# Alpaca{C++'s_template,_NTTP,_constexpr,_and_type_traits_are_too_powerful!}
```

See [`solve.py`](solve.py). Fully offline; no need to actually compile.

## Tools Used

| Tool | Purpose |
|------|---------|
| Python (big-int mod 256) | Reimplement xoshiro128++, deconvolve |

## Lessons Learned

- A compile-time check is just a computation you can mirror offline; here the "obfuscation" is a convolution with a reproducible PRNG, which inverts cleanly because the leading coefficient is a unit mod 256.

## Tags

`rev` `cpp` `constexpr` `convolution` `xoshiro` `deconvolution`
