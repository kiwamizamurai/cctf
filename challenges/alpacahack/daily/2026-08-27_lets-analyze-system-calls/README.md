# [rev] Let's analyze system calls

> Read two raw x86-64 syscalls to realize the "random" sum is just `getrandom()` (shown to you) plus the container's fixed UID.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | rev |
| Difficulty | ★☆☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{we_often_use_wrapper_functions_but_some_binaries_use_system_calls_directly}` |

## Problem Statement

> Let's analyze x86-64 Linux system calls!
>
> `lets-analyze-system-calls.tar.gz`

## TL;DR

- `chal.c` makes two inline-assembly syscalls: `rax=318` and `rax=102`.
- `318 = getrandom(&result_1, 8, 0)` — fills `result_1` with 8 random bytes, and the program **prints `result_1`**. `102 = getuid()` → `result_2`.
- The Dockerfile runs `USER 404:404`, so `getuid()` returns `404`. Thus `sum = result_1 + 404`. Read `result_1`, send `result_1 + 404`.

## Background Knowledge

### x86-64 Linux syscall convention

Syscall number in `rax`; arguments in `rdi, rsi, rdx, r10, r8, r9`; return value in `rax`. The two calls here:

```c
asm("syscall" :: "a"(318), "D"(&result_1), "S"(8), "d"(0) : ...); // getrandom(&result_1, 8, 0)
asm("syscall" : "=a"(result_2) : "a"(102) : ...);                 // result_2 = getuid()
```

Syscall 318 = `getrandom`, 102 = `getuid` on x86-64.

### Where the UID comes from

`getuid()` returns the real UID of the process. The container's `USER 404:404` directive fixes it at 404, so `result_2` is deterministic.

## Solution

### Step 1: Identify the syscalls

318 → `getrandom`, 102 → `getuid`. `result_1` is printed; `result_2 = 404`.

### Step 2: Compute and send

`answer = (result_1 + 404) mod 2⁶⁴` (C `unsigned long`). See [`solve.py`](solve.py).

```bash
$ python3 solve.py 34.170.146.252 14626
result_1 = 3899015204765878554 answer = 3899015204765878958
Alpaca{we_often_use_wrapper_functions_but_some_binaries_use_system_calls_directly}
```

## Tools Used

| Tool | Purpose |
|------|---------|
| Syscall tables (x86-64) | Map 318/102 to getrandom/getuid |
| Python stdlib `socket` | Read `result_1`, send the sum |

## Lessons Learned

- When a binary makes raw syscalls, look them up by number — the "randomness" here is handed to you, and the second operand (UID) is pinned by the Dockerfile's `USER`.

## Tags

`rev` `syscall` `x86-64` `getrandom` `getuid` `inline-asm`
