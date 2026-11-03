# [pwn] A slight mistake

> A 2-byte overflow into the saved RBP, plus a stack leak, pivots `main`'s `leave; ret` onto a buffer holding `&win`.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | pwn |
| Difficulty | ★★★☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{2bytes_wo_warau_mono_ha_2bytes_ni_naku}` |

## Problem Statement

> Oops, I made a slight mistake. But that's okay, it's not like anyone could exploit this mistake anyway.
>
> `a-slight-mistake.tar.gz` (no-PIE, no stack canary; `win()` calls `execve("/bin/sh")`)

## TL;DR

- `greet()` has `char name[64]` at `rbp-0x40` and does `read(0, name, 66)` — a **2-byte overflow** that overwrites only the low 2 bytes of the saved RBP (stored at `name[64]`).
- `main` leaks `&alpaca` (`= main_rbp - 0x10`), so all stack offsets are known.
- Overwrite saved RBP's low 2 bytes so that after `greet` returns, `main`'s `leave; ret` pivots `rsp` and reads the return address from our `name` buffer, where we placed `&win`.

## Background Knowledge

### Saved-RBP partial overwrite → stack pivot

`greet`'s `name[64]` sits exactly on the saved caller RBP. A 2-byte overflow changes only its low 16 bits. The corrupted RBP isn't used by `greet`'s own `ret` (that return address is intact), but `greet` restores it into the RBP register; then **`main`'s epilogue** `leave; ret` does `rsp = rbp'; pop rbp; ret`, so `rip = [rbp'+8]`. Point `rbp'+8` at attacker data → arbitrary control.

### Offsets (from disassembly)

- `greet_rbp = main_rbp - 0x20`, `name = greet_rbp - 0x40 = main_rbp - 0x60`.
- `leaked = &alpaca = main_rbp - 0x10` ⇒ `main_rbp = leaked + 0x10`, `name[0] = leaked - 0x50`.
- Want `rbp'+8 = name[0]` ⇒ `rbp' = leaked - 0x58`; write `(leaked - 0x58) & 0xffff` into `name[64..65]`.

## Solution

```python
payload  = p64(0x4011b6)                  # name[0..7] = &win  (ret target)
payload += b"A"*56                        # name[8..63]
payload += p16((leaked - 0x58) & 0xffff)  # name[64..65] = low 2 bytes of saved RBP
# send exactly 66 bytes (read reads 66; no trailing newline)
```

`win`'s address has null bytes but `read` doesn't stop on nulls, and `remove_newline`'s `strlen` stops at the first null (harmless). See [`solve.py`](solve.py).

```bash
$ python3 solve.py 34.170.146.252 56702
Alpaca{2bytes_wo_warau_mono_ha_2bytes_ni_naku}
```

## Tools Used

| Tool | Purpose |
|------|---------|
| objdump | Recover exact frame offsets |
| Python stdlib `socket`/`struct` | Build the overflow, drive the shell |

## Lessons Learned

- Even a 2-byte overflow is fatal when it lands on the saved frame pointer: the *caller's* `leave; ret` becomes a stack pivot, and a convenient stack leak supplies the absolute address.
- `read(buf, n)` with `n > sizeof(buf)` by even 2 is a real bug — size the read to the buffer.

## Tags

`pwn` `stack-overflow` `off-by-two` `saved-rbp` `stack-pivot` `ret2win` `no-pie`
