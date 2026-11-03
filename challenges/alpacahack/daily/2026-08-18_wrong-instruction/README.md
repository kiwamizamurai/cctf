# [rev] wrong instruction

> Anti-disassembly (overlapping instructions + a return-address trampoline) hides a simple per-byte check; follow the real control flow and invert it.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | rev |
| Difficulty | ★★★☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{These_methods_are_called_anti-disassembly_techniques}` |

## Problem Statement

> We need to analyze a flag verification process...what?
>
> `wrong-instruction` (ELF x86-64, not stripped)

## TL;DR

- `main` reads 60 bytes, requires length 60, and calls `is_correct(input, encoded, 60)`; if it returns 0 it prints `Correct! The flag is <input>` — so the correct input *is* the flag.
- `is_correct` is obfuscated with **anti-disassembly**: a `jmp` into its own operand byte decodes to `call rax` where `rax` points at a trampoline `add qword [rsp], 0x5; xor eax,eax; ret` that rewrites the return address to skip bytes, and a `je`/`jne` pair jumps into the middle of a `movabs` — so linear disassembly is wrong.
- The real loop is: `cl = (input[i] + 8*i + 0x37 - encoded[i]) & 0xff; al |= cl`. For `al == 0`, `input[i] = (encoded[i] - 8*i - 0x37) mod 256`.

## Background Knowledge

### Anti-disassembly via overlapping instructions

Linear-sweep disassemblers decode bytes sequentially. If a jump targets a byte *inside* another instruction, the real instruction stream is misaligned with what the disassembler prints. Here:

- `lea rax, [rip+0x30]` sets `rax = 0x1204` (a trampoline).
- `eb ff` = `jmp 0x11d5` jumps onto its own operand byte; from `0x11d5` the bytes `ff d0` decode as `call rax`.
- The trampoline at `0x1204` does `add qword [rsp], 0x5` — adding 5 to the saved return address — then `xor eax,eax; ret`, so execution resumes 5 bytes later (and `eax` is zeroed).
- A `je 0x11f2` / `jne 0x11f2` pair (always one taken) jumps into the middle of a 10-byte `movabs`, where the bytes actually decode as `lea ecx,[rcx+r10*8+0x37]; sub cl,dl; or al,cl`.

### Recovered logic

```
eax = 0
for i in 0..59:
    cl = (input[i] + 8*i + 0x37 - encoded[i]) & 0xff
    al |= cl
return al        # 0 == correct
```

## Solution

Follow the real flow (here with capstone + pyelftools, simulating the trampoline), read the 60-byte `encoded` table at `0x2020`, and invert:

```python
flag = bytes((encoded[i] - 8*i - 0x37) % 256 for i in range(60))
# Alpaca{These_methods_are_called_anti-disassembly_techniques}
```

See [`solve.py`](solve.py). No runtime needed — static recovery.

## Tools Used

| Tool | Purpose |
|------|---------|
| objdump | Initial (misleading) disassembly, raw bytes |
| capstone + pyelftools (venv) | Decode the real instruction stream by following control flow |

## Lessons Learned

- When a disassembly shows nonsense ops (`ror byte[rdi]`, stray `movabs`, `enter`), suspect overlapping-instruction anti-disassembly: follow jumps/calls byte-exactly and re-decode from the true targets.
- A trampoline that does `add [rsp], N; ret` is a compact way to skip bytes and desync the decoder.

## Tags

`rev` `anti-disassembly` `overlapping-instructions` `x86-64` `capstone` `obfuscation`
