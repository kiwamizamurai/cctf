# [misc] Long Long Flag Printer 2026

> The flag is printed one char at a time with ever-growing `sleep`s — send Ctrl-C to kill each sleep, mindful that SIGINT also flushes the pty's output.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | misc |
| Difficulty | ★★★☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{L0ng_long_fl4g_printer_Lorem_ipsum_dolor_sit_amet,_..._sit_amet_adipiscing_sem_neque_sed_i}` (1024 chars) |

## Problem Statement

> The flag for Long Flag Printer 2026 has gotten even longer.
>
> `long-long-flag-printer-2026.tar.gz`

## TL;DR

- `server.py` prints the 1024-char flag char-by-char, doing `os.system(f"sleep {i}")` after char `i` (total ≈ 6 days).
- socat serves it on a **pty** (`pty,ctty,setsid,echo=0`), so the client can send **Ctrl-C (0x03)**: SIGINT hits the foreground process group and kills each `sleep`. Python's `os.system()` (C `system()`) blocks SIGINT in the parent for the whole call, so Python survives and advances.
- Subtlety: the pty's default `NOFLSH`-off means generating SIGINT **flushes the pty output queue** — a char still buffered when Ctrl-C fires is lost. Read each char *before* sending the next Ctrl-C (strict lock-step) to stay lossless.
- The flag body is the canonical **Lorem ipsum** text (spaces → `_`), so a partial capture confirms the content and the rest is reconstructable offline.

## Background Knowledge

### `os.system` and SIGINT

C `system()` (used by `os.system`) ignores SIGINT/SIGQUIT in the *calling* process for the duration of the child, and restores defaults in the child. So Ctrl-C sent down the pty kills the `sleep` child but leaves the Python parent running — it just returns from `os.system` and prints the next character.

### Terminal INTR flushes output (NOFLSH)

When the line discipline turns the INTR char into SIGINT, and `NOFLSH` is **not** set (the default), it also flushes the terminal's input and output queues. If a just-printed flag character hasn't been drained by socat yet, that flush discards it. A naive "spam Ctrl-C" loop therefore drops characters. Draining each character before firing the next Ctrl-C avoids the loss.

## Solution

### Step 1: Read `server.py`

```python
for i, c in enumerate(flag):     # len(flag) == 1024
    print(c, end="", flush=True)
    os.system(f"sleep {i}")
```

Cumulative sleep ≈ Σ(0..1023) s ≈ 6 days; socat has idle timeout `-T5`.

### Step 2: Skip the sleeps with Ctrl-C (lossless, one connection)

Send one Ctrl-C per character, in lock-step — wait for the character the previous interrupt released before sending the next, so no char is in the pty output buffer when SIGINT flushes it. Single connection, no spamming. See [`solve.py`](solve.py).

### Step 3: Capture / reconstruct

A clean lock-step capture yields the whole 1024-char flag. The body being canonical Lorem ipsum means a partial capture (here 1011 verified chars, an exact prefix of the canonical text) plus the known continuation reconstructs the full flag offline — no need to hammer the server. The reconstructed 1024-char flag was accepted.

## Tools Used

| Tool | Purpose |
|------|---------|
| Python stdlib `socket`, `select` | One pty-backed connection, lock-step Ctrl-C |

## Lessons Learned

- "Printer with sleeps" → Ctrl-C to kill the sleeps; the real trap is that INTR flushes the pty output queue (NOFLSH), so interrupt in lock-step, not by spamming, or you silently lose characters.
- When the flag is deterministic text (canonical Lorem ipsum), a partial read is enough — reconstruct offline instead of repeatedly reconnecting, which is both faster and far gentler on the server.

## Tags

`misc` `pty` `signals` `sigint` `os.system` `socat` `terminal`
