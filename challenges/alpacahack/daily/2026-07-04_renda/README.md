# [rev/web] Renda

> Don't click 100,000 times — read the obfuscated JS and XOR the two embedded arrays that build the flag.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | rev (client-side JS) |
| Difficulty | ★★☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{oraoraoraoraoraoraoraoraora0raoraoraora}` |

## Problem Statement

> Just keep clicking!
>
> `index.html`

## TL;DR

- `index.html` is obfuscator.io-obfuscated. A click handler counts clicks; at 100,000 it computes the flag as `l.map((e,f) => String.fromCharCode(e ^ p[f])).join('')`.
- `p` (key) and `l` (ciphertext) are embedded arrays. XOR them element-wise → flag. No clicking required.

## Solution

Extract both arrays from the click-handler branch (their elements are obfuscated hex/arithmetic, e.g. `0x6ed*0x5+...`, which evaluate to ints), then `chr(l[i] ^ p[i])`:

```python
text = "".join(chr(e ^ p[i]) for i, e in enumerate(l))
# "FLAG: Alpaca{oraoraoraoraoraoraoraoraora0raoraoraora}"
```

See [`solve.py`](solve.py). Fully static, no browser needed.

## Background Knowledge

Obfuscator.io hides string/array literals and sprinkles self-defending `console`/debugger guards, but the actual payload (here a simple XOR-decode of two arrays) is unchanged. Find the sink (`fromCharCode(e ^ p[f])`), grab its operands, and compute offline — don't execute the anti-debug runtime.

## Tools Used

| Tool | Purpose |
|------|---------|
| Python (regex + eval of hex arithmetic) | Extract arrays, XOR-decode |

## Lessons Learned

- Gating a reveal behind "100,000 clicks" is just a client-side counter; the secret is in the code, decodable statically.
- For obfuscated JS, target the decode sink and its literal operands instead of running the protected code.

## Tags

`rev` `web` `javascript` `obfuscation` `xor` `obfuscator.io`
