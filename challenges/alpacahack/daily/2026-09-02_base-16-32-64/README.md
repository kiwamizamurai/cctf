# [misc] base 16-32-64

> base16/32/64 を20回ランダムに重ねただけ。各層のアルファベットで判別しつつ逆デコード。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | misc / crypto |
| Difficulty | Easy |
| Date | 2026-11-03 |
| Released | 2026-09-02 |
| Flag | `Alpaca{enc0ding_puzz1e!}` |

## Problem Statement

> I created new encoding method using base16, base32, and base64.

```python
for i in range(20):
    base = random.choice([16, 32, 64])
    flag = {16:b16encode,32:b32encode,64:b64encode}[base](flag)
print(flag.decode())
```

配布: `chall.py`, `output.txt`。

## TL;DR

- 20回 base16/32/64 を重ねただけ。逆に20層デコードすればよい。
- 各段で3種のデコードを試し、成立する経路を DFS で辿る（末尾に `Alpaca{...}` が出たら成功）。

## Solution

```python
def tries(b):
    for fn in (base64.b16decode, base64.b32decode, base64.b64decode):
        try:
            d = fn(b)
            if d: yield d
        except Exception: pass
def dfs(b, depth):
    if depth==0: return b if b.startswith(b"Alpaca{") else None
    for d in tries(b):
        r=dfs(d, depth-1)
        if r: return r
```

20層を DFS で辿ると一意に `Alpaca{enc0ding_puzz1e!}` に到達。実装は `solve.py`。

## Lessons Learned

- base16(0-9A-F) / base32(A-Z2-7=) / base64(A-Za-z0-9+/=) はアルファベットが異なるので、
  重ね掛けでも機械的に逆変換できる。曖昧でも分岐は少なく DFS で十分。

## Tags

`misc` `encoding` `base64` `base32` `base16` `dfs`
