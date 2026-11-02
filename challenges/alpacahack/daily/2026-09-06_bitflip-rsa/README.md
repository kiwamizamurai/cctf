# [crypto] Bitflip RSA

> `m` と `~m`(=-m-1) を同じ RSA で暗号化＝線形関係のある2メッセージ。Franklin–Reiter で解ける。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | crypto (RSA) |
| Difficulty | Medium |
| Date | 2026-11-03 |
| Released | 2026-09-06 |
| Flag | `Alpaca{hit the road Bob and don't you encrypt no more}` |

## Problem Statement

```python
m = bytes_to_long(FLAG)
n = p*q  # 512+512
e = 101
c1 = pow(m, e, n)
c2 = pow(~m, e, n)
```

配布: `chal.py`, `output.txt`（n,e,c1,c2）。

## TL;DR

- Python の `~m == -m-1`。`e=101` は奇数なので `(~m)^e = (-m-1)^e = -(m+1)^e`。
- よって `m` と `m+1` という**線形関係**の2メッセージの暗号文がある。
- **Franklin–Reiter 関連メッセージ攻撃**: `gcd(x^e - c1, (x+1)^e + c2)` を `Z_n[x]` で
  とると `(x - m)` になり、`m` が求まる。

## Background Knowledge

### Franklin–Reiter

同じ `n,e` で `c1=m^e`, `c2=(a m + b)^e`（a,b 既知）のとき、多項式
`f(x)=x^e - c1` と `g(x)=(a x + b)^e - c2` は共通根 `x=m` を持つので、
`Z_n[x]` 上の多項式 gcd が `(x - m)` を与える。`e` が小さいほど現実的。

本問: `(~m)^e = -(m+1)^e` なので `(m+1)^e = -c2`。したがって
`g(x) = (x+1)^e + c2`、`f(x) = x^e - c1`。

### 実装

`Z_n` は体ではないが、各ステップで leading 係数が可逆なら多項式 Euclid で gcd が計算できる
（可逆でなければ `n` の因数が得られるのでそれはそれで勝ち）。`e=101` 次でも十分高速。

## Solution

`solve.py`（純 Python、多項式 gcd 自前実装）で `m` を復元。

```
gcd(x^101 - c1, (x+1)^101 + c2) = x - m  -> m -> flag
```

## Lessons Learned

- 「ビット反転した平文も暗号化」のような**平文同士に既知の線形関係**があると、
  Franklin–Reiter / 関連メッセージ攻撃が刺さる。パディングの重要性を示す典型。
- `~m = -m-1` の符号と `e` の偶奇に注意して多項式を立てる。

## Tags

`crypto` `rsa` `franklin-reiter` `related-message` `polynomial-gcd`
