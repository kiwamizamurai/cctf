# [crypto] Shared Prime

> 2つの RSA 法が素数を共有していると、`gcd` 一発で両方が割れる。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | crypto (RSA) |
| Difficulty | ★★★☆☆ (Medium 3.5) |
| Date | 2026-11-02 |
| Released | 2026-10-03 |
| Flag | `Alpaca{greatest_common_disaster}` |

## Problem Statement

> simple!

配布物: `chall.py`, `output.txt`。同じ `m`(=flag) を2つの法で暗号化し、`n1,n2,c1,c2` を公開。

```python
p = getPrime(1024); q1 = getPrime(1024); q2 = getPrime(1024)
n1 = p*q1; n2 = p*q2          # ← p を共有
c1 = pow(m, e, n1); c2 = pow(m, e, n2)
```

## TL;DR

- `n1` と `n2` が素数 `p` を共有している。
- `p = gcd(n1, n2)` で即座に素因数分解できる。
- あとは通常の RSA 復号（`q1=n1/p`, `d=e^{-1} mod (p-1)(q1-1)`）。

## Solution

```python
from math import gcd
p = gcd(n1, n2)          # 共有素数
q1 = n1 // p
d = pow(e, -1, (p-1)*(q1-1))
m = pow(c1, d, n1)       # -> flag
```

完全な実装は `solve.py`。

## Lessons Learned

- 複数の RSA 公開鍵を集めたら、まず総当たりで `gcd` を取る（バッチ GCD）。素数の
  再利用は実運用（組み込み機器の弱い乱数など）でも起きる有名な脆弱性。

## Tags

`crypto` `rsa` `shared-prime` `gcd` `factorization`
