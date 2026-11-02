# [crypto] Almost Shared Prime

> 法が素数そのものではなく `p` と `p+2` を使っていても、連分数で小さい因子比を割り出せる。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | crypto (RSA) |
| Difficulty | ★★★★★ (Hard 8.0) |
| Date | 2026-11-02 |
| Released | 2026-10-09 |
| Flag | `Alpaca{approximate_common_disaster!}` |

## Problem Statement

> simple? A sequel to Shared Prime.

```python
while True:
    p = getPrime(1024)
    if isPrime(p + 2): break      # p と p+2 は双子素数
q1 = getPrime(256); q2 = getPrime(256)
n1 = p * q1
n2 = (p + 2) * q2
```

`q1, q2` が 256-bit と小さいのがポイント。

## TL;DR

- `gcd(n1,n2)=1`（共有素数ではない）。
- 変形: `n1/q1 = p`, `n2/q2 = p+2` ⇒ `n1·q2 - n2·q1 = -2·q1·q2`。
- 右辺は ~513-bit と小さいので、`q1/q2` は `n1/n2` の連分数の**近似分数**になる
  （Legendre の定理: `|n1/n2 - q1/q2| < 1/(2 q2²)`）。
- 近似分数を順に試し、`q1 | n1` かつ `(n1/q1)+2 | n2` を満たすものから `p` を得て復号。

## Background Knowledge

### 連分数による有理近似

`|a/b - h/k| < 1/(2k²)` を満たす既約分数 `h/k` は `a/b` の連分数の近似分数である
（Legendre）。ここでは `q1 ~ 2^256`, `n2 ~ 2^1280` なので
`|n1/n2 - q1/q2| ≈ 2q1/n2 ≈ 2^{-1023} < 1/(2 q2²) ≈ 2^{-513}` となり条件を満たす。
Wiener 攻撃と同じ道具立て。

## Solution

`n1/n2` の連分数展開の近似分数 `h/k` を順に生成し、`q1=h`（または `k`）が `n1` を
割り、`p=n1/q1` について `p+2` が `n2` を割るかを判定。見つかれば通常の RSA 復号。

```bash
python3 -I solve.py   # -> Alpaca{approximate_common_disaster!}
```

実装は `solve.py`（標準ライブラリのみ）。

## Lessons Learned

- 「素数を共有」から「近い素数を使用」に一段ひねっても、小さい補助因子 `q1,q2` が
  あると連分数（格子でも可）で破れる。小さい未知数の線形関係は連分数/LLL を疑う。

## Tags

`crypto` `rsa` `continued-fraction` `lattice` `wiener-like` `twin-prime`
