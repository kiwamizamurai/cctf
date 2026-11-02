# [crypto] neighboRhood_diStAnce

> 素数と「隣の素数(next_prime)」で法を組むと、`n1·n3/n2 ≈ p²` で近似平方根から素因数が割れる。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | crypto (RSA) |
| Difficulty | Medium-Hard |
| Date | 2026-11-03 |
| Released | 2026-09-16 |
| Flag | `Alpaca{Now_is_the_time_to_recite_those_lyrics_by_John_Lennon:'All_we_are_saying_is_give_peace_a_chance!'}` |

## Problem Statement

フラグを3分割し、6つの素数 `p,q,r` とその next_prime `pp,qq,rr` で:

```
n1 = p*qq, n2 = q*rr, n3 = r*pp
c1 = m1^e mod n1, c2 = m2^e mod n2, c3 = m3^e mod n3
assert (pp-p)<2^16 or (qq-q)<2^16 or (rr-r)<2^16   # gap は小さい
```

## TL;DR

- 法が「ある素数」と「別の素数の next_prime」の積。next_prime の gap は素数のサイズ
  (2^1024) に対して極めて小さい。
- 比を取ると補正項が消える:
  `n1·n3 / n2 = (p·qq·r·pp)/(q·rr) = p·pp·(qq/q)·(r/rr) ≈ p²`
  （`qq/q, r/rr ≈ 1`、`pp ≈ p`）。
- `p ≈ isqrt(n1·n3//n2)`。誤差は ~2^15 程度なので近傍を探索して `n1` の約数 `p` を確定。
- あとは芋づる: `qq=n1/p`, `pp=next_prime(p)`, `r=n3/pp`, `rr=next_prime(r)`, `q=n2/rr`。
- 3法それぞれ通常の RSA 復号 → 連結。

## Background Knowledge

### 近似平方根による素因数分解

`N ≈ p²` の形に持ち込めれば、整数平方根 `isqrt(N)` が `p` の良い近似になる。
本問は3法の積・商で補正項を消して `p²` を作る。補正項の相対誤差は
`O(δ/q) ~ 2^{-1008}` なので、`p` は `isqrt(n1·n3//n2)` から ~2^15 以内に収まる。
その窓を線形探索し、`n1` を割る値を `p` とする。

## Solution

近似 → 近傍探索で `p` を特定 → next_prime 連鎖で全6素数 → 3ブロック復号。
純 Python（Miller–Rabin 自作、pycryptodome 不要）。実装は `solve.py`。

## Lessons Learned

- 複数法が「近い素数」を共有/派生していると、積と商の組み合わせで補正項が消え、
  近似平方根から分解できる。gap が小さい（next_prime）ことが鍵。
- `isqrt` + 近傍線形探索は「ほぼ平方数」を割る定番テク。

## Tags

`crypto` `rsa` `next-prime` `approximate-sqrt` `factorization` `miller-rabin`
