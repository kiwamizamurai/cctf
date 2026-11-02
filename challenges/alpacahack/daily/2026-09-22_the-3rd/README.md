# [crypto] The 3rd

> 合成数 `n=p·q·r`（r 秘密）上の EC だが、既知の p,q に還元して ECDLP を解き CRT で k を復元。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | crypto (ECC) |
| Difficulty | Hard |
| Date | 2026-11-03 |
| Released | 2026-09-22 |
| Flag | `Alpaca{prprpr}` |

## Problem Statement

```python
p = 577131489751; q = 604663433347; r = secret prime
E = EllipticCurve(Zmod(p*q*r), [2,3])
S = E(...); T = int.from_bytes(flag) * S     # flag は14バイト Alpaca{......}
print(T)
```

## TL;DR

- 法は `n = p·q·r`。`r` は秘密だが **`p,q` は既知**。
- `E(Zmod(n))` 上の点を `mod p`、`mod q` に還元すると、それぞれ有限体上の楕円曲線になる。
- `T = k·S` を `mod p`, `mod q` で ECDLP として解き、`k mod ord(S_p)`、`k mod ord(S_q)` を得る。
- CRT で `k mod M`（M ≈ 2^76）。flag は14バイト固定構造（`Alpaca{`＋6バイト＋`}`）で
  未知は 48bit なので、`k = C + 256·mid`（mid<2^48）の窓内で `k ≡ r0 (mod M)` を満たす
  唯一の `k` を直接探して mid を確定。

## Background Knowledge

### 合成数上の EC と素数還元

`Zmod(n)` の EC は環上の曲線で直接 DLP を解くのは難しいが、`n` の素因数 `p` が分かれば
`E(GF(p))` へ還元して通常の ECDLP に落とせる。本問は `p,q` が平文で与えられるので
`r` を知らずとも2つの素数で十分な情報が得られる。

### ECDLP（BSGS）と位数

各素数上で BSGS により dlog を計算（bound は点の位数）。位数は Hasse 区間
`[pr+1-2√pr, pr+1+2√pr]` から BSGS で位数の倍数を求め、因数分解して確定。
pure Python 実装（Pollard-rho 因数分解、Miller–Rabin）。

### 構造による一意復元

`M` が偶数で 256 が可逆でない場合でも、`k = r0 + t·M` を flag の構造窓
`[C, C+256·2^48)` 内で探すと一意に決まる（`M ≫ 窓幅 2^56`）。

## Solution

`mod p`: dlog = 223318757821, ord = 288566009096。
`mod q`: dlog = 247372533797, ord = 302331052781。
CRT → `k mod M`（M=87242465326805302095976）→ 構造窓で `mid` 確定 → `Alpaca{prprpr}`。

実装は `solve.py`（Sage 不使用、純 Python の EC/BSGS/位数/因数分解）。

## Lessons Learned

- 合成数モジュラスの EC/RSA は、既知の素因数へ還元して部分情報を集め CRT するのが定石。
  秘密素数 r が1つあっても、既知の p,q だけで平文が十分拘束される。
- 短い未知(48bit)＋大きい法(2^76)なら、逆元が無くても構造窓の直接探索で復元できる。

## Tags

`crypto` `ecc` `ecdlp` `bsgs` `crt` `composite-modulus` `pohlig-hellman`
