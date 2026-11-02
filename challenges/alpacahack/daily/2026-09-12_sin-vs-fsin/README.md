# [misc/rev] sin function vs. fsin instruction

> x86 `fsin` は |x| ≥ 2^63 で計算せず入力をそのまま返す。巨大な有限値で libc `sin` と乖離させる。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | misc / rev |
| Difficulty | Easy-Medium |
| Date | 2026-11-03 |
| Released | 2026-09-12 |
| Flag | `Alpaca{Specifications_say_everything}` |

## Problem Statement

`theta`(double, inf/nan 不可) を入力。`sin(theta)`(libc) と `fsin`命令 の結果を比較し、
`|sine_1 - sine_2| > 1337.0` なら flag。

```c
double sine_1 = sin(theta);                 // libc: 常に [-1,1]
double result; __asm__("fsin":"=t"(result):"0"(theta)); // x86 fsin
if (fabs(sine_1 - sine_2) > 1337.0) print FLAG;
```

## TL;DR

- x86 の **`fsin`** は、operand の絶対値が `2^63` 以上だと**計算を行わず operand を
  そのまま st(0) に残す**（C2 フラグをセット）。引数の範囲縮約は 66bit の π 近似で、
  仕様上このレンジ外は未計算。
- libc の `sin` は適切に範囲縮約して必ず `[-1,1]` を返す。
- よって `theta = 1e300`（有限、inf/nan でない）を入れると
  `sine_2 = 1e300`, `sine_1 ∈ [-1,1]` → 差 ≈ `1e300 ≫ 1337`。flag。

## Background Knowledge

### `fsin` のレンジ制限

Intel SDM: `fsin`/`fcos`/`fptan`/`fsincos` は operand が `-2^63 < x < 2^63` の範囲
でのみ有効。範囲外では C2=1 を立て、**operand を変更しない**。レガシー x87 の範囲縮約が
限定的なため。現代の libc は Payne–Hanek などで厳密に縮約するので結果が大きく食い違う。

## Solution

```
theta> 1e300
sine_1: (ほぼ 0〜±1)
sine_2: 1e+300
-> Alpaca{Specifications_say_everything}
```

実装は `solve.py`（`1e300` を送るだけ）。

## Lessons Learned

- 「同じはず」の2実装（高級関数 vs CPU 命令）は、仕様の端（レンジ外・特殊値）で食い違う。
  `fsin` の 2^63 レンジ制限は有名な x87 の落とし穴。
- inf/nan ははじかれるが、巨大な**有限**値は通る点が鍵。

## Tags

`rev` `misc` `x86` `fsin` `x87` `floating-point` `range-reduction`
