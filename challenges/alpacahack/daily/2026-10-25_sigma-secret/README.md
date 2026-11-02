# [crypto] Σecret

> 2変数の冪和 `x+y`, `x²+y²` が分かれば、積 `xy` を経て各変数を2次方程式で復元できる。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | crypto |
| Difficulty | ★★☆☆☆ (Easy 🌱) |
| Date | 2026-11-02 |
| Released | 2026-10-25 |
| Flag | `Alpaca{Wa_wo_motte_toutoshi_to_nasu}` |

## Problem Statement

> wawawawa~!

配布物: `prob.py`。サーバーは FLAG を8バイトブロックに分け、各ブロックで

```python
x = int.from_bytes(block[:4], "big")
y = (1<<32) + int.from_bytes(block[4:], "big")
print([sum(v**k for v in (x, y)) for k in range(1, 3)])  # [x+y, x^2+y^2]
```

を出力する。

## TL;DR

- 各ブロックで冪和 `s1 = x+y`, `s2 = x²+y²` が与えられる。
- `xy = (s1² − s2) / 2`。
- `x, y` は `t² − s1·t + xy = 0` の2解。判別式の平方根から復元。
- `x`(小さい方, <2³²) が前半4B、`y − 2³²` が後半4B。連結して旗。

## Solution

```python
xy = (s1*s1 - s2)//2
disc = s1*s1 - 4*xy
r = isqrt(disc)
a, b = (s1+r)//2, (s1-r)//2       # {x, y}
x, y = min(a,b), max(a,b)
block = x.to_bytes(4,"big") + (y-(1<<32)).to_bytes(4,"big")
```

サーバー出力を読み、全ブロックを連結してヌルパディングを除去。実装は `solve.py`。

## Lessons Learned

- ニュートンの恒等式: 冪和 `p1, p2` から基本対称式 `e1=p1`, `e2=(p1²−p2)/2` が出る。
  対称式さえ揃えば、変数は多項式の根として一気に復元できる。
- `y` に `2³²` のオフセットを足すのは「どちらが上位4バイトか」を一意にするため。

## Tags

`crypto` `symmetric-polynomial` `newton-identities` `power-sums` `quadratic`
