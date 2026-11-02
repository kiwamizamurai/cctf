# [misc] Vending Machine: Revised Version

> `in リスト` を `str.find(mark)<0` に"整理"したことで、空文字列が検証を通り抜ける。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | misc |
| Difficulty | Medium |
| Date | 2026-11-03 |
| Released | 2026-09-05 |
| Flag | `Alpaca{!sp3ci41_drink_f0r_you!}` |

## Problem Statement

自販機。在庫 `'a'*30+'b'*60+'c'*20+'d'*50+'e'*40+'f'`、`'f'` が flag。
旧版の pop(-1) バグ修正版。

```python
if 'abcde'.find(mark) < 0:   # No 'f'? Hmm...
    print("Invalid choice."); return
if len(self.stock) <= 0: ...
loc = self.stock.find(mark)
if loc < 0:                   # 旧バグ(pop(-1))を修正
    print("The product is sold out."); return
item = stock_list.pop(loc)
```

## TL;DR

- 検証を `mark not in ['a'..'e']` から `'abcde'.find(mark) < 0` へ変更した点が穴。
- `find` は**部分文字列**検索なので、**空文字列 `''`** は `'abcde'.find('')==0` で合格。
- 空入力のとき `stock.find('')==0` で**先頭を pop**。
- 空入力を200回で a〜e(=30+60+20+50+40) を抜き切ると在庫は `'f'` だけ。もう一度空入力で
  `'f'` が出て flag。

## Background Knowledge

### `str.find('')` は 0

Python の `s.find('')` は常に 0 を返す（空文字列はどこにでも「ある」）。
`in リスト`（完全一致メンバーシップ）を `find`（部分一致）に置き換えると、
空文字列や部分列が意図せず通る。リファクタで意味が変わる典型的バグ。

## Solution

```
空行を 201 回送る: 先頭(a→…→e)を順に 200 個 pop → 在庫 'f' → 201個目で 'f' 排出
```

実装は `solve.py`（空行を送って `Flag:` を読む）。

## Lessons Learned

- 入力検証を「集合メンバーシップ」から「文字列検索」に変えると、空文字列・部分列という
  新たな入力クラスが通る。検証の意味論を変えるリファクタは要注意。

## Tags

`misc` `logic-bug` `input-validation` `str-find` `empty-string`
