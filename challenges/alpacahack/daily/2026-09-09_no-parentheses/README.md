# [misc] ＼^o^／ (no-parentheses)

> 括弧なしで属性代入できる内包表記 for ターゲットと、`__class_getitem__` 上書きで添字を呼び出しに化かす。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | misc (pyjail) |
| Difficulty | Medium |
| Date | 2026-11-03 |
| Released | 2026-09-09 |
| Flag | `Alpaca{v(^-^)v<nice!}` |

## Problem Statement

```python
# python -S jail.py
import re
eval(re.sub(r"[()]", "", input("> ")))
```

入力から `(` `)` が全除去されて `eval` される。flag は作業ディレクトリの `flag.txt`。

## TL;DR

- 括弧が消えるので**関数呼び出し(call ノード)が作れない**。
- だが2つの抜け道で呼び出しを合成する:
  1. **内包表記の for ターゲットは属性/添字を取れる** → `[d.x for d.x in [v]]` で
     括弧なしに `d.x = v` を代入できる。
  2. **クラスの添字 `Cls[...]` は `__class_getitem__` を呼ぶ**。`re.error`（Python 定義の
     例外クラス、`re` import 済みで参照可）の `__class_getitem__` を上書きすれば、
     `re.error[...]` が任意関数呼び出しになる。
- `__class_getitem__ = __import__` → `re.error["os"]` = `__import__("os")`。walrus で保存。
  次に `__class_getitem__ = os.system` → `re.error["cat flag.txt"]` でシェル実行。

## Solution

ペイロード（括弧ゼロ、カンマ区切りでタプルとして順次評価）:

```python
[re.error for re.error.__class_getitem__ in[__import__]],[osmod:=re.error["os"]],[re.error for re.error.__class_getitem__ in[osmod.system]],re.error["cat flag.txt"]
```

ローカルに同一 jail を立てて検証後、リモートへ送信。実装は `solve.py`。

## Background Knowledge

### for ターゲットの代入先

`for TARGET in ITER` の TARGET は代入可能な任意の左辺値（名前・属性 `a.b`・添字 `a[b]`・
タプル）。内包表記でも同じなので、`[a.b for a.b in [v]]` は `a.b = v` を括弧なしで行う。

### `__class_getitem__`

`SomeClass[x]` は `type(SomeClass).__class_getitem__` ではなく、クラス自身の
`__class_getitem__(x)` を呼ぶ（PEP 560、ジェネリクス用）。これを差し替えると、
クラスへの添字アクセスが「1引数の関数呼び出し」になる。`re.error` は Python 実装の
例外クラスなので属性を書き換えられる（C 実装の型は不可のことが多い）。

### walrus でグローバルに残す

内包表記内の for ターゲットはその内包のスコープに閉じる。モジュールを後段で使うため、
`osmod := re.error["os"]` と walrus で外側スコープの名前に束縛しておく。

## Lessons Learned

- 「括弧禁止」でも、**代入可能な for ターゲット**と**演算子/添字が呼ぶ dunder**を
  組み合わせると呼び出しを再現できる。pyjail の定番の深いテク。
- 書き換え可能なのは Python 実装クラス（`re.error` 等）。C 実装型の dunder は差し替え不可。

## Tags

`misc` `pyjail` `no-parentheses` `class_getitem` `comprehension-target` `walrus`
