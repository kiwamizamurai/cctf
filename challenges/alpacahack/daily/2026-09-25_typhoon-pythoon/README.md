# [rev] typhoon-pythoon

> Python 3.10 の .pyc を逆アセンブルし、位置依存 XOR の逆変換を再現する。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | rev |
| Difficulty | Easy-Medium |
| Date | 2026-11-03 |
| Released | 2026-09-25 |
| Flag | `Alpaca{dis_is_the_eye_of_the_typhoon}` |

## Problem Statement

配布: `server.pyc`（Python 3.10 コンパイル済み）。「台風の目の中にファイルを移動せよ」。

## TL;DR

- `.pyc` を `xdis`（クロスバージョン逆アセンブラ）で解析。
- `is_inside_the_typhoon_eye`: `Path(__file__).resolve().parent.name == "eye"`
  （親ディレクトリ名が `eye` であることを要求）。
- `main`: `input() == reverse_the_wind(EYE_DATA)` なら正解。つまり
  **flag = `reverse_the_wind(EYE_DATA)`**。
- `reverse_the_wind`（`location = b"eye"`）:
  ```
  place = location[i % 3]              # b"eye"[i%3]
  wind  = (i*7 + 41 + place) & 255
  flag[i] = chr(EYE_DATA[i] ^ wind)
  ```

## Background Knowledge

### .pyc の逆アセンブル

マジック `0x6f0d0d0a` は Python 3.10。手元が別バージョンでも、純 Python の `xdis`
（`pydisasm`）で定数テーブル（`EYE_DATA`）とバイトコードを取り出せる。
ロジックを読み取れば復号器を書ける（完全な逆コンパイル不要）。

### 位置依存 XOR

各バイトを「位置 i とディレクトリ名から導いた鍵 `wind`」で XOR。鍵は
`(i*7 + 41 + ("eye"の対応バイト)) & 255`。暗号化と復号が同形（XOR）なので、
同じ式を適用すれば flag が戻る。ディレクトリ名 `eye` が鍵材料なのが「台風の目」のネタ。

## Solution

`EYE_DATA`（37 バイト）と `location=b"eye"` から上式で復号。実装は `solve.py`。

## Tools Used

| Tool | Purpose |
|------|---------|
| xdis (pydisasm) | 3.10 .pyc の逆アセンブル・定数抽出 |

## Lessons Learned

- バージョン違いの `.pyc` でも、逆コンパイルに固執せず**逆アセンブル＋ロジック再現**で足りる。
- 鍵がファイルの配置（親ディレクトリ名）に依存する「環境依存チェック」も、読み解けば定数化できる。

## Tags

`rev` `python` `pyc` `bytecode` `xdis` `xor` `position-dependent`
