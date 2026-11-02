# [misc] QUIZ ALPACASHOCK

> Daily AlpacaHack 開始以来、2026/09/01 までに公開された A-SIDE 問題数を数える。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | misc (quiz / counting) |
| Difficulty | Medium |
| Date | 2026-11-03 |
| Released | 2026-09-01 |
| Flag | `Alpaca{259}` |

## Problem Statement

> Answer which A-SIDE challenge number today's challenge is since Daily
> AlpacaHack was released. Flag = `Alpaca{N}`.
> Hint: B-SIDE は数えない。リリース日なら Solves 統計の all-time 総数がそのまま答え。
> 後日解くなら、2026/09/01 までの A-SIDE 問題を数える。

## TL;DR

- Daily の開始月は **2025年12月**（2025/11 は calendar 範囲外にリダイレクトされる）。
- 各月の総数（SOLVE STATS の `/N`）:
  `Dec25=31, Jan=31, Feb=28, Mar=31, Apr=30, May=31, Jun=30, Jul=31, Aug=14` → **257**。
- 9月1日には `springing` と `quiz-alpacashock` の **2問**。→ 257 + 2 = **259**。

## Verification (all-time から逆算)

現在（2026/11/03）の all-time 総数 = **283**。9月2日以降を引く:
`Sep残(13-2=11) + Oct(11) + Nov(2) = 24` → `283 - 24 = 259`。2通りで一致。

## Background Knowledge

- SOLVE STATS パネルは Month と All time を切り替えでき、`/N` が A-SIDE の問題数
  （B-SIDE は別トラックで含まない）。all-time はリリース日時点でその日までの累計に一致する
  ため、ヒントの「リリース日なら all-time がそのまま答え」が成り立つ。
- 計数系クイズは、月別 `/N` の合計と all-time からの逆算の**2経路でクロスチェック**すると
  オフバイワンを潰せる。

## Tags

`misc` `quiz` `osint` `counting` `alpacahack-meta`
