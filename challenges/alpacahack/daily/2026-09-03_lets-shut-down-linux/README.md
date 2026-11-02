# [misc] Let's Shut Down Linux

> `reboot(2)` に正しい magic 定数3つを渡して UML を power off。magic2 の hex は日付。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | misc |
| Difficulty | Medium |
| Date | 2026-11-03 |
| Released | 2026-09-03 |
| Flag | `Alpaca{Did_you_notice_that_hex_values_of_magic2_represent_DD/MM/YYYY_format?}` |

## Problem Statement

User Mode Linux(UML) 上の `/chal` が、`reboot` システムコールの arg1/arg2/arg3 を10進で
受け取る。正しくシャットダウン（returncode 0 かつ出力に `Power down`）できれば flag。

## TL;DR

`reboot(int magic1, int magic2, int cmd, void *arg)` に以下を渡す:

| 引数 | 定数 | hex | 10進 |
|---|---|---|---|
| arg1 | `LINUX_REBOOT_MAGIC1` | `0xfee1dead` | 4276215469 |
| arg2 | `LINUX_REBOOT_MAGIC2` | `0x28121969` | 672274793 |
| arg3 | `LINUX_REBOOT_CMD_POWER_OFF` | `0x4321fedc` | 1126301404 |

## Background Knowledge

- `reboot(2)` は誤使用防止に2つの magic を要求する。`MAGIC1=0xfee1dead`、
  `MAGIC2` は `0x28121969`（他に 05121996 / 16041998 / 20112000 も可）。
- これらの hex は Linus やカーネル開発者の誕生日を DD/MM/YYYY で表す小ネタ
  （`28/12/1969` 等）。フラグがそれを示唆している。
- POWER_OFF (`0x4321fedc`) を指定すると UML は "Power down" を出して exit 0。

## Solution

プロンプトに従い arg1=4276215469, arg2=672274793, arg3=1126301404 を送るだけ。
`solve.py` は接続→3値送信→`Alpaca{...}` を回収（UML ビルド待ちのリトライ付き）。

## Lessons Learned

- `reboot(2)` の magic 定数は暗記ではなく `<linux/reboot.h>` を見る。
- 出題者の遊び心（hex=日付）に気づくと記憶に残る。

## Tags

`misc` `linux` `syscall` `reboot` `uml` `magic-constants`
