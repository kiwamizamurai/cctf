# [misc/pwn] integer division

> `y==0` だけ守っても足りない。`INT_MIN / -1` は x86 `idiv` で #DE(→SIGFPE) を起こす。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | misc / pwn |
| Difficulty | Easy |
| Date | 2026-11-03 |
| Released | 2026-09-14 |
| Flag | `Alpaca{The_IDIV_instruction_generates_#DE_and_Linux_converts_it_to_SIGFPE}` |

## Problem Statement

```c
scanf("%d", &x); scanf("%d", &y);
if (y == 0) puts("Division by zero is prohibited.");
else { int result = x / y; printf("result: %d\n", result); }
return 0;
```
`server.py` は `chal` の returncode が 0 以外なら flag を出す。

## TL;DR

- `y==0` 以外にも危険な入力がある: **`INT_MIN / -1`**。
- `-2147483648 / -1 = 2147483648` は `int`(32bit) に収まらずオーバーフロー。x86 の
  `idiv` は商がオペランド幅に収まらないと **#DE（Divide Error）例外**を出す。
- Linux は #DE を **SIGFPE** に変換してプロセスを殺す → returncode ≠ 0 → flag。
- 入力: `x = -2147483648`, `y = -1`。

## Background Knowledge

### `idiv` のオーバーフロー例外

x86 の除算命令 `div`/`idiv` は、**0 除算だけでなく商がデスティネーション幅を超えた
場合も #DE を発生**させる。符号付き 32bit では `INT_MIN / -1 = 2^31` が `int` の最大
`2^31-1` を超えるため #DE。C 言語的にも `INT_MIN / -1` は未定義動作。
Linux カーネルは #DE を SIGFPE にマップする。

## Solution

```
x> -2147483648
y> -1
-> SIGFPE -> returncode != 0 -> Alpaca{...}
```

実装は `solve.py`（2値を送るだけ）。

## Lessons Learned

- 整数除算の危険は 0 除算だけではない。符号付きオーバーフロー `INT_MIN / -1` も
  ハードウェア例外になる古典的な落とし穴。
- 「想定外終了で flag」= クラッシュを誘発する最小入力を探すのが定石。

## Tags

`misc` `pwn` `integer-overflow` `idiv` `sigfpe` `undefined-behavior`
