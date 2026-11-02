# [rev] x32 ABI flag checker

> 隣接2文字を16bitにして掛け算+XOR→MD5。入力空間が16bitなので総当たりで逆算できる。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | rev |
| Difficulty | ★★★★☆ (Hard) |
| Date | 2026-11-03 |
| Released | 2026-10-23 |
| Flag | `Alpaca{Wh@7_aN_Interesting_&_3X071C_ABI!}` |

## Problem Statement

> This is a flag checker built to use the x32 ABI!
> 静的解析だけでも解けると明記されている（x32 ABI は将来カーネルから削除される可能性）。

配布物: `chal`（**x32 ABI** = ELFCLASS32 ヘッダ + x86-64 命令、静的リンク、not stripped）。

## TL;DR

- 正解なら `Correct! The flag is %s`（= 正しい入力がそのままフラグ）。
- `is_correct`: 入力長 41 必須。`i=0..39` で隣接ペア `(flag[i], flag[i+1])` を変換して
  `expected[i]`（16バイト×40、0x4c40e0）と memcmp。
- 変換 `some_proc`:
  ```
  x   = (flag[i] << 8) | flag[i+1]              # 16bit
  val = (x * 0x3233504c49) ^ 0x4942412d323378   # "ILP32" を乗算, "x32-ABI" を XOR
  expected[i] = MD5( val.to_bytes(8,'little') )
  ```
- `x` が 0..65535 しかないので、全 `x` の MD5 を作って `expected` と照合→各ペア確定→連結。

## Background Knowledge

### x32 ABI

x86-64 の 64bit 命令セットを使いつつポインタ/long を 32bit(ILP32)にする ABI。
ディスアセンブルは x86-64 として読めるが、アドレスやポインタ演算が 32bit 幅
（`mov eax,...` でアドレス切り詰め、`67` アドレスサイズプリフィックス多用）。
実行には x32 対応カーネルが要るが、本問はロジックが静的に追えるため実行不要。

### 定数の正体

- `0x3233504c49` → バイト `49 4c 50 33 32` = `"ILP32"`
- `0x4942412d323378` → バイト `78 33 32 2d 41 42 49 00` = `"x32-ABI\0"`

味付けの定数だが、乗算・XOR はいずれも可逆で、かつ入力空間が小さいので総当たりで足りる。

## Solution

1. ELF の PT_LOAD を解析し、vaddr `0x4c40e0` の `expected`（640バイト）を取得。
2. `x=0..65535` について `MD5(LE64((x*M)^K))` を計算し、ダイジェスト→x の辞書を作る。
3. 各 `expected[i]` を辞書引きして `x` を得て、`flag[i]=x>>8`, `flag[i+1]=x&0xff`。
   連鎖するので 40 ペアから 41 文字が復元できる。

```bash
python3 -I solve.py dist/chal
# -> Alpaca{Wh@7_aN_Interesting_&_3X071C_ABI!}
```

実装は `solve.py`（標準ライブラリのみ、バイナリ実行不要）。

## Tools Used

| Tool | Purpose |
|------|---------|
| objdump | 逆アセンブル（main/is_correct/some_proc） |
| Python hashlib/struct | expected 抽出と MD5 総当たり逆算 |

## Lessons Learned

- 「ハッシュで比較」でも、ハッシュ入力の空間が小さければ（ここでは16bit）総当たりで
  前像を求められる。1文字ずつでなく隣接ペアでも、連鎖させれば全体が決まる。
- 見慣れない ABI（x32）でも、命令は x86-64 として読める。実行環境が無くても
  静的解析で十分攻略できる good example。

## Tags

`rev` `x32-abi` `md5` `bruteforce` `static-analysis` `flag-checker`
