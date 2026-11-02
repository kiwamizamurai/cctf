# [pwn] what is my pointer 4

> `malloc` を失敗させて `NULL` を返させると、`ptr[index]` が絶対アドレス読みになる。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | pwn |
| Difficulty | ★★★★☆ (Hard) |
| Date | 2026-11-02 |
| Released | 2026-10-25 |
| Flag | `Alpaca{u_w0n_7h3_g4m3_GG}` |

## Problem Statement

> Can you guess the address?

配布物: `chal`（ELF, PIE, not stripped）, `chal.c`, `Dockerfile`, `compose.yml`。
リモート: `nc HOST PORT`（xinetd 経由、環境変数 `FLAG` に旗）。

## TL;DR

- プログラムは最初に `getenv("FLAG")` の**アドレスを leak** する。
- `item = malloc(size)` の `size` を巨大にすると `malloc` が `NULL` を返す。
- NULL チェックが無いので `item[index]` = `*(unsigned long*)(index*8)` という**絶対読み**になる。
- `index = leak/8` でフラグを8バイトずつ読む。1接続1読みなので、再接続しながら連結する。

## Background Knowledge

### ポインタ添字の算術

`unsigned long *item; item[index]` は `*(item + index)` であり、ポインタ加算は
`sizeof(unsigned long)=8` でスケールされる。`item == NULL(0)` なら、読むアドレスは
`0 + index*8 = index*8`。つまり `index` を選べば任意アドレスの8バイトを読める。

### malloc を失敗させる

`scanf("%ld", &size)` に非常に大きな値を渡すと、`malloc(size)` は割当不能で `NULL` を返す。
本問はその戻り値を検査せずに添字アクセスするため、そのまま絶対読みの原始関数になる。

### ASLR と leak

旗の文字列はスタック上（`envp`）に置かれ、アドレスは実行ごとにランダム化される。
しかし毎回 `[DEBUG] flag: %p` で leak されるため、各接続でその接続のアドレスが分かる。

## Solution

### Step 1: ソース解析

```c
printf("[DEBUG] flag: %p\n", getenv("FLAG")); // ← 旗のアドレスが漏れる
...
unsigned long *item = malloc(size);           // size は任意
scanf("%ld%*c", &index);
printf("0x%lx\n", item[index]);               // ← 絶対読み(size巨大時)
```

### Step 2: 絶対読みの原始関数化

`size = 1<<62` 程度を送って `malloc` を失敗させ `item = NULL` にする。
`index = addr/8` を送れば `*(addr)` の8バイトが16進で返る。

### Step 3: 8バイトずつ回収して連結

1接続で読めるのは1回（8バイト）だけ。再接続しながら、leak した旗アドレスを基準に
8バイト境界で順に読む。接続ごとに `flag_addr % 8` が変わるため、読んだ8バイトを
**旗先頭からの相対オフセット**で辞書に格納して整列させ、NUL 終端まで集める。

```bash
python3 -I solve.py HOST PORT
# -> Alpaca{u_w0n_7h3_g4m3_GG}
```

完全な実装は `solve.py` を参照。pwntools 不使用（標準 socket のみ）。

## Tools Used

| Tool | Purpose |
|------|---------|
| Python socket | リモートとの対話・8バイト読み |

## Lessons Learned

- `malloc`/`calloc` の戻り値を検査しないコードは、割当失敗（NULL）経由で
  「アドレス0基準の任意アクセス」という強力な原始関数を与えてしまう。
- leak されたアドレスと「8倍スケールの添字」を組み合わせるだけで任意アドレス読みになる。
- 1リクエスト1読みでも、再接続と相対オフセット整列で任意長データを復元できる。

## Tags

`pwn` `null-deref` `arbitrary-read` `aslr` `info-leak` `malloc`
