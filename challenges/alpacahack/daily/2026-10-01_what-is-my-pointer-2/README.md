# [pwn] what is my pointer 2

> libc leak と任意アドレス読みがあれば、`environ` 経由でスタック上の環境変数を読める。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | pwn |
| Difficulty | ★★★★☆ (Hard) |
| Date | 2026-11-02 |
| Released | 2026-10-01 |
| Flag | `Alpaca{33333333nnnnnnnnvvvvvvvv11111111rrrrrrrr00000000nnnnnnnn}` |

## Problem Statement

> "The Usefulness of Useless Knowledge" (Abraham Flexner, 1939)

配布物: `chal`(ELF), `chal.c`, `Dockerfile`, `compose.yml`。リモートは xinetd + `nc`、FLAG は環境変数。

```c
printf("printf @ %p\n", printf);     // libc leak
while (1) {
    scanf("%lx%*c", &ptr);
    printf("%lx\n", *(unsigned long *)ptr);   // 任意アドレス読み(無限)
}
```

## TL;DR

- `printf` のアドレスが漏れる → libc ベース = `printf − printf_off`。
- libc の `environ` シンボルはスタック上の `envp` 配列アドレスを保持している。
- `*environ` を読んで `envp` を辿り、`FLAG=` で始まる文字列を読む。

## Background Knowledge

### `environ` でスタックアドレスを得る

glibc は `char **environ` をエクスポートしており、その値はスタック上の環境変数
ポインタ配列を指す。スタックの leak が無くても、libc ベースさえ分かれば
`libc_base + off(environ)` を読めばスタックアドレスが手に入る。pwn 定番テク。

### libc の特定

`Dockerfile` は `ubuntu:24.04` を digest 固定。glibc は 2.39 系。リモートで
`printf` 末尾が `0x100` だったため、ローカルの `2.39-0ubuntu8`(printf 末尾 `0x0f0`)
とは別ビルド。任意読みで実アドレスを確認し、`printf_off=0x60100`,
`environ_off=0x20ad58` を確定した（`*environ` がスタックアドレス `0x7ff...` を返すことで検証）。

## Solution

1. `printf` を leak、`base = printf − 0x60100`。
2. `envp = *(base + 0x20ad58)`。
3. `envp[0], envp[1], ...` を辿り、`FLAG=` で始まる文字列をバイト列として読む。

読みは1回ごとにネットワーク往復で、リモートは180秒で `timeout` するため、オフセット
直打ちで読み回数を十数回に抑えるのが肝（メモリ上 ELF をフル解析すると数百往復で間に合わない）。
実装は `solve.py`（標準 socket のみ）。

## Lessons Learned

- 任意アドレス読み + 任意の libc leak = 実質「どこでも読める」。`environ` は
  スタックへの定番の入口。
- リモート libc の特定は重要。digest 固定でもローカルに同一ビルドが無ければ、
  任意読みで実オフセットを現地採取するのが確実。
- ネットワーク越しの1リクエスト1リードは高コスト。往復回数が解けるか否かを分ける。

## Tags

`pwn` `arbitrary-read` `libc-leak` `environ` `aslr` `info-leak`
