# [rev] C# File-based app

> 比較対象が埋め込まれているだけの逆算問題。base64 → Brotli 解凍で平文が出る。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | rev |
| Difficulty | ★★☆☆☆ (Easy 🌱) |
| Date | 2026-11-02 |
| Released | 2026-10-03 |
| Flag | `Alpaca{broooooooooooooooooooooooooooooooooooooootli}` |

## Problem Statement

> Thanks to the File-based apps feature added in .NET 10, we can now run a .cs
> file directly!
> Hint1: Implicit using directives / Hint2: How to handle the Brotli compression format

配布物: `chal.cs`, `run-using-docker.sh`。

## TL;DR

- `chal.cs` は入力を、埋め込み base64 を **base64 デコード → Brotli 解凍**した結果と比較するだけ。
- その平文がそのままフラグ。

## Solution

`chal.cs` の核心:

```csharp
ReadOnlySpan<byte> encoded = "GzMA+MVtbG/XtFYgGNGLSpSiwoAdaiYvxraqBw=="u8;
Base64.DecodeFromUtf8(encoded, temp1, ...);      // base64 デコード
new BrotliDecoder().Decompress(temp1, temp2, ...);// Brotli 解凍
return temp2.SequenceEqual(utf8(input));           // 入力と一致判定
```

よって埋め込み文字列を復号すればよい:

```bash
printf 'GzMA+MVtbG/XtFYgGNGLSpSiwoAdaiYvxraqBw==' | base64 -d | brotli -d -c
# -> Alpaca{broooooooooooooooooooooooooooooooooooooootli}
```

## Tools Used

| Tool | Purpose |
|------|---------|
| base64 | base64 デコード |
| brotli (CLI) | Brotli 解凍 |

## Lessons Learned

- 「入力 == 既知の値を変換したもの」という比較は、変換を逆に辿るだけで解ける。
  暗号ではなく単なるエンコード（base64 / 圧縮）であることを見抜く。
- .NET 10 の file-based app (`#!/usr/bin/env dotnet`) と implicit usings の小ネタ。

## Tags

`rev` `csharp` `dotnet` `base64` `brotli` `encoding`
