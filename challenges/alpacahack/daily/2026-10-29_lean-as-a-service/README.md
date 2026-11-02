# [misc] Lean as a Service

> 「証明を検証するだけ」の Web サービスでも、処理系が評価器を内蔵していれば RCE になる。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | misc |
| Difficulty | ★★★★☆ (Medium 4.5) |
| Date | 2026-11-02 |
| Released | 2026-10-29 |
| Flag | `Alpaca{proof_of_presence}` |

## Problem Statement

> I made a web service where you can easily play with the trendy Lean.
> It only verifies proofs, so you can't do anything bad to the server, right?

配布物: `lean-as-a-service.tar.gz`（`app.py`, `Dockerfile`, `compose.yaml`, `flag.txt`）。
リモート: `Spawn Challenge Server` で払い出される `http://HOST:PORT`。

## TL;DR

- Flask が投稿された Lean ソースを `lean Main.lean` でそのまま処理する。
- Lean 4 は **elaboration 時に `#eval` で IO アクションを実行する**。つまり任意コード実行。
- `#eval` から `sh -c 'cat /flag-*.txt'` を実行し、stdout に出力させて結果欄で回収する。

## Background Knowledge

### Lean 4 の `#eval`

Lean 4 はコマンド `#eval e` を**ファイルの読み込み（elaboration）時**に評価する。
`e` が `IO α` 型なら、その IO アクションが実際に走る。`IO.Process.run` で外部プロセスを
起動できるため、「証明の検証」だけのつもりでも任意コマンド実行になってしまう。
`lean Main.lean` は検証コマンドだが、ソースに `#eval` が含まれれば評価は避けられない。

### フラグの場所

Dockerfile で `flag.txt` を `/flag-<md5>.txt` にリネームしている。
名前の md5 部分は不明だが、`/flag-*.txt` のグロブで一致させればよい。

```dockerfile
COPY --chmod=444 flag.txt /flag.txt
RUN mv /flag.txt /flag-$(md5sum /flag.txt | awk '{print $1}').txt
```

## Solution

### Step 1: ソースを読む

`app.py` の `check()` は、投稿された `source` を `Main.lean` に書き出して
`lean Main.lean` を実行し、stdout+stderr をそのまま結果として返す。
入力に対するフィルタは「4000 バイト以下」のみ。

### Step 2: `#eval` で RCE

Lean の `#eval` が elaboration 時に IO を実行することを使う。

```lean
#eval do
  let out ← IO.Process.run { cmd := "sh", args := #["-c", "cat /flag-*.txt"] }
  IO.print out
```

これを `source` として POST すると、`lean` が `#eval` を評価して `cat` を実行し、
フラグが stdout に出る。app はそれを `<pre>` に表示する（status は `accepted`）。

### Step 3: フラグ回収

```bash
python3 -I solve.py "http://HOST:PORT"
# status: accepted
# result: Alpaca{proof_of_presence}
```

`solve.py` 参照。

## Tools Used

| Tool | Purpose |
|------|---------|
| tar | 配布アーカイブ展開 |
| Python urllib | ペイロード POST |

## Lessons Learned

- 「評価しない／検証だけ」をうたうサービスでも、処理系に評価器（`#eval`, マクロ,
  コンパイル時実行）があれば RCE になりうる。Lean, TeX, SQL, テンプレートエンジンなど
  同系統の罠は多い。
- フラグ名が動的（md5 付き）でもグロブで回避できる。

## Tags

`misc` `rce` `lean4` `code-evaluation` `web`
