# B-SIDE is Back

- **Platform**: AlpacaHack (Daily)
- **Category**: Misc / OSINT (Welcome 🌱)
- **Released**: 2026-11-01
- **Flag**: `Alpaca{we_will_rock_you}`

## Challenge

> A vinyl single has an A-side and a B-side. What song was on the B-side of
> Queen's 1977 UK single "We Are the Champions"?
>
> Submit the song title in lowercase, replacing spaces with `_`, in the format `Alpaca{...}`.

## Solution

トリビア（調べ物）問題。Queen は1977年10月に「We Are the Champions」を UK シングルとして
発売し、その B面が「We Will Rock You」だった（両曲ともアルバム『News of the World』収録）。

指定の形式に合わせて変換する。

```
"We Will Rock You"  ->  小文字化・スペースを _  ->  we_will_rock_you
```

## Flag

```
Alpaca{we_will_rock_you}
```
