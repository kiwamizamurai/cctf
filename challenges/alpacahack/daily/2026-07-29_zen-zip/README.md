# [forensics] zen.zip

> ZipCrypto with a known-plaintext file (`python -m this`) falls to the Biham–Kocher attack, recovering keys that decrypt every entry.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | forensics / crypto |
| Difficulty | ★★☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{Neurogolf 7957 is a scam.}` |

## Problem Statement

> Beautiful is better than ugly.
>
> `zen-zip.tar.gz`

## TL;DR

- `make_zip.sh`: `python -m this > zen.txt; printf '%s\n' "$FLAG" > flag.txt; zip -0 -X -P "$PASSWORD" zen.zip zen.txt flag.txt`.
- Both entries use legacy **ZipCrypto** with the same password. `zen.txt` is `python -m this` — the Zen of Python — a byte-for-byte **known plaintext** (857 bytes).
- ZipCrypto is vulnerable to the Biham–Kocher known-plaintext attack: recover the 96-bit internal keys from `zen.txt`, then decrypt `flag.txt` (same keys for all entries). Tool: `bkcrack`.

## Background Knowledge

### ZipCrypto (traditional PKWARE) is weak

ZipCrypto keeps three 32-bit keys initialized from the password, then updated byte-by-byte. Given ≥~12 bytes of known plaintext for one entry, the Biham–Kocher attack recovers the internal key state. Because the password-derived initial keys are shared by all entries in the archive, those recovered keys decrypt **every** file — you never need the password itself.

### Why `python -m this` is perfect known plaintext

`python -m this` prints a fixed text (the Zen of Python). Stored with `-0` (no compression), the archived `zen.txt` bytes equal that text exactly — here 857 bytes, matching the archive's entry size.

## Solution

```sh
python3 -m this > zen_plain.txt                 # 857-byte known plaintext
bkcrack -C zen.zip -c zen.txt -p zen_plain.txt  # -> Keys: af181a46 04beb6d8 cbfe0bd2
bkcrack -C zen.zip -c flag.txt -k af181a46 04beb6d8 cbfe0bd2 -d flag_dec.bin
cat flag_dec.bin                                # Alpaca{Neurogolf 7957 is a scam.}
```

See [`solve.sh`](solve.sh). `bkcrack` was built from source (kimci86/bkcrack). The attack took a few seconds.

## Tools Used

| Tool | Purpose |
|------|---------|
| `python -m this` | Generate the exact known plaintext |
| `bkcrack` | Biham–Kocher known-plaintext attack on ZipCrypto |

## Lessons Learned

- Never rely on ZipCrypto: any predictable file in the archive (a license, a known header, `python -m this`) gives a known-plaintext break that exposes every entry.
- Store mode (`-0`) makes the plaintext equal the file bytes, simplifying the attack — compression would have required knowing the deflate stream.

## Tags

`forensics` `zipcrypto` `known-plaintext` `biham-kocher` `bkcrack` `zip`
