#!/bin/sh
# zen-zip — AlpacaHack Daily 2026-07-29
#
# zen.zip holds zen.txt and flag.txt, both ZipCrypto-encrypted with the same
# password (`zip -0 -X -P ...`). zen.txt is `python -m this` output — the Zen of
# Python — a fully known plaintext. ZipCrypto is broken by a known-plaintext
# attack (Biham-Kocher) that recovers the 96-bit internal keys, which decrypt
# EVERY entry (including flag.txt) regardless of per-file headers.
#
# Requires bkcrack (https://github.com/kimci86/bkcrack).
set -eu

BK=${BK:-bkcrack}

# 1) Known plaintext (identical bytes to the archived zen.txt, 857 bytes)
python3 -m this > zen_plain.txt

# 2) Recover the internal keys from zen.txt
$BK -C zen.zip -c zen.txt -p zen_plain.txt
# -> Keys: af181a46 04beb6d8 cbfe0bd2

# 3) Decrypt flag.txt with those keys
$BK -C zen.zip -c flag.txt -k af181a46 04beb6d8 cbfe0bd2 -d flag_dec.bin
cat flag_dec.bin
# -> Alpaca{Neurogolf 7957 is a scam.}
