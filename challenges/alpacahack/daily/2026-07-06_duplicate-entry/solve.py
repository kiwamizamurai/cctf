#!/usr/bin/env python3
"""
duplicate-entry — AlpacaHack Daily 2026-07-06

make_zip.py writes 100 entries all named "flag.txt"; only i==50 holds the real
FLAG, the rest are "No flag here. Try harder." Normal extraction keeps just one
(the last/overwriting one), so you "won't get the real flag.txt after
extraction." But every entry is still in the archive — the real one is the
single entry whose size/CRC differ from the decoys. Read that entry directly.
"""
import zipfile

z = zipfile.ZipFile("dist/ex/duplicate-entry/flag.zip")
for info in z.infolist():
    if info.filename == "flag.txt" and info.file_size != 25:  # decoys are 25 bytes
        print(z.open(info).read().decode())
