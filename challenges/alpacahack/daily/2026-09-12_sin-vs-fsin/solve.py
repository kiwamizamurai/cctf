#!/usr/bin/env python3
"""sin function vs. fsin instruction - AlpacaHack Daily (rev/misc).
The x86 `fsin` instruction does not compute for |operand| >= 2**63; it returns
the operand unchanged (sets C2). libc sin() always returns a value in [-1,1].
So a large finite theta (e.g. 1e300) makes |sin_1 - sin_2| ~= 1e300 > 1337.
Usage: python3 -I solve.py HOST PORT"""
import re, socket, sys
H, P = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((H, P), timeout=20); s.settimeout(8)
buf=b""
try:
    while b"theta" not in buf:
        buf += s.recv(4096)
    s.sendall(b"1e300\n")
    data=buf
    while True:
        try: ch=s.recv(4096)
        except socket.timeout: break
        if not ch: break
        data+=ch
finally:
    s.close()
m=re.search(rb"Alpaca\{[^}]*\}", data)
print(m.group(0).decode() if m else data.decode(errors="replace"))
