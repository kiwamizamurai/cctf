#!/usr/bin/env python3
"""
lets-poly1305 — AlpacaHack Daily 2026-07-08

The server prints r (the Poly1305 key half), tags one chosen message, and gives
the flag if we supply the tag for TARGET=b"admin=true" (which we may not send as
the message). Poly1305 tag = (acc_r(m) + s) mod 2^128 with s secret. Since r is
known, one (message, tag) pair reveals s = (tag - acc_r(m)) mod 2^128, and then
we forge TARGET's tag = (acc_r(TARGET) + s) mod 2^128.

Usage: python3 solve.py <host> <port>
"""
import socket, sys, time, re

P = (1 << 130) - 5
CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffff
TARGET = b"admin=true"

def acc(r16, m):
    r = int.from_bytes(r16, "little") & CLAMP
    a = 0
    for i in range(0, len(m), 16):
        blk = m[i:i+16]
        a = (a + (int.from_bytes(blk, "little") | (1 << (8*len(blk))))) * r % P
    return a

def tag_for(r16, s, m):
    return ((acc(r16, m) + s) % (1 << 128)).to_bytes(16, "little").hex()

HOST, PORT = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((HOST, PORT), timeout=20); s.settimeout(20)
f = s.makefile("rwb", buffering=0)
r_hex = re.search(r"r:\s*([0-9a-f]{32})", f.readline().decode()).group(1)
r16 = bytes.fromhex(r_hex)
msg = b"forge me please!"
time.sleep(0.2); s.sendall(msg + b"\n")
# read the tag for our message (line may be prefixed with the "message: " prompt)
tag1 = None
while tag1 is None:
    line = f.readline().decode(errors="replace")
    m = re.search(r"([0-9a-f]{32})", line)
    if m:
        tag1 = m.group(1)
sval = (int.from_bytes(bytes.fromhex(tag1), "little") - acc(r16, msg)) % (1 << 128)
forged = tag_for(r16, sval, TARGET)
time.sleep(0.2); s.sendall(forged.encode() + b"\n")
out = b""
try:
    while True:
        d = s.recv(4096)
        if not d:
            break
        out += d
except Exception:
    pass
out = out.decode(errors="replace")
mm = re.search(r"Alpaca\{[^}]*\}", out)
print(mm.group(0) if mm else repr(out))
