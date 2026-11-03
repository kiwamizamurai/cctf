#!/usr/bin/env python3
"""
lets-poly1305-2 — AlpacaHack Daily 2026-07-14

This time `s` is leaked (not `r`). Poly1305 tag = (acc_r(m) + s) mod 2^128.
Send a one-block message m1 (16 bytes); its tag gives
  acc_r(m1) mod 2^128 = (tag1 - s) mod 2^128
and acc_r(m1) = c1 * r mod p, with p = 2^130-5 and c1 = int(m1,'little')|2^128.
The full acc is one of acc0 + k*2^128 (k=0..3, < p). For each candidate solve
  r = acc * c1^{-1} mod p
and keep the one matching Poly1305's clamp (r == r & CLAMP, r < 2^128). Then
forge the TARGET tag with recovered r and known s.

Usage: python3 solve.py <host> <port>
"""
import socket, sys, time, re

P = (1 << 130) - 5
CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffff
TARGET = b"admin=true"

def acc_clamped(r_int, m):
    a = 0
    for i in range(0, len(m), 16):
        blk = m[i:i+16]
        a = (a + (int.from_bytes(blk, "little") | (1 << (8*len(blk))))) * r_int % P
    return a

def recover_r(m1, s16, tag1_hex):
    c1 = int.from_bytes(m1, "little") | (1 << (8*len(m1)))
    a0 = (int.from_bytes(bytes.fromhex(tag1_hex), "little") - int.from_bytes(s16, "little")) % (1 << 128)
    invc = pow(c1 % P, -1, P)
    out = []
    for k in range(5):
        a = a0 + k * (1 << 128)
        if a >= P:
            break
        r = a * invc % P
        if r == (r & CLAMP) and r < (1 << 128):
            out.append(r)
    return out

def forge(r_int, s16, m):
    return ((acc_clamped(r_int, m) + int.from_bytes(s16, "little")) % (1 << 128)).to_bytes(16, "little").hex()

HOST, PORT = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((HOST, PORT), timeout=20); s.settimeout(20)
f = s.makefile("rwb", buffering=0)
s_hex = re.search(r"s:\s*([0-9a-f]{32})", f.readline().decode()).group(1)
s16 = bytes.fromhex(s_hex)
m1 = b"A" * 16
time.sleep(0.2); s.sendall(m1 + b"\n")
tag1 = None
while tag1 is None:
    line = f.readline().decode(errors="replace")
    m = re.search(r"([0-9a-f]{32})", line)
    if m:
        tag1 = m.group(1)
cands = recover_r(m1, s16, tag1)
assert cands, "no clamped r candidate"
forged = forge(cands[0], s16, TARGET)
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
s.close()
mm = re.search(rb"Alpaca\{[^}]*\}", out)
print(mm.group(0).decode() if mm else repr(out))
