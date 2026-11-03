#!/usr/bin/env python3
"""
happy-birthday — AlpacaHack Daily 2026-08-05

Server reveals FLAG iff two byte strings a,b satisfy:
  a != b, a.startswith(b"user="), b.startswith(b"admin="),
  and H(a)==H(b) where H(m)=sha256(m)[:5]  (40-bit truncated hash).

A 40-bit digest → ~2^20 work per side to find a cross-collision between the
"user=" family and the "admin=" family (birthday attack). Build a table of
H(user=<i>), then scan H(admin=<j>) until one hits the table.

Usage: python3 solve.py [host port]  (omit host/port to only print a,b hex)
"""
import socket, sys
from hashlib import sha256

def H(m): return sha256(m).digest()[:5]

def find_collision():
    seen = {}
    i = 0
    while True:
        a = b"user=" + str(i).encode()
        seen[H(a)] = a
        i += 1
        if i % 2000000 == 0:   # safety valve; shouldn't be needed for 40-bit
            pass
        # interleave the admin search once we have a decent table
        if i >= 1 << 20:
            j = 0
            while True:
                b = b"admin=" + str(j).encode()
                h = H(b)
                if h in seen:
                    return seen[h], b
                j += 1

if __name__ == "__main__":
    a, b = find_collision()
    assert a != b and a.startswith(b"user=") and b.startswith(b"admin=") and H(a) == H(b)
    print("a =", a.hex())
    print("b =", b.hex())
    if len(sys.argv) >= 3:
        host, port = sys.argv[1], int(sys.argv[2])
        s = socket.create_connection((host, port), timeout=30); s.settimeout(30)
        import time
        f = s.makefile("rwb", buffering=0)
        # read "user hex > " prompt then send
        time.sleep(0.3); s.sendall(a.hex().encode() + b"\n")
        time.sleep(0.3); s.sendall(b.hex().encode() + b"\n")
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                data += chunk
        except Exception: pass
        s.close()
        print(data.decode(errors="replace"))
