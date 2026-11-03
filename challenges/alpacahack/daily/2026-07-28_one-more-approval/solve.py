#!/usr/bin/env python3
"""
one-more-approval — AlpacaHack Daily 2026-07-28

The server signs a fixed message with ECDSA (P-256, PyCryptodome DSS
"fips-186-3"), prints the signature, and gives the flag if we submit a *different*
signature that still verifies for the same message.

ECDSA signatures are malleable: if (r, s) is valid then so is (r, n - s), where n
is the curve group order (FIPS 186-3 mode does not enforce low-s). The DSS
encoding is r||s as two fixed 32-byte big-endian integers, so we just negate s.

Usage: python3 solve.py <host> <port>
"""
import socket, sys, time, re

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # P-256 order

def forge(sig: bytes) -> bytes:
    assert len(sig) == 64
    r, s = sig[:32], int.from_bytes(sig[32:], "big")
    s2 = (N - s) % N
    return r + s2.to_bytes(32, "big")

def solve(host, port):
    s = socket.create_connection((host, port), timeout=20); s.settimeout(20)
    f = s.makefile("rwb", buffering=0)
    given = bytes.fromhex(f.readline().decode().strip())
    forged = forge(given)
    assert forged != given
    time.sleep(0.2)
    s.sendall(forged.hex().encode() + b"\n")
    buf = b""
    try:
        while True:
            d = s.recv(4096)
            if not d: break
            buf += d
    except Exception: pass
    s.close()
    m = re.search(rb"Alpaca\{[^}]*\}", buf)
    return m.group(0).decode() if m else buf.decode(errors="replace")

if __name__ == "__main__":
    print(solve(sys.argv[1], int(sys.argv[2])))
