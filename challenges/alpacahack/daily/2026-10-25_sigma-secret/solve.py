#!/usr/bin/env python3
"""Sigma-secret (Σecret) - AlpacaHack Daily (crypto, Easy).

For each 8-byte flag block: x = block[:4], y = 2**32 + block[4:]. The server
prints the power sums [s1, s2] = [x+y, x^2+y^2]. From them:
    xy = (s1^2 - s2) / 2
so x, y are the roots of t^2 - s1*t + xy = 0. Recover each block, concatenate.

Usage: python3 -I solve.py HOST PORT
"""
import ast
import socket
import sys
from math import isqrt

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
OFFSET = 1 << 32


def read_all(host, port):
    s = socket.create_connection((host, port), timeout=20)
    s.settimeout(5)
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    finally:
        s.close()
    return data.decode(errors="replace")


def solve_block(s1, s2):
    xy = (s1 * s1 - s2) // 2
    disc = s1 * s1 - 4 * xy
    r = isqrt(disc)
    assert r * r == disc, "non-square discriminant"
    a = (s1 + r) // 2
    b = (s1 - r) // 2
    # x is the small root (< 2**32), y the large (>= OFFSET)
    x, y = (a, b) if a < b else (b, a)
    return x.to_bytes(4, "big") + (y - OFFSET).to_bytes(4, "big")


def main():
    text = read_all(HOST, PORT)
    flag = b""
    for line in text.splitlines():
        line = line.strip()
        if not (line.startswith("[") and line.endswith("]")):
            continue
        s1, s2 = ast.literal_eval(line)
        flag += solve_block(s1, s2)
    print(flag.rstrip(b"\x00").decode())


if __name__ == "__main__":
    main()
