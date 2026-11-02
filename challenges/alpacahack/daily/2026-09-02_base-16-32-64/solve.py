#!/usr/bin/env python3
"""base 16-32-64 - AlpacaHack Daily (crypto/misc).
flag was encoded 20 times, each a random choice of base16/base32/base64.
Invert by DFS: at each layer try all three decoders that fit the alphabet,
recurse 20 levels, stop at Alpaca{...}."""
import base64, sys, re, os

enc = open(os.path.join(os.path.dirname(__file__), "dist/ex/base-16-32-64/output.txt")).read().strip().encode()

def tries(b):
    for name, fn in (("16", base64.b16decode), ("32", base64.b32decode), ("64", base64.b64decode)):
        try:
            d = fn(b)
            if d:
                yield d
        except Exception:
            pass

def dfs(b, depth):
    if depth == 0:
        if b.startswith(b"Alpaca{") and b.endswith(b"}"):
            return b
        return None
    for d in tries(b):
        r = dfs(d, depth - 1)
        if r:
            return r
    return None

res = dfs(enc, 20)
print(res.decode() if res else "[not found]")
