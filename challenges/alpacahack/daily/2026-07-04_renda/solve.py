#!/usr/bin/env python3
"""
renda — AlpacaHack Daily 2026-07-04

index.html is obfuscator.io-obfuscated. The click handler increments a counter
and, once it reaches 100,000, reveals the flag by XORing two embedded arrays:
    C = l.map((e, f) => String.fromCharCode(e ^ p[f])).join('')
So the flag is simply l[i] ^ p[i]. Extract both arrays (their elements are
hex/arithmetic expressions) and XOR — no need to click 100k times.
"""
import re

html = open("dist/index.html").read()
m = re.search(r"const p=\[(.*?)\],l=\[(.*?)\],", html)
p = [eval(x, {"__builtins__": {}}) for x in m.group(1).split(",")]
l = [eval(x, {"__builtins__": {}}) for x in m.group(2).split(",")]
text = "".join(chr(e ^ p[i]) for i, e in enumerate(l))
flag = re.search(r"Alpaca\{[^}]*\}", text).group(0)
print(flag)
