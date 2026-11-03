#!/usr/bin/env python3
"""
biribiri — AlpacaHack Daily 2026-07-16

signature = bcrypt.hashpw(SECRET(16) + ticket, salt). bcrypt only hashes the
first 72 bytes of the password, so only SECRET + ticket[:56] is authenticated.
checkpw(SECRET + submitted, signature) therefore passes whenever submitted[:56]
== ticket[:56] — SECRET is an unknown but identical 16-byte prefix in both, so we
don't need it. Byte 56 lands inside the memo's run of 'A's, so we just truncate
the memo there and append a valid tail with "admin":true:
    submitted = ticket[:56] + b'","admin":true}'

Usage: python3 solve.py <host> <port>
"""
import socket, sys, time, re

HOST, PORT = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((HOST, PORT), timeout=20); s.settimeout(20)
f = s.makefile("rwb", buffering=0)
ticket = None
while ticket is None:
    line = f.readline().decode(errors="replace")
    m = re.search(r"ticket:\s*([0-9a-f]+)", line)
    if m:
        ticket = bytes.fromhex(m.group(1))
submitted = ticket[:56] + b'","admin":true}'
# wait for the prompt, then send
time.sleep(0.2)
s.sendall(submitted.hex().encode() + b"\n")
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
print(mm.group(0).decode() if mm else out.decode(errors="replace"))
