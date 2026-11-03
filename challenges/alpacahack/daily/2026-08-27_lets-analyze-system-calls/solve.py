#!/usr/bin/env python3
"""
lets-analyze-system-calls — AlpacaHack Daily 2026-08-27

chal.c issues two raw x86-64 syscalls:
  rax=318 -> getrandom(&result_1, 8, 0)   # result_1 = 8 random bytes, printed to us
  rax=102 -> getuid()                      # result_2 = real UID
The Dockerfile runs `USER 404:404`, so getuid() == 404.
It wants  input == result_1 + result_2  (unsigned long, i.e. mod 2**64).
So:  answer = (result_1 + 404) % 2**64.

Usage: python3 solve.py <host> <port>
"""
import socket, sys, re
HOST, PORT = sys.argv[1], int(sys.argv[2])
UID = 404
s = socket.create_connection((HOST, PORT), timeout=30); s.settimeout(30)
buf = b""
# read until we see the "What will be the sum?" prompt
while b"sum?" not in buf:
    chunk = s.recv(4096)
    if not chunk: break
    buf += chunk
r1 = int(re.search(rb"result_1:\s*(\d+)", buf).group(1))
ans = (r1 + UID) % (2**64)
s.sendall(str(ans).encode() + b"\n")
while True:
    chunk = s.recv(4096)
    if not chunk: break
    buf += chunk
s.close()
m = re.search(rb"Alpaca\{[^}]*\}", buf)
print("result_1 =", r1, "answer =", ans)
print(m.group(0).decode() if m else buf.decode(errors="replace"))
