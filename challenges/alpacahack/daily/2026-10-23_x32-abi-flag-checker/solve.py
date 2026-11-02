#!/usr/bin/env python3
"""x32 ABI flag checker - AlpacaHack Daily (rev, Hard).

is_correct() requires len(flag)==41 and, for each i in 0..39, checks
    expected[i] == MD5( LE64( ((flag[i]<<8 | flag[i+1]) * M) ^ K ) )
with M=0x3233504c49 ("ILP32"), K=0x4942412d323378 ("x32-ABI").
Since (flag[i]<<8|flag[i+1]) is only 16 bits, brute all x in 0..65535,
match each expected[i], and chain the recovered byte pairs into the flag."""
import hashlib, struct, sys

BIN = sys.argv[1] if len(sys.argv) > 1 else "dist/chal"
EXP_VADDR = 0x4C40E0
N = 40
M = 0x3233504C49
K = 0x4942412D323378
MASK = (1 << 64) - 1

data = open(BIN, "rb").read()

# ELF64-ish header fields (x32 uses ELFCLASS32 header? file says elf32). Parse
# program headers to map vaddr->file offset via PT_LOAD segments.
ei_class = data[4]  # 1=32,2=64
if ei_class == 2:
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    def ph(i):
        o = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, o)[0]
        p_offset = struct.unpack_from("<Q", data, o + 0x08)[0]
        p_vaddr = struct.unpack_from("<Q", data, o + 0x10)[0]
        p_filesz = struct.unpack_from("<Q", data, o + 0x20)[0]
        return p_type, p_offset, p_vaddr, p_filesz
else:  # ELFCLASS32 header layout
    e_phoff = struct.unpack_from("<I", data, 0x1C)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x2A)[0]
    e_phnum = struct.unpack_from("<H", data, 0x2C)[0]
    def ph(i):
        o = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, o)[0]
        p_offset = struct.unpack_from("<I", data, o + 0x04)[0]
        p_vaddr = struct.unpack_from("<I", data, o + 0x08)[0]
        p_filesz = struct.unpack_from("<I", data, o + 0x10)[0]
        return p_type, p_offset, p_vaddr, p_filesz

def v2o(vaddr):
    for i in range(e_phnum):
        t, off, va, fsz = ph(i)
        if t == 1 and va <= vaddr < va + fsz:
            return off + (vaddr - va)
    raise ValueError("vaddr not mapped")

eo = v2o(EXP_VADDR)
expected = [data[eo + i * 16: eo + i * 16 + 16] for i in range(N)]

# brute all 16-bit x, map MD5 digest -> x
digest_to_x = {}
for x in range(0x10000):
    val = ((x * M) ^ K) & MASK
    d = hashlib.md5(struct.pack("<Q", val)).digest()
    digest_to_x[d] = x

flag = [None] * (N + 1)
for i in range(N):
    x = digest_to_x.get(expected[i])
    if x is None:
        print(f"[!] no match at i={i}")
        sys.exit(1)
    c0, c1 = x >> 8, x & 0xFF
    if flag[i] is None:
        flag[i] = c0
    elif flag[i] != c0:
        print(f"[!] chain mismatch at i={i}: {flag[i]} vs {c0}")
    flag[i + 1] = c1

print(bytes(flag).decode())
