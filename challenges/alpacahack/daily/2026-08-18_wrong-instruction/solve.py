#!/usr/bin/env python3
"""
wrong-instruction — AlpacaHack Daily 2026-08-18

The ELF uses anti-disassembly: overlapping instructions + a return-address
trampoline hide the real check in is_correct. Following the true control flow:

    eax = 0                      # via `call rax` -> add [rsp],5 -> xor eax,eax
    for i in range(60):
        cl = (input[i] + 8*i + 0x37 - encoded[i]) & 0xff
        al |= cl                 # must stay 0 for "correct"

So each byte must satisfy input[i] == (encoded[i] - 8*i - 0x37) mod 256, which
directly yields the 60-byte flag from the embedded `encoded` table.
"""
encoded = [
    120,171,183,176,186,192,226,195,223,228,250,244,246,12,12,35,31,46,43,66,
    54,64,89,84,86,98,104,123,131,132,139,142,152,173,187,184,132,195,208,226,
    216,242,250,244,4,1,19,40,22,51,44,50,63,77,80,96,108,100,122,140,
]

flag = bytes((encoded[i] - 8 * i - 0x37) % 256 for i in range(len(encoded)))
print(flag.decode())
