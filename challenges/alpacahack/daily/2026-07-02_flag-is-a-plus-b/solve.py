#!/usr/bin/env python3
"""
flag-is-a-plus-b — AlpacaHack Daily 2026-07-02

chall.py splits FLAG = A + B (A random in [0, FLAG]) and leaks A|B and A^B.
Recover A + B via the identity:
    A + B = (A & B) + (A | B),  and  A & B = (A | B) - (A ^ B)
    => FLAG = 2*(A|B) - (A^B)
"""
A_or_B = 1708520672692343497693425015709016883325158039728511260268583494549501
A_xor_B = 1653224853895272618878301831150773792186632776885840473347068872416893

FLAG = 2 * A_or_B - A_xor_B
print(FLAG.to_bytes((FLAG.bit_length() + 7) // 8, "big").decode())
