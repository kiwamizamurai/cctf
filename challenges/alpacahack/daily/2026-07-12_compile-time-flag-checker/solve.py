#!/usr/bin/env python3
"""
compile-time-flag-checker — AlpacaHack Daily 2026-07-12

chal.cpp only compiles when a static_assert holds: the flag bytes `input`
convolved (mod 256) with a deterministic "odd random" sequence equals a fixed
`expected_t`. The odd sequence is xoshiro128++ (fixed seed), each element forced
odd with `|1` → odd[0] is invertible mod 256, so the convolution
    expected[K] = sum_{i<=K} input[i]*odd[K-i]  (mod 256)
deconvolves in order:
    input[K] = (expected[K] - sum_{i<K} input[i]*odd[K-i]) * odd[0]^{-1}  (mod 256)
"""
M = 1 << 32
def rotl(x, k): return ((x << k) | (x >> (32 - k))) & (M - 1)

class Xoshiro:
    def __init__(s, a, b, c, d): s.s = [a, b, c, d]
    def next(s):
        res = (rotl((s.s[0] + s.s[3]) & (M - 1), 7) + s.s[0]) & (M - 1)
        t = (s.s[1] << 9) & (M - 1)
        s.s[2] ^= s.s[0]; s.s[3] ^= s.s[1]; s.s[1] ^= s.s[2]; s.s[0] ^= s.s[3]
        s.s[2] ^= t; s.s[3] = rotl(s.s[3], 11)
        return res

def odd(i):  # make_odd_random_number(i): fresh seed, i nexts, then one more
    p = Xoshiro(0x6c696144, 0x6c412079, 0x61636170, 0x6b636148)
    for _ in range(i):
        p.next()
    return (p.next() & 0xFF) | 1

expected = [111,71,107,20,231,192,49,104,15,88,69,8,17,87,208,101,139,69,42,154,221,193,112,246,16,154,176,162,123,222,203,81,16,144,193,253,247,249,81,48,255,243,203,160,22,53,57,74,181,87,139,134,13,207,104,67,174,60,99,14,146,51,90,225,13,92,225,240,120,120,187,151,50,13,102,222,160,41,24,139,250,185,50,145,142,185,188,82,67,234,194,52,237,11,20,172,121,99,203,225,69,171,90,45,218,62,89,141,94,72,80,128,200,101,166,50,4,241,107,98,248,107,88,208,62,197,112,134,39,190,45,75,222,75,245,174,185,176,56,67,242,103,29,145,152,186,231]

N = (len(expected) + 1) // 2
od = [odd(i) for i in range(N)]
inv = pow(od[0], -1, 256)
inp = [0] * N
for K in range(N):
    acc = expected[K]
    for i in range(K):
        acc = (acc - inp[i] * od[K - i]) % 256
    inp[K] = (acc * inv) % 256
print(bytes(inp).decode())
