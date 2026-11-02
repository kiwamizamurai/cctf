#!/usr/bin/env python3
"""Bitflip RSA - AlpacaHack Daily (crypto). c1=m^e, c2=(~m)^e, ~m=-m-1.
e odd => (~m)^e = -(m+1)^e, so m and m+1 are linearly related messages.
Franklin-Reiter: gcd(x^e - c1, (x+1)^e + c2) over Z_n[x] == (x - m)."""
n = 101273193912221128677312091288955352576109075183462216370990420473799430730198161444188487758885283452275159680717120178872230024556694906874358624815295721958816491500225333612147806532900017757199114647710840807041833729446217301962142807801135110859174811501290078733878246852315931404944353889836368959887
e = 101
c1 = 50306563709976884019768504050252397601555001863689807681652220359687329840857082415062320925648845595304473464800935073685547514032412317605873017051581499290430198179222189464861251114298719534514992096286588304537094131783282219308339218797794453878809847200031314230829456741899911712788284836703895627436
c2 = 15448917957435394901896199585926160357046707920118462327430192121434475490502504557941949440904640586905888673658795142626235566220586195293704437546394914433698324657999933231097646419930078960379570200080426224595748955942069098811819334097972568165041541701956778330511753131179144021751380995544133172198

def normalize(p):
    while p and p[-1] % n == 0:
        p.pop()
    return [x % n for x in p]

def polymulmod(a, b):
    r = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                r[i + j] = (r[i + j] + x * y) % n
    return normalize(r)

def polymod(a, b):
    a = normalize(a[:]); b = normalize(b[:])
    inv = pow(b[-1], -1, n)
    while len(a) >= len(b) and a:
        coef = (a[-1] * inv) % n
        shift = len(a) - len(b)
        for i in range(len(b)):
            a[shift + i] = (a[shift + i] - coef * b[i]) % n
        a = normalize(a)
    return a

def polygcd(a, b):
    a = normalize(a[:]); b = normalize(b[:])
    while b:
        a, b = b, polymod(a, b)
    return a

from math import comb
# f = x^e - c1
f = [0] * (e + 1); f[e] = 1; f[0] = (-c1) % n
# g = (x+1)^e + c2
g = [comb(e, k) % n for k in range(e + 1)]
g[0] = (g[0] + c2) % n

h = polygcd(f, g)
# h should be linear: h1*x + h0 = x - m  (after making monic)
h = normalize(h)
assert len(h) == 2, f"gcd degree {len(h)-1}"
m = (-h[0] * pow(h[1], -1, n)) % n
mb = m.to_bytes((m.bit_length() + 7) // 8, "big")
print(mb.decode())
