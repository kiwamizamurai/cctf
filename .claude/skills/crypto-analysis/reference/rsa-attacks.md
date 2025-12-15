# RSA Attack Implementations

## 1. Small e Attack (e=3)
```python
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes

c = <ciphertext>
e = 3

# Try direct root
m, exact = iroot(c, e)
if exact:
    print(long_to_bytes(int(m)))
else:
    # Try with padding: m^e = c + k*n for small k
    for k in range(10000):
        m, exact = iroot(c + k * n, e)
        if exact:
            print(f"k={k}: {long_to_bytes(int(m))}")
            break
```

## 2. Wiener's Attack (Large e, Small d)
```python
from Crypto.Util.number import long_to_bytes
import gmpy2

def wiener_attack(e, n):
    """Wiener's attack when d < n^0.25"""
    def continued_fractions(n, d):
        fracs = []
        while d:
            fracs.append(n // d)
            n, d = d, n % d
        return fracs

    def convergents(cf):
        n1, d1 = 1, 0
        n2, d2 = cf[0], 1
        yield (n2, d2)
        for i in range(1, len(cf)):
            n1, n2 = n2, cf[i] * n2 + n1
            d1, d2 = d2, cf[i] * d2 + d1
            yield (n2, d2)

    cf = continued_fractions(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        phi = (e * d - 1) // k
        b = n - phi + 1
        discriminant = b * b - 4 * n
        if discriminant >= 0:
            root = gmpy2.isqrt(discriminant)
            if root * root == discriminant:
                return d
    return None

d = wiener_attack(e, n)
if d:
    m = pow(c, d, n)
    print(long_to_bytes(m))
```

## 3. Hastad's Broadcast Attack
```python
from sympy.ntheory.modular import crt
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes

# Same message encrypted with same e to different n
ns = [n1, n2, n3]  # At least e moduli needed
cs = [c1, c2, c3]
e = 3

# CRT to combine
result, _ = crt(ns, cs)
m, _ = iroot(result, e)
print(long_to_bytes(int(m)))
```

## 4. Common Modulus Attack
```python
from Crypto.Util.number import long_to_bytes, inverse
import gmpy2

def common_modulus(n, e1, e2, c1, c2):
    """Same n, different e, same plaintext"""
    g, a, b = gmpy2.gcdext(e1, e2)
    if a < 0:
        c1 = inverse(c1, n)
        a = -a
    if b < 0:
        c2 = inverse(c2, n)
        b = -b
    return pow(c1, a, n) * pow(c2, b, n) % n

m = common_modulus(n, e1, e2, c1, c2)
print(long_to_bytes(m))
```

## 5. Fermat Factorization
```python
from gmpy2 import isqrt, is_square
from Crypto.Util.number import inverse

def fermat_factor(n):
    """Works when p and q are close"""
    a = isqrt(n) + 1
    b2 = a * a - n
    while not is_square(b2):
        a += 1
        b2 = a * a - n
        if a - isqrt(n) > 100000:
            return None, None
    b = isqrt(b2)
    return int(a - b), int(a + b)

p, q = fermat_factor(n)
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = pow(c, d, n)
```

## 6. FactorDB Lookup
```python
import requests

def factordb(n):
    r = requests.get(f'http://factordb.com/api?query={n}')
    data = r.json()
    if data['status'] == 'FF':  # Fully Factored
        factors = [int(f[0]) for f in data['factors']]
        return factors
    return None
```

## 7. Common Factor Attack
```python
from math import gcd

# If you have multiple n values
ns = [n1, n2, n3, ...]
for i in range(len(ns)):
    for j in range(i+1, len(ns)):
        g = gcd(ns[i], ns[j])
        if g > 1:
            p = g
            q = ns[i] // p
            print(f"Found! n{i} = {p} * {q}")
```
