# Lattice Attacks (SageMath)

## Coppersmith Small Roots
```python
# Run in SageMath
n = ...
e = 3
c = ...
known_bits = 1024  # Known high bits of message

P.<x> = PolynomialRing(Zmod(n))
m_known = 0x...00000  # Known prefix with zeros for unknown part
f = (m_known + x)^e - c
roots = f.small_roots(X=2^(bits_unknown), beta=1)
if roots:
    m = m_known + roots[0]
    print(bytes.fromhex(hex(m)[2:]))
```

## LLL for Hidden Number Problem
```python
# SageMath
def solve_hnp(samples, modulus, hidden_bits):
    """Solve Hidden Number Problem with LLL"""
    n = len(samples)
    B = 2^hidden_bits

    M = Matrix(ZZ, n + 2, n + 2)
    for i in range(n):
        M[i, i] = modulus
        M[n, i] = samples[i][0]  # multiplier
        M[n + 1, i] = samples[i][1]  # result
    M[n, n] = B / modulus
    M[n + 1, n + 1] = B

    L = M.LLL()
    # Extract solution from short vector
```

## When to Use Lattice
- Partial plaintext known (Coppersmith)
- Biased nonces in ECDSA (HNP → LLL)
- Polynomial relationships modulo n
- Small secret recovery
