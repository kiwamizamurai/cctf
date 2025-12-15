# Classical Ciphers & XOR

## Ciphey - Auto-Decrypt
```bash
pip install ciphey

ciphey -t "U0VDQ09Oe2V4YW1wbGV9"  # From text
ciphey -f encrypted.txt           # From file

# Handles: Base64, ROT13, Caesar, Vigenère, XOR, and 50+ more
```

## xortool - XOR Analysis
```bash
pip install xortool

xortool encrypted.bin              # Find key length and likely keys
xortool -c 20 encrypted.bin        # 0x20 = space (common in text)
xortool -b encrypted.bin           # Brute force all printable chars
```

## Frequency Analysis
```python
from collections import Counter

def frequency_analysis(text):
    freq = Counter(text.upper())
    english_freq = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'
    sorted_freq = [c for c, _ in freq.most_common()]
    return dict(zip(sorted_freq, english_freq))
```

## XOR Cipher
```python
from pwn import xor

# Known plaintext attack
def xor_known_plaintext(ciphertext, known_plain):
    key = xor(ciphertext[:len(known_plain)], known_plain)
    return key

# Single-byte XOR brute force
def xor_single_byte(ciphertext):
    for k in range(256):
        plain = bytes([c ^ k for c in ciphertext])
        if all(32 <= b <= 126 for b in plain):
            print(f"Key: {k} -> {plain}")

# Repeating key XOR
def xor_repeating_key(ciphertext, key_len):
    """Break repeating-key XOR given key length"""
    key = b''
    for i in range(key_len):
        column = ciphertext[i::key_len]
        best_k, best_score = 0, 0
        for k in range(256):
            plain = bytes([c ^ k for c in column])
            score = sum(1 for b in plain if chr(b).lower() in 'etaoinshrdlu ')
            if score > best_score:
                best_score = score
                best_k = k
        key += bytes([best_k])
    return key
```

## Vigenère
```python
def kasiski_examination(ciphertext, min_len=3):
    """Find likely key lengths for Vigenère cipher"""
    from math import gcd
    from collections import defaultdict

    distances = defaultdict(list)
    for length in range(min_len, 20):
        for i in range(len(ciphertext) - length):
            pattern = ciphertext[i:i+length]
            for j in range(i + length, len(ciphertext) - length):
                if ciphertext[j:j+length] == pattern:
                    distances[pattern].append(j - i)

    all_distances = [d for dists in distances.values() for d in dists]
    return gcd(*all_distances) if all_distances else None
```

## Online Tools
- **dcode.fr** - Cipher identifier and solver
- **quipqiup** - Substitution cipher solver
- **CyberChef** - Multi-tool transformer
