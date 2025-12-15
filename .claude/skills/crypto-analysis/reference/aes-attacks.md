# AES/Block Cipher Attacks

## ECB Detection & Exploitation
```python
from Crypto.Cipher import AES

def detect_ecb(ciphertext, block_size=16):
    """Detect ECB mode by finding duplicate blocks"""
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    return len(blocks) != len(set(blocks))

# ECB byte-at-a-time attack
def ecb_oracle_attack(oracle_func, block_size=16):
    """Decrypt ECB when you can prepend to plaintext"""
    known = b''
    for i in range(256):  # Adjust based on flag length
        padding = b'A' * (block_size - 1 - (len(known) % block_size))
        target_block = oracle_func(padding)[:((len(known) // block_size) + 1) * block_size]

        for c in range(256):
            test = oracle_func(padding + known + bytes([c]))
            if test[:len(target_block)] == target_block:
                known += bytes([c])
                break
    return known
```

## CBC Bit Flipping
```python
def cbc_flip(ciphertext, position, old_byte, new_byte, block_size=16):
    """Flip bit in CBC ciphertext to change plaintext"""
    block_num = position // block_size
    byte_in_block = position % block_size

    # Modify previous block (or IV for first block)
    target_pos = (block_num - 1) * block_size + byte_in_block
    ct = bytearray(ciphertext)
    ct[target_pos] ^= old_byte ^ new_byte
    return bytes(ct)
```

## Padding Oracle Attack
```python
def padding_oracle_attack(oracle, ciphertext, block_size=16):
    """Decrypt using padding oracle"""
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    plaintext = b''

    for block_idx in range(1, len(blocks)):
        decrypted_block = bytearray(block_size)
        for byte_idx in range(block_size - 1, -1, -1):
            padding_value = block_size - byte_idx

            for guess in range(256):
                modified = bytearray(blocks[block_idx - 1])
                modified[byte_idx] = guess

                for i in range(byte_idx + 1, block_size):
                    modified[i] ^= decrypted_block[i] ^ padding_value

                if oracle(bytes(modified) + blocks[block_idx]):
                    decrypted_block[byte_idx] = guess ^ padding_value
                    break

        plaintext += bytes([decrypted_block[i] ^ blocks[block_idx - 1][i] for i in range(block_size)])

    return plaintext
```

## CLI Tool: padding-oracle-attacker
```bash
npm i -g padding-oracle-attacker

# Usage
padding-oracle-attacker "http://target/decrypt?ct=" "CIPHERTEXT_HEX"
```
