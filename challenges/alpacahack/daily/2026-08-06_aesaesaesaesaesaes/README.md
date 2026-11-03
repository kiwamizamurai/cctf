# [crypto] AESAESAESAESAESAES

> A known-IV AES-CBC "encryption oracle" is enough to decrypt a CBC ciphertext byte-by-byte when the plaintext is a short, mostly-known, repeating message.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | crypto |
| Difficulty | ★★☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{AES_challenge_is_puzzle}` |

## Problem Statement

> I said it many times because it's important!
>
> `server.py`

Released: Aug 6, 2026. Remote service (`nc <host> <port>`), source provided.

## TL;DR

- The service prints the AES-CBC encryption of `msg = ("FLAG IS:" + flag) * 16` under a fixed `(key, iv)`, and the **IV is printed**.
- It then acts as an oracle: for each 16-byte input `P` it returns a fresh `AES-CBC(key, iv)` of that one block, i.e. `Enc(P ⊕ iv)`. Since `iv` is known, sending `P = V ⊕ iv` yields `Enc(V)` — a full **ECB encryption oracle**.
- CBC is `C_j = Enc(P_j ⊕ C_{j-1})`. The plaintext has a known prefix `FLAG IS:Alpaca{` and known suffix `}`, and repeats with period 39 (coprime to 16), so every unknown byte eventually sits as the last byte of a block whose other 15 bytes are known → classic **byte-at-a-time** recovery over the flag charset.

## Background Knowledge

### AES-CBC and the "fresh cipher, same IV" oracle

CBC encrypts block `j` as `C_j = Enc_key(P_j ⊕ C_{j-1})`, with `C_{-1} = iv`. The server's oracle loop does:

```python
cipher = AES.new(key, AES.MODE_CBC, iv)   # same key, same iv, every time
ciphertext = cipher.encrypt(user_input)   # one 16-byte block
```

For a single block, CBC reduces to `Enc_key(P ⊕ iv)`. Because `key`/`iv` are constant and **`iv` is printed**, we can evaluate `Enc_key(V)` at any point `V` by querying with `P = V ⊕ iv`. That is an arbitrary-plaintext ECB encryption oracle.

### Why the repetition matters

`msg = "FLAG IS:" + flag` is 39 bytes; `flag` is exactly 31 bytes (`Alpaca{` + 23 + `}`). The ciphertext covers `msg * 16 = 624 = 39 blocks`. Block `j` holds message indices `(16j .. 16j+15) mod 39` — 16 *consecutive* indices mod 39. Since `gcd(16,39)=1`, as `j` varies every message index becomes the last byte of some block. Recovering indices in order (starting from the known prefix), each new byte is eventually the single unknown at the end of an otherwise-known block.

## Solution

### Step 1: Recon

`server.py` shows:
- `flag` is 31 bytes, `flag_charset` is `[A-Za-z]{}_` (54 chars).
- Initial output: `iv(hex)` and `ciphertext(hex)` for `("FLAG IS:"+flag)*16`.
- Oracle: read 16 bytes of hex, print `iv(hex)` (always the same IV) and `ciphertext(hex)` = `Enc(input ⊕ iv)`.

### Step 2: Build the ECB oracle

```python
def enc(V):                 # returns Enc_key(V)
    P = bytes(a ^ b for a, b in zip(V, iv))   # iv is known from the banner
    send(P.hex()); return recv_ciphertext()
```

### Step 3: Byte-at-a-time CBC recovery

Seed the known message bytes: `msg[0:15] = "FLAG IS:Alpaca{"` and `msg[38] = "}"`. Then repeatedly scan the 39 blocks; for any block whose first 15 message bytes are known and whose 16th is unknown, brute-force that byte over the 54-char charset:

```python
for guess in CHARSET:
    blk = known15 + bytes([guess])
    if enc(bytes(a ^ b for a, b in zip(blk, C[j-1]))) == C_j:   # C_j = Enc(P_j ⊕ C_{j-1})
        msg[last_index] = guess; break
```

Cascade until all 39 bytes are known; `flag = msg[8:]`. Full script: [`solve.py`](solve.py).

### Step 4: Capture

```bash
$ python3 solve.py 34.170.146.252 65499
Alpaca{AES_challenge_is_puzzle}
```

Validated locally first against `server.py` with a dummy 31-byte flag (recovered in ~1.5s); the remote run took ~3m14s due to ~600 sequential oracle round-trips.

## Tools Used

| Tool | Purpose |
|------|---------|
| Python stdlib `socket` | Talk to the oracle, no external deps |
| pycryptodome (venv) | Run `server.py` locally for validation only |

## Lessons Learned

### What I Learned
- A per-block "encrypt one block" service is a full ECB oracle; CBC's single-block case is just `Enc(P ⊕ iv)`.
- Printing the IV (even when it "should be fine" for CBC) hands the attacker the offset needed to query arbitrary plaintexts.
- A short, mostly-known, repeating plaintext turns an encryption oracle into a decryption primitive via byte-at-a-time — no decryption oracle required.

### Mistakes Made
- First local test used a 27-byte dummy flag and hit the server's `len(flag) == 31` assert; fixed the test flag length.

## References

- [Byte-at-a-time ECB decryption (cryptopals set 2)](https://cryptopals.com/sets/2/challenges/12) — the adaptive-plaintext idea reused here.

## Tags

`crypto` `aes` `cbc` `ecb-oracle` `byte-at-a-time` `chosen-plaintext`
