#!/usr/bin/env python3
"""
aesaesaesaesaesaes — AlpacaHack Daily 2026-08-06

The service encrypts msg_16 = ("FLAG IS:" + flag) * 16 under AES-CBC with a
fixed (key, iv) and prints iv + ciphertext. Then it offers an oracle that, for
each 16-byte input P, returns a FRESH AES-CBC(key, iv) encryption of that single
block: ct = Enc(P XOR iv). Crucially the iv is printed, so it is known.

Because iv is known, querying with P = V XOR iv yields Enc(V) for any V, i.e. a
full ECB encryption oracle. The target is CBC: C_j = Enc(P_j XOR C_{j-1}),
C_{-1} = iv. The plaintext msg (period 39, coprime to the 16-byte block size)
has a known prefix "FLAG IS:Alpaca{" and known suffix "}". We recover it one
byte at a time: whenever a block's first 15 message bytes are known, brute-force
the 16th (over the flag charset) by checking Enc(guess_block XOR C_{j-1}) == C_j.
"""
import socket, sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "localhost"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 12345

CHARSET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz{}_"
MSG_LEN = 39          # len("FLAG IS:" + 31-byte flag)
NBLOCKS = MSG_LEN     # msg*16 = 624 bytes = 39 blocks


class Oracle:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=30)
        self.f = self.s.makefile("rwb", buffering=0)
        self.cache = {}
        iv_line = self._readline_with("iv(hex):")
        ct_line = self._readline_with("ciphertext(hex):")
        self.iv = bytes.fromhex(iv_line.split(":", 1)[1].strip())
        self.ct = bytes.fromhex(ct_line.split(":", 1)[1].strip())

    def _readline(self):
        line = self.f.readline()
        if not line:
            raise EOFError("connection closed")
        return line.decode(errors="replace")

    def _readline_with(self, needle):
        while True:
            line = self._readline()
            if needle in line:
                return line

    def enc(self, v: bytes) -> bytes:
        """Return Enc(v) (single-block AES-ECB under the server's key)."""
        assert len(v) == 16
        if v in self.cache:
            return self.cache[v]
        p = bytes(a ^ b for a, b in zip(v, self.iv))   # P = V XOR iv
        # consume the prompt, then send our hex input
        # (prompt text is "plaintext to encrypt (hex): " without newline)
        self.f.write(p.hex().encode() + b"\n")
        line = self._readline_with("ciphertext(hex):")
        out = bytes.fromhex(line.split(":", 1)[1].strip())
        self.cache[v] = out
        return out


def solve(host, port):
    o = Oracle(host, port)
    assert len(o.ct) == NBLOCKS * 16, f"unexpected ct len {len(o.ct)}"
    C = [o.iv] + [o.ct[i*16:(i+1)*16] for i in range(NBLOCKS)]  # C[0]=iv, C[1..]=blocks

    # known message bytes: "FLAG IS:" + "Alpaca{" ... "}"
    msg = [None] * MSG_LEN
    prefix = b"FLAG IS:Alpaca{"     # 15 bytes (msg[0:15])
    for i, ch in enumerate(prefix):
        msg[i] = ch
    msg[38] = ord("}")              # flag ends with '}'

    def block_indices(j):
        return [(16 * j + t) % MSG_LEN for t in range(16)]

    progress = True
    while progress and any(m is None for m in msg):
        progress = False
        for j in range(NBLOCKS):
            idx = block_indices(j)
            known = [msg[k] for k in idx]
            if known[-1] is not None:
                continue                       # last byte already known
            if any(k is None for k in known[:15]):
                continue                       # need all 15 preceding bytes
            target = o.ct[j*16:(j+1)*16]
            prev = C[j]                        # C_{j-1} in chaining terms
            base = bytes(known[:15])
            for guess in CHARSET:
                blk = base + bytes([guess])
                v = bytes(a ^ b for a, b in zip(blk, prev))
                if o.enc(v) == target:
                    msg[idx[15]] = guess
                    progress = True
                    break
            if msg[idx[15]] is None:
                raise RuntimeError(f"no charset match at msg index {idx[15]}")

    if any(m is None for m in msg):
        missing = [i for i, m in enumerate(msg) if m is None]
        raise RuntimeError(f"incomplete recovery, missing msg indices {missing}")

    recovered = bytes(msg)
    assert recovered.startswith(b"FLAG IS:")
    flag = recovered[8:]
    return flag.decode()


if __name__ == "__main__":
    print(solve(HOST, PORT))
