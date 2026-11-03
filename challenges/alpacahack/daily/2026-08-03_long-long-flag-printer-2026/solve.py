#!/usr/bin/env python3
"""
long-long-flag-printer-2026 — AlpacaHack Daily 2026-08-03

server.py prints the 1024-char flag one character at a time, running
os.system(f"sleep {i}") after char i (cumulative ~6 days). socat serves it over
a pty (pty,ctty,setsid,echo=0, idle timeout -T5). Sending Ctrl-C (0x03) raises
SIGINT in the foreground process group and kills each `sleep`; Python's
os.system()/C system() blocks SIGINT in the parent for the whole call, so Python
survives and the loop advances.

Key subtlety: with the pty's default NOFLSH off, generating SIGINT flushes the
pty *output* queue, so a character still buffered when Ctrl-C fires is lost.
Read each character BEFORE sending the next Ctrl-C (strict lock-step) to stay
lossless. One connection, one Ctrl-C per character — no spamming, no retries.

The flag body is the canonical "Lorem ipsum" text with spaces replaced by '_',
so a partial capture is enough to confirm the content and reconstruct the rest
offline if a run is cut short.

Usage: python3 solve.py <host> <port>
"""
import socket, sys, time, select, re

HOST, PORT = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((HOST, PORT), timeout=10)

def read_chunk(timeout=4.5):
    r, _, _ = select.select([s], [], [], timeout)   # under socat -T5
    return s.recv(4096) if r else None

flag = read_chunk() or b""          # first char(s) before any long sleep
deadline = time.time() + 1200
while time.time() < deadline and not (flag.rstrip().endswith(b"}") and b"Alpaca{" in flag):
    time.sleep(0.02)                # ensure os.system(sleep) has started
    try:
        s.sendall(b"\x03")          # interrupt exactly one sleep
    except OSError:
        break
    chunk = read_chunk()            # drain its char BEFORE the next Ctrl-C (lossless)
    if not chunk:
        break
    flag += chunk
s.close()

clean = flag.replace(b"\x03", b"").replace(b"^C", b"")
m = re.search(rb"Alpaca\{.*\}", clean, re.S)
print(m.group(0).decode(errors="replace") if m else repr(clean))
