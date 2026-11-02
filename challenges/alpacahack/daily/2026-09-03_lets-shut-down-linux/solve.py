#!/usr/bin/env python3
"""Let's Shut Down Linux - AlpacaHack Daily (misc).
Call reboot(magic1, magic2, cmd, arg) with the canonical constants to power off
the UML cleanly so the server sees returncode 0 and "Power down".
  arg1 = LINUX_REBOOT_MAGIC1      = 0xfee1dead = 4276215469
  arg2 = LINUX_REBOOT_MAGIC2      = 0x28121969 = 672274793
  arg3 = LINUX_REBOOT_CMD_POWER_OFF = 0x4321fedc = 1126301404
Usage: python3 -I solve.py HOST PORT"""
import re, socket, sys, time
H, P = sys.argv[1], int(sys.argv[2])
A = (b"4276215469\n", b"672274793\n", b"1126301404\n")
deadline = time.time() + 300
flag = None
while time.time() < deadline and not flag:
    try:
        s = socket.create_connection((H, P), timeout=20); s.settimeout(30)
    except Exception:
        time.sleep(5); continue
    data = b""
    try:
        for a in A:
            # wait for a prompt then send
            s.sendall(a)
        while True:
            ch = s.recv(65536)
            if not ch: break
            data += ch
    except Exception:
        pass
    finally:
        s.close()
    m = re.search(rb"Alpaca\{[^}]*\}", data)
    if m:
        flag = m.group(0).decode(); break
    if b"Power down" in data:
        print("powered down but no flag yet:\n", data[-300:]); 
    time.sleep(5)
print(flag or "[no flag]")
