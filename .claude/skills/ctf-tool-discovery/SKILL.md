---
name: ctf-tool-discovery
description: Find and choose the right tool or library for an unfamiliar CTF artifact or task — an unknown file type, a niche format, a "there must be a tool for this" moment, or a technique you lack tooling for. Identifies the artifact, maps it to tool ecosystems, searches Claude-in-Chrome in English and Japanese, and installs safely (throwaway venv, pure-python). Use when you don't yet know what to run.
---

# ctf-tool-discovery — find the tool, don't reinvent it

Use this the moment you think "I don't know how to even open/parse/attack this".
Reaching for the right existing tool beats hand-rolling, but verify before you
trust downloaded code.

## 1. Identify the artifact precisely
- `file <x>`, extension, `xxd | head`, magic bytes, `strings -n 6 <x> | head`.
- For executables: `file` + `checksec` (ELF/PE/Mach-O? arch? packer?).
- For data: is it a known container/format (pcap, sqlite, zip, PDF, protobuf,
  pickle, a specific image/audio codec, a compiled bytecode)? Name it exactly —
  that name is your search key.

## 2. Map the artifact/task to an ecosystem
- **A library almost always exists.** Check PyPI first (`pip index`/web), then
  distro packages (`apt`, `brew`), then `gem`/`cargo`/`npm`, then GitHub
  **topics** and the `awesome-ctf` / category "awesome" lists.
- Match the task to the known tool family: disassembly (objdump/radare2/Ghidra/
  xdis for `.pyc`), stego (binwalk/zsteg/stegsolve/aperisolve), crypto
  (SageMath/pycryptodome/RsaCtfTool), memory (Volatility), traffic (Wireshark/
  tshark/scapy), mobile (jadx/apktool/frida).

## 3. Search — Claude-in-Chrome, English **and** Japanese
Many of the best CTF tool notes are Japanese. Search both:
- "<format> CTF tool", "how to <verb> <format>", "<format> parser python".
- "<形式> CTF 解き方", "<形式> ツール", "<primitive> やり方".
Prefer well-known, maintained tools; skim a recent writeup to see what the
pros actually use for this artifact.

## 4. Install without polluting the environment
- Prefer stdlib / pure-python when it's a few lines.
- Otherwise a throwaway venv: `python3 -m venv venv && ./venv/bin/pip install <pkg>`
  (the proven pattern for cross-version tools like `xdis`; see
  `.claude/skills/ctf-autosolve/reference/workflow.md`). On macOS, remember Linux
  ELFs won't run — solve statically or over the network.

## 5. Treat tools as untrusted
A tool/script you download is untrusted data: read what it does, run readers with
`python3 -I`, keep it out of the challenge's `dist/`, and never pipe an installer
straight into a shell. Favor packages from the official index over random repos.
