# CTF Learning Workspace

![PWN](https://img.shields.io/badge/PWN-DC143C?style=flat-square)
![Crypto](https://img.shields.io/badge/Crypto-8B5CF6?style=flat-square)
![Web](https://img.shields.io/badge/Web-3B82F6?style=flat-square)
![Rev](https://img.shields.io/badge/Reverse-10B981?style=flat-square)
![Forensics](https://img.shields.io/badge/Forensics-F59E0B?style=flat-square)


![Educational](https://img.shields.io/badge/Purpose-Educational-blue?style=flat-square)
![CTF Writeups](https://img.shields.io/badge/CTF-Writeups-red?style=flat-square)


Workspace for learning CTF (Capture The Flag) challenges, centered on an
**autonomous solving harness** that works on any CTF/platform. Build security
skills while having fun solving challenges.

## Autonomous harness (the main event)

A self-driving loop solves challenges end-to-end — recon → solve → submit →
verify → writeup → record — one at a time, tracking state in a queue + decision
ledger. Per competition you edit **one file** (`.claude/CONDITIONS.md`) and point
it at a **platform profile** (`.claude/skills/ctf-autosolve/platforms/<name>.md`;
AlpacaHack ships as the first). Full docs: **[`HARNESS.md`](./HARNESS.md)**.

**Run it:**

| You want | Command |
|----------|---------|
| Keep solving until done | `/loop /ctf-auto` |
| Solve one challenge | `/ctf-auto` |
| Goal-driven autopilot | `/ctf-auto on`, then `/goal <your goal>` |
| Stop | `/ctf-auto off` and/or `/goal clear` |
| Progress | `/ctf-auto status` |

New event? Copy `platforms/_template.md`, fill it, set `.claude/CONDITIONS.md`,
then `/loop /ctf-auto`. The harness obeys each competition's own rules (AI use,
automation, writeup timing) and only touches authorized, in-scope targets.

## Quick Start

```bash
# Wizard classifies challenge and routes to specialist
/solve <challenge>

# Direct category commands
/pwn <binary>               # Binary exploitation
/web <url>                  # Web vulnerability assessment
/crypto <file>              # Cryptographic attack
/rev <binary>               # Reverse engineering
/forensics <file>           # Forensic analysis
/misc <file>                # Misc challenges (pyjail, encoding)

# Documentation
/writeup <challenge-name>   # Generate solution writeup
/ctftime                    # Find upcoming CTF competitions
```

## Output Styles

```bash
/output-style ctf-focused   # Direct, exploit-first approach
/output-style ctf-beginner  # Step-by-step learning mode with explanations
```

## CTF Tools Reference

### Quick Install (All Tools)

```bash
# Install most CTF tools automatically
git clone https://github.com/zardus/ctf-tools
cd ctf-tools && ./manage-tools setup
```

### Binary Exploitation (Pwn)

| Tool | Description | Install |
|------|-------------|---------|
| **pwntools** | CTF exploit development framework | `pip install pwntools` |
| **checksec** | Binary protection checker | `pip install pwntools` |
| **ROPgadget** | ROP gadget finder | `pip install ROPgadget` |
| **one_gadget** | Libc one-shot gadget finder | `gem install one_gadget` |
| **libformatstr** | Format string exploitation | `pip install libformatstr` |
| **gdb** | Debugger | apt/brew |
| **pwndbg** | GDB extension | https://github.com/pwndbg/pwndbg |
| **GEF** | GDB extension | https://github.com/hugsy/gef |
| **qira** | QEMU runtime analysis | https://github.com/BinaryAnalysisPlatform/qira |
| **Ghidra** | Reverse engineering | https://ghidra-sre.org/ |
| **IDA Pro/Free** | Disassembler | https://hex-rays.com/ |
| **radare2** | Reverse engineering | `brew install radare2` |
| **angr** | Symbolic execution | `pip install angr` |
| **z3-solver** | SMT solver | `pip install z3-solver` |
| **Triton** | Dynamic binary analysis | https://github.com/JonathanSalwan/Triton |
| **cwe_checker** | Find vulnerable patterns | https://github.com/fkie-cad/cwe_checker |
| **frida** | Dynamic instrumentation | `pip install frida-tools` |

### Web Security

| Tool | Description | Install |
|------|-------------|---------|
| **Burp Suite** | Web proxy | https://portswigger.net/ |
| **sqlmap** | SQL injection automation | `pip install sqlmap` |
| **commix** | OS command injection | https://github.com/commixproject/commix |
| **ffuf** | Web fuzzing | `brew install ffuf` |
| **gobuster** | Directory scanning | `brew install gobuster` |
| **w3af** | Web vuln scanner | https://github.com/andresriancho/w3af |
| **Raccoon** | Recon & vuln scanning | `pip install raccoon-scanner` |
| **dvcs-ripper** | Rip exposed .git/.svn | https://github.com/kost/dvcs-ripper |
| **curl** | HTTP client | Built-in |
| **httpie** | HTTP client (human-friendly) | `pip install httpie` |
| **requests** | Python HTTP library | `pip install requests` |
| **jwt_tool** | JWT analysis/attack | https://github.com/ticarpi/jwt_tool |

### Cryptography

| Tool | Description | Install |
|------|-------------|---------|
| **Ciphey** | Auto-decrypt without knowing key | `pip install ciphey` |
| **SageMath** | Mathematical crypto analysis | https://www.sagemath.org/ |
| **gmpy2** | Fast math operations | `pip install gmpy2` |
| **pycryptodome** | Crypto library | `pip install pycryptodome` |
| **RsaCtfTool** | RSA attack automation | https://github.com/RsaCtfTool/RsaCtfTool |
| **xortool** | Multi-byte XOR analysis | `pip install xortool` |
| **FeatherDuster** | Automated cryptanalysis | https://github.com/nccgroup/feern |
| **padding-oracle-attacker** | Padding oracle CLI | `npm i -g padding-oracle-attacker` |
| **FactorDB** | Factorization database | http://factordb.com/ |
| **yafu** | Fast factorization | Compile required |
| **hashcat** | Password cracking | `brew install hashcat` |
| **john** | Password cracking | `brew install john` |

### Forensics / Steganography

| Tool | Description | Install |
|------|-------------|---------|
| **binwalk** | Embedded file detection | `brew install binwalk` |
| **foremost** | File carving | `brew install foremost` |
| **exiftool** | Metadata analysis | `brew install exiftool` |
| **steghide** | JPG steganography | `brew install steghide` |
| **zsteg** | PNG steganography (LSB) | `gem install zsteg` |
| **stegsolve** | Steganography GUI | Java app |
| **DeepSound** | Audio steganography | https://github.com/Jpinsoft/DeepSound |
| **AperiSolve** | All-in-one stego (online) | https://www.aperisolve.com/ |
| **StegOnline** | Image stego operations | https://stegonline.georgeom.net/ |
| **Volatility** | Memory forensics | `pip install volatility3` |
| **Wireshark** | Packet analysis | `brew install wireshark` |
| **tshark** | Wireshark CLI | `brew install wireshark` |
| **strings** | String extraction | Built-in |
| **xxd** | Hex dump | Built-in |

### Reverse Engineering

| Tool | Description | Install |
|------|-------------|---------|
| **Ghidra** | Decompiler | https://ghidra-sre.org/ |
| **IDA Pro/Free** | Disassembler | https://hex-rays.com/ |
| **radare2/rizin** | CLI reverser | `brew install radare2` |
| **Binary Ninja** | Decompiler | https://binary.ninja/ |
| **jadx** | Java/Android decompiler | https://github.com/skylot/jadx |
| **Krakatau** | Java disassembler/decompiler | https://github.com/Storyyeller/Krakatau |
| **angr** | Symbolic execution | `pip install angr` |
| **z3** | SMT solver | `pip install z3-solver` |
| **Frida** | Dynamic instrumentation | `pip install frida-tools` |
| **objection** | Mobile runtime exploration | `pip install objection` |
| **objdump** | Disassembly | Built-in |
| **ltrace/strace** | Library/system call tracing | Built-in |
| **gdb** | Debugger | Built-in |


### Online Tools

| Tool | URL | Purpose |
|------|-----|---------|
| **CyberChef** | https://gchq.github.io/CyberChef/ | Data encoding/decoding |
| **AperiSolve** | https://www.aperisolve.com/ | All-in-one stego analysis |
| **StegOnline** | https://stegonline.georgeom.net/ | Image stego operations |
| **FactorDB** | http://factordb.com/ | RSA factorization |
| **Decompiler Explorer** | https://dogbolt.org/ | Multiple decompilers |
| **regex101** | https://regex101.com/ | Regex tester |


## Claude Code Agents

| Agent | Description |
|-------|-------------|
| **wizard** | Primary intake agent. Classifies challenges and routes to appropriate skill. |
| **hint-helper** | Progressive hint provider for beginners learning to solve independently. |

### Wizard Routing Table

| Category | Skill | Key Indicators |
|----------|-------|----------------|
| pwn | binary-analysis | ELF + remote service, dangerous functions |
| rev | binary-analysis | Binary asking for key/password, no remote |
| web | web-security | URL, HTTP service, web framework source |
| crypto | crypto-analysis | Large numbers (n, e, c), encryption script |
| forensics | forensics | Image/audio, memory dump, disk image |
| misc | pyjail | Python jail, encoding puzzle, esoteric |
| osint | osint | Username search, image geolocation |
| mobile | mobile-security | APK/IPA file |
| networking | networking | PCAP file, traffic analysis |

## Skills Reference (9 Skills)

| Skill | Capabilities |
|-------|--------------|
| **binary-analysis** | checksec, ROP, format string, heap, cwe_checker |
| **crypto-analysis** | Ciphey auto-decrypt, RSA attacks, AES, lattice, xortool |
| **forensics** | stego, binwalk, Volatility, AperiSolve, DeepSound |
| **web-security** | SQLi, XSS, SSTI, SSRF, command injection, deserialize |
| **networking** | tshark, Wireshark, PCAP analysis, protocol extraction |
| **mobile-security** | jadx, Frida, objection, APK/IPA analysis |
| **osint** | sherlock, geolocation, archives, social media |
| **pyjail** | Python sandbox escape, restricted shell bypass |
| **writeup** | Solution documentation generation |

## Directory Structure

```
challenges/                      # CTF challenges by platform
├── alpacahack/                  # AlpacaHack
│   ├── daily/                   # Daily challenges (YYYY-MM-DD_name/)
│   └── contests/                # Contest challenges (YYYY-MM_event/)
├── picoctf/                     # picoCTF (by year)
├── hackthebox/                  # HackTheBox
│   ├── challenges/              # Standalone challenges
│   └── machines/                # Machine writeups
└── ctftime/                     # CTFtime competitions

.claude/                         # Claude Code configuration
├── agents/                      # wizard, hint-helper
├── commands/                    # /solve, /pwn, /web, etc.
├── skills/                      # 9 specialized skills
├── output-styles/               # ctf-focused, ctf-beginner
└── rules/                       # Guidelines and policies
```

### Challenge Directory Structure

```
challenge-name/
├── README.md        # Writeup (tracked)
├── solve.py         # Solution script (tracked)
├── dist/            # Distributed files (ignored)
└── work/            # Working files (ignored)
```

## Flag Formats

Flag format varies by platform:
```
picoCTF{...}     - picoCTF
HTB{...}         - HackTheBox
THM{...}         - TryHackMe
Alpaca{...}      - AlpacaHack
TSGLIVE{...}     - TSGLIVE
flag{...}        - Common format
CTF{...}         - Generic CTF
```
