# CTF Learning Workspace


![Ghidra](https://img.shields.io/badge/Ghidra-FF0000?style=flat-square&logo=ghidra&logoColor=white)
![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=flat-square&logo=wireshark&logoColor=white)
![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=flat-square&logo=burpsuite&logoColor=white)

![picoCTF](https://img.shields.io/badge/picoCTF-000000?style=flat-square)
![HackTheBox](https://img.shields.io/badge/HackTheBox-9FEF00?style=flat-square&logo=hackthebox&logoColor=black)
![TryHackMe](https://img.shields.io/badge/TryHackMe-212C42?style=flat-square&logo=tryhackme&logoColor=white)

![PWN](https://img.shields.io/badge/PWN-DC143C?style=flat-square)
![Crypto](https://img.shields.io/badge/Crypto-8B5CF6?style=flat-square)
![Web](https://img.shields.io/badge/Web-3B82F6?style=flat-square)
![Rev](https://img.shields.io/badge/Reverse-10B981?style=flat-square)
![Forensics](https://img.shields.io/badge/Forensics-F59E0B?style=flat-square)


![Educational](https://img.shields.io/badge/Purpose-Educational-blue?style=flat-square)
![CTF Writeups](https://img.shields.io/badge/CTF-Writeups-red?style=flat-square)


Workspace for learning CTF (Capture The Flag) challenges.
Build security skills while having fun solving challenges.

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
# Install most CTF tools automatically (9.2k)
git clone https://github.com/zardus/ctf-tools
cd ctf-tools && ./manage-tools setup
```

### Binary Exploitation (Pwn)

| Tool | Description | Install |
|------|-------------|---------|
| **pwntools** | CTF exploit development framework (13k) | `pip install pwntools` |
| **checksec** | Binary protection checker | `pip install pwntools` |
| **ROPgadget** | ROP gadget finder (4.3k) | `pip install ROPgadget` |
| **one_gadget** | Libc one-shot gadget finder (2.3k) | `gem install one_gadget` |
| **libformatstr** | Format string exploitation | `pip install libformatstr` |
| **gdb** | Debugger | apt/brew |
| **pwndbg** | GDB extension (9.7k) | https://github.com/pwndbg/pwndbg |
| **GEF** | GDB extension (7.9k) | https://github.com/hugsy/gef |
| **qira** | QEMU runtime analysis (4k) | https://github.com/BinaryAnalysisPlatform/qira |
| **Ghidra** | Reverse engineering | https://ghidra-sre.org/ |
| **IDA Pro/Free** | Disassembler | https://hex-rays.com/ |
| **radare2** | Reverse engineering (22.7k) | `brew install radare2` |
| **angr** | Symbolic execution (8.4k) | `pip install angr` |
| **z3-solver** | SMT solver (11.7k) | `pip install z3-solver` |
| **Triton** | Dynamic binary analysis (4k) | https://github.com/JonathanSalwan/Triton |
| **cwe_checker** | Find vulnerable patterns (1.3k) | https://github.com/fkie-cad/cwe_checker |
| **frida** | Dynamic instrumentation (19k) | `pip install frida-tools` |

### Web Security

| Tool | Description | Install |
|------|-------------|---------|
| **Burp Suite** | Web proxy | https://portswigger.net/ |
| **sqlmap** | SQL injection automation (36k) | `pip install sqlmap` |
| **commix** | OS command injection (5.5k) | https://github.com/commixproject/commix |
| **ffuf** | Web fuzzing | `brew install ffuf` |
| **gobuster** | Directory scanning | `brew install gobuster` |
| **w3af** | Web vuln scanner (4.8k) | https://github.com/andresriancho/w3af |
| **Raccoon** | Recon & vuln scanning (3.3k) | `pip install raccoon-scanner` |
| **dvcs-ripper** | Rip exposed .git/.svn (1.8k) | https://github.com/kost/dvcs-ripper |
| **curl** | HTTP client | Built-in |
| **httpie** | HTTP client (human-friendly) | `pip install httpie` |
| **requests** | Python HTTP library | `pip install requests` |
| **jwt_tool** | JWT analysis/attack | https://github.com/ticarpi/jwt_tool |

### Cryptography

| Tool | Description | Install |
|------|-------------|---------|
| **Ciphey** | Auto-decrypt without knowing key (20k) | `pip install ciphey` |
| **SageMath** | Mathematical crypto analysis | https://www.sagemath.org/ |
| **gmpy2** | Fast math operations | `pip install gmpy2` |
| **pycryptodome** | Crypto library | `pip install pycryptodome` |
| **RsaCtfTool** | RSA attack automation | https://github.com/RsaCtfTool/RsaCtfTool |
| **xortool** | Multi-byte XOR analysis (1.5k) | `pip install xortool` |
| **FeatherDuster** | Automated cryptanalysis (1.1k) | https://github.com/nccgroup/feern |
| **padding-oracle-attacker** | Padding oracle CLI | `npm i -g padding-oracle-attacker` |
| **FactorDB** | Factorization database | http://factordb.com/ |
| **yafu** | Fast factorization | Compile required |
| **hashcat** | Password cracking (25k) | `brew install hashcat` |
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
| **jadx** | Java/Android decompiler (46k) | https://github.com/skylot/jadx |
| **Krakatau** | Java disassembler/decompiler (2.2k) | https://github.com/Storyyeller/Krakatau |
| **angr** | Symbolic execution | `pip install angr` |
| **z3** | SMT solver | `pip install z3-solver` |
| **Frida** | Dynamic instrumentation | `pip install frida-tools` |
| **objection** | Mobile runtime exploration (8.7k) | `pip install objection` |
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
