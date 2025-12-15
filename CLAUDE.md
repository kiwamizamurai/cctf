# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CTF (Capture The Flag) learning workspace. Solve challenges from picoCTF, CTFlearn, HackTheBox, TryHackMe, and CTFtime competitions.

## Solving Workflow

Follow this pattern for each challenge:

```
1. Classify → Use `wizard` agent to identify challenge type
2. Analyze  → Spawn specialist agent for the category
3. Exploit  → Develop and test solution locally
4. Capture  → Test against remote, extract flag
5. Document → Generate writeup with /writeup
```

### Quick Start

```bash
/solve <challenge>          # Wizard classifies, then routes to specialist
/pwn <binary>               # Direct binary exploitation
/web <url>                  # Direct web vulnerability assessment
/crypto <file>              # Direct cryptographic attack
/rev <binary>               # Direct reverse engineering
/forensics <file>           # Direct forensic analysis
/misc <file>                # Direct misc challenge
/writeup <challenge-name>   # Generate solution writeup
/ctftime                    # Find upcoming CTF competitions
```

### Extended Thinking

Use these keywords for deeper analysis:
- `ultrathink` - Heap exploitation, multi-step attacks

## Agent Routing

The `wizard` agent is the entry point for challenge classification:

| Category | Agent | Skill | Indicators |
|----------|-------|-------|------------|
| pwn | pwn-expert | binary-analysis | ELF + remote service, dangerous funcs |
| rev | rev-expert | binary-analysis | Binary asking for key/serial, no remote |
| web | web-expert | web-security | URL, HTTP service, web source code |
| crypto | crypto-expert | crypto-analysis | Large numbers (n,e,c), ciphertext |
| forensics | forensics-expert | forensics | Images, memory dumps, disk images |
| misc | misc-expert | pyjail | Python jail, encoding puzzles |
| osint | osint-expert | osint | Username search, geolocation |
| mobile | mobile-expert | mobile-security | APK/IPA files |
| networking | networking-expert | networking | PCAP files, traffic analysis |

## Directory Structure

```
challenges/                      # CTF challenges by platform
├── alpacahack/                  # AlpacaHack
│   ├── daily/                   # Daily challenges
│   │   └── YYYY-MM-DD_name/     # Date + challenge name
│   └── contests/                # Contest challenges
│       └── YYYY-MM_event/
├── picoctf/                     # picoCTF
│   └── YYYY/                    # By year
├── hackthebox/                  # HackTheBox
│   ├── challenges/              # Standalone challenges
│   └── machines/                # Machine writeups
└── ctftime/                     # CTFtime competitions
    └── YYYY-MM_competition/

.claude/                         # Claude Code configuration
```

### Challenge Directory Structure

Each challenge directory follows this structure:

```
challenge-name/
├── README.md        # Writeup (tracked)
├── solve.py         # Solution script (tracked)
├── dist/            # Distributed files (ignored)
│   ├── challenge.tar.gz
│   └── challenge/   # Extracted files
└── work/            # Working files (ignored)
    └── ...          # Debug output, temp files
```

**Tracked files**: `README.md`, `solve.py`, `exploit.py`
**Ignored files**: `dist/`, `work/`, `*.tar.gz`, binaries

### Writeup Location

Each challenge's writeup is stored as `README.md` in its directory.
Use the `writeup-generator` skill or `/writeup` command to generate.

## Initial Recon Commands

```bash
# Binary analysis
checksec --file=<binary>
objdump -d <binary> | grep -E "gets|strcpy|sprintf|system"

# File analysis
file <unknown>
strings <file> | grep -iE "flag|ctf|password|key"
exiftool <file>
binwalk <file>

# Crypto auto-decrypt
ciphey -t "ciphertext"
```

## Flag Formats

```
picoCTF{...}  - picoCTF
HTB{...}      - HackTheBox
THM{...}      - TryHackMe
flag{...}     - Common format
CTF{...}      - Generic CTF
```

## Notes

- Skills (`.claude/skills/`) contain detailed tool references and attack patterns
- README.md has comprehensive tool installation and cheatsheets
- All activities for educational purposes on authorized platforms only
