# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CTF (Capture The Flag) learning workspace. Solve challenges from picoCTF, CTFlearn, HackTheBox, TryHackMe, and CTFtime competitions.

## Solving Workflow

Follow this pattern for each challenge:

```
1. Classify → Use the `wizard` agent to identify the challenge type
2. Analyze  → Invoke the matching specialist skill for the category
3. Exploit  → Develop and test the solution locally
4. Capture  → Test against remote, extract flag
5. Document → Generate writeup with /writeup
```

### Quick Start

```bash
/solve <challenge>          # Wizard classifies, then you invoke the matching skill
/writeup <challenge-name>   # Generate solution writeup
/ctftime                    # Find upcoming CTF competitions
```

For an end-to-end autonomous run, drive the `ctf-autosolve` skill with `/loop`
or `/goal` (see `HARNESS.md`). To work a single category by hand, let `wizard`
classify (or just pick) and invoke the matching skill directly.

### Extended Thinking

Use these keywords for deeper analysis:
- `ultrathink` - Heap exploitation, multi-step attacks

## Category Routing

The `wizard` agent is the entry point: it classifies the challenge, then you
invoke the matching **skill** (via the Skill tool) to solve it. There are no
`*-expert` agents — the specialists are the skills below.

| Category | Skill | Indicators |
|----------|-------|------------|
| pwn | binary-analysis | ELF + remote service, dangerous funcs |
| rev | binary-analysis | Binary asking for key/serial, no remote |
| web | web-security | URL, HTTP service, web source code |
| crypto | crypto-analysis | Large numbers (n,e,c), ciphertext |
| forensics | forensics | Images, memory dumps, disk images |
| misc | pyjail | Python jail, encoding puzzles |
| osint | osint | Username search, geolocation |
| mobile | mobile-security | APK/IPA files |
| networking | networking | PCAP files, traffic analysis |

For an end-to-end autonomous run (recon → solve → submit → writeup → record),
use the `ctf-autosolve` skill, driven by `/loop` or `/goal` (see `HARNESS.md`).

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
- When you don't know what to run, use the `ctf-tool-discovery` skill; when stuck,
  `ctf-get-unstuck`; to learn from prior writeups, `ctf-writeup-mining`
- README.md explains the autonomous harness (see `HARNESS.md`)
- All activities for educational purposes on authorized platforms only
