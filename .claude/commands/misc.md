---
allowed-tools: Bash, Read, Write, Edit, Grep, Glob, Task
argument-hint: <file-or-description>
description: Miscellaneous challenge analysis
---

## Context

Target: $ARGUMENTS

File contents (if file):
!`head -50 $ARGUMENTS 2>/dev/null`

## Task

Spawn `misc-expert` agent using `pyjail` skill to:

### Python Jail
1. Identify restrictions
2. Try: `__import__('os').system('cat flag')`
3. Class hierarchy bypass if builtins blocked

### Encoding
- Try Ciphey: `ciphey -t "encoded"`

### Other
- QR: `zbarimg`
- Archives: nested extraction
- Esoteric languages

Flag format: varies by platform (e.g., `flag{...}`, `picoCTF{...}`, `HTB{...}`)
