---
allowed-tools: Bash, Read, Write, Edit, Grep, Glob, Task
argument-hint: <file>
description: Forensic artifact analysis
---

## Context

Target: $ARGUMENTS

File info:
!`file $ARGUMENTS 2>/dev/null`

Metadata:
!`exiftool $ARGUMENTS 2>/dev/null | head -20`

Embedded data:
!`binwalk $ARGUMENTS 2>/dev/null | head -10`

Strings search:
!`strings $ARGUMENTS 2>/dev/null | grep -iE "flag|ctf|key|secret" | head -5`

## Task

Spawn `forensics-expert` agent using `forensics` skill to:
1. Identify file type and anomalies
2. Check for steganography (images: AperiSolve, zsteg, steghide)
3. Extract hidden data
4. Memory/disk analysis if applicable

Flag format: varies by platform (e.g., `flag{...}`, `picoCTF{...}`, `HTB{...}`)
