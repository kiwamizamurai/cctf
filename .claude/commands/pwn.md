---
allowed-tools: Bash, Read, Write, Edit, Grep, Glob, Task
argument-hint: <binary-file>
description: Binary exploitation analysis
---

## Context

Target: $ARGUMENTS

Binary info:
!`file $ARGUMENTS 2>/dev/null`

Security:
!`checksec --file=$ARGUMENTS 2>/dev/null`

Dangerous functions:
!`objdump -d $ARGUMENTS 2>/dev/null | grep -E "gets|strcpy|sprintf|scanf|system" | head -10`

## Task

Spawn `pwn-expert` agent using `binary-analysis` skill to:
1. Analyze binary protections
2. Find vulnerability (BOF/format string/heap)
3. Develop exploit with pwntools
4. Capture flag

Flag format: varies by platform (e.g., `flag{...}`, `picoCTF{...}`, `HTB{...}`)
