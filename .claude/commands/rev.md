---
allowed-tools: Bash, Read, Write, Edit, Grep, Glob, Task
argument-hint: <binary-file>
description: Reverse engineering workflow
---

## Context

Target: $ARGUMENTS

Binary info:
!`file $ARGUMENTS 2>/dev/null`

Strings:
!`strings $ARGUMENTS 2>/dev/null | grep -iE "flag|correct|wrong|password|key" | head -10`

## Task

Spawn `rev-expert` agent using `binary-analysis` skill to:
1. Static analysis (Ghidra/IDA)
2. Find flag check logic
3. Dynamic analysis if needed (GDB)
4. Solve with keygen/patch/symbolic execution

Flag format: varies by platform (e.g., `flag{...}`, `picoCTF{...}`, `HTB{...}`)
