---
allowed-tools: Bash, Read, Write, Edit, Grep, Glob, Task
argument-hint: <challenge-path-or-description>
description: Analyze CTF challenge with wizard classification
---

## Context

Challenge target: $ARGUMENTS

Current directory contents:
!`ls -la 2>/dev/null | head -20`

File types:
!`file * 2>/dev/null | head -10`

## Task

1. **First, spawn the `wizard` agent** to classify the challenge
2. Based on the wizard's classification, invoke the matching specialist **skill**
   (via the Skill tool)
3. Solve the challenge and capture the flag

## Category Routing (classification → skill)

| Category | Skill |
|----------|-------|
| pwn | binary-analysis |
| rev | binary-analysis |
| web | web-security |
| crypto | crypto-analysis |
| forensics | forensics |
| networking | networking |
| mobile | mobile-security |
| osint | osint |
| misc | pyjail |

Flag format: varies by platform (e.g., `flag{...}`, `picoCTF{...}`, `HTB{...}`)
