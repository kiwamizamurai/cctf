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

1. **First, spawn `wizard` agent** to classify the challenge
2. Based on wizard's classification, spawn the appropriate specialist agent
3. Solve the challenge and capture the flag

## Agent Routing

| Category | Agent | Skill |
|----------|-------|-------|
| pwn | pwn-expert | binary-analysis |
| rev | rev-expert | binary-analysis |
| web | web-expert | web-security |
| crypto | crypto-expert | crypto-analysis |
| forensics | forensics-expert | forensics |
| networking | networking-expert | networking |
| mobile | mobile-expert | mobile-security |
| osint | osint-expert | osint |
| misc | misc-expert | pyjail |

Flag format: varies by platform (e.g., `flag{...}`, `picoCTF{...}`, `HTB{...}`)
