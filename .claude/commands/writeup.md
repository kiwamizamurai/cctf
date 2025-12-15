---
allowed-tools: Bash, Read, Write, Edit, Grep, Glob
argument-hint: <challenge-name>
description: Generate writeup for solved CTF challenges
---

## Context

Challenge: $ARGUMENTS

Current directory:
!`pwd`

Recent files:
!`ls -lt 2>/dev/null | head -10`

Solution scripts:
!`ls *.py solve.* exploit.* 2>/dev/null | head -5`

Distributed files:
!`ls dist/ 2>/dev/null | head -5`

Work files:
!`ls work/ 2>/dev/null | head -5`

## Task

Generate a comprehensive CTF writeup using the `writeup-generator` skill.

Read the skill documentation at `.claude/skills/writeup/SKILL.md` and format specification at `.claude/skills/writeup/format.md`.

## Output

Save writeup as `README.md` in the current challenge directory.

```
challenge-name/
├── README.md      # <- CREATE THIS
├── solve.py       # Solution (tracked)
├── dist/          # Challenge files (ignored)
└── work/          # Working files (ignored)
```
