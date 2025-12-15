# Writeup Format Specification

Complete format specification for CTF writeups.

## Document Structure

### 1. Title & One-liner

```markdown
# [Category] Challenge Name

> One sentence describing what you can learn from this challenge
```

**Guidelines:**
- Category in brackets: `[pwn]`, `[web]`, `[crypto]`, `[rev]`, `[misc]`, `[forensics]`
- Challenge name exactly as shown on the platform
- One-liner should highlight the key learning, not just the vulnerability

### 2. Overview Table

```markdown
## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | pwn |
| Difficulty | ★★☆☆☆ |
| Date | 2024-12-14 |
| Flag | `Alpaca{...}` |
```

**Field Definitions:**

| Field | Description | Examples |
|-------|-------------|----------|
| Platform | CTF platform name | AlpacaHack, picoCTF, HackTheBox |
| Event | Event type or name | Daily Challenge, picoCTF 2024, Round 1 |
| Category | Challenge category | pwn, web, crypto, rev, misc, forensics |
| Difficulty | Star rating (1-5) | ★☆☆☆☆ to ★★★★★ |
| Date | Date solved | YYYY-MM-DD format |
| Flag | Captured flag | Redact if platform requires |

### 3. Problem Statement

```markdown
## Problem Statement

> Original problem description from the platform
>
> Include any hints if provided
```

**Guidelines:**
- Quote the original text verbatim
- Include provided files list
- Note connection details for remote challenges

### 4. TL;DR

```markdown
## TL;DR

- Key vulnerability or weakness exploited
- Core technique used
- Brief description of the attack flow
```

**Guidelines:**
- Maximum 3-5 bullet points
- Should give experienced readers a quick understanding
- No code in this section

### 5. Background Knowledge

```markdown
## Background Knowledge

Explain prerequisite concepts needed to understand this writeup.

### Concept 1
Explanation...

### Concept 2
Explanation...
```

**Guidelines:**
- Target readers who are learning
- Link to external resources for deep dives
- Include diagrams or examples where helpful
- Skip obvious basics, focus on challenge-specific knowledge

### 6. Solution

```markdown
## Solution

### Step 1: Initial Reconnaissance

Description of initial analysis...

```bash
# Commands used
file challenge
checksec --file=challenge
```

### Step 2: Vulnerability Analysis

Description of vulnerability discovery...

### Step 3: Exploit Development

Description of exploit strategy...

```python
# solve.py
from pwn import *
# ...
```

### Step 4: Capturing the Flag

Final exploitation and flag capture...
```

**Guidelines:**
- Use numbered steps with descriptive titles
- Show actual commands/code with output when relevant
- Explain the "why" not just the "what"
- Include failed attempts if they provide learning value
- Reference line numbers in source code analysis

### 7. Tools Used

```markdown
## Tools Used

| Tool | Purpose |
|------|---------|
| checksec | Binary security analysis |
| Ghidra | Reverse engineering |
| pwntools | Exploit development |
```

**Guidelines:**
- List all tools used during the solve
- Include version if relevant to reproducibility
- Brief description of how each tool was used

### 8. Lessons Learned

```markdown
## Lessons Learned

### What I Learned
- New technique or concept discovered
- Tool usage improvement

### Mistakes Made
- Initial wrong approaches
- Time wasted on dead ends

### Future Improvements
- Skills to develop
- Related topics to study
```

**Guidelines:**
- Be honest about difficulties
- Focus on personal growth
- Reference resources for further learning

### 9. References

```markdown
## References

- [Resource Title](URL) - Brief description
- [Another Resource](URL) - Brief description
```

**Guidelines:**
- Include all resources consulted
- Credit other writeups if referenced
- Link to official documentation when applicable

### 10. Tags

```markdown
## Tags

`category` `technique` `vulnerability` `tool`
```

**Tag Categories:**

| Type | Examples |
|------|----------|
| Category | `pwn`, `web`, `crypto`, `rev` |
| Vulnerability | `buffer-overflow`, `sql-injection`, `xss` |
| Technique | `rop`, `ret2libc`, `format-string` |
| Tool | `ghidra`, `burpsuite`, `z3` |
| Concept | `heap`, `kernel`, `aes` |

## Platform-Specific Notes

### AlpacaHack
- Flag format: `Alpaca{...}` or `TSGLIVE{...}`
- Daily challenges: `daily/YYYY-MM-DD_name/`
- Contests: `contests/YYYY-MM_event/challenge/`

### picoCTF
- Flag format: `picoCTF{...}`
- Organize by year: `YYYY/challenge-name/`

### HackTheBox
- Flag format: `HTB{...}`
- Challenges: `challenges/category/name/`
- Machines: `machines/machine-name/`

### CTFtime Competitions
- Various flag formats
- Directory: `YYYY-MM_competition/challenge/`
