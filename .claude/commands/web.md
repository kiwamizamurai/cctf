---
allowed-tools: Bash, Read, Write, Edit, Grep, Glob, Task, WebFetch
argument-hint: <url-or-source-path>
description: Web vulnerability assessment
---

## Context

Target: $ARGUMENTS

## Task

Spawn `web-expert` agent using `web-security` skill to:
1. Reconnaissance (robots.txt, .git, directory enum)
2. Test injection points (SQLi, XSS, SSTI, Command Injection)
3. Check authentication/session flaws
4. Develop exploit
5. Capture flag

## Quick Checks
- SQLi: `' OR '1'='1`
- SSTI: `{{7*7}}`
- XSS: `<script>alert(1)</script>`

Flag format: varies by platform (e.g., `flag{...}`, `picoCTF{...}`, `HTB{...}`)
