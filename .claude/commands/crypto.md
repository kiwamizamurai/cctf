---
allowed-tools: Bash, Read, Write, Edit, Grep, Glob, Task
argument-hint: <crypto-file-or-ciphertext>
description: Cryptographic attack analysis
---

## Context

Target: $ARGUMENTS

File contents (if file):
!`head -50 $ARGUMENTS 2>/dev/null`

## Task

Spawn `crypto-expert` agent using `crypto-analysis` skill to:
1. Try Ciphey auto-decrypt first: `ciphey -t "ciphertext"`
2. Identify algorithm (RSA/AES/XOR/classical)
3. Find weakness and implement attack
4. Decrypt flag

## RSA Quick Check
- Small e → direct eth root
- Large e → Wiener's attack
- Check FactorDB for n

Flag format: varies by platform (e.g., `flag{...}`, `picoCTF{...}`, `HTB{...}`)
