---
name: ctf-writeup-mining
description: Find and responsibly use prior CTF writeups to learn a technique or study an ENDED challenge's published solution. Searches Claude-in-Chrome in English and Japanese across CTFtime, top players'/teams' blogs and GitHub writeup repos, and the platform's own writeups tab. Extracts the technique and mental model to re-derive yourself. Enforces the boundary: the specific challenge's solution only after its window has ended.
---

# ctf-writeup-mining — stand on the shoulders of the best

Use this to learn a technique from prior writeups, or to study an **ENDED**
challenge's published solution. The world's strong CTF players publish how they
think — mine it, but understand and re-derive, never blind-copy.

## The boundary (check this first)
- The **specific challenge's** solution/writeup: only when its window has
  **ENDED** (confirm via the platform profile's "ENDED vs ACTIVE" check, e.g.
  AlpacaHack's `/writeups` page returns 200 when closed, 404 while active). See
  `.claude/CONDITIONS.md` publishing boundary.
- While a challenge/competition is **ACTIVE**: study only the **general technique
  class**, never the exact solve, and never publish anything.

## Where to look (search in English **and** Japanese)
Use **Claude-in-Chrome** (bilingual — much top CTF writing is Japanese):
- **CTFtime** task writeups (`ctftime.org/task/...`), team writeups.
- Top players'/teams' **blogs and GitHub writeup repos** (search the challenge
  or technique name + "writeup" / "解法" / "writeup ja").
- The platform's own **writeups tab** for the exact (ended) challenge.
- Search shapes: "<challenge> writeup", "<challenge> 解法", "<technique> ctf
  writeup", "<technique> とは".

## How to use what you find
1. Read for the **mental model and the technique name**, not the final payload.
2. Come back and **re-derive** it against this challenge's exact numbers/binary/
   constraints — adapt, don't paste. Verify with your own `solve.py`.
3. **Cross-check** across two sources when the idea is surprising.
4. **Cite** the source in the local `README.md` "References" (as done for
   `decreasing` and `no-parentheses`). Credit the author.

This generalizes the technique-name lookup that `ctf-auditor` does into a skill
the solver can invoke directly. For idea generation before you have a lead, use
`ctf-get-unstuck`; for finding an unfamiliar tool, use `ctf-tool-discovery`.
