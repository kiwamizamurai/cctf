---
name: ctf-get-unstuck
description: Escalation ladder for a STUCK CTF challenge — when the obvious approach failed, you've looped on one idea, or you need fresh/creative/lateral ideas. Re-reads constraints, questions the classification, abstracts the problem to its primitives, deliberately generates wild ideas, and (when long-stuck) studies how top CTF players think via Claude-in-Chrome in English and Japanese. Complements ctf-auditor (deep checklist) and ctf-writeup-mining (per-challenge writeups).
---

# ctf-get-unstuck — think your way out, then learn from the best

Use this when an approach failed, you've been looping on one idea, or you need
ideas you don't have yet. Climb the ladder in order; stop as soon as one rung
produces a concrete next step. Record each hypothesis you try (and why you
dropped it) with `ctf_state note <slug> "..."` so the ledger stays honest and
`ctf-auditor` can build on it.

## The ladder

**0. Re-read everything, slowly.** The prompt and **every** distributed file
(source, `strings`, Dockerfile/compose for the flag path + pinned versions,
Makefile, configs). Most "stuck" is a missed constraint: exact length/charset,
a filter's real semantics (`str.find('')`, membership vs substring), word-size/
ABI, the flag's own wording, or the challenge **title** as a hint.

**1. Question the classification.** Is it really the category you assumed? A
"rev" may be a tiny brute force; a "web" may be an authz bug; a "misc" may be a
jail. Re-run the `wizard` lens on it.

**2. Find a cleaner primitive.** Restate what you *actually* control and what it
gives you. Is there a stronger/simpler primitive hiding in the same bug (an
absolute read instead of a relative one, an oracle instead of a decrypt)?

**3. Abstract — strip the flavor.** Delete the theme/story and write the bare
mechanism: *"I have primitive X; I need Y; what bridges X→Y?"* Solve the abstract
version, then map it back. Most CTF challenges are a known technique wearing a
costume.

**4. Lateral & wild ideas — generate before you judge.** Deliberately list
several off-the-wall ideas *without* filtering, then test them:
- Invert each assumption ("what if the intended bug is the opposite of what I
  think?", "what if the check is bypassable, not solvable?").
- Combine two weak primitives into one strong one.
- Hunt the **unintended** solve (crash for a flag, a trivially-true comparison,
  a side channel, an error message that leaks).
- Read the signals the author left: the flag text, the title, the point value,
  the hint, the exact wording of the prompt.

**5. Long-stuck → learn how the best think.** Use **Claude-in-Chrome** to search
in **both English and Japanese** for how strong CTF players reason about this
*class* of challenge (not this exact one — for the exact challenge's writeup use
`ctf-writeup-mining`, and only if its window has ENDED). Read top players'/teams'
writeups, blog posts, and their **comments/explanations** for the mental model;
extract the **technique name**, then come back and **re-derive it yourself**.
Good search shapes: "<mechanism> CTF technique", "<format> 解き方", "<primitive>
exploit writeup". Cross-check anything you borrow.

## When to hand off
- Need a thorough, adversarial second opinion on what you overlooked → spawn the
  **`ctf-auditor`** subagent (don't re-implement its checklist here).
- Need to find/choose an unfamiliar tool → **`ctf-tool-discovery`**.
- The challenge is ENDED and you want its published solution → **`ctf-writeup-mining`**.
- Truly blocked by a missing environment (hardware we lack): mark `stuck` with a
  note and move on; revisit later.

Stay honest: never claim a path works until `solve.py` actually produced the
flag. Respect the active-challenge publishing boundary in `.claude/CONDITIONS.md`.
