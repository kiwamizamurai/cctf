# How strong CTF players actually think

Distilled from the methodology top hackers repeatedly articulate (LiveOverflow's
"understand the system, don't follow steps"; Gynvael Coldwind's structured
problem-solving; Google Project Zero's root-cause + variant analysis; and the
recurring advice in strong players'/teams' writeups). Use it as the *mental
model* behind the ladder in `SKILL.md` — not a checklist, a way of seeing.

## Core stance
- **Understand the system deeply, don't pattern-match steps.** Weak solvers try
  tools until something sticks; strong solvers build a correct mental model of
  how the target actually works, then the bug is obvious. If you're guessing,
  you don't understand it yet — go read/trace more.
- **The challenge has an essence; the rest is costume.** Authors embed one
  intended idea and deliberately strip pointless distractors. Name the essence
  in one sentence ("this is a related-message RSA", "this is a filter whose
  check ≠ what it guards"). If you can't, you haven't found it yet.
- **Every oddity exists for a reason.** Each provided file, weird constant,
  version pin, extra endpoint, or strange constraint was put there on purpose.
  Enumerate *why each one is present* — the unexplained oddity is usually the
  key.
- **Assume nothing; verify everything.** Confirm the data type, the exact
  length/charset, what a function *actually* does (not what its name says), the
  precise version. Most "stuck" is a false assumption you never checked.

## Reasoning loop
- **Decompose** the big problem into the smallest independently-checkable pieces,
  solve/verify each, then compose. Don't hold the whole thing in your head.
- **Hypothesize → test cheaply → iterate fast.** Form a concrete falsifiable
  hypothesis ("if X, then this byte is a length"), run the smallest experiment
  that proves or kills it, and move on. Speed of iteration beats depth of a
  single guess.
- **Root cause + variant.** When something half-works, find *why* exactly, then
  ask "what's the neighboring version of this bug?" — the intended solve is often
  one variant away.
- **Work backward from the goal.** "I need the flag file / RCE / the key. What's
  the last step that yields it, and what must be true just before it?" Chain
  backward to something you already control.

## When it resists
- **Being stuck for hours is normal — even for the best.** It's a signal to
  change *level*, not to grind the same idea. Switch between zooming in (bytes,
  one function) and zooming out (what is the author testing?).
- **Widen the angle; stay humble.** The intended path is usually short and
  elegant. If your plan is monstrous, you're probably off the intended path —
  step back and look for the simpler primitive you walked past.
- **Invert.** "What if the check is bypassable, not solvable?" "What if the
  intended bug is the opposite of what I assumed?" "What if the unintended solve
  (a crash, a trivially-true compare, an error that leaks) is the point?"
- **Read the author's signals.** Flag text, challenge title, point value,
  category, and the exact wording of the prompt are hints the author chose.
- **Learn deliberately from the best.** Reading strong players' writeups —
  especially the parts where they explain their *reasoning and dead-ends*, not
  just the final payload — is how you acquire new mental models. Extract the
  technique and the way-of-thinking, then re-derive it yourself (see
  `ctf-writeup-mining`; the specific challenge's writeup only when ENDED).

## Anti-patterns to catch yourself in
- Running tools without a hypothesis. Re-reading the *same* way and expecting a
  new result. Building an elaborate contraption instead of questioning the
  premise. Refusing to look things up out of pride — using search/AI/writeups to
  get unstuck is how top players learn, not cheating.
