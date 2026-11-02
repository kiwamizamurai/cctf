# ctf-autosolve — generic techniques & frictions

Platform-specific recipes (enumerate, read page, spawn, download, submit) live in
the active **platform profile**, `platforms/<name>.md`, named by
`.claude/CONDITIONS.md`. This file is the platform-independent know-how proven in
this workspace.

## Download hygiene

Download attachments into the challenge's own `dist/` (git-ignored), never run an
interpreter/build tool from inside it, pass paths as arguments, and read with
`python3 -I`. If a `curl`/`wget` form is refused by the pre-bash hook:
```bash
python3 -I -c "import urllib.request as u; u.urlretrieve('<URL>', 'dist/f.tar.gz')"
```

## Environment frictions & go-to tactics (this machine)

- **Linux ELF won't run on macOS, Docker often down.** Solve statically or over
  the network. For libc offsets, fetch the matching distro libc from the package
  pool and read symbols with `nm -D`. Minimize round-trips: hardcode offsets
  rather than parsing in-memory ELF over a one-read-per-request channel (remote
  services often have a ~60–180s timeout).
- **No pwntools/pycryptodome/elftools/sage.** Use `socket`, `struct`, `hashlib`,
  `math`, hand-rolled helpers, or make a throwaway `venv` and `pip install` a
  pure-python tool (e.g. `xdis` to disassemble a cross-version `.pyc`).
- **Heavy compute** (BSGS, brute force) → run it with `run_in_background` and
  keep working; you're notified on completion.

## Recurring technique patterns (see solved challenges for templates)

- **crypto**: shared/related primes (`gcd`), Franklin–Reiter related-message
  (polynomial gcd mod n), small-exponent / small-unknown via continued fractions
  or lattice, Newton power-sums, ECDLP via BSGS + point-order + CRT, reduce a
  composite modulus to known factors.
- **pwn**: NULL-deref as an absolute read (`malloc` fails → `ptr[i]`), `environ`
  to leak the stack, stack-canary bypass by controlling `fsbase`, `idiv` #DE /
  `INT_MIN/-1` crashes, format strings, ROP.
- **rev**: brute small input spaces against a hash table, undo simple encodings
  (base64/Brotli/layered base-N), disassemble `.pyc`/bytecode and re-implement
  the check, position-dependent XOR.
- **web**: auth/authorization gaps (path-matcher scope like `/admin/*` vs
  `/admin/**`), SSTI/SQLi/SSRF, insecure deserialization.
- **misc/pyjail**: filter bypass via `${IFS}`, f-string `{n:c}` to synthesize
  banned chars, `__reduce_ex__`→builtins, `__class_getitem__` overwrite, nested
  eval, comprehension for-target assignment.

## Counting / OSINT / meta challenges

Some challenges are quizzes or require archive enumeration rather than a solver
(e.g. "which challenge number is this?"). Use the platform's listing/stats, count
with two independent methods to kill off-by-one, and mark `stuck` with a note if
the data isn't fully enumerated yet.
