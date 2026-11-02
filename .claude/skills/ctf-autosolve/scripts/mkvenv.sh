#!/usr/bin/env bash
# Build (or reuse) a cached throwaway venv for CTF solving.
#
# Many challenges need libraries that are not installed system-wide
# (pycryptodome, pwntools, flask, xdis, ...). Rebuilding one per run wastes
# time; this creates a single cached venv and only installs what is missing.
#
# Usage:
#   source .claude/skills/ctf-autosolve/scripts/mkvenv.sh        # default pkgs
#   source .claude/skills/ctf-autosolve/scripts/mkvenv.sh pkg... # extra pkgs
# After sourcing, $CTF_PY points at the venv's python.
#
# Notes:
# - Pure-python / stdlib is still preferred; use this only when a dep is needed.
# - Lives under the system temp dir so it is never committed.
set -u

CTF_VENV="${CTF_VENV:-${TMPDIR:-/tmp}/ctf-solve-venv}"
DEFAULT_PKGS=(pycryptodome pwntools flask xdis)
EXTRA_PKGS=("$@")

if [ ! -x "$CTF_VENV/bin/python" ]; then
  echo "[mkvenv] creating $CTF_VENV" >&2
  python3 -m venv "$CTF_VENV" || { echo "[mkvenv] venv creation failed" >&2; return 1 2>/dev/null || exit 1; }
  "$CTF_VENV/bin/python" -m pip install -q --upgrade pip >&2
fi

export CTF_PY="$CTF_VENV/bin/python"

# Install any requested/default package that is not importable yet.
import_name() { case "$1" in pycryptodome) echo Crypto;; pwntools) echo pwn;; *) echo "$1";; esac; }
for pkg in "${DEFAULT_PKGS[@]}" "${EXTRA_PKGS[@]}"; do
  mod="$(import_name "$pkg")"
  if ! "$CTF_PY" -c "import $mod" >/dev/null 2>&1; then
    echo "[mkvenv] installing $pkg" >&2
    "$CTF_PY" -m pip install -q "$pkg" >&2
  fi
done

echo "[mkvenv] ready: CTF_PY=$CTF_PY" >&2
