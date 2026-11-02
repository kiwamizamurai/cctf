#!/usr/bin/env python3
"""
ctf_state.py - state backbone for the autonomous CTF-solving harness.

Two files under .claude/state/ctf/ (git-ignored, operational state):
  queue.json    : current status of every known challenge
  ledger.ndjson : append-only decision ledger (one JSON object per line)

A challenge record:
  {slug, platform, event, date, category, difficulty, url, status,
   flag, attempts, notes, updated}
status in: todo | solving | solved | stuck | skip(active)

Usage:
  ctf_state.py add <slug> [--platform ..] [--date ..] [--category ..]
                          [--difficulty ..] [--url ..] [--status ..]
  ctf_state.py import <file.json|-->            # bulk add from a JSON list
  ctf_state.py status <slug> <status>
  ctf_state.py flag <slug> <FLAG> [--note ..]   # marks solved + records flag
  ctf_state.py note <slug> <text>
  ctf_state.py next [--category ..]             # print next todo slug (JSON)
  ctf_state.py summary                          # counts + remaining
  ctf_state.py list [--status ..]
  ctf_state.py log <event> [--slug ..] [--data ..]   # append to the ledger

All writes also append a ledger entry so the run is auditable.
Designed to be safe to call from hooks and from the model.
"""
import argparse
import json
import os
import sys
import time

ROOT = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
STATE_DIR = os.path.join(ROOT, ".claude", "state", "ctf")
QUEUE = os.path.join(STATE_DIR, "queue.json")
LEDGER = os.path.join(STATE_DIR, "ledger.ndjson")

VALID_STATUS = {"todo", "solving", "solved", "stuck", "skip"}


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _load():
    try:
        with open(QUEUE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"challenges": {}}


def _save(db):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = QUEUE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(db, f, indent=1, ensure_ascii=False)
    os.replace(tmp, QUEUE)


def ledger(event, slug=None, **data):
    os.makedirs(STATE_DIR, exist_ok=True)
    rec = {"t": _now(), "event": event}
    if slug:
        rec["slug"] = slug
    if data:
        rec["data"] = data
    with open(LEDGER, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _rec(db, slug):
    return db["challenges"].setdefault(
        slug,
        {"slug": slug, "platform": "alpacahack", "event": "daily",
         "date": "", "category": "", "difficulty": "", "url": "",
         "status": "todo", "flag": "", "attempts": 0, "notes": [],
         "updated": _now()},
    )


def cmd_add(a):
    db = _load()
    r = _rec(db, a.slug)
    for k in ("platform", "date", "category", "difficulty", "url", "status"):
        v = getattr(a, k, None)
        if v:
            r[k] = v
    r["updated"] = _now()
    _save(db)
    ledger("add", a.slug, status=r["status"])
    print(f"added {a.slug} [{r['status']}]")


def cmd_import(a):
    raw = sys.stdin.read() if a.file == "-" else open(a.file).read()
    items = json.loads(raw)
    db = _load()
    n = 0
    for it in items:
        slug = it["slug"]
        r = _rec(db, slug)
        for k in ("platform", "event", "date", "category", "difficulty", "url", "status", "flag"):
            if it.get(k):
                r[k] = it[k]
        r["updated"] = _now()
        n += 1
    _save(db)
    ledger("import", data={"count": n})
    print(f"imported {n} challenges")


def cmd_status(a):
    if a.value not in VALID_STATUS:
        sys.exit(f"status must be one of {sorted(VALID_STATUS)}")
    db = _load()
    r = _rec(db, a.slug)
    r["status"] = a.value
    r["updated"] = _now()
    _save(db)
    ledger("status", a.slug, status=a.value)
    print(f"{a.slug} -> {a.value}")


def cmd_flag(a):
    db = _load()
    r = _rec(db, a.slug)
    r["flag"] = a.flag
    r["status"] = "solved"
    r["attempts"] = r.get("attempts", 0) + 1
    if a.note:
        r["notes"].append(a.note)
    r["updated"] = _now()
    _save(db)
    ledger("solved", a.slug, flag=a.flag)
    print(f"SOLVED {a.slug}: {a.flag}")


def cmd_note(a):
    db = _load()
    r = _rec(db, a.slug)
    r["notes"].append(a.text)
    r["updated"] = _now()
    _save(db)
    ledger("note", a.slug, text=a.text)
    print("noted")


def cmd_next(a):
    db = _load()
    best = None
    for r in db["challenges"].values():
        if r["status"] != "todo":
            continue
        if a.category and r["category"].lower() != a.category.lower():
            continue
        # oldest-first by date then slug
        key = (r.get("date", ""), r["slug"])
        if best is None or key < best[0]:
            best = (key, r)
    if best is None:
        print(json.dumps({"next": None}))
    else:
        print(json.dumps({"next": best[1]}, ensure_ascii=False))


def cmd_summary(a):
    db = _load()
    counts = {}
    for r in db["challenges"].values():
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    total = len(db["challenges"])
    remaining = counts.get("todo", 0) + counts.get("solving", 0) + counts.get("stuck", 0)
    print(json.dumps({"total": total, "counts": counts, "remaining": remaining},
                     ensure_ascii=False))


def cmd_list(a):
    db = _load()
    for r in sorted(db["challenges"].values(), key=lambda x: (x.get("date", ""), x["slug"])):
        if a.status and r["status"] != a.status:
            continue
        print(f"{r['status']:8} {r.get('date',''):12} {r['category']:10} {r['slug']}  {r.get('flag','')}")


def cmd_log(a):
    data = json.loads(a.data) if a.data else {}
    ledger(a.event, a.slug, **data)
    print("logged")


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("add"); s.add_argument("slug")
    for k in ("platform", "date", "category", "difficulty", "url", "status"):
        s.add_argument(f"--{k}")
    s.set_defaults(fn=cmd_add)

    s = sub.add_parser("import"); s.add_argument("file"); s.set_defaults(fn=cmd_import)
    s = sub.add_parser("status"); s.add_argument("slug"); s.add_argument("value"); s.set_defaults(fn=cmd_status)
    s = sub.add_parser("flag"); s.add_argument("slug"); s.add_argument("flag"); s.add_argument("--note"); s.set_defaults(fn=cmd_flag)
    s = sub.add_parser("note"); s.add_argument("slug"); s.add_argument("text"); s.set_defaults(fn=cmd_note)
    s = sub.add_parser("next"); s.add_argument("--category"); s.set_defaults(fn=cmd_next)
    s = sub.add_parser("summary"); s.set_defaults(fn=cmd_summary)
    s = sub.add_parser("list"); s.add_argument("--status"); s.set_defaults(fn=cmd_list)
    s = sub.add_parser("log"); s.add_argument("event"); s.add_argument("--slug"); s.add_argument("--data"); s.set_defaults(fn=cmd_log)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
