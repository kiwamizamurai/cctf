# [web] Beat the Alpaca Lord

> A Python front-end and a Go back-end parse the same JSON differently: Go matches keys case-insensitively (last wins), so uppercase duplicates bypass the Python caps.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | web (parser differential) |
| Difficulty | ★★★☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{He_was_the_weakest_of_the_Four_Heavenly_Kings}` |

## Problem Statement

> We need your help, heroes!
>
> `beat-the-alpaca-lord.tar.gz` (Flask front `/api/fight` → Go `calc` service)

## TL;DR

- Flask checks (lowercase keys): `atk+int+luk <= 500` and `def+dex <= 500`, then forwards the JSON unchanged to Go.
- Go requires each sum `>= 1000` (each stat 0..1000). Impossible honestly — but Go's `encoding/json` matches struct fields **case-insensitively**, and with duplicate matches the **last** one wins.
- Send lowercase keys with value 1 (Python validates/sums these) followed by `Atk`,`Int`,… = 1000 (Go uses these). Python passes; Go sees 3000 and 2000 → flag.

## Background Knowledge

### Python vs Go JSON key handling

- Python `request.json` keeps `"atk"` and `"Atk"` as **distinct** dict keys; the validator only inspects the lowercase set and forwards everything via `requests.post(json=...)` (order preserved).
- Go `encoding/json` unmarshals into struct fields by **case-insensitive** name; when several JSON keys match one field, the decoder processes them in order and the last assignment wins. So trailing uppercase duplicates override the leading lowercase ones.

This is a classic HTTP parameter / JSON **parser differential**.

## Solution

```json
{"atk":1,"int":1,"luk":1,"def":1,"dex":1,
 "Atk":1000,"Int":1000,"Luk":1000,"Def":1000,"Dex":1000}
```

POST to `/api/fight`. See [`solve.py`](solve.py).

```bash
$ python3 solve.py 34.170.146.252 28608
Alpaca{He_was_the_weakest_of_the_Four_Heavenly_Kings}
```

## Tools Used

| Tool | Purpose |
|------|---------|
| Python stdlib `http.client` | Send the crafted JSON |

## Lessons Learned

- Two services validating the "same" request with different parsers is a vulnerability. Go's case-insensitive JSON keys + last-wins let the back-end see values the front-end never validated.
- Normalize/canonicalize once and forward the *validated* object, not raw client JSON.

## Tags

`web` `parser-differential` `json` `golang` `case-insensitive` `smuggling`
