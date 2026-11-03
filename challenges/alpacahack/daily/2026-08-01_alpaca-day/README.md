# [misc/osint] Día Nacional de la Alpaca (alpaca-day)

> A pure trivia challenge: know the two alpaca breeds and which one has crimpy, fluffy fleece.

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | misc (trivia/osint) |
| Difficulty | ★☆☆☆☆ |
| Date | 2026-11-03 |
| Flag | `Alpaca{huacaya}` |

## Problem Statement

> 🦙 < Today is "Alpaca Day", established by the Peruvian government.
>
> According to an article by the Peruvian government, there are two breeds of alpaca. Answer in flag format, using lowercase English letters, with the name of the breed known for having "curly fiber and a fluffy appearance". For example, if the breed name were "Bulldog", the flag would be `Alpaca{bulldog}`.

Released: Aug 1, 2026. No files; answer is the breed name.

## TL;DR

- The two alpaca breeds are **Huacaya** and **Suri**.
- **Huacaya** has crimpy (curly/wavy), dense, fluffy "teddy-bear" fleece; **Suri** has long, silky, straight locks that hang in dreadlock-like twists.
- "Curly fiber and a fluffy appearance" → Huacaya → `Alpaca{huacaya}`.

## Solution

### Step 1: Identify the two breeds

Alpacas come in exactly two breeds: **Huacaya** and **Suri**.

### Step 2: Match the description

| Breed | Fleece | Appearance |
|-------|--------|------------|
| Huacaya | crimpy, dense, wavy/curly | fluffy, "teddy-bear" |
| Suri | long, silky, lustrous, straight | drapes in pencil-like locks / dreadlocks |

"Curly fiber and a fluffy appearance" unambiguously describes **Huacaya**.

### Step 3: Submit

Formatted as required (lowercase English letters): `Alpaca{huacaya}` → SOLVED.

## Tools Used

| Tool | Purpose |
|------|---------|
| Claude-in-Chrome | Read the prompt and submit the flag on the SPA |

## Lessons Learned

- Some AlpacaHack "misc" challenges are knowledge/trivia, not code — read the prompt literally and answer in the exact requested format (here, lowercase).

## Tags

`misc` `osint` `trivia` `alpaca`
