---
description: Find upcoming CTF competitions with Japan-friendly schedules
---

# Task: Find Upcoming CTF Competitions

Use Playwright MCP to access CTFtime.org and find upcoming CTF competitions that are suitable for participation from Japan (JST, UTC+9).

## Steps

1. **Navigate to CTFtime Events Page**
   - Go to https://ctftime.org/event/list/upcoming
   - Wait for the page to fully load
   - Scope: **Events within the next 3 months only**

2. **Extract Event Information**
   - Get the list of upcoming CTF events (next 3 months)
   - For each event, extract:
     - Event name
     - Start date/time (with timezone)
     - End date/time
     - CTF format (Jeopardy, Attack-Defense, etc.)
     - Weight/rating if available
     - URL to event page

3. **Filter for Japan-Friendly Times**
   - Convert times to JST (UTC+9)
   - Prioritize events that:
     - Start on Friday evening JST (after 18:00)
     - Start on Saturday morning JST
     - Run during weekend JST hours
     - Have duration of 24-48 hours (typical for online CTFs)

4. **Compile Recommendations**
   - List recommended upcoming CTFs from the next 3 months
   - For each, show:
     - Name and link
     - Start time in JST
     - Duration
     - Format
     - Why it's good for Japan participation

## Output Format

Present findings as a table with:
| Event | Date (JST) | Duration | Format | Weight | Link |

Then provide brief recommendations on which events are best suited for weekend participation from Japan.
