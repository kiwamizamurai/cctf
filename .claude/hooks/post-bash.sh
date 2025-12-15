#!/bin/bash
# Post-bash hook: Track CTF exploit execution

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.args.command // ""')
EXIT_CODE=$(echo "$INPUT" | jq -r '.result.exitCode // 0')
STDOUT=$(echo "$INPUT" | jq -r '.result.stdout // ""')

# Check for flag patterns in output
FLAG_PATTERNS=(
  "flag{"
  "FLAG{"
  "ctf{"
  "CTF{"
  "picoCTF{"
  "HTB{"
  "THM{"
  "Alpaca{"
  "TSGLIVE{"
)

FLAG_FOUND=false
for PATTERN in "${FLAG_PATTERNS[@]}"; do
  if [[ "$STDOUT" == *"$PATTERN"* ]]; then
    FLAG_FOUND=true
    break
  fi
done

# Play sound when flag is captured
if [ "$FLAG_FOUND" = true ]; then
  afplay /System/Library/Sounds/Funk.aiff &
fi

exit 0
