#!/bin/bash
# User prompt submit hook: Add CTF context

INPUT=$(cat)
PROMPT=$(echo "$INPUT" | jq -r '.prompt // ""')

# Detect if user is asking about a specific category
CONTEXT=""
if [[ "$PROMPT" =~ (pwn|exploit|buffer|overflow|rop|heap) ]]; then
  CONTEXT="Category detected: Binary Exploitation"
elif [[ "$PROMPT" =~ (xss|sqli|sql|injection|ssrf|ssti|web) ]]; then
  CONTEXT="Category detected: Web Security"
elif [[ "$PROMPT" =~ (rsa|aes|cipher|decrypt|crypto|xor) ]]; then
  CONTEXT="Category detected: Cryptography"
elif [[ "$PROMPT" =~ (reverse|binary|disassemble|ghidra|ida) ]]; then
  CONTEXT="Category detected: Reverse Engineering"
elif [[ "$PROMPT" =~ (forensic|stego|hidden|carv|pcap|wireshark) ]]; then
  CONTEXT="Category detected: Forensics"
fi

# Output context
cat <<EOF
{
  "hookSpecificOutput": {
    "hookEventName": "UserPromptSubmit",
    "additionalContext": "CTF Learning mode active${CONTEXT:+. $CONTEXT}"
  }
}
EOF

exit 0
