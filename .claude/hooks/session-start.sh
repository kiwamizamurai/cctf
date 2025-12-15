#!/bin/bash
# SessionStart hook: CTF Learning welcome message

CURRENT_TIME=$(date "+%Y-%m-%d %H:%M")

# Random learning-themed announcement
STYLES=(1 2 3)
RANDOM_STYLE=${STYLES[$RANDOM % ${#STYLES[@]}]}

case $RANDOM_STYLE in
  1)
    ANNOUNCEMENT="
    +-------------------------------------------+
    |  CTF Learning Mode                        |
    +-------------------------------------------+
    |  /solve   - Wizard classification         |
    |  /pwn     - Binary exploitation           |
    |  /web     - Web vulnerability             |
    |  /crypto  - Cryptographic attack          |
    |  /writeup - Generate documentation        |
    +-------------------------------------------+"
    ;;
  2)
    ANNOUNCEMENT="
============================================================

    CTF Learning Workspace
    ------------------------------------
    Categories: pwn | web | crypto | rev | forensics | misc
    Platforms:  picoCTF, HackTheBox, AlpacaHack

============================================================"
    ;;
  3)
    ANNOUNCEMENT="
+----------------------------------------------------------+
|                                                          |
|   CTF Learning Workspace                                 |
|   ==================================                     |
|   ultrathink: Deep analysis for heap/multi-step         |
|                                                          |
+----------------------------------------------------------+"
    ;;
esac

# Check for essential CTF tools
TOOLS_STATUS=""
MISSING_TOOLS=0

check_tool() {
  local cmd="$1"
  local name="${2:-$1}"
  if command -v "$cmd" &> /dev/null; then
    TOOLS_STATUS="${TOOLS_STATUS}    [OK] ${name}\n"
  else
    TOOLS_STATUS="${TOOLS_STATUS}    [NG] ${name}\n"
    ((MISSING_TOOLS++))
  fi
}

# Binary analysis
check_tool "checksec" "checksec"
check_tool "gdb" "gdb"

# Python tools (check via python)
if python3 -c "import pwn" 2>/dev/null; then
  TOOLS_STATUS="${TOOLS_STATUS}    [OK] pwntools\n"
else
  TOOLS_STATUS="${TOOLS_STATUS}    [NG] pwntools\n"
  ((MISSING_TOOLS++))
fi

# File analysis
check_tool "binwalk" "binwalk"
check_tool "exiftool" "exiftool"

# Crypto
check_tool "openssl" "openssl"

# Status summary
if [ "$MISSING_TOOLS" -eq 0 ]; then
  TOOL_HEADER="    Tools: All essential tools ready"
else
  TOOL_HEADER="    Tools: ${MISSING_TOOLS} tool(s) missing"
fi

FULL_MESSAGE="${ANNOUNCEMENT}

${TOOL_HEADER}
    -------------------------------------------
$(echo -e "${TOOLS_STATUS}")
    Time: ${CURRENT_TIME}
"

# JSON escape
JSON_MESSAGE=$(echo "$FULL_MESSAGE" | sed 's/"/\\"/g' | awk '{printf "%s\\n", $0}' | sed 's/\\n$//')

cat <<EOF
{
  "systemMessage": "${JSON_MESSAGE}",
  "hookSpecificOutput": {
    "hookEventName": "SessionStart",
    "additionalContext": "CTF Learning mode active"
  }
}
EOF

exit 0
