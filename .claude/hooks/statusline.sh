#!/bin/bash
# StatusLine hook: CTF challenge status display

INPUT=$(cat)

# Extract information from JSON
MODEL=$(echo "$INPUT" | jq -r '.model.display_name // .model.id // "Claude"')
CWD=$(echo "$INPUT" | jq -r '.workspace.current_dir // .cwd // ""')
PROJECT_DIR=$(echo "$INPUT" | jq -r '.workspace.project_dir // ""')
TOTAL_COST=$(echo "$INPUT" | jq -r '.cost.total_cost_usd // 0')

# Format cost
COST_DISPLAY=$(printf "\$%.2f" ${TOTAL_COST})

# Get current directory name
DIR_NAME="${CWD##*/}"

# Get git branch
if [ -n "$PROJECT_DIR" ]; then
  GIT_BRANCH=$(cd "$PROJECT_DIR" 2>/dev/null && git branch --show-current 2>/dev/null || echo "")
else
  GIT_BRANCH=$(cd "$CLAUDE_PROJECT_DIR" 2>/dev/null && git branch --show-current 2>/dev/null || echo "")
fi

# Build status line
STATUS="${DIR_NAME}"

if [ -n "$GIT_BRANCH" ]; then
  STATUS="$STATUS | $GIT_BRANCH"
fi

STATUS="$STATUS | ${MODEL} | ${COST_DISPLAY}"

echo "$STATUS"

exit 0
