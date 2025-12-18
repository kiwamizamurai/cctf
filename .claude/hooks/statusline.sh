#!/bin/bash
# StatusLine hook: Enhanced display for Rails + Docker development

# Color codes (only for diff stats and context)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Read JSON input from stdin
INPUT=$(cat)

# Helper functions for JSON parsing (more efficient)
get_json_value() {
    echo "$INPUT" | jq -r "$1 // \"$2\""
}

# Extract information from JSON
MODEL=$(get_json_value '.model.display_name' 'Sonnet 4')
CWD=$(get_json_value '.workspace.current_dir' '' | sed "s|$HOME|~|")
PROJECT_DIR=$(get_json_value '.workspace.project_dir' '')

# Get cost and context information
TOTAL_COST=$(get_json_value '.cost.total_cost_usd' '0')
CONTEXT_SIZE=$(get_json_value '.context_window.context_window_size' '0')
CURRENT_USAGE=$(echo "$INPUT" | jq '.context_window.current_usage')

# Calculate context usage percentage
if [ "$CURRENT_USAGE" != "null" ] && [[ "$CONTEXT_SIZE" =~ ^[0-9]+$ ]] && [ "$CONTEXT_SIZE" -ne 0 ]; then
    CURRENT_TOKENS=$(echo "$CURRENT_USAGE" | jq '.input_tokens + .cache_creation_input_tokens + .cache_read_input_tokens')
    CONTEXT_PERCENT=$((CURRENT_TOKENS * 100 / CONTEXT_SIZE))
else
    CONTEXT_PERCENT=0
fi

# Format cost display
COST_DISPLAY=$(printf "%.2f" "${TOTAL_COST}")

# Get git information from current directory
WORK_DIR="${PROJECT_DIR:-$CWD}"
if [ -d "$WORK_DIR/.git" ]; then
    GIT_BRANCH=$(cd "$WORK_DIR" 2>/dev/null && git branch --show-current 2>/dev/null || echo "")
    # Check if there are uncommitted changes
    if cd "$WORK_DIR" 2>/dev/null && ! git diff-index --quiet HEAD -- 2>/dev/null; then
        GIT_STATUS="*" # Dirty working tree
    else
        GIT_STATUS=""
    fi

    # Get diff stats against master if not on master
    GIT_DIFF_STATS=""
    if [ -n "$GIT_BRANCH" ] && [ "$GIT_BRANCH" != "master" ] && [ "$GIT_BRANCH" != "main" ]; then
        # Check if master or main exists
        if cd "$WORK_DIR" 2>/dev/null && git rev-parse --verify master >/dev/null 2>&1; then
            BASE_BRANCH="master"
        elif cd "$WORK_DIR" 2>/dev/null && git rev-parse --verify main >/dev/null 2>&1; then
            BASE_BRANCH="main"
        else
            BASE_BRANCH=""
        fi

        if [ -n "$BASE_BRANCH" ]; then
            # Get diff stats (added and deleted lines)
            DIFF_NUMS=""
            if cd "$WORK_DIR" 2>/dev/null; then
                DIFF_OUTPUT=$(git diff --numstat "$BASE_BRANCH"...HEAD 2>/dev/null)
                if [ -n "$DIFF_OUTPUT" ]; then
                    DIFF_NUMS=$(echo "$DIFF_OUTPUT" | awk '{added+=$1; deleted+=$2} END {print added" "deleted}' 2>/dev/null || echo "")
                fi
            fi
            if [ -n "$DIFF_NUMS" ] && [ "$DIFF_NUMS" != "0 0" ]; then
                ADDED=$(echo "$DIFF_NUMS" | cut -d' ' -f1)
                DELETED=$(echo "$DIFF_NUMS" | cut -d' ' -f2)
                if [ "$ADDED" != "0" ] || [ "$DELETED" != "0" ]; then
                    GIT_DIFF_STATS=" (${GREEN}+${ADDED}${NC}${RED}-${DELETED}${NC})"
                fi
            fi
        fi
    fi
else
    GIT_BRANCH=""
    GIT_STATUS=""
    GIT_DIFF_STATS=""
fi


# Build status line components
DIR_NAME="${CWD##*/}"
STATUS_PARTS=()

# Directory
STATUS_PARTS+=("${DIR_NAME}")

# Git branch with status
if [ -n "$GIT_BRANCH" ]; then
    STATUS_PARTS+=("${GIT_BRANCH}${GIT_STATUS}${GIT_DIFF_STATS}")
fi

# Model and cost
STATUS_PARTS+=("${MODEL}")
STATUS_PARTS+=("\$${COST_DISPLAY}")

# Context usage with color coding (last)
if [ "$CONTEXT_PERCENT" -gt 80 ]; then
    CONTEXT_COLOR="$RED"
elif [ "$CONTEXT_PERCENT" -gt 60 ]; then
    CONTEXT_COLOR="$YELLOW"
else
    CONTEXT_COLOR="$GREEN"
fi
STATUS_PARTS+=("${CONTEXT_COLOR}${CONTEXT_PERCENT}%${NC}")

# Join all parts with " | "
OLD_IFS="$IFS"
IFS=' | '
FINAL_STATUS="${STATUS_PARTS[*]}"
IFS="$OLD_IFS"

# Output the status line
echo -e "$FINAL_STATUS"

exit 0
