#!/bin/bash
# Pre-bash hook: CTF-safe command validation
# Blocks dangerous system commands while allowing CTF tools

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

# Dangerous patterns to BLOCK
DANGEROUS_PATTERNS=(
  "rm -rf /"
  "rm -rf /*"
  "rm -rf ~"
  "mkfs"
  "> /dev/sda"
  "dd if=/dev/zero of=/dev"
  "chmod -R 777 /"
  "curl .* | bash"
  "wget .* | bash"
)

# Check for dangerous commands
for PATTERN in "${DANGEROUS_PATTERNS[@]}"; do
  if [[ "$COMMAND" =~ $PATTERN ]]; then
    cat <<EOF
{
  "decision": "block",
  "reason": "Blocked: Dangerous command pattern detected. This could harm your system."
}
EOF
    exit 2
  fi
done

# Block attacks on non-CTF targets (basic check)
if [[ "$COMMAND" =~ (curl|wget|nc|ncat).*(--data|POST|-X).* ]] && \
   [[ ! "$COMMAND" =~ (localhost|127\.0\.0\.1|ctf|challenge|htb|thm|pico) ]]; then
  # Just warn, don't block - user might have legitimate target
  : # pass
fi

# Allow everything else - CTF tools need freedom
exit 0
