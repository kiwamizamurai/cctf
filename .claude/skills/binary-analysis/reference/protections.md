# Binary Protections & Vulnerability Detection

## Protection Analysis

| Protection | Enabled | Exploitation Impact |
|------------|---------|---------------------|
| **RELRO** | Partial | GOT writable |
| **RELRO** | Full | GOT read-only, target other areas |
| **Stack Canary** | Yes | Need to leak or bypass |
| **NX** | Yes | No shellcode, use ROP |
| **PIE** | Yes | Need address leak |
| **ASLR** | Yes | Need address leak |

## Vulnerability Detection Patterns

### Buffer Overflow
```bash
# Look for dangerous functions
objdump -d <binary> | grep -B5 -A5 "gets\|strcpy\|sprintf"

# Check buffer sizes
objdump -d <binary> | grep "sub.*rsp\|sub.*esp"
```

### Format String
```bash
# printf with user-controlled format
objdump -d <binary> | grep -B10 "printf" | grep -v "mov.*esi\|mov.*rdi.*0x"
```

### Heap Issues
```bash
# malloc/free patterns
objdump -d <binary> | grep -E "malloc|free|realloc" | wc -l
```

## cwe_checker - Automated Vulnerability Detection
```bash
# Automatically find vulnerable patterns in binaries
# https://github.com/fkie-cad/cwe_checker

# Run analysis
cwe_checker <binary>

# Detects:
# - CWE-119: Buffer overflow
# - CWE-125: Out-of-bounds read
# - CWE-416: Use after free
# - CWE-476: NULL pointer dereference
# - CWE-787: Out-of-bounds write
# - Double free, format string, etc.

# JSON output with filtering
cwe_checker <binary> --json | jq '.[] | select(.name | contains("CWE-119"))'
```
