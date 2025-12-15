# Memory Forensics (Volatility)

## Volatility 3

```bash
# System info
vol -f memory.dmp windows.info

# Process list
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.pstree

# Command history
vol -f memory.dmp windows.cmdline

# File search
vol -f memory.dmp windows.filescan | grep -i "flag\|secret\|password"

# Dump files
vol -f memory.dmp windows.dumpfiles --virtaddr <addr>
vol -f memory.dmp windows.dumpfiles --physaddr <addr>

# Registry
vol -f memory.dmp windows.registry.hivelist
vol -f memory.dmp windows.registry.printkey

# Network connections
vol -f memory.dmp windows.netscan

# Password hashes
vol -f memory.dmp windows.hashdump
```

## Volatility 2 (Legacy)

```bash
# Identify profile
volatility -f memory.dmp imageinfo

# Use profile
volatility -f memory.dmp --profile=Win7SP1x64 pslist
volatility -f memory.dmp --profile=Win7SP1x64 filescan
volatility -f memory.dmp --profile=Win7SP1x64 dumpfiles -Q <offset> -D output/
```

## Quick String Search

```bash
strings memory.dmp | grep -i "flag\|password\|secret\|ctf\|key"
strings -e l memory.dmp | grep -i flag  # 16-bit little-endian
```
