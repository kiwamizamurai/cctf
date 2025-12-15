# Advanced Binary Analysis Tools

## qira - QEMU Runtime Analysis
```bash
# qira records execution for time-travel debugging
# https://github.com/BinaryAnalysisPlatform/qira

# Start qira server
qira ./binary

# Access web interface
# http://localhost:3002

# Features:
# - Record/replay execution
# - View registers/memory at any instruction
# - Track changes over time
# - IDA integration
```

## Triton - Dynamic Binary Analysis
```python
# Triton: Dynamic symbolic execution
# https://github.com/JonathanSalwan/Triton

from triton import *

ctx = TritonContext()
ctx.setArchitecture(ARCH.X86_64)

# Load binary
with open('./binary', 'rb') as f:
    code = f.read()

ctx.setConcreteMemoryAreaValue(0x400000, code)

# Symbolic execution for constraint solving
# Useful for: keygen, license cracking, path exploration
```

## ROPgadget
```bash
# Find ROP gadgets
ROPgadget --binary <binary>
ROPgadget --binary <binary> | grep "pop rdi"
ROPgadget --binary <binary> --ropchain
```

## one_gadget
```bash
# Find one-shot RCE gadgets in libc
one_gadget <libc>
one_gadget <libc> -l 2  # More constraints
```

## pwntools Utilities
```bash
# Generate cyclic pattern
python3 -c "from pwn import *; print(cyclic(200))"

# Find offset from pattern
python3 -c "from pwn import *; print(cyclic_find(0x61616167))"

# Find offset from string
python3 -c "from pwn import *; print(cyclic_find('gaaa'))"
```

## GDB with pwndbg/GEF
```bash
# Breakpoints
b *main
b *0x401234

# Examine
x/20gx $rsp    # Stack
x/s 0x404000   # String
vmmap          # Memory map
heap           # Heap info

# PIE handling
piebase        # Show PIE base
b *$piebase+0x1234
```

## angr - Symbolic Execution
```python
import angr

proj = angr.Project('./binary')
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)

# Find path to success
simgr.explore(find=0x401234, avoid=0x401300)
if simgr.found:
    print(simgr.found[0].posix.dumps(0))  # Input
```
