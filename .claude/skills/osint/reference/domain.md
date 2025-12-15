# Domain & IP OSINT Reference

## DNS Reconnaissance
```bash
# DNS records
dig target.com ANY
dig target.com MX
dig target.com TXT
nslookup -type=any target.com

# Subdomain enumeration
subfinder -d target.com
amass enum -d target.com

# Zone transfer (if misconfigured)
dig axfr @ns1.target.com target.com
```

## WHOIS
```bash
whois target.com
whois 1.2.3.4

# Historical WHOIS
https://whois.domaintools.com/
```

## Web Archives
```bash
# Wayback Machine
https://web.archive.org/web/*/target.com

# API access
curl "http://archive.org/wayback/available?url=target.com"

# Other archives
https://archive.today/
```

## Email OSINT
```bash
# Check email breach
https://haveibeenpwned.com/

# Email to social media
https://epieos.com/

# Hunter.io for corporate emails
https://hunter.io/
```

## Crypto/Blockchain
```bash
# Bitcoin address lookup
https://www.blockchain.com/explorer
https://blockchair.com/

# Ethereum
https://etherscan.io/

# Trace transactions, check associated addresses
```
