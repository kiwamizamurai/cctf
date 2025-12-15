# Protocol Analysis Reference

## HTTP/HTTPS
```bash
# Find requests
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri -e http.request.method

# Find POST data
tshark -r capture.pcap -Y "http.request.method==POST" -T fields -e http.file_data

# Cookies and auth
tshark -r capture.pcap -Y http -T fields -e http.cookie -e http.authorization

# TLS SNI (HTTPS server names)
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields -e tls.handshake.extensions_server_name
```

## DNS
```bash
# All DNS queries
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name

# DNS exfiltration (TXT records)
tshark -r capture.pcap -Y "dns.qry.type == 16" -T fields -e dns.txt

# Unique queries
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name | grep -v "in-addr" | sort -u
```

## FTP
```bash
# FTP commands
tshark -r capture.pcap -Y ftp -T fields -e ftp.request.command -e ftp.request.arg

# Credentials
tshark -r capture.pcap -Y "ftp.request.command == USER || ftp.request.command == PASS"

# Follow FTP data stream
tshark -r capture.pcap -Y ftp-data -z follow,tcp,ascii,X
```

## SMTP/Email
```bash
# Email headers
tshark -r capture.pcap -Y smtp -T fields -e smtp.req.parameter

# Extract email content
tshark -r capture.pcap -Y "smtp.data.fragment" -T fields -e smtp.data.fragment
```

## ICMP
```bash
# Data in ICMP packets (exfil method)
tshark -r capture.pcap -Y icmp -T fields -e data
tshark -r capture.pcap -Y icmp -T fields -e icmp.data | xxd -r -p
```
