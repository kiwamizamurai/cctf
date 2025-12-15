# CTF Network Patterns & Attacks

## Pattern 1: Flag in HTTP Traffic
```bash
tshark -r capture.pcap -Y http --export-objects http,./output/
strings ./output/* | grep -i flag

# Or search directly
tshark -r capture.pcap -Y "http contains flag" -T fields -e http.file_data
```

## Pattern 2: DNS Exfiltration
```bash
# Data hidden in DNS queries/responses
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name | \
    cut -d'.' -f1 | tr -d '\n' | base64 -d
```

## Pattern 3: ICMP Tunnel
```bash
# Data in ICMP payload
tshark -r capture.pcap -Y icmp -T fields -e data | xxd -r -p
```

## Pattern 4: Credentials in Plaintext
```bash
# FTP
tshark -r capture.pcap -Y ftp | grep -E "USER|PASS"

# HTTP Basic Auth
tshark -r capture.pcap -Y http -T fields -e http.authorization | base64 -d

# Telnet
strings capture.pcap | grep -A2 -B2 login
```

## Pattern 5: Encrypted Traffic with Key
```bash
# If TLS key is provided
tshark -r capture.pcap -o "tls.keylog_file:keylog.txt" -Y http
```

## Network Attacks Detection

### ARP Spoofing
```bash
# Duplicate IPs with different MACs
tshark -r capture.pcap -Y arp -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac | sort | uniq -d
```

### TCP RST Injection
```bash
tshark -r capture.pcap -Y "tcp.flags.reset == 1" -T fields -e ip.src -e tcp.srcport
```

### DNS Poisoning
```bash
# Multiple responses for same query
tshark -r capture.pcap -Y "dns.flags.response == 1" -T fields -e dns.qry.name -e dns.a | sort | uniq -c
```

## Port Scanning
```bash
# Nmap
nmap -sV target.com
nmap -sC -sV target.com  # With scripts
nmap -p- target.com      # All ports

# Masscan (fast)
masscan -p1-65535 target.com --rate=1000
```
