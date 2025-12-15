# Wireshark & tshark Reference

## Display Filters

### By Protocol
```
http
tcp
udp
dns
ftp
smtp
icmp
```

### By IP
```
ip.addr == 192.168.1.1
ip.src == 192.168.1.1
ip.dst == 192.168.1.1
```

### By Port
```
tcp.port == 80
tcp.srcport == 443
udp.port == 53
```

### HTTP Specific
```
http.request.method == "GET"
http.request.method == "POST"
http.response.code == 200
http.request.uri contains "flag"
http.cookie contains "session"
```

### TCP Flags
```
tcp.flags.syn == 1
tcp.flags.ack == 1
tcp.flags.reset == 1
```

### Contains Data
```
frame contains "password"
http contains "flag"
```

## tshark Commands

### Export Objects
```bash
tshark -r capture.pcap --export-objects http,./extracted/
tshark -r capture.pcap --export-objects smb,./extracted/
```

### Follow Streams
```bash
tshark -r capture.pcap -z follow,tcp,ascii,0
tshark -r capture.pcap -z follow,tcp,hex,1
```

### Extract Fields
```bash
tshark -r capture.pcap -Y http -T fields -e http.request.uri
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name -e dns.a
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
```

### Statistics
```bash
tshark -r capture.pcap -z endpoints,ip
tshark -r capture.pcap -z http,tree
tshark -r capture.pcap -z conv,tcp
```

## File Extraction

```bash
# HTTP files
tshark -r capture.pcap --export-objects http,./http_files/

# FTP files (follow streams)
tshark -r capture.pcap -Y "ftp-data" -T fields -e data > ftp_data.hex

# TCP reassembly
tcpflow -r capture.pcap -o output/
```
