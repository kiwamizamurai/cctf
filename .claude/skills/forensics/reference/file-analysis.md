# File Analysis & Carving

## Basic Analysis Pipeline

```bash
# 1. File type
file suspicious_file
file -b suspicious_file  # Brief

# 2. Metadata
exiftool suspicious_file
exiftool -a -u -g1 suspicious_file  # All metadata

# 3. Strings
strings suspicious_file | grep -iE "flag|ctf|key|secret|password"
strings -n 8 suspicious_file  # Min 8 chars

# 4. Hex dump
xxd suspicious_file | head -50
```

## Embedded Files

```bash
# binwalk - detect embedded files
binwalk suspicious_file
binwalk -e suspicious_file  # Extract

# foremost - file carving
foremost -i suspicious_file -o output/
```

## File Magic Bytes

| Type | Magic Bytes | Footer |
|------|-------------|--------|
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `IEND` |
| JPEG | `FF D8 FF` | `FF D9` |
| GIF | `47 49 46 38` | `3B` |
| PDF | `25 50 44 46` | `%%EOF` |
| ZIP | `50 4B 03 04` | `50 4B 05 06` |
| RAR | `52 61 72 21` | - |
| ELF | `7F 45 4C 46` | - |
| PCAP | `D4 C3 B2 A1` | - |

## Fix Corrupted Headers

```bash
# PNG header
printf '\x89PNG\r\n\x1a\n' | dd of=broken.png bs=1 conv=notrunc

# JPEG header
printf '\xff\xd8\xff' | dd of=broken.jpg bs=1 conv=notrunc
```

## Password Cracking

```bash
# ZIP
zip2john archive.zip > hash.txt
john --wordlist=rockyou.txt hash.txt
fcrackzip -u -D -p rockyou.txt archive.zip

# PDF
pdf2john file.pdf > hash.txt
john hash.txt

# hashcat
hashcat -m 17200 hash.txt rockyou.txt  # PKZIP
```

## Exposed .git/.svn

```bash
# dvcs-ripper
./rip-git.pl -v -u http://target/.git/
./rip-svn.pl -v -u http://target/.svn/

# Manual
wget -r --no-parent http://target/.git/
git checkout -- .
git log --oneline
git show <commit>
```
