# Social Media & Username OSINT Reference

## Username Search
```bash
# sherlock - username across platforms
sherlock username

# Online tools
https://namechk.com/
https://whatsmyname.app/
https://instantusername.com/
```

## Twitter/X Advanced Search
```
from:username
to:username
@username since:2023-01-01 until:2023-12-31
"exact phrase" filter:links
geocode:35.6812,139.7671,10km
```

## GitHub
```bash
# Search commits for secrets
https://github.com/search?q=password+filename%3A.env&type=code

# GitDorking
filename:.env password
filename:id_rsa
filename:.npmrc _auth
extension:pem private
```

## LinkedIn
```
site:linkedin.com/in/ "company name" "job title"
```

## Document Metadata

### PDF
```bash
exiftool document.pdf
pdfinfo document.pdf
strings document.pdf | grep -i author
```

### Office Documents
```bash
# Extract metadata
exiftool document.docx

# Unzip and inspect
unzip document.docx -d extracted/
cat extracted/docProps/core.xml
```

## CTF Patterns

### Find Person
```
1. sherlock/namechk username
2. Check social media profiles
3. Look for linked accounts
4. Search breach databases
```

### Find Deleted Content
```
1. Wayback Machine
2. Google cache
3. Archive.today
4. Social media caches
```
