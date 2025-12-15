# iOS IPA Analysis Reference

## IPA Structure
```
app.ipa (ZIP file)
└── Payload/
    └── App.app/
        ├── Info.plist      # App config
        ├── App             # Main binary (Mach-O)
        ├── embedded.mobileprovision
        └── Frameworks/
```

## Basic Analysis
```bash
# IPA is just a ZIP
unzip app.ipa -d extracted/

# Check architecture
file Payload/App.app/App
otool -h Payload/App.app/App

# Strings
strings Payload/App.app/App | grep -i flag
```

## Binary Analysis
```bash
# List classes
class-dump Payload/App.app/App > classes.h

# Check for encryption (FairPlay DRM)
otool -l Payload/App.app/App | grep -A4 LC_ENCRYPTION
# If cryptid is 1, app is encrypted
```

## Plist Analysis
```bash
# Convert binary plist to XML
plutil -convert xml1 Info.plist -o Info.xml
cat Info.xml

# Or use Python
pip install biplist
python -c "import biplist; print(biplist.readPlist('Info.plist'))"
```

## Important Files
```bash
# App bundle
Info.plist          # Configuration
embedded.mobileprovision  # Provisioning profile

# Data directories (on device)
/var/mobile/Containers/Data/Application/<UUID>/
├── Documents/
├── Library/
│   ├── Caches/
│   └── Preferences/
└── tmp/
```

## Decryption (Jailbroken)
```bash
# If encrypted, use frida-ios-dump or Clutch
# Or dump from memory on jailbroken device
```
