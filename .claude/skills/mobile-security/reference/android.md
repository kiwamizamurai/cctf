# Android APK Analysis Reference

## APK Structure
```
app.apk
├── AndroidManifest.xml  # App config, permissions
├── classes.dex          # Compiled Java/Kotlin code
├── classes2.dex         # Additional DEX files
├── res/                 # Resources (layouts, strings)
├── assets/              # Raw assets
├── lib/                 # Native libraries (.so files)
│   ├── armeabi-v7a/
│   ├── arm64-v8a/
│   └── x86_64/
└── META-INF/            # Signatures
```

## Basic Analysis
```bash
# File info
file app.apk
unzip -l app.apk

# Extract APK
apktool d app.apk -o extracted/
# or
unzip app.apk -d extracted/

# Search for flags/secrets
grep -r "flag\|secret\|password\|api_key" extracted/
strings extracted/classes.dex | grep -i flag
```

## jadx Decompilation
```bash
# GUI
jadx-gui app.apk

# CLI - decompile to Java
jadx app.apk -d output/

# Search in decompiled code
grep -r "flag" output/
grep -r "BuildConfig" output/  # Often contains secrets
```

## apktool
```bash
# Decode resources and smali
apktool d app.apk -o decoded/

# Rebuild after modification
apktool b decoded/ -o modified.apk

# Sign the modified APK
jarsigner -keystore my.keystore modified.apk alias
# or
apksigner sign --ks my.keystore modified.apk
```

## Strings and Secrets
```bash
# Extract strings.xml
cat extracted/res/values/strings.xml

# Search in all resources
grep -r "http\|https\|api\|key\|secret\|password" extracted/res/

# Native libraries secrets
strings extracted/lib/arm64-v8a/*.so | grep -i flag
```

## Insecure Storage Locations
```bash
# Shared preferences (unencrypted)
cat /data/data/com.app.name/shared_prefs/*.xml

# SQLite databases
sqlite3 /data/data/com.app.name/databases/*.db
.tables
SELECT * FROM users;
```
