# Frida & objection Reference

## Frida Setup
```bash
# Install
pip install frida-tools

# List running apps
frida-ps -U

# Attach to app
frida -U -n "app.name" -l script.js
```

## Common Frida Scripts

### Bypass Root Detection
```javascript
Java.perform(function() {
    var RootCheck = Java.use("com.app.RootCheck");
    RootCheck.isRooted.implementation = function() {
        console.log("Root check bypassed");
        return false;
    };
});
```

### Hook Method and Print Args
```javascript
Java.perform(function() {
    var MainActivity = Java.use("com.app.MainActivity");
    MainActivity.checkFlag.implementation = function(input) {
        console.log("Input: " + input);
        var result = this.checkFlag(input);
        console.log("Result: " + result);
        return result;
    };
});
```

### List All Methods
```javascript
Java.perform(function() {
    var cls = Java.use("com.app.Target");
    var methods = cls.class.getDeclaredMethods();
    methods.forEach(function(method) {
        console.log(method.getName());
    });
});
```

### SSL Pinning Bypass
```javascript
Java.perform(function() {
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    // Custom TrustManager that accepts all certificates
});
```

## objection

### Setup & Launch
```bash
pip install objection

# Explore app
objection -g "com.app.name" explore
```

### Common Commands
```bash
# List components
android hooking list activities
android hooking list classes
android hooking list services

# Search classes
android hooking search classes flag

# Watch class
android hooking watch class com.app.MainActivity

# Bypass protections
android sslpinning disable
android root disable

# File operations
file download /data/data/com.app/file.db ./local.db
```

## CTF Patterns

### Pattern 1: Flag in Resources
```bash
apktool d app.apk
grep -r "flag\|ctf\|secret" decoded/res/
```

### Pattern 2: Flag in Native Library
```bash
strings extracted/lib/*/*.so | grep -i flag
# May need Ghidra for complex cases
```

### Pattern 3: Runtime Flag Check
```bash
# 1. Find check function in jadx
# 2. Hook with Frida to see expected value
# 3. Or patch smali and rebuild
```
