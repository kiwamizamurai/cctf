# Steganography Techniques

## Image Stego - Online First!

**AperiSolve** (Try First!): https://www.aperisolve.com/
- Runs 10+ tools automatically
- zsteg, steghide, binwalk, strings, exiftool

**StegOnline**: https://stegonline.georgeom.net/
- LSB extraction, bit planes, XOR

## PNG Analysis

```bash
# zsteg - LSB analysis
zsteg image.png
zsteg -a image.png  # All methods

# Check PNG structure
pngcheck -v image.png
```

## JPEG Analysis

```bash
# steghide - password protected
steghide extract -sf image.jpg
steghide extract -sf image.jpg -p ""  # Empty password

# Brute force password
stegseek image.jpg rockyou.txt
```

## Audio Stego

```bash
# Spectrogram (visual message)
sox audio.wav -n spectrogram -o spec.png

# DeepSound - Windows tool for audio stego
# Sonic Visualiser - spectrogram analysis
```

## LSB Manual Extraction

```python
from PIL import Image

img = Image.open('image.png')
pixels = list(img.getdata())

# Extract LSB from each channel
bits = ''
for pixel in pixels:
    for channel in pixel[:3]:  # RGB
        bits += str(channel & 1)

# Convert to bytes
flag = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
print(flag)
```

## Appended Data Detection

```python
def check_appended(filepath, footer_bytes):
    with open(filepath, 'rb') as f:
        data = f.read()

    pos = data.rfind(footer_bytes)
    if pos != -1:
        extra = data[pos + len(footer_bytes):]
        if extra:
            print(f"Found {len(extra)} bytes after footer")
            return extra
    return None

# PNG footer
check_appended('image.png', b'\x00\x00\x00\x00IEND\xaeB`\x82')

# JPEG footer
check_appended('image.jpg', b'\xff\xd9')
```
