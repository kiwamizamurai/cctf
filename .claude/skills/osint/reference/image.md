# Image Analysis Reference

## Metadata Extraction
```bash
# EXIF data (GPS, camera, date)
exiftool image.jpg
exiftool -a -u -g1 image.jpg

# GPS coordinates extraction
exiftool -gpslatitude -gpslongitude image.jpg

# Convert to Google Maps URL
# Latitude: 35.6812° N, Longitude: 139.7671° E
# https://www.google.com/maps?q=35.6812,139.7671
```

## Reverse Image Search
```
Google Images: https://images.google.com/
TinEye: https://tineye.com/
Yandex Images: https://yandex.com/images/ (best for faces/places)
Bing Visual Search: https://www.bing.com/visualsearch
```

## Geolocation Techniques

### From Photos
```
1. Check EXIF GPS data first
2. Reverse image search
3. Analyze visible elements:
   - Street signs, store names
   - Language on signs
   - License plate formats
   - Sun position/shadows
   - Architecture style
   - Vegetation
   - Road markings
```

### From Text Clues
```
- Phone number format (+1, +81, etc.)
- Currency symbols
- Date formats (MM/DD vs DD/MM)
- Language/dialect hints
- Time zone references
```

## Tools
```
GeoGuessr techniques
Google Street View
Shadows for time estimation
```
