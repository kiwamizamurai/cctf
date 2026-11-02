#!/usr/bin/env python3
"""typhoon-pythoon - AlpacaHack Daily (rev, Python 3.10 .pyc).
server.pyc checks input == reverse_the_wind(EYE_DATA), where location is the
parent directory name (must be "eye", per is_inside_the_typhoon_eye):
    place = location[i % len(location)]        # b"eye"[i%3]
    wind  = (i*7 + 41 + place) & 255
    flag[i] = chr(EYE_DATA[i] ^ wind)
"""
EYE_DATA = [207,197,236,194,221,208,195,183,175,190,183,178,145,162,132,159,
            119,90,105,94,127,126,83,73,105,37,44,46,57,45,25,11,6,26,255,237,247]
loc = b"eye"
flag = ''.join(chr(v ^ ((i*7 + 41 + loc[i % len(loc)]) & 255)) for i, v in enumerate(EYE_DATA))
print(flag)
