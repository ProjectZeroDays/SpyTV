"""Generate the SpyTV desktop app icon.

Produces electron/icon.png at 1024x1024 (electron-builder's Windows icon
pipeline needs a source >= 256x256 and scales it into the .ico itself).

Design: the same palette the Android launcher and dashboard use — a dark
#0B0E14 rounded tile carrying a blue #3B82F6 television whose screen holds an
eye, so the desktop C2 reads as "Spy TV" at 16px as well as at 256px.

Drawn at 4x and downsampled with LANCZOS so the edges stay crisp in the
generated .ico sizes.
"""
from PIL import Image, ImageDraw, ImageFilter

# Design coordinates below are authored directly on a 4096px canvas (inset 128,
# centre 2048, …), so there is no per-coordinate scaling — draw at full size and
# downsample once, which is also what antialiases the edges.
SIZE = 4096
SCALE = 1
OUT = 1024

BG = (11, 14, 20, 255)          # #0B0E14  background
SURFACE = (21, 27, 39, 255)     # #151B27  screen
BLUE = (59, 130, 246, 255)      # #3B82F6  accent
BLUE_D = (37, 99, 235, 255)     # #2563EB  glow / stand
TEXT = (243, 244, 246, 255)     # #F3F4F6  eye white


def main():
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # Rounded app tile
    tile = (128 * SCALE, 128 * SCALE, 3968 * SCALE, 3968 * SCALE)
    d.rounded_rectangle(tile, radius=800 * SCALE, fill=BG)

    # Soft accent glow behind the set
    glow = Image.new("RGBA", img.size, (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.ellipse(
        (348 * SCALE, 1050 * SCALE, 3748 * SCALE, 3450 * SCALE),
        fill=(37, 99, 235, 90),
    )
    glow = glow.filter(ImageFilter.GaussianBlur(240 * SCALE))
    img = Image.alpha_composite(img, glow)
    d = ImageDraw.Draw(img)

    cx = 2048 * SCALE

    # Antennas
    d.line([(cx - 300 * SCALE, 1520 * SCALE), (cx - 560 * SCALE, 940 * SCALE)],
           fill=BLUE, width=72 * SCALE)
    d.line([(cx + 300 * SCALE, 1520 * SCALE), (cx + 560 * SCALE, 940 * SCALE)],
           fill=BLUE, width=72 * SCALE)
    for x in (cx - 560 * SCALE, cx + 560 * SCALE):
        r = 56 * SCALE
        d.ellipse((x - r, 940 * SCALE - r, x + r, 940 * SCALE + r), fill=BLUE)

    # Television body
    body = (cx - 1300 * SCALE, 1500 * SCALE, cx + 1300 * SCALE, 3000 * SCALE)
    d.rounded_rectangle(body, radius=140 * SCALE, fill=SURFACE,
                        outline=BLUE, width=80 * SCALE)

    # Eye
    ey = 2250 * SCALE
    d.ellipse((cx - 780 * SCALE, ey - 430 * SCALE,
               cx + 780 * SCALE, ey + 430 * SCALE), fill=TEXT)
    d.ellipse((cx - 300 * SCALE, ey - 300 * SCALE,
               cx + 300 * SCALE, ey + 300 * SCALE), fill=BLUE)
    d.ellipse((cx - 145 * SCALE, ey - 145 * SCALE,
               cx + 145 * SCALE, ey + 145 * SCALE), fill=BG)
    hr = 70 * SCALE
    d.ellipse((cx + 90 * SCALE - hr, ey - 190 * SCALE - hr,
               cx + 90 * SCALE + hr, ey - 190 * SCALE + hr), fill=TEXT)

    # Stand
    d.rounded_rectangle((cx - 200 * SCALE, 3000 * SCALE,
                         cx + 200 * SCALE, 3230 * SCALE),
                        radius=40 * SCALE, fill=BLUE_D)
    d.rounded_rectangle((cx - 500 * SCALE, 3230 * SCALE,
                         cx + 500 * SCALE, 3380 * SCALE),
                        radius=75 * SCALE, fill=BLUE)

    out = img.resize((OUT, OUT), Image.LANCZOS)
    out.save("electron/icon.png")
    print(f"wrote electron/icon.png {out.size} {out.mode}")


if __name__ == "__main__":
    main()
