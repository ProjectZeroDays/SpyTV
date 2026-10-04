"""Derive every SpyTV app icon from the brand artwork.

Source of truth: ``resources/logo_source.jpg`` — a 1408x768 render of the mark
(a dark disc carrying the retro TV + binoculars artwork). It is a JPEG, so the
"transparent" backdrop is actually a baked grey/white checkerboard and nothing
in the file has alpha. This script therefore:

  1. locates the disc by its luminance (the disc is ~#141E27, the checkerboard
     is >= #CCCCCC), so the crop is measured rather than hard-coded;
  2. crops the largest square around it and paints everything outside the disc
     with the disc's own sampled fill — the checkerboard disappears and the
     result is seamless at any size, on light or dark backgrounds;
  3. downsamples with LANCZOS and writes every consumer its icon:

        electron/icon.png                                1024x1024  desktop exe
        icon.png                                          192x192   widget builders
        android/.../drawable-*/ic_launcher_foreground.png 108dp @ density

Run: python tools/make_icon.py
"""
import os

from PIL import Image, ImageDraw

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = os.path.join(REPO, "resources", "logo_source.jpg")
DESKTOP = os.path.join(REPO, "electron", "icon.png")
WIDGET = os.path.join(REPO, "icon.png")
ANDROID_RES = os.path.join(REPO, "android", "app", "src", "main", "res")

# Adaptive-icon canvas is 108dp; density buckets are 1/1.5/2/3/4 x 160dpi.
ANDROID_DENSITIES = {
    "mdpi": 108,
    "hdpi": 162,
    "xhdpi": 216,
    "xxhdpi": 324,
    "xxxhdpi": 432,
}

DESKTOP_SIZE = 1024   # documented contract: electron/icon.png is 1024 squared
WIDGET_SIZE = 192     # size both widget builders already consume
DARK_LUMA = 70        # disc ~20,30,39 — the checkerboard never goes below 204
FRINGE = 4            # JPEG halo just inside the disc edge; drop it


def find_mark(img):
    """Bounding box of the dark disc: (left, top, right, bottom)."""
    mask = img.convert("L").point(lambda v: 255 if v < DARK_LUMA else 0)
    bbox = mask.getbbox()
    if not bbox:
        raise SystemExit(f"{SOURCE}: no dark artwork found — is the source right?")
    return bbox


def disc_fill(img, bbox, fringe=FRINGE):
    """Sample the disc's flat fill just inside its edge, away from the artwork."""
    left, top, right, bottom = bbox
    cx = (left + right) // 2
    cy = (top + bottom) // 2
    inset = fringe + 12
    points = [
        (cx, top + inset),      # top rim
        (cx, bottom - inset),   # bottom rim (below the stand bar)
        (left + inset, cy),     # left rim
        (right - inset, cy),    # right rim
    ]
    samples = [img.getpixel(p) for p in points]
    return tuple(sum(c[i] for c in samples) // len(samples) for i in range(3))


def build_square(img, bbox, side, fill):
    """Largest `side`-squared crop around the disc, checkerboard painted over."""
    left, top, right, bottom = bbox
    cx = (left + right) / 2
    cy = (top + bottom) / 2
    half = side / 2

    # Centre the crop on the disc and keep it inside the source (the source is
    # 1408x768, so the square is height-limited and only slides horizontally).
    x0 = int(round(min(max(cx - half, 0), img.width - side)))
    y0 = int(round(min(max(cy - half, 0), img.height - side)))
    crop = img.crop((x0, y0, x0 + side, y0 + side))

    # Disc position/size expressed in crop coordinates, then inset by FRINGE so
    # no checkerboard halo survives along the rim.
    ccx = cx - x0
    ccy = cy - y0
    radius = max(right - left, bottom - top) / 2.0

    mask = Image.new("L", (side, side), 0)
    ImageDraw.Draw(mask).ellipse(
        (ccx - radius + FRINGE, ccy - radius + FRINGE,
         ccx + radius - FRINGE, ccy + radius - FRINGE),
        fill=255,
    )

    out = Image.new("RGB", (side, side), fill)
    out.paste(crop, (0, 0), mask)
    return out


def save(img, path, size, circle=False):
    out = img.resize((size, size), Image.LANCZOS)
    if circle:
        # Legacy round icon (API 25): a square tile would show navy corners on
        # a round launcher, so clip it to an antialiased circle instead. Built
        # at 4x and downsampled to keep the edge smooth.
        mask = Image.new("L", (size * 4, size * 4), 0)
        ImageDraw.Draw(mask).ellipse((0, 0, size * 4 - 1, size * 4 - 1), fill=255)
        mask = mask.resize((size, size), Image.LANCZOS)
        rgba = out.convert("RGBA")
        rgba.putalpha(mask)
        out = rgba
    os.makedirs(os.path.dirname(path), exist_ok=True)
    out.save(path)
    print(f"wrote {os.path.relpath(path, REPO):<58} {size}x{size} {out.mode}")


def main():
    if not os.path.exists(SOURCE):
        raise SystemExit(f"missing source artwork: {SOURCE}")

    img = Image.open(SOURCE).convert("RGB")
    bbox = find_mark(img)
    fill = disc_fill(img, bbox)
    side = min(img.width, img.height)

    left, top, right, bottom = bbox
    print(f"source {os.path.relpath(SOURCE, REPO)} {img.size[0]}x{img.size[1]} "
          f"disc=({left},{top})-({right},{bottom}) fill=#{fill[0]:02X}"
          f"{fill[1]:02X}{fill[2]:02X} canvas={side}px")

    square = build_square(img, bbox, side, fill)

    save(square, DESKTOP, DESKTOP_SIZE)
    save(square, WIDGET, WIDGET_SIZE)
    for density, px in ANDROID_DENSITIES.items():
        drawable = os.path.join(ANDROID_RES, f"drawable-{density}")
        save(square, os.path.join(drawable, "ic_launcher_foreground.png"), px)
        save(square, os.path.join(drawable, "ic_launcher_round_foreground.png"),
             px, circle=True)


if __name__ == "__main__":
    main()
