"""Generate the social-share thumbnail (docs/og.png, 1200x630) in the phosphor-CRT style.

Run:  python scripts/make_og.py
Uses Pillow's bundled DejaVu fonts, so no system font is required.
"""
from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFont

W, H = 1200, 630
BG = (5, 7, 10)
PHOS = (51, 255, 138)
PHOS_DIM = (31, 127, 74)
AMBER = (255, 176, 0)
OUT = os.path.join(os.path.dirname(__file__), "..", "docs", "og.png")


def font(size: int, mono: bool = True) -> ImageFont.FreeTypeFont:
    name = "DejaVuSansMono.ttf" if mono else "DejaVuSans-Bold.ttf"
    try:
        return ImageFont.truetype(name, size)
    except OSError:
        return ImageFont.load_default()


def main() -> None:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # subtle radial-ish darkening at edges (cheap vignette)
    vignette = Image.new("L", (W, H), 0)
    vd = ImageDraw.Draw(vignette)
    vd.ellipse([-W * 0.25, -H * 0.25, W * 1.25, H * 1.25], fill=70)
    img.paste(Image.new("RGB", (W, H), (0, 0, 0)), (0, 0),
              Image.eval(vignette, lambda a: 90 - a if a < 90 else 0))

    # phosphor screen glow panel border
    d.rounded_rectangle([40, 40, W - 40, H - 40], radius=18, outline=PHOS_DIM, width=3)

    # terminal title bar
    d.line([40, 92, W - 40, 92], fill=PHOS_DIM, width=2)
    for i, cx in enumerate((70, 92, 114)):
        d.ellipse([cx - 7, 58, cx + 7, 72], outline=PHOS_DIM, width=2)
    d.text((140, 56), "/dev/ttyS0 — hackbot session", font=font(22), fill=PHOS_DIM)
    # authorized-only amber note, top-right of the title bar
    note = "authorized use only"
    nw = d.textlength(note, font=font(22))
    d.text((W - 60 - nw, 56), note, font=font(22), fill=AMBER)

    # big title
    d.text((70, 150), "hackbot", font=font(120, mono=False), fill=PHOS)
    # underline caret block
    d.rectangle([70, 285, 560, 292], fill=PHOS_DIM)

    # tagline
    d.text((72, 320), "an LLM-orchestrated pentest harness", font=font(40), fill=PHOS)
    d.text((72, 372), "ReAct + LangGraph", font=font(30), fill=PHOS_DIM)

    # prompt line
    d.text((72, 450), "root@target:~#", font=font(30), fill=PHOS_DIM)
    d.text((340, 450), "hackbot demo --dry-run", font=font(30), fill=PHOS)
    d.rectangle([742, 450, 760, 484], fill=PHOS)  # cursor

    # safety chips
    chips = ["scope-guarded", "dry-run default", "kill-switch budget"]
    x = 72
    for c in chips:
        w = d.textlength(c, font=font(24)) + 34
        d.rounded_rectangle([x, 520, x + w, 562], radius=8, outline=PHOS_DIM, width=2)
        d.text((x + 17, 528), c, font=font(24), fill=PHOS)
        x += w + 18

    # scanlines overlay (every 3px)
    for y in range(44, H - 44, 3):
        d.line([44, y, W - 44, y], fill=(0, 0, 0), width=1)

    img.save(os.path.normpath(OUT), "PNG")
    print("wrote", os.path.normpath(OUT), img.size)


if __name__ == "__main__":
    main()
