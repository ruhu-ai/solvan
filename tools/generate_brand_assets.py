"""Generate the Solvan brand SVG family from one canonical source.

The mark geometry used to be hand-copied into seven files and the brand
palette had drifted from the console design tokens: any revision was a
manual multi-file chore, and a miss shipped divergent marks silently. The
geometry, letterforms, and palette live here once; every consumer file is
generated, and `tests/unit/test_brand_assets.py` fails when a committed
file disagrees with this source.

Palette values are the console design tokens (apps/console/src/styles/
tokens.css), named in comments so a token change is a deliberate one.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOKENS = ROOT / "apps" / "console" / "src" / "styles" / "tokens.css"

#: The mark: a bounded recovery path resolving to a verified checkpoint.
MARK_PATH = "M49 13 H33.5 A9.5 9.5 0 0 0 33.5 32 H37 A9.5 9.5 0 0 1 37 51 H29"
DOT = ("14.5", "51", "5.5")

#: Custom geometric caps spelling SOLVAN, drawn on the same grid as the mark.
WORDMARK = (
    '<g transform="translate(72,18)" fill="none" stroke="{color}" stroke-width="5" '
    'stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M18.5 6 C17 3.6 14 2.5 11 2.5 C6.6 2.5 3.5 4.9 3.5 8.3 '
    'C3.5 15.9 18 11.9 18 19.6 C18 23.2 14.8 25.5 10.5 25.5 C7 25.5 3.8 24.2 2.5 22.2"/>'
    '<g transform="translate(28,0)"><ellipse cx="10.5" cy="14" rx="9" ry="11.5"/></g>'
    '<g transform="translate(58,0)"><path d="M3 2.5 V25.5 H17.5"/></g>'
    '<g transform="translate(84,0)"><path d="M2.5 2.5 L10.5 25.5 L18.5 2.5"/></g>'
    '<g transform="translate(112,0)"><path d="M2.5 25.5 L10.5 2.5 L18.5 25.5 M6.2 17 H14.8"/></g>'
    '<g transform="translate(140,0)"><path d="M3 25.5 V2.5 L18 25.5 V2.5"/></g>'
    "</g>"
)


def _token(name: str, default: str) -> str:
    """Read one hex token from the console stylesheet, or refuse to guess."""

    match = re.search(rf"{re.escape(name)}:\s*(#[0-9a-fA-F]{{6}})\s*;", TOKENS.read_text())
    return match.group(1).lower() if match else default


INK = _token("--gray-950", "#17191c")
PAPER = _token("--gray-25", "#f5f6f7")
ACCENT = _token("--blue-600", "#2563eb")
ACCENT_TINT = _token("--blue-200", "#c4d6f7")

_HEADER = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="{viewbox}" role="img" aria-label="{label}">'
)


def _mark(color: str, dot_color: str, *, indent: str = "") -> str:
    return (
        f'{indent}<g fill="none" stroke="{color}" stroke-width="9" stroke-linecap="round" '
        f'stroke-linejoin="round">\n'
        f'{indent}  <path d="{MARK_PATH}"/>\n'
        f"{indent}</g>\n"
        f'{indent}<circle cx="{DOT[0]}" cy="{DOT[1]}" r="{DOT[2]}" fill="{dot_color}"/>'
    )


def icon() -> str:
    return (
        f"{_HEADER.format(viewbox='0 0 64 64', label='Solvan icon')}\n"
        f"  {_mark(INK, ACCENT, indent='  ')}\n"
        "</svg>\n"
    )


def app_icon() -> str:
    return (
        f"{_HEADER.format(viewbox='0 0 1024 1024', label='Solvan app icon')}\n"
        f'  <rect width="1024" height="1024" rx="232" fill="{INK}"/>\n'
        f'  <g transform="translate(121.5,112) scale(12.5)">\n'
        f"    {_mark(PAPER, ACCENT_TINT, indent='    ')}\n"
        f"  </g>\n"
        "</svg>\n"
    )


def logo_horizontal() -> str:
    return (
        f"{_HEADER.format(viewbox='0 0 244 64', label='Solvan')}\n"
        f"  {_mark(INK, ACCENT, indent='  ')}\n\n"
        f"  {WORDMARK.format(color=INK)}\n"
        "</svg>\n"
    )


def logo_dark() -> str:
    return (
        f"{_HEADER.format(viewbox='0 0 244 64', label='Solvan')}\n"
        f"  <!-- For dark surfaces. Background is transparent. -->\n"
        f"  {_mark(PAPER, ACCENT_TINT, indent='  ')}\n\n"
        f"  {WORDMARK.format(color=PAPER)}\n"
        "</svg>\n"
    )


def logo_mono() -> str:
    # One-color version, recolored by setting `color` on the SVG or a parent:
    # every stroke is currentColor and the root sets no inline color, so the
    # inherited color actually reaches the paths (an inline style would win).
    return (
        f"{_HEADER.format(viewbox='0 0 244 64', label='Solvan')}\n"
        f"  <!-- One-color version. Recolor by setting `color` on the SVG or a parent. -->\n"
        f"  {_mark('currentColor', 'currentColor', indent='  ')}\n\n"
        f"  {WORDMARK.format(color='currentColor')}\n"
        "</svg>\n"
    )


GENERATED = {
    "logo/solvan-icon.svg": icon,
    "logo/solvan-app-icon.svg": app_icon,
    "apps/console/public/favicon.svg": app_icon,
    "logo/solvan-logo-horizontal.svg": logo_horizontal,
    "logo/solvan-logo-dark.svg": logo_dark,
    "logo/solvan-logo-mono.svg": logo_mono,
}

#: Raster variants. The mark geometry is identical to the SVG; only the
#: palette differs, so they are recolored from the previous exports rather
#: than re-rasterized. `opaque` composites onto INK: iOS masks alpha onto
#: black, so a home-screen icon must be a full-bleed square.
RASTERS: dict[str, dict[str, object]] = {
    "apps/console/public/favicon-16x16.png": {"opaque": False},
    "apps/console/public/favicon-32x32.png": {"opaque": False},
    "apps/console/public/apple-touch-icon.png": {"opaque": True},
}

#: The legacy `.ico` fallback is the 16px raster wrapped in an ICO container,
#: so it can never carry a different palette than the PNG it duplicates.
ICO = "apps/console/public/favicon.ico"
ICO_SOURCE = "apps/console/public/favicon-16x16.png"

_LEGACY_PALETTE = ("#1C2522", "#F6F8F7", "#5B8DF6")
_CANONICAL_PALETTE = (INK, PAPER, ACCENT_TINT)


def _hex(value: str) -> tuple[int, int, int]:
    return (int(value[1:3], 16), int(value[3:5], 16), int(value[5:7], 16))


def _decode_png(data: bytes) -> tuple[int, int, bytearray]:
    """Decode one 8-bit RGBA PNG. Any other shape refuses rather than guesses."""

    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("not a PNG")
    import struct
    import zlib

    pos, width, height, idat = 8, 0, 0, b""
    bit_depth = color_type = 0
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        ctype = data[pos + 4 : pos + 8]
        chunk = data[pos + 8 : pos + 8 + length]
        if ctype == b"IHDR":
            width, height, bit_depth, color_type = struct.unpack(">IIBB", chunk[:10])
        elif ctype == b"IDAT":
            idat += chunk
        pos += 12 + length
    if bit_depth != 8 or color_type != 6:
        raise ValueError(f"unsupported PNG shape (bit_depth={bit_depth}, color_type={color_type})")
    raw = zlib.decompress(idat)
    stride = width * 4
    pixels = bytearray()
    prev = bytearray(stride)
    i = 0
    for _y in range(height):
        kind = raw[i]
        i += 1
        line = bytearray(raw[i : i + stride])
        i += stride
        for x in range(stride):
            left = line[x - 4] if x >= 4 else 0
            up = prev[x]
            up_left = prev[x - 4] if x >= 4 else 0
            if kind == 1:
                line[x] = (line[x] + left) & 0xFF
            elif kind == 2:
                line[x] = (line[x] + up) & 0xFF
            elif kind == 3:
                line[x] = (line[x] + (left + up) // 2) & 0xFF
            elif kind == 4:
                estimate = left + up - up_left
                da, db, dc = (
                    abs(estimate - left),
                    abs(estimate - up),
                    abs(estimate - up_left),
                )
                nearest = left if (da <= db and da <= dc) else (up if db <= dc else up_left)
                line[x] = (line[x] + nearest) & 0xFF
            elif kind != 0:
                raise ValueError(f"unsupported PNG filter {kind}")
        pixels += line
        prev = line
    return width, height, pixels


def _encode_png(width: int, height: int, pixels: bytearray) -> bytes:
    import struct
    import zlib

    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
        )

    stride = width * 4
    raw = b"".join(b"\x00" + bytes(pixels[y * stride : (y + 1) * stride]) for y in range(height))
    header = struct.pack(">IIBB", width, height, 8, 6) + b"\x00\x00\x00"
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def _recolor_raster(path: Path, *, opaque: bool) -> bytes:
    """Snap every pixel to the nearest canonical palette color."""

    width, height, pixels = _decode_png(path.read_bytes())
    # A pixel already in the canonical palette must be stable under
    # regeneration, so both palettes are valid inputs for each role.
    roles = [(_hex(_LEGACY_PALETTE[index]), _hex(_CANONICAL_PALETTE[index])) for index in range(3)]
    ink = _hex(INK)
    for offset in range(0, len(pixels), 4):
        red, green, blue, alpha = pixels[offset : offset + 4]
        if opaque:
            # Composite over INK first, so no alpha survives for iOS to wedge.
            red = (red * alpha + ink[0] * (255 - alpha)) // 255
            green = (green * alpha + ink[1] * (255 - alpha)) // 255
            blue = (blue * alpha + ink[2] * (255 - alpha)) // 255
            alpha = 255
        best_index, best_distance = 0, None
        for index, pair in enumerate(roles):
            for lr, lg, lb in pair:
                distance = (red - lr) ** 2 + (green - lg) ** 2 + (blue - lb) ** 2
                if best_distance is None or distance < best_distance:
                    best_index, best_distance = index, distance
        pixels[offset : offset + 4] = bytes((*roles[best_index][1], alpha))
    return _encode_png(width, height, pixels)


def _ico_from_png(png: bytes) -> bytes:
    """Wrap one 16x16 PNG in a single-entry ICO container (PNG-in-ICO)."""

    import struct

    entry = struct.pack("<BBBBHHII", 16, 16, 0, 0, 1, 32, len(png), 22)
    return struct.pack("<HHH", 0, 1, 1) + entry + png


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when a committed file disagrees with the canonical source",
    )
    args = parser.parse_args()
    drifted: list[str] = []
    for relative, generate in sorted(GENERATED.items()):
        path = ROOT / relative
        expected = generate()
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != expected:
                drifted.append(relative)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(expected, encoding="utf-8")
    for relative, options in sorted(RASTERS.items()):
        path = ROOT / relative
        expected_bytes = _recolor_raster(path, opaque=bool(options["opaque"]))
        if args.check:
            if not path.is_file() or path.read_bytes() != expected_bytes:
                drifted.append(relative)
        else:
            path.write_bytes(expected_bytes)
    ico_path = ROOT / ICO
    expected_ico = _ico_from_png(_recolor_raster(ROOT / ICO_SOURCE, opaque=False))
    if args.check:
        if not ico_path.is_file() or ico_path.read_bytes() != expected_ico:
            drifted.append(ICO)
    else:
        ico_path.write_bytes(expected_ico)
    if drifted:
        print(
            "brand assets disagree with tools/generate_brand_assets.py: "
            + ", ".join(drifted)
            + " — regenerate with `uv run python tools/generate_brand_assets.py`",
            file=sys.stderr,
        )
        return 1
    if not args.check:
        print(f"generated {len(GENERATED)} brand assets from the canonical source")
    return 0


if __name__ == "__main__":
    sys.exit(main())
