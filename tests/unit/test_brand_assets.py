"""The brand mark has one canonical source; every consumer agrees with it.

The geometry used to be hand-copied into seven files with no link between
them, so any revision could ship divergent marks silently. The generator owns
the geometry and palette; this proves the committed files are its output and
that the React component renders the same paths.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_committed_brand_assets_match_the_canonical_source() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "generate_brand_assets.py"), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0, result.stderr


def test_the_react_mark_uses_the_canonical_geometry() -> None:
    source = (ROOT / "tools" / "generate_brand_assets.py").read_text(encoding="utf-8")
    component = (ROOT / "apps" / "console" / "src" / "components.tsx").read_text(encoding="utf-8")
    mark_path = next(
        line.split('"')[1] for line in source.splitlines() if line.startswith('MARK_PATH = "M')
    )
    assert mark_path in component, (
        "components.tsx SolvanMark path data disagrees with MARK_PATH in "
        "tools/generate_brand_assets.py"
    )
    dot = next(
        line.split("=", 1)[1].strip() for line in source.splitlines() if line.startswith("DOT = (")
    )
    cx, cy, r = ast.literal_eval(dot)
    assert f"<circle cx={{{cx}}} cy={{{cy}}} r={{{r}}}" in component, (
        "components.tsx SolvanMark checkpoint dot disagrees with DOT in "
        "tools/generate_brand_assets.py"
    )


def test_the_monochrome_logo_carries_no_inline_color() -> None:
    """An inline style wins over inherited color, so recoloring could not work."""

    mono = (ROOT / "logo" / "solvan-logo-mono.svg").read_text(encoding="utf-8")
    assert "style=" not in mono
    assert "currentColor" in mono


def test_the_apple_touch_icon_is_a_fully_opaque_square() -> None:
    """iOS composites alpha onto black: transparent corners become dark wedges."""

    import struct

    data = (ROOT / "apps" / "console" / "public" / "apple-touch-icon.png").read_bytes()
    pos = 8
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        ctype = data[pos + 4 : pos + 8]
        chunk = data[pos + 8 : pos + 8 + length]
        if ctype == b"IHDR":
            _width, _height, bit_depth, color_type = struct.unpack(">IIBB", chunk[:10])
            assert bit_depth == 8 and color_type == 6, "expected an 8-bit RGBA icon"
        pos += 12 + length
    # Decode fully via the generator's own decoder and verify corner alpha.
    sys.path.insert(0, str(ROOT / "tools"))
    from generate_brand_assets import _decode_png

    decoded_width, decoded_height, pixels = _decode_png(data)
    corner_alpha = []
    for x, y in [
        (0, 0),
        (decoded_width - 1, 0),
        (0, decoded_height - 1),
        (decoded_width - 1, decoded_height - 1),
        (decoded_width // 2, decoded_height // 2),
    ]:
        offset = (y * decoded_width + x) * 4
        corner_alpha.append(pixels[offset + 3])
    assert all(alpha == 255 for alpha in corner_alpha), (
        f"apple-touch-icon has non-opaque pixels: {corner_alpha}"
    )
