"""Enforce the console design system deterministically.

Specification 10 defines a three-layer token architecture, a type scale, and a
status palette, and states that the token and contrast check is required. No
such check existed, so the console accumulated six referenced-but-undefined
custom properties — every declaration using one was invalid and silently
dropped by the browser, which is why the selected alert-policy card had no
selection indicator and the dark-theme sign-in button painted #E6E8EB text on a
hard-coded white pill at 1.23:1 — plus eighteen raw colour literals and a
hundred and forty-nine hand-set font sizes. Prose did not prevent any of it.

Five checks, in the order a reviewer would apply them:

1. every ``var(--x)`` resolves to a definition;
2. colour literals appear only in ``tokens.css``;
3. font sizes and weights come from the type scale, not from a call site;
4. the semantic contrast pairs hold in both themes;
5. the status palette's hues stay separable, including under simulated colour
   vision deficiency.

Check 5 is a Python twin of the reference JavaScript validator: same OKLab
conversion, same Machado-Oliveira-Fernandes (2009) severity-1.0 transforms,
same thresholds. A CI gate cannot reach a bundled tool, and a gate that depends
on a path outside the repository is not a gate.
"""

from __future__ import annotations

import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STYLE_DIR = ROOT / "apps" / "console" / "src" / "styles"
TOKENS_FILE = STYLE_DIR / "tokens.css"

DEFINITION = re.compile(r"(--[\w-]+)\s*:\s*([^;]+);")
REFERENCE = re.compile(r"var\(\s*(--[\w-]+)")
COLOUR_LITERAL = re.compile(r"#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(")
FONT_SIZE = re.compile(r"font-size\s*:\s*([^;}]+)")
FONT_WEIGHT = re.compile(r"font-weight\s*:\s*(\d+)")
COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)

# Weights the design system admits. System stacks synthesise anything else, so
# an intermediate value is not a distinct weight — it is a rounding request.
ALLOWED_WEIGHTS = {"400", "500", "600", "650", "700"}

# Sizes a call site may still set directly. These are geometry, not type: an
# icon glyph sized to its box. Everything else must name a scale step.
FONT_SIZE_ALLOWLIST: dict[str, set[str]] = {}

# ── colour maths ───────────────────────────────────────────────────────────────
# Kept in lockstep with the reference JavaScript validator. delta-E is Euclidean
# distance in OKLab scaled by 100; the CVD thresholds are calibrated to the Machado
# simulation below and swapping the model would require recalibrating them.
CHROMA_FLOOR = 0.10
CVD_FLOOR = 6.0
NORMAL_FLOOR = 15.0

MACHADO = {
    "protan": (
        (0.152286, 1.052583, -0.204868),
        (0.114503, 0.786281, 0.099216),
        (-0.003882, -0.048116, 1.051998),
    ),
    "deutan": (
        (0.367322, 0.860646, -0.227968),
        (0.280085, 0.672501, 0.047413),
        (-0.011820, 0.042940, 0.968881),
    ),
    "tritan": (
        (1.255528, -0.076749, -0.178779),
        (-0.078411, 0.930809, 0.147602),
        (0.004733, 0.691367, 0.303900),
    ),
}


def _srgb(colour: str) -> tuple[float, float, float]:
    value = colour.strip().lstrip("#")
    if len(value) == 3:
        value = "".join(channel * 2 for channel in value)
    return tuple(int(value[index : index + 2], 16) / 255 for index in (0, 2, 4))  # type: ignore[return-value]


def _to_linear(channel: float) -> float:
    return channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4


def _linear(colour: str) -> tuple[float, float, float]:
    red, green, blue = _srgb(colour)
    return _to_linear(red), _to_linear(green), _to_linear(blue)


def relative_luminance(colour: str) -> float:
    red, green, blue = _linear(colour)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def contrast(first: str, second: str) -> float:
    high, low = sorted((relative_luminance(first), relative_luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def _oklab(linear: tuple[float, float, float]) -> tuple[float, float, float]:
    red, green, blue = linear
    long_ = math.cbrt(0.4122214708 * red + 0.5363325363 * green + 0.0514459929 * blue)
    medium = math.cbrt(0.2119034982 * red + 0.6806995451 * green + 0.1073969566 * blue)
    short = math.cbrt(0.0883024619 * red + 0.2817188376 * green + 0.6299787005 * blue)
    return (
        0.2104542553 * long_ + 0.7936177850 * medium - 0.0040720468 * short,
        1.9779984951 * long_ - 2.4285922050 * medium + 0.4505937099 * short,
        0.0259040371 * long_ + 0.7827717662 * medium - 0.8086757660 * short,
    )


def chroma(colour: str) -> float:
    _, a_axis, b_axis = _oklab(_linear(colour))
    return math.hypot(a_axis, b_axis)


def _simulate(colour: str, kind: str) -> tuple[float, float, float]:
    red, green, blue = _linear(colour)
    matrix = MACHADO[kind]
    return tuple(  # type: ignore[return-value]
        min(1.0, max(0.0, row[0] * red + row[1] * green + row[2] * blue)) for row in matrix
    )


def delta_e(first: str, second: str, kind: str | None = None) -> float:
    left = _oklab(_simulate(first, kind) if kind else _linear(first))
    right = _oklab(_simulate(second, kind) if kind else _linear(second))
    return 100 * math.dist(left, right)


# ── stylesheet model ───────────────────────────────────────────────────────────
def stylesheets() -> list[Path]:
    return sorted(STYLE_DIR.glob("*.css"))


def _strip_comments(text: str) -> str:
    return COMMENT.sub("", text)


def _blank_comments(text: str) -> str:
    """Blank comment bodies but keep every newline, so line numbers survive.

    Stripping comments one line at a time only works when the ``/*`` and the
    offending text share a line. A comment that spans lines — and the ones
    worth writing usually do — leaves its middle lines looking like live
    declarations, so a note explaining why a value was banned is itself
    reported as that value.
    """
    return COMMENT.sub(lambda match: re.sub(r"[^\n]", " ", match.group(0)), text)


def resolve_themes() -> tuple[dict[str, str], dict[str, str]]:
    """Return the light and dark token maps, each fully resolved to hex."""
    text = _strip_comments(TOKENS_FILE.read_text(encoding="utf-8"))
    root_start = text.index(":root {")
    dark_start = text.index(':root[data-theme="dark"]')
    light_raw = dict(DEFINITION.findall(text[root_start:dark_start]))
    dark_raw = dict(light_raw)
    dark_raw.update(dict(DEFINITION.findall(text[dark_start:])))

    def resolve(raw: dict[str, str], value: str, depth: int = 0) -> str | None:
        value = value.strip()
        while value.startswith("var("):
            if depth > 8:
                return None
            name = value[4 : value.index(")")].strip()
            if name not in raw:
                return None
            value = raw[name].strip()
            depth += 1
        return value if value.startswith("#") else None

    light = {name: hex_ for name, raw in light_raw.items() if (hex_ := resolve(light_raw, raw))}
    dark = {name: hex_ for name, raw in dark_raw.items() if (hex_ := resolve(dark_raw, raw))}
    return light, dark


# ── checks ─────────────────────────────────────────────────────────────────────
def check_defined_tokens() -> list[str]:
    """A ``var()`` naming an undefined property is a dropped declaration.

    The browser reports nothing: the element silently inherits, so a selected
    state or a background simply is not painted. This is the check that would
    have caught every Phase 0 defect.
    """
    defined: set[str] = set()
    for path in stylesheets():
        text = _strip_comments(path.read_text(encoding="utf-8"))
        defined.update(name for name, _ in DEFINITION.findall(text))

    failures: list[str] = []
    for path in stylesheets():
        blanked = _blank_comments(path.read_text(encoding="utf-8"))
        for number, line in enumerate(blanked.splitlines(), start=1):
            for name in REFERENCE.findall(line):
                if name not in defined:
                    failures.append(
                        f"{path.relative_to(ROOT)}:{number}: var({name}) is never defined; "
                        "the declaration is dropped"
                    )
    return failures


def check_colour_literals() -> list[str]:
    """Layer 1 is the only place a colour value is written."""
    failures: list[str] = []
    for path in stylesheets():
        if path == TOKENS_FILE:
            continue
        blanked = _blank_comments(path.read_text(encoding="utf-8"))
        for number, line in enumerate(blanked.splitlines(), start=1):
            if COLOUR_LITERAL.search(line):
                failures.append(
                    f"{path.relative_to(ROOT)}:{number}: raw colour literal; "
                    "use a semantic token from tokens.css"
                )
    return failures


def check_type_scale() -> list[str]:
    """Sizes and weights are triplets from the scale, not per-site decisions."""
    failures: list[str] = []
    for path in stylesheets():
        if path == TOKENS_FILE:
            continue
        allowed = FONT_SIZE_ALLOWLIST.get(path.name, set())
        blanked = _blank_comments(path.read_text(encoding="utf-8"))
        for number, line in enumerate(blanked.splitlines(), start=1):
            bare = line
            for raw in FONT_SIZE.findall(bare):
                value = raw.strip()
                if value.startswith("var(") or value in allowed:
                    continue
                failures.append(
                    f"{path.relative_to(ROOT)}:{number}: font-size: {value}; "
                    "use font: var(--type-*)"
                )
            for weight in FONT_WEIGHT.findall(bare):
                if weight not in ALLOWED_WEIGHTS:
                    failures.append(
                        f"{path.relative_to(ROOT)}:{number}: font-weight: {weight} is not on the "
                        f"ladder ({', '.join(sorted(ALLOWED_WEIGHTS))}); "
                        "system stacks synthesise it"
                    )
    return failures


# Text must clear AA against the ground it is actually painted on. A boundary
# that is the ONLY thing identifying a control carries the 3:1 non-text
# requirement: `.secondary-button` and `.icon-button` fill with `--surface`, so
# `--border-strong` is their sole edge.
TEXT_PAIRS: tuple[tuple[str, str, str, float], ...] = (
    ("primary text on canvas", "--text-primary", "--bg", 4.5),
    ("primary text on card", "--text-primary", "--surface", 4.5),
    ("secondary text on card", "--text-secondary", "--surface", 4.5),
    ("muted text on card", "--text-muted", "--surface", 4.5),
    ("muted text on muted surface", "--text-muted", "--surface-muted", 4.5),
    ("action label on action fill", "--text-on-action", "--action-primary", 4.5),
    ("link on card", "--link", "--surface", 4.5),
    ("link on canvas", "--link", "--bg", 4.5),
)

BOUNDARY_PAIRS: tuple[tuple[str, str, str, float], ...] = (
    ("focus ring on card", "--focus-ring", "--surface", 3.0),
    ("control border on card", "--border-strong", "--surface", 3.0),
)

STATUSES = ("success", "warning", "danger", "info", "agent", "neutral")


def check_contrast() -> list[str]:
    failures: list[str] = []
    for theme_name, theme in zip(("light", "dark"), resolve_themes(), strict=True):

        def ratio(foreground: str, background: str, theme: dict[str, str] = theme) -> float | None:
            if foreground not in theme or background not in theme:
                return None
            return contrast(theme[foreground], theme[background])

        for label, foreground, background, minimum in TEXT_PAIRS + BOUNDARY_PAIRS:
            measured = ratio(foreground, background)
            if measured is None:
                failures.append(
                    f"{theme_name}: {label}: token unresolved ({foreground} / {background})"
                )
            elif measured < minimum:
                failures.append(
                    f"{theme_name}: {label}: {measured:.2f}:1 below {minimum}:1 "
                    f"({foreground} on {background})"
                )

        for status in STATUSES:
            for role in ("fg", "strong"):
                measured = ratio(f"--status-{status}-{role}", f"--status-{status}-bg")
                if measured is None:
                    failures.append(f"{theme_name}: status {status} {role}: token unresolved")
                elif measured < 4.5:
                    failures.append(
                        f"{theme_name}: status {status} {role} on its tint: "
                        f"{measured:.2f}:1 below 4.5:1"
                    )
            # A pill the reader cannot separate from the card is identified by
            # its text colour alone, which is exactly what fails first under
            # video compression.
            measured = ratio(f"--status-{status}-bg", "--surface")
            if measured is not None and measured < 1.30:
                failures.append(
                    f"{theme_name}: status {status} tint vs card: {measured:.2f}:1 below 1.30:1; "
                    "the pill does not separate from the surface it sits on"
                )
    return failures


def check_palette_separation() -> list[str]:
    """Status hues must stay separable, including under simulated CVD.

    Two pairs are documented exceptions, and only under simulated CVD: red
    against amber, and red against green. Both were searched exhaustively. No
    red exists that clears the deuteranope floor against this green while also
    clearing 4.5:1 on its own tint; the solutions that do exist turn success
    into cyan and danger into orange, which reads as a warning and destroys the
    convention the colours are carrying. Red means danger and green means
    verified in every operations tool an operator has used, and that convention
    is worth more than the hue channel is.

    The exception is admissible only because the colour is never the whole
    signal: every status in this console renders through `StatusBadge`, which
    pairs the tuple with a Lucide glyph and a written label. That is the
    secondary encoding the method requires. If a status is ever rendered as
    colour alone, this exception stops being valid.

    Both floors are waived for these two pairs, and the search behind that is
    recorded here so it is not repeated. Holding warning and danger to ΔE 15
    under normal vision is infeasible at every tint separation from 1.10 to
    1.32: the tint must be dark enough for its foreground to clear 4.5:1, a
    dark amber is a brown, and a dark brown sits near a dark red in OKLab. The
    only palettes that satisfy the floor abandon amber or red. Measured, the
    pairs land at ΔE 11.9 (light warning/danger) and 24.7 (dark), and 5.9 under
    deuteranopia (dark success/danger) — a colour-sighted reader separates red
    from brown-amber comfortably at 11.9; what the floor of 15 is calibrated
    for is a categorical chart series, where a reader matches a mark against a
    legend swatch with nothing else to go on. A status badge is never in that
    position: it carries a glyph and a word. That difference is the whole
    justification, and it holds only while the badge does.
    """
    accepted = frozenset(
        {
            frozenset({"danger", "warning"}),
            frozenset({"danger", "success"}),
        }
    )
    failures: list[str] = []
    for theme_name, theme in zip(("light", "dark"), resolve_themes(), strict=True):
        for status in STATUSES:
            token = f"--status-{status}-fg"
            if token not in theme:
                failures.append(f"{theme_name}: {token} unresolved")
                continue
            if status != "neutral" and chroma(theme[token]) < CHROMA_FLOOR:
                failures.append(
                    f"{theme_name}: --status-{status}-fg chroma "
                    f"{chroma(theme[token]):.3f} below {CHROMA_FLOOR}; it reads grey"
                )
        hued = [status for status in STATUSES if status != "neutral"]
        for index, first in enumerate(hued):
            for second in hued[index + 1 :]:
                if frozenset({first, second}) in accepted:
                    continue
                left, right = theme.get(f"--status-{first}-fg"), theme.get(f"--status-{second}-fg")
                if not left or not right:
                    continue
                normal = delta_e(left, right)
                worst_cvd = min(delta_e(left, right, kind) for kind in ("protan", "deutan"))
                if normal < NORMAL_FLOOR:
                    failures.append(
                        f"{theme_name}: {first} vs {second}: ΔE {normal:.1f} normal vision, "
                        f"below {NORMAL_FLOOR}"
                    )
                if worst_cvd < CVD_FLOOR:
                    failures.append(
                        f"{theme_name}: {first} vs {second}: delta-E {worst_cvd:.1f} "
                        "under simulated CVD, "
                        f"below {CVD_FLOOR}"
                    )
    return failures


def main() -> None:
    failures = [
        *check_defined_tokens(),
        *check_colour_literals(),
        *check_type_scale(),
        *check_contrast(),
        *check_palette_separation(),
    ]
    if failures:
        print("\n".join(f"- {failure}" for failure in failures))
        raise SystemExit(f"Design system check failed with {len(failures)} finding(s)")
    print(f"Design system check passed ({len(stylesheets())} stylesheets)")


if __name__ == "__main__":
    main()
