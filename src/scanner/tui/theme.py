"""The palette, shared with the console reporter and the HTML report.

Defined once here and imported by the stylesheet loader so a severity looks
the same in the terminal UI, in ``rich`` output and in a browser. The hexes
are the ones already checked for WCAG AA contrast against the dark surface
and for colour-vision separation in :mod:`scanner.reporting.console`.

Severity is never carried by colour alone anywhere in this interface: every
row, badge and bar segment is labelled in writing, because a terminal may be
monochrome, remote, or read by someone who cannot separate the hues.
"""

from __future__ import annotations

from ..core.models import Confidence, Severity

__all__ = [
    "BG",
    "PANEL",
    "LINE",
    "LINE_HOT",
    "INK",
    "MUTED",
    "ACCENT",
    "SEVERITY_COLOURS",
    "CONFIDENCE_COLOURS",
    "STATUS_COLOURS",
    "css_variables",
]

BG = "#05070a"
PANEL = "#0a0f16"
LINE = "#17232f"
LINE_HOT = "#1d3442"
INK = "#d7e7ee"
MUTED = "#7d95a1"
ACCENT = "#00f5c8"

SEVERITY_COLOURS: dict[Severity, str] = {
    Severity.CRITICAL: "#ff2d6f",
    Severity.HIGH: "#ff8a3d",
    Severity.MEDIUM: "#ffd166",
    Severity.LOW: "#4dd8ff",
    Severity.INFO: "#8aa4b8",
}

CONFIDENCE_COLOURS: dict[Confidence, str] = {
    Confidence.HIGH: INK,
    Confidence.MEDIUM: MUTED,
    Confidence.LOW: MUTED,
}

#: Colour per HTTP status family. A 3xx is not a problem and a 4xx is not a
#: finding, so these are wayfinding only and deliberately avoid the severity
#: hues — nothing in the history pane should read as a verdict.
STATUS_COLOURS: dict[str, str] = {
    "2xx": "#00f5c8",
    "3xx": "#4dd8ff",
    "4xx": "#ffd166",
    "5xx": "#ff8a3d",
    "???": MUTED,
}


def css_variables() -> str:
    """Return the palette as Textual CSS variable declarations.

    Textual CSS has no ``:root``; variables are declared at the top of a
    stylesheet. Generating them from the same constants the widgets use keeps
    a single source of truth instead of two lists that drift apart.
    """
    lines = [
        f"$bg: {BG};",
        f"$panel: {PANEL};",
        f"$line: {LINE};",
        f"$line-hot: {LINE_HOT};",
        f"$ink: {INK};",
        f"$muted: {MUTED};",
        f"$accent: {ACCENT};",
    ]
    lines += [f"$sev-{sev.label}: {hex_};" for sev, hex_ in SEVERITY_COLOURS.items()]
    return "\n".join(lines)
