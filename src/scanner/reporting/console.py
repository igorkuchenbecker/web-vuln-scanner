"""Console rendering with ``rich``.

The console report is a scan summary plus a findings table, colour-coded by
severity. ``rich`` is used rather than hand-rolled ANSI because it handles
terminal width, colour capability detection and ``--no-color`` degradation for
free.
"""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..core.models import ScanReport, Severity

__all__ = ["render_console_report", "SEVERITY_STYLES"]

#: The same hexes the HTML report uses, so a finding looks like itself whether
#: it is read in a terminal or in a browser. Every one of them was checked for
#: WCAG contrast against a dark background and for colour-vision separation.
_ACCENT = "#00f5c8"
_MUTED = "#7d95a1"

SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold #ff2d6f",
    Severity.HIGH: "bold #ff8a3d",
    Severity.MEDIUM: "#ffd166",
    Severity.LOW: "#4dd8ff",
    Severity.INFO: "#8aa4b8",
}


def render_console_report(report: ScanReport, *, no_color: bool = False) -> None:
    """Print ``report`` to stdout."""
    console = Console(no_color=no_color, highlight=False)
    _render_banner(console, report)
    _render_summary(console, report)
    _render_severity_counts(console, report)
    _render_findings(console, report)
    if report.errors:
        _render_errors(console, report)


def _render_banner(console: Console, report: ScanReport) -> None:
    """Print a compact header identifying the run."""
    console.print()
    console.print(Text("// WEB-VULN-SCANNER", style=f"bold {_ACCENT}"))
    console.print(Text(f"   {report.target.url}", style=_MUTED))
    console.print()


def _render_summary(console: Console, report: ScanReport) -> None:
    table = Table(
        title="Scan Summary",
        show_header=False,
        title_justify="left",
        title_style=f"bold {_ACCENT}",
        box=box.SIMPLE_HEAD,
        border_style=_MUTED,
    )
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Target", report.target.url)
    table.add_row("Duration", f"{report.duration_seconds:.2f}s")
    table.add_row("Pages discovered", str(report.pages_discovered))
    table.add_row("Endpoints discovered", str(report.endpoints_discovered))
    table.add_row("Forms discovered", str(report.forms_discovered))
    table.add_row("Requests sent", str(report.requests_sent))
    table.add_row("Scanners run", ", ".join(report.scanners_run) or "-")
    table.add_row("Findings", str(len(report.findings)))
    console.print(table)


def _render_severity_counts(console: Console, report: ScanReport) -> None:
    counts = report.severity_counts()
    line = Text("Severity  ", style=_MUTED)
    parts = []
    for severity, count in counts.items():
        chunk = Text(f"{severity.label.upper()}={count}", style=SEVERITY_STYLES[severity])
        parts.append(chunk)
    for index, chunk in enumerate(parts):
        if index:
            line.append("  ")
        line.append_text(chunk)
    console.print(line)


def _render_findings(console: Console, report: ScanReport) -> None:
    findings = report.sorted_findings()
    if not findings:
        console.print(Text("No findings.", style=f"bold {_ACCENT}"))
        return

    table = Table(
        title="Findings",
        title_justify="left",
        title_style=f"bold {_ACCENT}",
        box=box.SIMPLE_HEAD,
        border_style=_MUTED,
        header_style=_MUTED,
    )
    table.add_column("Severity")
    table.add_column("Conf.")
    table.add_column("Vulnerability")
    table.add_column("Param")
    table.add_column("URL", overflow="fold")

    for finding in findings:
        table.add_row(
            Text(finding.severity.label.upper(), style=SEVERITY_STYLES[finding.severity]),
            finding.confidence.label,
            finding.vulnerability,
            finding.parameter or "-",
            finding.url,
        )
    console.print(table)


def _render_errors(console: Console, report: ScanReport) -> None:
    console.print(Text(f"{len(report.errors)} non-fatal error(s):", style="#ffd166"))
    for message in report.errors[:20]:
        console.print(Text(f"  - {message}", style="dim"))
