"""Self-contained HTML report generation.

The report is a single file with inlined CSS so it opens directly in a browser
with no assets to serve. It is built with :class:`string.Template` rather than
a templating engine to avoid a dependency, and every value that originates from
the scanned application (URLs, evidence, parameter names) is HTML-escaped to
prevent the report itself from becoming an injection sink.
"""

from __future__ import annotations

import html
from importlib import resources
from string import Template

from ..core.models import ScanReport, ScanResult, Severity

__all__ = ["render_html_report", "write_html_report"]

#: Suffix shared by the CSS classes of a severity: ``s-`` frames a finding,
#: ``b-`` paints its badge, ``p-`` a summary pill and ``d-`` a bar segment.
_SEVERITY_SUFFIX = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "info",
}


def _e(value: object) -> str:
    """HTML-escape any value for safe embedding."""
    return html.escape(str(value), quote=True)


def _load_template() -> Template:
    text = (
        resources.files("scanner.reporting.templates")
        .joinpath("report.html")
        .read_text(encoding="utf-8")
    )
    return Template(text)


def render_html_report(report: ScanReport) -> str:
    """Return the full HTML document for ``report`` as a string."""
    template = _load_template()
    counts = report.severity_counts()

    return template.safe_substitute(
        target_host=_e(report.target.host),
        target_url=_e(report.target.url),
        generated_at=_e(report.finished_at.strftime("%Y-%m-%d %H:%M:%S UTC")),
        duration=f"{report.duration_seconds:.2f}",
        executive_summary=_e(_executive_summary(report)),
        severity_counts=_render_counts(counts),
        severity_bar=_render_severity_bar(counts),
        pages=report.pages_discovered,
        endpoints=report.endpoints_discovered,
        forms=report.forms_discovered,
        requests=report.requests_sent,
        findings_count=len(report.findings),
        findings_html=_render_findings(report),
        scanners_run=_e(", ".join(report.scanners_run) or "none"),
        errors_html=_render_errors(report),
    )


def write_html_report(report: ScanReport, path: str) -> None:
    """Write the HTML report for ``report`` to ``path``."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render_html_report(report))


def _executive_summary(report: ScanReport) -> str:
    if not report.findings:
        return (
            "No findings were produced by the selected scanners within the "
            "configured crawl limits."
        )
    counts = report.severity_counts()
    highest = max((f.severity for f in report.findings), key=lambda s: s.rank)
    parts = [f"{count} {sev.label}" for sev, count in counts.items() if count]
    return (
        f"{len(report.findings)} finding(s) across {len(report.scanners_run)} "
        f"scanner(s); highest severity: {highest.label.upper()}. "
        f"Breakdown: {', '.join(parts)}."
    )


def _render_counts(counts: dict[Severity, int]) -> str:
    """Render one labelled pill per severity.

    Every pill carries its written label, so the breakdown reads correctly
    without relying on the colour at all.
    """
    return "".join(
        f'<span class="pill p-{_SEVERITY_SUFFIX[severity]}">'
        f"{_e(severity.label.upper())}: {count}</span>"
        for severity, count in counts.items()
    )


def _render_severity_bar(counts: dict[Severity, int]) -> str:
    """Render the severity distribution as one proportional bar.

    Returns an empty bar when there is nothing to show, rather than dividing by
    zero or drawing a misleading full-width segment.
    """
    total = sum(counts.values())
    if total == 0:
        return ""
    return "".join(
        f'<span class="d-{_SEVERITY_SUFFIX[severity]}" '
        f'style="width:{count / total * 100:.2f}%" '
        f'title="{_e(severity.label)}: {count}"></span>'
        for severity, count in counts.items()
        if count
    )


def _render_findings(report: ScanReport) -> str:
    findings = report.sorted_findings()
    if not findings:
        return '<div class="panel"><span class="none">No findings.</span></div>'
    return "\n".join(_render_finding(f) for f in findings)


def _render_finding(finding: ScanResult) -> str:
    suffix = _SEVERITY_SUFFIX[finding.severity]
    return f"""<article class="finding s-{suffix}">
  <h3><span class="badge b-{suffix}">{_e(finding.severity.label.upper())}</span>
      {_e(finding.vulnerability)}
      <span class="scanner">[{_e(finding.scanner)}]</span></h3>
  <dl class="kv">
    <dt>Confidence</dt><dd>{_e(finding.confidence.label)}</dd>
    <dt>URL</dt><dd class="url">{_e(finding.url)}</dd>
    <dt>Method</dt><dd>{_e(finding.method)}</dd>
    <dt>Parameter</dt><dd>{_e(finding.parameter or "-")}</dd>
    <dt>Description</dt><dd>{_e(finding.description)}</dd>
    <dt>Impact</dt><dd>{_e(finding.impact)}</dd>
    <dt>Severity rationale</dt><dd>{_e(finding.severity_rationale)}</dd>
    <dt>Remediation</dt><dd>{_e(finding.remediation)}</dd>
  </dl>
  <div class="evidence">{_e(finding.evidence)}</div>
</article>"""


def _render_errors(report: ScanReport) -> str:
    if not report.errors:
        return ""
    items = "".join(f"<li>{_e(msg)}</li>" for msg in report.errors[:50])
    return f" {len(report.errors)} non-fatal error(s):<ul>{items}</ul>"
