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

_SEVERITY_CLASS = {
    Severity.CRITICAL: "s-critical",
    Severity.HIGH: "s-high",
    Severity.MEDIUM: "s-medium",
    Severity.LOW: "s-low",
    Severity.INFO: "s-info",
}


def _e(value: object) -> str:
    """HTML-escape any value for safe embedding."""
    return html.escape(str(value), quote=True)


def _load_template() -> Template:
    text = resources.files("scanner.reporting.templates").joinpath("report.html").read_text(
        encoding="utf-8"
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
    parts = [
        f"{count} {sev.label}"
        for sev, count in counts.items()
        if count
    ]
    return (
        f"{len(report.findings)} finding(s) across {len(report.scanners_run)} "
        f"scanner(s); highest severity: {highest.label.upper()}. "
        f"Breakdown: {', '.join(parts)}."
    )


def _render_counts(counts: dict[Severity, int]) -> str:
    chunks = []
    for severity, count in counts.items():
        cls = _SEVERITY_CLASS[severity]
        chunks.append(
            f'<span class="pill {cls}">{_e(severity.label.upper())}: {count}</span>'
        )
    return "".join(chunks)


def _render_findings(report: ScanReport) -> str:
    findings = report.sorted_findings()
    if not findings:
        return '<div class="card"><span class="none">No findings.</span></div>'
    return "\n".join(_render_finding(f) for f in findings)


def _render_finding(finding: ScanResult) -> str:
    cls = _SEVERITY_CLASS[finding.severity]
    return f"""<div class="card finding {cls}">
  <h3><span class="pill {cls}">{_e(finding.severity.label.upper())}</span>
      {_e(finding.vulnerability)}
      <span class="muted mono">[{_e(finding.scanner)}]</span></h3>
  <dl class="kv">
    <dt>Confidence</dt><dd>{_e(finding.confidence.label)}</dd>
    <dt>URL</dt><dd class="mono">{_e(finding.url)}</dd>
    <dt>Method</dt><dd>{_e(finding.method)}</dd>
    <dt>Parameter</dt><dd class="mono">{_e(finding.parameter or "-")}</dd>
    <dt>Description</dt><dd>{_e(finding.description)}</dd>
    <dt>Impact</dt><dd>{_e(finding.impact)}</dd>
    <dt>Severity rationale</dt><dd>{_e(finding.severity_rationale)}</dd>
    <dt>Remediation</dt><dd>{_e(finding.remediation)}</dd>
  </dl>
  <div class="evidence">{_e(finding.evidence)}</div>
</div>"""


def _render_errors(report: ScanReport) -> str:
    if not report.errors:
        return ""
    items = "".join(f"<li>{_e(msg)}</li>" for msg in report.errors[:50])
    return f' {len(report.errors)} non-fatal error(s):<ul>{items}</ul>'
