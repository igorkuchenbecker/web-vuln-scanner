"""Typed domain models shared by every component.

Plain ``dataclasses`` are used rather than pydantic: all values are produced
internally (parsed HTML, HTTP responses) and validated at their boundary, so
a runtime validation/serialisation framework would add a dependency without
solving a problem this project actually has.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

__all__ = [
    "Severity",
    "Confidence",
    "HttpMethod",
    "Target",
    "FormField",
    "Form",
    "Endpoint",
    "Page",
    "SiteMap",
    "ScanResult",
    "ScanReport",
]


class Severity(Enum):
    """Impact-ordered severity levels.

    The numeric ``rank`` exists so findings can be sorted and summarised
    without mapping strings back to an order at every call site.
    """

    INFO = ("info", 0)
    LOW = ("low", 1)
    MEDIUM = ("medium", 2)
    HIGH = ("high", 3)
    CRITICAL = ("critical", 4)

    def __init__(self, label: str, rank: int) -> None:
        self.label = label
        self.rank = rank

    def __str__(self) -> str:
        return self.label

    @classmethod
    def from_label(cls, label: str) -> Severity:
        """Return the severity whose label matches ``label`` (case-insensitive)."""
        normalised = label.strip().lower()
        for member in cls:
            if member.label == normalised:
                return member
        raise ValueError(f"unknown severity: {label!r}")


class Confidence(Enum):
    """How strongly the evidence supports the finding.

    Severity answers "how bad is this if real"; confidence answers "how sure
    are we that it is real". Keeping them separate avoids the common mistake
    of downgrading a serious issue merely because detection was heuristic.
    """

    LOW = ("low", 0)
    MEDIUM = ("medium", 1)
    HIGH = ("high", 2)

    def __init__(self, label: str, rank: int) -> None:
        self.label = label
        self.rank = rank

    def __str__(self) -> str:
        return self.label


class HttpMethod(Enum):
    """HTTP methods the scanner is allowed to send.

    Only safe/idempotent methods plus POST (needed to submit discovered
    forms) are modelled; destructive verbs are deliberately absent.
    """

    GET = "GET"
    POST = "POST"
    HEAD = "HEAD"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class Target:
    """The single authorised target of a scan."""

    url: str
    host: str
    scheme: str

    @property
    def is_https(self) -> bool:
        """Whether the target is reached over TLS."""
        return self.scheme == "https"


@dataclass(frozen=True, slots=True)
class FormField:
    """A single input control inside an HTML form."""

    name: str
    field_type: str = "text"
    value: str = ""

    @property
    def is_submittable(self) -> bool:
        """Whether the field carries a value the scanner may fuzz."""
        return self.field_type not in {"submit", "button", "image", "reset", "file"}


@dataclass(frozen=True, slots=True)
class Form:
    """An HTML form discovered on a page."""

    action: str
    method: HttpMethod
    fields: tuple[FormField, ...]
    source_url: str

    @property
    def field_names(self) -> tuple[str, ...]:
        """Names of every field, in document order."""
        return tuple(f.name for f in self.fields)

    def baseline_data(self) -> dict[str, str]:
        """Return the form's default payload (its unmodified values)."""
        return {f.name: f.value for f in self.fields if f.name}

    def fuzzable_fields(self) -> tuple[FormField, ...]:
        """Return the fields that are meaningful to inject test values into."""
        return tuple(f for f in self.fields if f.name and f.is_submittable)


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A testable request surface discovered during crawling.

    ``params`` holds the parameter names only; values live on the
    originating URL or on the form defaults.
    """

    url: str
    method: HttpMethod
    params: tuple[str, ...] = ()
    form: Form | None = None

    @property
    def has_params(self) -> bool:
        """Whether the endpoint exposes at least one parameter."""
        return bool(self.params)

    def key(self) -> tuple[str, str, tuple[str, ...]]:
        """Return a hashable identity used to de-duplicate endpoints."""
        return (self.url, self.method.value, self.params)


@dataclass(frozen=True, slots=True)
class Page:
    """A page fetched by the crawler, kept for later analysis."""

    url: str
    status_code: int
    headers: Mapping[str, str]
    content_type: str
    body: str
    depth: int


@dataclass(slots=True)
class SiteMap:
    """Everything the crawler discovered, handed to the scanners."""

    pages: list[Page] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)

    def add_endpoint(self, endpoint: Endpoint) -> bool:
        """Append ``endpoint`` unless an identical one is already known."""
        known = {e.key() for e in self.endpoints}
        if endpoint.key() in known:
            return False
        self.endpoints.append(endpoint)
        return True


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class ScanResult:
    """A single finding produced by a scanner."""

    scanner: str
    vulnerability: str
    severity: Severity
    confidence: Confidence
    url: str
    description: str
    remediation: str
    impact: str
    severity_rationale: str
    method: HttpMethod = HttpMethod.GET
    parameter: str | None = None
    evidence: str = ""
    timestamp: datetime = field(default_factory=_utc_now)

    def sort_key(self) -> tuple[int, int, str]:
        """Order findings by severity, then confidence, then URL (descending)."""
        return (-self.severity.rank, -self.confidence.rank, self.url)


@dataclass(slots=True)
class ScanReport:
    """Aggregated outcome of one scan run."""

    target: Target
    started_at: datetime
    finished_at: datetime
    pages_discovered: int
    endpoints_discovered: int
    forms_discovered: int
    requests_sent: int
    scanners_run: tuple[str, ...]
    findings: list[ScanResult]
    errors: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        """Wall-clock duration of the scan."""
        return (self.finished_at - self.started_at).total_seconds()

    def severity_counts(self) -> dict[Severity, int]:
        """Return the number of findings per severity, highest first."""
        counts = {severity: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return dict(sorted(counts.items(), key=lambda item: item[0].rank, reverse=True))

    def sorted_findings(self) -> list[ScanResult]:
        """Return findings ordered by severity then confidence."""
        return sorted(self.findings, key=lambda f: f.sort_key())
