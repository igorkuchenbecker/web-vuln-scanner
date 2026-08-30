"""Scanner abstraction and registry.

Design decision — **registry + strategy**, not a heavyweight plugin loader.
Each scanner is a strategy implementing one interface (:class:`Scanner`); a
decorator registers it by name. The engine depends only on the interface and
the registry, so adding ``CSRFScanner`` tomorrow means writing one class and a
``@register`` line, with no change to the engine. Dynamic discovery from the
filesystem was rejected: it adds import-time magic and a remote-code-execution
surface for a project whose scanner set is small and known.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from ..core.models import ScanResult, SiteMap
from ..http.client import HttpClient
from ..utils.logging import get_logger

__all__ = ["ScanContext", "Scanner", "register", "get_scanner", "available_scanners"]


class ScanContext:
    """Everything a scanner needs to run, passed by the engine."""

    def __init__(self, site_map: SiteMap, client: HttpClient) -> None:
        self.site_map = site_map
        self.client = client

    @property
    def secrets(self) -> tuple[str, ...]:
        """Operator secrets that findings must redact from evidence."""
        return self.client.secrets


class Scanner(ABC):
    """Base class for every vulnerability check.

    Subclasses implement :meth:`scan`. They should never raise for a single
    bad endpoint; the engine isolates failures, but scanners are expected to
    be defensive so one dead URL does not lose an entire check's results.
    """

    #: Stable identifier used on the CLI and in reports.
    name: str = ""
    #: One-line human description shown in ``--help`` style listings.
    description: str = ""

    def __init__(self) -> None:
        if not self.name:
            raise ValueError(f"{type(self).__name__} must define a name")
        self._log = get_logger(f"scanner.{self.name}")

    @abstractmethod
    def scan(self, context: ScanContext) -> list[ScanResult]:
        """Return the findings produced against ``context``."""
        raise NotImplementedError


_REGISTRY: dict[str, type[Scanner]] = {}


def register(cls: type[Scanner]) -> type[Scanner]:
    """Class decorator registering ``cls`` under its ``name``."""
    name = cls.name
    if not name:
        raise ValueError(f"{cls.__name__} must define a name before registration")
    if name in _REGISTRY:
        raise ValueError(f"duplicate scanner name: {name!r}")
    _REGISTRY[name] = cls
    return cls


def get_scanner(name: str) -> Scanner:
    """Instantiate the scanner registered under ``name``."""
    try:
        return _REGISTRY[name]()
    except KeyError as exc:
        raise KeyError(f"unknown scanner: {name!r}") from exc


def available_scanners() -> tuple[str, ...]:
    """Return the names of every registered scanner, sorted."""
    return tuple(sorted(_REGISTRY))


def build_scanners(names: Iterable[str] | None) -> list[Scanner]:
    """Instantiate the requested scanners, or all of them when ``names`` is empty."""
    selected = tuple(names) if names else available_scanners()
    return [get_scanner(name) for name in selected]
