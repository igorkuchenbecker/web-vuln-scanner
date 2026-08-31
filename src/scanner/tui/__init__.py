"""Terminal user interface for the scanner.

This package is an optional front end. It imports the engine but nothing in
the engine imports it, so the scanner remains usable — and testable — with
no interface library installed. Install it with the ``tui`` extra:

.. code-block:: sh

    pip install -e ".[tui]"

The interface adds no scanning capability. It configures the same
:class:`~scanner.core.config.ScanConfig` the CLI does and runs the same
engine, so scope, pacing and the request budget apply identically.
"""

from __future__ import annotations

__all__ = ["main"]


def main(argv: list[str] | None = None) -> int:
    """Launch the interface.

    Imported lazily so that ``scanner.tui`` can be imported (and its absence
    diagnosed) without requiring ``textual`` to be installed.
    """
    from .app import main as _main

    return _main(argv)
