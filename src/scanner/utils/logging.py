"""Logging setup.

Uses the standard library only. ``rich`` renders the report, but log records
stay plain so they remain greppable when redirected to a file.
"""

from __future__ import annotations

import logging
import sys

__all__ = ["configure_logging", "get_logger"]

_LOGGER_NAME = "scanner"
_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"


def configure_logging(*, verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """Configure and return the package logger.

    Handlers are replaced rather than appended so repeated calls (tests, CLI
    re-entry) cannot duplicate every log line.
    """
    level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter(_FORMAT))
    logger.addHandler(handler)
    return logger


def get_logger(component: str | None = None) -> logging.Logger:
    """Return the package logger, optionally scoped to ``component``."""
    if component:
        return logging.getLogger(f"{_LOGGER_NAME}.{component}")
    return logging.getLogger(_LOGGER_NAME)
