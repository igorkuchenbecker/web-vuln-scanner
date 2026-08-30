"""Shared helpers for scanners that fuzz a single parameter at a time.

Both the SQLi and XSS scanners need the same primitive: take an endpoint,
substitute one probe value into one parameter while leaving every other
parameter at its baseline, send the request, and read the response. Factoring
it out keeps the two scanners focused on *interpreting* responses rather than
on request plumbing.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.exceptions import HttpError, ScopeError
from ..core.models import Endpoint, HttpMethod
from ..http.client import HttpClient, HttpResponse
from ..utils.urls import with_query_param

__all__ = ["Probe", "send_probe", "iter_parameters"]


@dataclass(frozen=True, slots=True)
class Probe:
    """A response paired with the parameter and value that produced it."""

    parameter: str
    value: str
    response: HttpResponse


def iter_parameters(endpoint: Endpoint) -> tuple[str, ...]:
    """Return the parameter names worth fuzzing on ``endpoint``."""
    return endpoint.params


def send_probe(
    client: HttpClient,
    endpoint: Endpoint,
    parameter: str,
    value: str,
) -> Probe | None:
    """Send one request with ``value`` injected into ``parameter``.

    Returns ``None`` if the request could not be completed; callers treat a
    missing probe as "no evidence" rather than as a finding, so a flaky
    endpoint never manufactures a false positive.
    """
    try:
        if endpoint.method is HttpMethod.POST:
            response = client.post(endpoint.url, _post_payload(endpoint, parameter, value))
        else:
            response = client.get(with_query_param(endpoint.url, parameter, value))
    except (HttpError, ScopeError):
        return None
    return Probe(parameter=parameter, value=value, response=response)


def _post_payload(endpoint: Endpoint, parameter: str, value: str) -> dict[str, str]:
    """Build a form body with ``parameter`` set to ``value`` and others baseline."""
    if endpoint.form is not None:
        payload = endpoint.form.baseline_data()
    else:
        payload = {name: "1" for name in endpoint.params}
    payload[parameter] = value
    return payload
