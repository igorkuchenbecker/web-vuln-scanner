"""HTML parsing: links and forms.

Parsing is isolated from crawling so both can be unit-tested against static
HTML fixtures without any network involved.
"""

from __future__ import annotations

from bs4 import BeautifulSoup
from bs4.element import Tag

from ..core.models import Form, FormField, HttpMethod
from ..utils.urls import absolutize

__all__ = ["parse_html", "extract_links", "extract_forms"]

_PARSER = "html.parser"
_LINK_ATTRS = (("a", "href"), ("area", "href"), ("iframe", "src"), ("frame", "src"))


def parse_html(html: str) -> BeautifulSoup:
    """Parse ``html`` with the standard library backend.

    ``html.parser`` is used instead of ``lxml`` to avoid a compiled
    dependency; it is lenient enough for the malformed markup a scanner
    routinely meets.
    """
    return BeautifulSoup(html, _PARSER)


def extract_links(html: str, base_url: str) -> list[str]:
    """Return the absolute, normalised, de-duplicated links found in ``html``.

    ``<base href>`` is honoured because ignoring it yields wrong URLs on the
    sites that use it.
    """
    soup = parse_html(html)
    effective_base = _effective_base(soup, base_url)

    found: list[str] = []
    seen: set[str] = set()
    for tag_name, attribute in _LINK_ATTRS:
        for tag in soup.find_all(tag_name):
            if not isinstance(tag, Tag):
                continue
            href = tag.get(attribute)
            if not isinstance(href, str):
                continue
            resolved = absolutize(effective_base, href)
            if resolved and resolved not in seen:
                seen.add(resolved)
                found.append(resolved)
    return found


def extract_forms(html: str, base_url: str) -> list[Form]:
    """Return every form in ``html`` as a structured :class:`Form`."""
    soup = parse_html(html)
    effective_base = _effective_base(soup, base_url)

    forms: list[Form] = []
    for tag in soup.find_all("form"):
        if not isinstance(tag, Tag):
            continue
        form = _build_form(tag, effective_base, base_url)
        if form is not None:
            forms.append(form)
    return forms


def _effective_base(soup: BeautifulSoup, base_url: str) -> str:
    base_tag = soup.find("base")
    if isinstance(base_tag, Tag):
        href = base_tag.get("href")
        if isinstance(href, str):
            resolved = absolutize(base_url, href)
            if resolved:
                return resolved
    return base_url


def _build_form(tag: Tag, effective_base: str, source_url: str) -> Form | None:
    raw_action = tag.get("action")
    action_value = raw_action if isinstance(raw_action, str) else ""
    action = absolutize(effective_base, action_value or effective_base)
    if action is None:
        return None

    raw_method = tag.get("method")
    method_name = raw_method.strip().upper() if isinstance(raw_method, str) else "GET"
    method = HttpMethod.POST if method_name == "POST" else HttpMethod.GET

    return Form(
        action=action,
        method=method,
        fields=tuple(_extract_fields(tag)),
        source_url=source_url,
    )


def _extract_fields(form_tag: Tag) -> list[FormField]:
    fields: list[FormField] = []
    for control in form_tag.find_all(("input", "textarea", "select", "button")):
        if not isinstance(control, Tag):
            continue
        name = control.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        fields.append(_build_field(control, name.strip()))
    return fields


def _build_field(control: Tag, name: str) -> FormField:
    tag_name = control.name.lower()

    if tag_name == "textarea":
        return FormField(name=name, field_type="textarea", value=control.get_text())

    if tag_name == "select":
        return FormField(name=name, field_type="select", value=_selected_option(control))

    raw_type = control.get("type")
    if isinstance(raw_type, str) and raw_type.strip():
        field_type = raw_type.strip().lower()
    else:
        field_type = "submit" if tag_name == "button" else "text"

    raw_value = control.get("value")
    value = raw_value if isinstance(raw_value, str) else ""
    return FormField(name=name, field_type=field_type, value=value)


def _selected_option(select_tag: Tag) -> str:
    options = [opt for opt in select_tag.find_all("option") if isinstance(opt, Tag)]
    if not options:
        return ""
    chosen = next((opt for opt in options if opt.has_attr("selected")), options[0])
    raw_value = chosen.get("value")
    return raw_value if isinstance(raw_value, str) else chosen.get_text(strip=True)
