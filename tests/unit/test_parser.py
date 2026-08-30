"""Tests for HTML link and form extraction."""

from __future__ import annotations

from scanner.core.models import HttpMethod
from scanner.crawler.parser import extract_forms, extract_links

_BASE = "http://example.test/dir/page"


def test_extract_links_resolves_and_filters() -> None:
    html = """
    <a href="/a">a</a>
    <a href="sub">b</a>
    <a href="http://example.test/c">c</a>
    <a href="mailto:x@y.test">mail</a>
    <a href="#frag">frag</a>
    <a href="/a">dup</a>
    """
    links = extract_links(html, _BASE)
    assert "http://example.test/a" in links
    assert "http://example.test/dir/sub" in links
    assert "http://example.test/c" in links
    assert all("mailto" not in link for link in links)
    assert links.count("http://example.test/a") == 1


def test_extract_links_honours_base_tag() -> None:
    html = '<head><base href="http://example.test/other/"></head><a href="x">x</a>'
    assert extract_links(html, _BASE) == ["http://example.test/other/x"]


def test_extract_forms_parses_fields() -> None:
    html = """
    <form action="/login" method="POST">
      <input type="text" name="username" value="u">
      <input type="password" name="password">
      <textarea name="note">hi</textarea>
      <select name="role"><option value="admin" selected>admin</option></select>
      <button type="submit" name="go">Go</button>
    </form>
    """
    forms = extract_forms(html, _BASE)
    assert len(forms) == 1
    form = forms[0]
    assert form.action == "http://example.test/login"
    assert form.method is HttpMethod.POST
    assert set(form.field_names) == {"username", "password", "note", "role", "go"}
    assert form.baseline_data()["role"] == "admin"
    assert form.baseline_data()["note"] == "hi"
    assert "username" in {f.name for f in form.fuzzable_fields()}
    assert "go" not in {f.name for f in form.fuzzable_fields()}


def test_form_without_action_defaults_to_page() -> None:
    forms = extract_forms('<form method="get"><input name="q"></form>', _BASE)
    assert forms[0].action == _BASE
    assert forms[0].method is HttpMethod.GET
