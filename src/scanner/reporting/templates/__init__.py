"""Packaged HTML report templates.

This module exists so the directory is a real package: the HTML renderer
loads ``report.html`` through :func:`importlib.resources.files`, which needs
an importable package, and ``[tool.setuptools.package-data]`` only ships the
template for a package that ``packages.find`` actually discovers.
"""
