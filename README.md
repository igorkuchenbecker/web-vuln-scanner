# web-vuln-scanner

[![CI](https://github.com/igorkuchenbecker/web-vuln-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/igorkuchenbecker/web-vuln-scanner/actions/workflows/ci.yml)

A modular, **safe-by-design**, non-destructive web application vulnerability
scanner written in Python. It crawls an authorised target, discovers request
surface (links, GET parameters, HTML forms), runs a set of pluggable scanners
against it, and produces a console summary and a self-contained HTML report.

> ⚠️ **Authorised use only.** Use this tool exclusively against systems you own
> or have explicit, written permission to test. See the
> [Legal Disclaimer](#legal-disclaimer).

---

## Overview

The project is a small **scanning platform**, not a single script. Discovery,
transport, and vulnerability logic are separate layers, so new checks can be
added as self-contained plugins without touching the engine. Every design
choice favours, in order:

> Security → Reliability → Testability → Modularity → Maintainability →
> Extensibility → Performance.

## Features

- **Scope-enforced crawler** — stays on the authorised host(s); every request
  is checked against an immutable scope.
- **Centralised HTTP layer** — one client applies timeouts, rate limiting, a
  global request budget, response-size limits and manual (scope-checked)
  redirect handling.
- **Pluggable scanners** via a registry + strategy pattern:
  - Reflected XSS (context-aware, distinguishes encoded vs. unencoded reflection)
  - SQL injection (error-based **and** boolean-based, non-destructive)
  - Security headers & cookie flags (context-aware severity)
  - Authentication-surface discovery (mapping only — no exploitation)
- **Two reports** — a `rich` console table and a standalone HTML file.
- **Severity + confidence** on every finding, each with a written rationale.
- **Secret redaction** — cookies / auth headers never appear in logs or reports.
- **Fully tested** — unit tests plus an end-to-end integration test against a
  bundled, deliberately vulnerable local app (no external services).

## Architecture

```
src/scanner/
├── cli/          # argparse CLI (thin; delegates to the engine)
├── core/         # config, models, scope, engine, exceptions
├── http/         # the single outbound HTTP client, rate limiter, budget
├── crawler/      # scope-bounded BFS crawler + HTML parser
├── scanners/     # Scanner ABC + registry, and the built-in checks
├── reporting/    # console (rich) and self-contained HTML renderers
└── utils/        # URL normalisation, logging, redaction
```

**Execution flow:** `CLI → ScanConfig → ScanEngine`. The engine builds an
immutable `Scope`, opens one `HttpClient`, runs the `Crawler` to produce a
`SiteMap`, then runs each selected `Scanner` against a shared `ScanContext`.
Scanner failures are isolated so one broken check never loses the others'
results. Findings are aggregated into a `ScanReport` and rendered.

**Key decisions**

- *Registry + strategy* over a filesystem plugin loader: the scanner set is
  small and known, so dynamic import magic (and its RCE surface) isn't worth
  it. Adding a scanner = one class + one `@register` line.
- *Single HTTP chokepoint*: scope, pacing, budget and size limits are applied
  by construction, not by convention — no module calls `requests` directly.
- *Plain dataclasses* over pydantic: all data is produced and validated
  internally, so a validation framework would add a dependency without solving
  a real problem.
- *stdlib `argparse` / `string.Template` / `html.parser`*: kept the dependency
  list to `requests`, `beautifulsoup4`, `rich` (+ `pytest` for dev).

## Installation

Requires **Python 3.12+**.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .                   # or: pip install -r requirements.txt
```

## Usage

```bash
python -m scanner \
    --target http://127.0.0.1:8000 \
    --max-depth 3 \
    --max-pages 100 \
    --delay 0.5 \
    --timeout 10 \
    --output report.html
```

Run only specific scanners:

```bash
python -m scanner --target http://127.0.0.1:8000 --scanner xss --scanner headers
```

After `pip install`, a `web-vuln-scanner` console entry point is also available.

### CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | *(required)* | Root URL to scan. |
| `--max-depth` | `3` | Maximum crawl depth. |
| `--max-pages` | `50` | Maximum pages to crawl. |
| `--max-requests` | `500` | Hard cap on total requests (global budget). |
| `--timeout` | `10` | Per-request timeout (seconds). |
| `--max-redirects` | `5` | Maximum redirects followed (each scope-checked). |
| `--max-response-bytes` | `2 MiB` | Maximum response body read. |
| `--insecure` | off | Disable TLS verification (staging only; logged). |
| `--delay` | `0.5` | Minimum delay between requests (seconds). |
| `--requests-per-second` | – | Rate cap; combined with `--delay`, the stricter wins. |
| `--user-agent` | scanner UA | Custom User-Agent. |
| `--header NAME:VALUE` | – | Extra request header (repeatable). |
| `--cookie NAME=VALUE` | – | Request cookie (repeatable). |
| `--scope-host HOST` | – | Additional in-scope host (repeatable). |
| `--allow-subdomains` | off | Treat subdomains of in-scope hosts as in scope. |
| `--path-prefix` | – | Restrict scope to URLs under a path prefix. |
| `--scanner NAME` | all | Run only the named scanner (repeatable). |
| `--output FILE.html` | – | Write an HTML report. |
| `--no-color` | off | Disable coloured console output. |
| `--verbose` / `--quiet` | – | Adjust logging verbosity. |

**Exit code:** `0` when no actionable (non-INFO) findings, `1` otherwise — so
the tool can gate CI.

## Supported Checks

| Scanner | Detects | Max severity | Notes |
|---------|---------|--------------|-------|
| `xss` | Reflected XSS | HIGH | Context-aware; encoded reflection is INFO only. |
| `sqli` | SQL injection | HIGH | Error-based + boolean-based; never extracts data. |
| `headers` | Missing/weak security headers, cookie flags | MEDIUM | Context-aware severity. |
| `auth-surface` | Login/auth endpoints | INFO | Discovery only; no exploitation. |

## Testing

```bash
pip install -e ".[dev]"
pytest                       # run the test suite
pytest --cov=scanner         # with coverage
ruff check .                 # lint
ruff format --check .        # formatting
```

Continuous integration runs the suite on Python 3.12 and 3.13 plus `ruff`
lint/format checks on every push and pull request (see
`.github/workflows/ci.yml`).

The suite includes unit tests for every component and an **integration test**
that starts a bundled, deliberately vulnerable app on `127.0.0.1` (random port)
and runs a full scan against it. No external services are contacted.

Run the vulnerable app manually to try the scanner by hand:

```bash
python -m tests.fixtures.vulnerable_app          # serves on http://127.0.0.1:8000
python -m scanner --target http://127.0.0.1:8000 --delay 0 --output report.html
```

## Example Output

```
Severity: CRITICAL=0  HIGH=1  MEDIUM=2  LOW=2  INFO=4

HIGH     Potential SQL Injection            id   /item?id=1
MEDIUM   Missing Content-Security-Policy     -   /
MEDIUM   Potential Reflected XSS             q   /search?q=hello
LOW      Missing X-Frame-Options             -   /
INFO     Authentication surface (login)      -   /login
```

## Limitations

- **No JavaScript execution.** XSS findings indicate *potential* execution
  based on unencoded reflection; a human must confirm in a browser. The tool
  never claims "confirmed XSS".
- **Heuristic SQLi.** Boolean-based detection compares response similarity;
  highly dynamic pages can, in rare cases, resemble the signal (reported at
  MEDIUM confidence, not HIGH).
- **Static HTML crawling only** — no SPA/JS-rendered link discovery, no
  authenticated multi-step flows.
- **Not exhaustive.** Absence of a finding is not proof of absence of a
  vulnerability. It targets a handful of common, high-signal classes.

## Roadmap

- Additional scanners: CSRF, open redirect, path traversal, SSRF, cookie
  scope — each is a drop-in `Scanner` subclass.
- Optional headless-browser confirmation for XSS.
- JSON / SARIF report output for CI ingestion.
- Authenticated crawling with a login recipe.

## Security Considerations

The tool is built to make accidental misuse hard:

- **Explicit target** and **immutable scope** — set once from the target;
  nothing discovered mid-scan can widen it.
- **No off-scope requests**, including redirect targets, which are followed
  manually and re-checked at every hop.
- **Rate limiting**, **per-request timeouts**, a **global request budget**,
  **page/depth limits** and **response-size limits** bound total load.
- **Non-destructive by design** — no data modification, no dumping, no command
  execution, no brute force, no auth bypass, no DoS.
- **Secret redaction** — cookies and `Authorization`/API-key headers are never
  written to logs or reports.

## Legal Disclaimer

This software is provided for **authorised security testing and educational
purposes only**. You must have explicit permission to test any system you point
it at. Unauthorised scanning may be illegal. The authors accept no liability
for misuse or for any damage arising from use of this software. See
[`LICENSE`](LICENSE).

## License

Released under the [MIT License](LICENSE) — permissive and widely understood,
appropriate for an open-source portfolio project meant to be read, reused and
learned from with minimal friction.
