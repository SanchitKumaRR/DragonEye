# Changelog

All notable changes to DragonEye are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-22

First stable release. The core pipeline, scope engine and report formats are
now considered stable; the CLI and on-disk data model are the supported
interface.

### Fixed

- **CIDR scope rules now match hostnames whose resolved addresses fall inside
  the CIDR**, not just IP literals. The resolve stage feeds DNS answers into
  `Scope.check(target, resolved)`, and deny/private/metadata screening happens
  before an allow rule can win.
- **Out-of-scope findings are dropped before storage.** Previously a scanner
  finding on an unapproved host could be persisted with no asset attached.
- **Findings no longer survive a later scope demotion.** If an asset is
  discovered to resolve into a deny CIDR or private range, it is removed from
  the run and marked out of scope.
- **Malformed URL ports raise `ScopeError`** instead of leaking a raw
  `ValueError` out of `program add` / the web API.
- **ASN rules fail with a clear error.** They were advertised but never
  implementable because no adapter supplies an ASN; accepting them silently
  created a program that could never match anything.
- **Triage accounting includes search and JSON-repair rounds.** Cost and token
  totals now match what the provider actually billed.
- **The cost cap warns when it cannot be enforced** because the model is not in
  the local price table.
- **`katana` is pinned to `fqdn` field scope**, so a crawl does not wander to
  sibling subdomains, and **`nuclei` runs with `-ni` and `-duc`** to disable
  OOB callbacks and incidental update traffic.
- **API keys are written atomically with mode 0600**; config and data
  directories are chmod 0700.
- **SQLite schema migrations** are versioned (`PRAGMA user_version`); a newer
  database is refused instead of silently corrupted.

### Added

- Per-decision scope auditing: `scope_loaded`, `scope_reject` (capped per run)
  and `scope_summary` rows, exposed through `dragoneye audit --run` and in the
  HTML/Markdown/JSON report.
- `dragoneye audit --run ID --action scope_reject` and `audit --action`
  filters.
- Report sections for scope rejections and the exact commands executed.
- `dragoneye serve --insecure-bind` gate; remote binds are refused by default.
- Security headers (CSP, nosniff, frame denial, no-store API responses) and
  header-only CSRF token handling in the web GUI.
- Concurrency is now passed to ProjectDiscovery tools (`-t` / `-c`) from
  `config.concurrency`.
- Nuclei severities are configurable via `config.nuclei_severities`.
- A web guard against starting two runs for the same program at once.
- `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, and GitHub Actions CI
  (pytest + ruff on Python 3.11–3.13).
- Tests for resolved-CIDR scope, finding scope gates, audit rows, schema
  migration, secret permissions, web headers and version metadata.

### Changed

- Version bumped to **1.0.0**; `dragoneye --version` prints it.
- Dependency ranges are bounded for reproducible installs.
- README's scope table and safety claims now match the implementation.
- Removed the unused "ASN" scope syntax and the `--allow-private` escape for
  cloud metadata endpoints (metadata stays blocked regardless).

## [0.1.0] - 2026-11-20

Initial public prototype: scope engine, staged resumable pipeline, SQLite
history, five ProjectDiscovery adapters, LLM triage with budgets and
calibration, CLI, local web GUI, and Markdown/JSON/HTML reports.
