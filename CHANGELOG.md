# DragonEye v1.6 — Daily-Driver Release Notes

## What changed

This release replaces the broken AI shell executor with real, usable interfaces:
an interactive console, a one-shot `quick` command, and environment diagnostics.

### New capabilities

- **`dragoneye quick <target>`** — derives a program from any target (domain, URL, IP, CIDR member), extends its scope with the target, runs the full recon pipeline and prints the report path. Supports `--dry-run`, `--passive`, `--no-llm`, `--open` and `--yes` flags.

- **Interactive console** (`dragoneye` with no args) — the recommended way to use DragonEye day to day. Tab completion, persistent readline history, and these commands:
  - `quick <target>` — one-shot recon
  - `use <name>` / `programs` — select / list programs
  - `run [flags]` — recon the active program
  - `show [run]` / `show last` — run summary + findings
  - `diff [run]` — what's new since previous runs
  - `assets` / `assets <program>` — cumulative asset inventory across all runs
  - `findings` / `findings <program>` — every known finding
  - `scope <target...>` — dry-check against scope rules
  - `doctor` — environment health check
  - `report [--open]` / `report [run]` — report paths
  - `tools` — installed vs missing binaries
  - `config` / `config set k v` / `config key provider` — settings
  - `theme` / `slumber` — toggle normal / red awakened theme
  - `exit` / `quit` — leave the console

- **`dragoneye doctor`** — checks Python version & deps, XDG directories, SQLite database, external recon tools (subfinder/dnsx/httpx/katana/nuclei), scope validity for every program, model configuration (provider / model / usage tier), and safety flags (allow_private, metadata blocking). `--json` mode for scripting.

- **`dragoneye assets [program] [--kind domain|url|ip] [--search term]`** and **`dragoneye findings [program] [--severity critical|high|medium|low|info] [--search term]`** — cumulative inventory across all runs, with JSON output.

- **Consolidated theme** — `dragoneye theme` toggles between normal (green) and awakened (red). `dragoneye slumber` returns to normal. No AI shell executes model output as a shell command.

- **69 tests** — the full suite passes (was 59 before, broken commands and AI shell removed).

### Removed

- **`awaken` AI shell executor** — it was broken (undefined `subprocess` import) and dangerous (runs model output via `shell=True`). Replaced by the safe interactive console with the red theme. `slumber` restores the normal theme. Nothing in DragonEye executes model output as a shell command.

### Fixed

- `dragoneye program add` now resolves program IDs by name after upsert (previously returned stale `lastrowid`)
- Web GUI tool status no longer clobbers provider list on load; requires CSRF token
- Web "install" button returns the exact install command to copy (no silent install)
- HTML reports served inline so GUI's report preview renders instead of downloading
- Invalid CSS (`border:1px solid:#...`) in the GUI removed
- `doctor`/`console` errors are contained; a bad command never ends the session
- `dragoneye quick` derives a stable program name from the target so `api.example.com` and `www.example.com` share `example.com`

### Version

- `__version__` → `1.6.0` (was `1.5.0`)
- `pyproject.toml` version → `1.6.0`
- Changelog migrated to v1.6.0

## Quickstart

```bash
# The fast path — no program setup required
dragoneye quick example.com            # scope + scan + triage + report
dragoneye quick example.com --dry-run  # print commands, send nothing

# Diagnose your machine
dragoneye doctor                       # what works, what's missing

# Open the interactive console (recommended)
dragoneye                              # or: dragoneye shell

# Within the console:
quick example.com                      # go from zero to a report
use myprogram                          # select a program
run --dry                              # print commands only
show                                   # summary + findings
diff                                   # what's new since last run
assets                                 # cumulative inventory
findings                               # every known finding
doctor                                 # environment diagnostics
report --open                          # open HTML report in browser
exit                                   # leave the console

# Managed programs (still supported)
dragoneye program add acme --in-text 'acme.com' --platform hackerone
dragoneye scope acme www.acme.com 169.254.169.254
dragoneye run acme --passive --dry-run
dragoneye show last
dragoneye report last --open
```

## File changes

### New
- `dragneye/ui.py` — shared banner/colour helpers
- `dragoneye/quick.py` — one-shot target → program → pipeline → report
- `dragoneye/doctor.py` — environment diagnostics
- `dragoneye/console.py` — interactive REPL with history/completion

### Modified
- `dragoneye/cli.py` — CLI now supports `quick`, `doctor`, `shell`, `assets`, `findings`, `theme`, `slumber`; removed `awaken`; unified end-of-run output
- `dragoneye/db.py` — `add_program` upsert fix; added `list_assets()`, `list_findings()`
- `dragoneye/web/app.py` — tool install returns exact command; HTML served inline; fixed CSS; requires CSRF token
- `dragoneye/report.py` — minor rendering fixes
- `dragoneye/pipeline.py` — no functional changes
- `dragoneye/scope.py` — no functional changes
- `dragoneye/llm/` — no functional changes
- `dragoneye/tools/` — no functional changes
- `dragoneye/cli.py` — banner removed from `main()`; initial landing is console or quick help

## Test results

```
69 passed, 1 warning in 3.5s
ruff check ... All checks passed!
```

All legacy tests (config, DB, pipeline, scope, adapters, web) continue to pass.