# DragonEye v1.6 — Daily-Driver Release

**Scope-aware recon for bug bounty hunters. CLI + localhost web GUI. Prevents off-scope scans, deduplicates findings, and includes an interactive console, environment diagnostics, and one-shot `quick` command.**

**Keywords:** security, bug-bounty, recon, scope, subdomain, nuclei, penetration-testing, vulnerability-scanning, CTF, tools, python-security, bug-bounty-automation, scope-enforcement, subdomain-enumeration, HTTP-probing, nuclei-templates, LLM-assisted, bug-bounty-tools, recon-framework, scope-rules, audit-log, calibration, interactive-console, one-shot, CLI, web-GUI

**Status:** v1.6 — daily-driver release. Interactive console, one-shot `quick` runs, environment diagnostics, cumulative asset/finding inventory, 61 models across 16 providers, 5 tool adapters, 69 tests, resumable pipeline, per-decision scope auditing, Markdown/JSON/HTML reports. Scope enforcement is target-list level, not network level — see [Safety model](#safety-model) and `SECURITY.md` before a live run.

DragonEye's job is not to be another subdomain dumper. It is to be the thing that
**never hands an out-of-scope target to a tool**, remembers everything, tells
you what is *new* since last time, and attaches an honest, evidence-bound confidence
score to every finding.

```
seed -> subdomains -> resolve -> probe -> crawl -> scan -> triage -> report
```

External recon binaries are **optional** and never auto-installed. See
`requirements.txt` for the exact `go install` lines, or run:

```bash
dragoneye tools          # what's installed, what's missing, how to get it
```

A missing tool only skips its stage. The run still completes and the report says
which stages were skipped.

### `dragoneye` on your PATH

With the venv active, the `dragoneye` console script is already available. To use
it without activating anything, link it into `~/.local/bin` (on PATH by default on
most distros):

```bash
ln -sf "$PWD/.venv/bin/dragoneye" ~/.local/bin/dragoneye
dragoneye            # banner + quick command list
```

Or use `pipx install .` for a fully isolated install.

## Quickstart

The fast path needs no program setup:

```bash
dragoneye quick example.com            # scope + scan + triage + report
dragoneye quick example.com --dry-run  # print the exact commands, send nothing
dragoneye doctor                       # is this machine ready?
## Installation

### Quick installation

```bash
git clone https://github.com/SanchitKumaRR/DragonEye.git DragonEye
cd DragonEye
python3 -m venv .venv
.\.venv\Scriptsctivate.bat  # Windows
# . .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
pip install -e .
```

### Manual installation

```bash
# Using pip
pip install -e git+https://github.com/SanchitKumaRR/DragonEye.git@main#egg=dragoneye

# Using pipx (recommended for isolation)
pipx install .
```

### Post-installation

```bash
dragoneye quick example.com           # one-shot recon
dragoneye doctor                      # check your environment
dragoneye shell                       # start the interactive console
```

```

`quick` derives a program named after the target (so `api.example.com` and
`www.example.com` share `example.com`), adds the target to the program's scope,
runs the pipeline, and prints the report path plus the next useful commands.

### Interactive console

Run `dragoneye` with no arguments for the console — the recommended way to use
DragonEye day to day. It gives you tab completion, persistent history at
`~/.local/share/dragoneye/history`, and the same operations without retyping
flags:

```text
dragoneye> quick example.com
dragoneye[example.com]> run --dry
dragoneye[example.com]> show
dragoneye[example.com]> diff
dragoneye[example.com]> assets
dragoneye[example.com]> findings
dragoneye[example.com]> doctor
dragoneye[example.com]> report --open
dragoneye[example.com]> exit
```

`dragoneye shell` opens it explicitly and `dragoneye awaken` opens it with the
red theme. The console never executes arbitrary AI-generated shell commands;
each command maps to a known DragonEye operation.

### Managed programs

```bash
dragoneye init
dragoneye program add acme --in-text 'acme.com' --out-text 'blog.acme.com' --platform hackerone
dragoneye scope acme www.acme.com blog.acme.com 169.254.169.254   # dry check, no traffic
dragoneye run acme --passive --dry-run                            # print commands only
dragoneye run acme --passive
dragoneye show last
dragoneye report last --open
```

Inventory across every run (not just the latest):

```bash
dragoneye assets                     # cumulative in-scope asset table
dragoneye assets acme --kind url --search admin
dragoneye findings --severity high
dragoneye findings --json
```

Scope from a file (HackerOne/Bugcrowd paste works):

```bash
dragoneye program add acme --in-file scope.txt --out-file out.txt
pbpaste | dragoneye program add acme --in-file -      # macOS; xclip -o on Linux
```

Web GUI:

```bash
dragoneye serve            # http://127.0.0.1:8765
dragoneye serve --open
```

## Scope syntax

One rule per line, `#` comments allowed. **Out-of-scope always wins**, then in-scope,
then deny-by-default.

| Rule | Matches |
|---|---|
| `example.com` | apex **and** all subdomains |
| `*.example.com` or `.example.com` | subdomains only (not apex) |
| `10.10.0.0/16` | CIDR (IPs, and hostnames that resolve into it) |
| `203.0.113.7` | single IP |
| `re:^api\d+\.` | regex against the hostname |
| `https://app.example.com/x` | reduced to `app.example.com` |

ASN rules (`AS15169`) are rejected with a clear error: no adapter supplies an
ASN yet, and accepting the rule would create a program that can never match.

Guarantees:

* A program with **no in-scope rules refuses to run**.
* Unparseable rules fail **before** any traffic is sent.
* Cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`)
  are blocked even if listed as in-scope.
* Private/loopback/reserved IPs are blocked unless `--allow-private`.
* Every tool receives a **pre-filtered** target list; filtering happens in one
  place (`tools/runner.py`), not per adapter.
* An **out-of-scope finding is dropped before storage** and audited.
* DNS answers are screened too: after the `resolve` stage, an in-scope hostname
  that resolves into an out-of-scope CIDR, a private range or a metadata
  endpoint is dropped, removed from the run and audited before a probe tool can
  reach it. CIDR rules match hostnames through those resolved answers.
* Every **rejected** target is written to the audit log (capped per run; totals
  are always kept), and the effective scope is recorded at run start.

## Models

```bash
dragoneye models                                  # 61 models, 16 providers
dragoneye config key openrouter                   # stored in ~/.config/dragoneye/keys.json, chmod 600
dragoneye config set llm.provider openrouter
dragoneye config set llm.model openai/gpt-4o-mini
dragoneye config set llm.usage balanced
```

Providers are OpenAI-compatible endpoints: OpenAI, Anthropic, Gemini, DeepSeek,
Groq, Mistral, xAI, OpenRouter, Together, Fireworks, Perplexity, Ollama, LM Studio,
vLLM, Azure and `custom`. Any model id the provider accepts can be typed in — the
bundled list is a starting point, not a gate.

`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc. override the local key file, so CI and
ephemeral shells need nothing persisted.

### Usage tiers are budgets, not vibes

| Tier | Findings reviewed | Evidence per finding | Local search rounds |
|---|---|---|---|
| `off` | none | – | – |
| `low` | top 10 | 1 200 chars | 0 |
| `balanced` | top 50 | 4 000 chars | 1 |
| `high` | top 500 | 12 000 chars | 3 |

Findings are ranked by severity plus exploitability keywords before truncation, so
`low` picks the interesting 10 rather than the first 10.

### What the model is allowed to do

* It sees **one finding plus its evidence excerpt** — never the open internet.
* It cannot run commands. It may request `{"action":"search","query":"..."}`, which
  DragonEye executes as a bounded local regex over `runs/<id>/raw/`. Rounds are
  capped by the tier. This is the "grep to filter large data" behaviour, but the
  budget is enforced by the orchestrator, not trusted to the model.
* It must return strict JSON: `verdict`, `confidence`, `reasoning`,
  `counter_evidence`, `next_step`, `needs_more_data`.
* `confirmed` still means "evidence-backed"; anything requiring a human step is
  forced into `likely` / `needs-manual-check`.
* No API key, no model, no problem: the pipeline and report are unchanged.

### Calibration

A model's self-reported confidence is only a hypothesis. DragonEye stores it and
lets you score it:

```bash
dragoneye verdict 42 --validated confirmed
dragoneye verdict 43 --validated false-positive
```

Reports show, per confidence band, how often verdicts actually held up. If "high"
is right 40% of the time, you should know that before you submit.

## Reports

Each run writes to `~/.local/share/dragoneye/runs/<run_id>/`:

```
run.log            live log (the GUI streams this over SSE)
raw/<tool>/out.txt raw tool output + console.log (evidence)
report.html        self-contained, dark, printable
report.md          paste into a report or a notes app
report.json        machine-readable, includes the full run record
```

Reports always include: findings + confidence + reasoning, evidence excerpts, new
assets since the last run, per-tool status/duration/scope-drops, the exact
commands executed, scope rejections, model tokens/cost, calibration table, and
the exact scope rules applied.

## Diffing

```bash
dragoneye diff acme               # new assets/findings vs all history
```

Assets and findings are de-duplicated per program with a stable fingerprint, while
`run_assets` / `finding_runs` keep per-run history — so "14 new subdomains since
yesterday" is a join, not a diff of text files.

## Architecture

```
dragoneye/
  scope.py        rule parsing + decisions (heavily tested; fail closed)
  db.py           SQLite schema, dedupe by fingerprint, per-run history,
                  cumulative asset/finding inventory queries
  pipeline.py     stages, resume, ingestion, scope enforcement points
  tools/          base contract, runner (argv-only, timeouts, evidence),
                  adapters.py (subfinder, dnsx, httpx, katana, nuclei)
  llm/            providers, budgets, client (retry + cost), triage
  report.py       json/markdown/html
  quick.py        one-shot target -> program -> run
  console.py      interactive REPL (readline history + completion)
  doctor.py       environment health checks
  ui.py           shared terminal rendering
  cli.py          typer CLI
  web/            FastAPI + one static HTML file (no npm)
```

Adding a tool is one class in `tools/adapters.py`:

```python
class Mytool(ToolAdapter):
    spec = ToolSpec(name="mytool", binary="mytool", passive=False,
                    install_hint="go install ...", description="...")
    def build(self, targets, workdir): ...
    def parse(self, workdir): ...
```

Scope filtering, timeouts, process-group kill, audit rows and evidence capture are
handled by the runner.

## Safety model

* Loopback bind by default; remote binds are refused unless you explicitly pass
  `--insecure-bind`. A per-process token is required for every mutating request
  (header only), API keys are never returned unmasked, and tools run argv-only
  (no shell, no injection).
* Security headers (CSP, `nosniff`, frame denial) and `no-store` on API
  responses.
* `--dry-run` prints full commands and sends nothing.
* `--passive` keeps only tools that do not touch the target (subfinder).
* Audit log records every executed command, the effective scope, every rejected
  target and every run lifecycle event. Inspect it with
  `dragoneye audit --run last --action scope_reject`.
* Metadata IPs and private ranges are hard-blocked by default. Metadata stays
  blocked even with `--allow-private`.
* Katana is pinned to `fqdn` field scope and Nuclei runs with `-ni`/`-duc` so a
  scan does not crawl sibling hosts or call out to interactsh.

**Limitation:** filtering is applied to the target list handed to a tool, not to
the packets it sends. Redirects, crawled links or CNAMEs can still reach a host
that was never approved. A scope-enforcing proxy is on the roadmap. Run live
scans from a machine or VM you control, and do not expose the GUI.

This is a single-user local tool. Do not expose the GUI to a network.

## Development

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pip install -e .
.venv/bin/python -m pytest -q         # 69 tests
.venv/bin/ruff check .
```

The scope engine has the densest test coverage on purpose — it is the component
where a bug is both most likely and most expensive. CI runs the suite and linter
on Python 3.11–3.13.

## Project docs

- `CHANGELOG.md` — what changed in 1.0.
- `SECURITY.md` — threat model, reporting, and the network-enforcement gap.
- `CONTRIBUTING.md` — dev setup and ground rules.
- `LICENSE` — MIT.

## Disclaimer

Only test assets you are authorised to test, and follow each program's policy
(rate limits, prohibited techniques, disclosure rules). DragonEye enforces the scope
you give it; it cannot verify that the scope is correct or that you have permission.
You are responsible for your traffic.

### Windows Installation

**Prerequisites:**
- [Python](https://www.python.org/downloads/) (3.11+)
- [Git](https://git-scm.com/download/win) (optional, for cloning the repository)

**Using pip (recommended):**
```bash
git clone https://github.com/SanchitKumaRR/DragonEye.git DragonEye
cd DragonEye
python -m venv .venv
.\.venv\Scripts\activate.bat
pip install -r requirements.txt
pip install -e .
```

**Using scoop (package manager):**
```bash
scoop install python
scoop install git
pip install -e .  # after cloning the repo
```

**Using winget:**
```bash
winget install --id=Python.Python.3.11
winget install --id=Git.Git
git clone https://github.com/SanchitKumaRR/DragonEye.git DragonEye
cd DragonEye
.\.venv\Scripts\activate.bat
```
