# DragonEye

Scope-aware recon for bug bounty hunters. **CLI + localhost web GUI**, one SQLite
store, one report per run.

DragonEye's job is not to be another subdomain dumper. It is to be the thing that
**never touches an asset you are not allowed to touch**, remembers everything, tells
you what is *new* since last time, and attaches an honest, evidence-bound confidence
score to every finding.

```
seed -> subdomains -> resolve -> probe -> crawl -> scan -> triage -> report
```

Status: **v0.1 — working core.** 61 models across 16 providers, 5 tool adapters,
42 tests, resumable pipeline, Markdown/JSON/HTML reports. See
[Not built yet](#not-built-yet) for the honest gaps.

---

## Install

```bash
git clone https://github.com/SanchitKumaRR/DragonEye.git DragonEye && cd DragonEye
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e .
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

```bash
dragoneye init
dragoneye program add acme --in-text 'acme.com' --out-text 'blog.acme.com' --platform hackerone
dragoneye scope acme www.acme.com blog.acme.com 169.254.169.254   # dry check, no traffic
dragoneye run acme --passive --dry-run                            # print commands only
dragoneye run acme --passive
dragoneye show last
dragoneye report last --open
```

Running `dragoneye` with no arguments prints the red wordmark and the short command
list; `dragoneye --help` shows every option.

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
| `AS15169` | ASN (when the asset carries one) |
| `https://app.example.com/x` | reduced to `app.example.com` |

Guarantees:

* A program with **no in-scope rules refuses to run**.
* Unparseable rules fail **before** any traffic is sent.
* Cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`)
  are blocked even if listed as in-scope.
* Private/loopback/reserved IPs are blocked unless `--allow-private`.
* Every tool receives a **pre-filtered** target list; filtering happens in one
  place (`tools/runner.py`), not per adapter.
* DNS answers are screened too: an in-scope hostname that resolves into an
  out-of-scope CIDR, a private range or a metadata endpoint is dropped (and
  recorded) before any tool can reach it.
* Every decision is written to the audit log.

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
assets since the last run, per-tool status/duration/scope-drops, model tokens/cost,
calibration table, and the exact scope rules applied.

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
  db.py           SQLite schema, dedupe by fingerprint, per-run history
  pipeline.py     stages, resume, ingestion, scope enforcement points
  tools/          base contract, runner (argv-only, timeouts, evidence),
                  adapters.py (subfinder, dnsx, httpx, katana, nuclei)
  llm/            providers, budgets, client (retry + cost), triage
  report.py       json/markdown/html
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

* Loopback bind by default; per-process CSRF token required for every mutating
  request; keys never returned unmasked; args as lists (no shell, no injection).
* `--dry-run` prints full commands and sends nothing.
* `--passive` keeps only tools that do not touch the target (subfinder).
* Audit log records every executed command and every run lifecycle event.
* Metadata IPs and private ranges are hard-blocked by default.

This is a single-user local tool. Do not expose the GUI to a network.

## Not built yet

Ordered roughly by value:

1. **Run-to-run diffing in the GUI** (the data is there; the UI only shows the latest run).
2. **Notifications** (Discord/Telegram/webhook on new findings).
3. **Screenshots** (gowitness) and a port/service adapter (naabu/nmap).
4. **Scope-enforcing proxy hookup** (mitmproxy/Caido) for network-level enforcement.
5. **More adapters** (gau, waybackurls, chaos, assetfinder, ffuf).
6. **Batch triage** — the `batch_size` budget field exists but triage is per-finding.
7. **Calibration dashboard**, program importers (HackerOne API), scheduled runs.
8. **Packaging** — no PyPI wheel, no `pipx` entry point yet.

## Development

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q         # 42 tests
```

The scope engine has the densest test coverage on purpose — it is the component
where a bug is both most likely and most expensive.

## Disclaimer

Only test assets you are authorised to test, and follow each program's policy
(rate limits, prohibited techniques, disclosure rules). DragonEye enforces the scope
you give it; it cannot verify that the scope is correct or that you have permission.
You are responsible for your traffic.
