"""Report generation: JSON (machine), Markdown (paste), HTML (read)."""

from __future__ import annotations

import html
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import db
from .scope import Scope

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]

SEV_COLORS = {
    "critical": "#ff4d6d",
    "high": "#ff8a3d",
    "medium": "#f2c14e",
    "low": "#5ec7a5",
    "info": "#6ea8fe",
    "unknown": "#8b93a7",
}


def build_report(con: sqlite3.Connection, run_id: str, outdir: Path) -> dict[str, str]:
    data = collect(con, run_id)
    outdir.mkdir(parents=True, exist_ok=True)
    json_path = outdir / "report.json"
    md_path = outdir / "report.md"
    html_path = outdir / "report.html"

    json_path.write_text(json.dumps(data, indent=2))
    md_path.write_text(render_markdown(data))
    html_path.write_text(render_html(data))
    return {"json": str(json_path), "md": str(md_path), "html": str(html_path)}


def collect(con: sqlite3.Connection, run_id: str) -> dict[str, Any]:
    run = db.get_run(con, run_id)
    if not run:
        raise ValueError(f"run {run_id} not found")
    program = db.get_program(con, int(run["program_id"])) or {}
    assets = db.run_assets(con, run_id)
    findings = db.run_findings(con, run_id)

    scope_summary: dict[str, Any] = {}
    if program:
        try:
            scope_summary = Scope(
                program.get("in_scope") or [], program.get("out_of_scope") or []
            ).summary()
        except Exception:  # noqa: BLE001
            scope_summary = {"error": "scope could not be loaded"}

    for finding in findings:
        finding["evidence_excerpt"] = _evidence_excerpt(finding)

    counts: dict[str, int] = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        counts[(finding.get("severity") or "unknown").lower()] = (
            counts.get((finding.get("severity") or "unknown").lower(), 0) + 1
        )

    tools = db.tool_runs(con, run_id)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "run": run,
        "program": program,
        "scope": scope_summary,
        "stats": run.get("stats") or {},
        "counts": counts,
        "assets": assets,
        "new_assets": db.diff_assets(con, int(run["program_id"]), run_id) if run else [],
        "findings": findings,
        "new_findings": [f for f in findings if f.get("is_new")],
        "tools": tools,
        "calibration": db.calibration(con, int(run["program_id"])) if run else [],
    }


def _evidence_excerpt(finding: dict[str, Any], limit: int = 1200) -> str:
    path = finding.get("evidence_path")
    if not path:
        return ""
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return ""
    template = finding.get("template_id") or ""
    matched = (finding.get("asset_value") or "")[:200]
    for line in text.splitlines():
        if template and template in line and (not matched or matched in line):
            return line[:limit]
    return text[:limit]


# --- markdown -------------------------------------------------------------


def render_markdown(data: dict[str, Any]) -> str:
    run = data["run"]
    program = data["program"]
    stats = data.get("stats") or {}
    lines: list[str] = []
    add = lines.append

    add(f"# DragonEye report - {program.get('name', 'unknown program')}")
    add("")
    add(f"- **Run**: `{run.get('id')}`")
    add(f"- **Generated**: {data['generated_at']}")
    add(f"- **Mode**: {'DRY RUN' if run.get('dry_run') else 'live'}"
        f" / {'passive-only' if run.get('passive_only') else 'passive+active'}")
    add(f"- **Status**: {run.get('status')}")
    add(f"- **Duration**: {stats.get('duration_seconds', 0)}s")
    add(f"- **Assets (in scope)**: {len(data['assets'])}")
    add(f"- **Findings**: {len(data['findings'])}")
    if stats.get("skipped_scope"):
        add(f"- **Targets rejected by scope engine**: {stats['skipped_scope']}")
    add("")

    missing = [t for t in data["tools"] if t.get("status") == "missing"]
    if missing:
        add("> **Missing tools - stages skipped.** Install these and re-run for full coverage:")
        for tool in missing:
            add(f"> - `{tool['tool']}` - {tool.get('message') or ''}")
        add("")

    add("## Findings")
    add("")
    if not data["findings"]:
        add("_No findings recorded._")
        add("")
    else:
        add("| Severity | Finding | Asset | Confidence | Verdict |")
        add("|---|---|---|---|---|")
        for finding in data["findings"]:
            confidence = (
                f"{finding['confidence']}% ({finding['band']})"
                if finding.get("confidence") is not None
                else "-"
            )
            add(
                f"| {finding.get('severity', '?')} | {_md(finding.get('title') or '')} | "
                f"`{_md(finding.get('asset_value') or '')}` | {confidence} | "
                f"{finding.get('verdict') or '-'} |"
            )
        add("")

        add("### Finding details")
        add("")
        for finding in data["findings"]:
            add(f"#### [{finding.get('severity', '?').upper()}] {finding.get('title') or finding.get('template_id')}")
            add("")
            add(f"- **Asset**: `{finding.get('asset_value') or 'unknown'}`")
            add(f"- **Tool / template**: `{finding.get('tool')}` / `{finding.get('template_id')}`")
            add(f"- **Fingerprint**: `{finding.get('fingerprint')}`")
            if finding.get("confidence") is not None:
                add(
                    f"- **Model verdict**: {finding.get('verdict')} "
                    f"({finding.get('confidence')}% confidence, {finding.get('band')} band)"
                )
                if finding.get("reasoning"):
                    add(f"- **Why**: {finding['reasoning']}")
                if finding.get("counter_evidence"):
                    add(f"- **Counter-evidence**: {finding['counter_evidence']}")
                if finding.get("next_step"):
                    add(f"- **Next step**: {finding['next_step']}")
            add("")
            excerpt = finding.get("evidence_excerpt")
            if excerpt:
                add("```")
                add(excerpt)
                add("```")
                add("")

    add("## Assets")
    add("")
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for asset in data["assets"]:
        by_kind.setdefault(asset["kind"], []).append(asset)
    for kind, items in sorted(by_kind.items()):
        add(f"### {kind} ({len(items)})")
        add("")
        for asset in items:
            flag = " *(new)*" if asset.get("is_new") else ""
            add(f"- `{asset['value']}`{flag}")
        add("")

    add("## Tool execution")
    add("")
    add("| Tool | Status | Duration | Assets | Findings | Scope drops |")
    add("|---|---|---|---|---|---|")
    for tool in data["tools"]:
        add(
            f"| {tool.get('tool')} | {tool.get('status')} | {tool.get('duration', 0)}s | "
            f"{tool.get('assets_found', 0)} | {tool.get('findings_found', 0)} | "
            f"{tool.get('skipped_scope', 0)} |"
        )
    add("")

    llm = stats.get("llm") or {}
    add("## Model usage")
    add("")
    add(f"- Provider / model: `{llm.get('provider')}` / `{llm.get('model')}`")
    add(f"- Mode: `{llm.get('usage')}`")
    add(f"- Calls: {llm.get('calls', 0)}")
    add(f"- Tokens: {llm.get('tokens_in', 0)} in / {llm.get('tokens_out', 0)} out")
    add(f"- Estimated cost: ${llm.get('cost_usd', 0):.4f}")
    if data.get("calibration"):
        add("")
        add("### Confidence calibration (how often each band was actually right)")
        add("")
        add("| Band | Assessed | Confirmed | False positives |")
        add("|---|---|---|---|")
        for row in data["calibration"]:
            add(
                f"| {row.get('band')} | {row.get('total')} | "
                f"{row.get('confirmed') or 0} | {row.get('rejected') or 0} |"
            )
    add("")
    add("## Scope applied")
    add("")
    for rule in data["scope"].get("in_scope", []):
        add(f"- IN: {rule}")
    for rule in data["scope"].get("out_of_scope", []):
        add(f"- OUT: {rule}")
    add("")
    add("_Generated by DragonEye. Verify every finding manually before submitting._")
    return "\n".join(lines)


def _md(text: str) -> str:
    return str(text).replace("|", "\\|")


# --- html -----------------------------------------------------------------

HTML_CSS = """
:root{--bg:#0b0e14;--panel:#121722;--line:#1f2735;--txt:#d7dce6;--dim:#8b93a7;
--acc:#7dd3a7;--crit:#ff4d6d;--high:#ff8a3d;--med:#f2c14e;--low:#5ec7a5;--info:#6ea8fe}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);
font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace}
header{padding:24px 32px;border-bottom:1px solid var(--line);background:var(--panel)}
h1{margin:0;font-size:20px;letter-spacing:.5px}
h1 span{color:var(--acc)}
h2{font-size:15px;margin:32px 0 10px;color:var(--acc);text-transform:uppercase;letter-spacing:1.5px}
h3{font-size:13px;margin:20px 0 6px;color:var(--dim);text-transform:uppercase}
main{padding:8px 32px 64px;max-width:1200px}
.kv{display:flex;flex-wrap:wrap;gap:8px 28px;margin-top:14px;color:var(--dim);font-size:12.5px}
.kv b{color:var(--txt);font-weight:600}
table{width:100%;border-collapse:collapse;margin:8px 0 4px;font-size:12.5px}
th{text-align:left;color:var(--dim);border-bottom:1px solid var(--line);padding:7px 9px;
font-weight:600;text-transform:uppercase;font-size:10.5px;letter-spacing:1px}
td{padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
tr:hover td{background:#0f1420}
.tag{display:inline-block;padding:1px 7px;border-radius:3px;font-size:10.5px;
text-transform:uppercase;letter-spacing:.6px;font-weight:700}
.new{color:var(--acc);font-size:10.5px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:6px;
padding:14px 16px;margin:10px 0}
.card h4{margin:0 0 6px;font-size:13.5px}
.meta{color:var(--dim);font-size:11.5px;margin:0 0 8px}
pre{background:#0a0d13;border:1px solid var(--line);border-radius:4px;padding:10px;
overflow:auto;font-size:11.5px;max-height:260px;color:#a9b6cc}
details summary{cursor:pointer;color:var(--dim);font-size:12px;margin-top:8px}
.warn{border-left:3px solid var(--med);background:#1a1610;padding:10px 14px;
border-radius:0 4px 4px 0;margin:12px 0;font-size:12.5px}
.warn b{color:var(--med)}
footer{color:var(--dim);font-size:11px;padding:24px 32px;border-top:1px solid var(--line)}
.counts{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}
.count{background:var(--panel);border:1px solid var(--line);border-radius:5px;
padding:8px 14px;min-width:86px}
.count b{display:block;font-size:19px}
.count span{color:var(--dim);font-size:10.5px;text-transform:uppercase;letter-spacing:1px}
"""


def render_html(data: dict[str, Any]) -> str:
    run = data["run"]
    program = data["program"]
    stats = data.get("stats") or {}
    esc = html.escape
    parts: list[str] = []
    add = parts.append

    add("<!doctype html><html lang=en><head><meta charset=utf-8>")
    add("<meta name=viewport content='width=device-width,initial-scale=1'>")
    add(f"<title>DragonEye - {esc(str(program.get('name', 'report')))}</title>")
    add(f"<style>{HTML_CSS}</style></head><body>")
    add("<header><h1><span>Dragon</span>Eye report</h1>")
    add("<div class=kv>")
    for label, value in (
        ("program", program.get("name")),
        ("run", run.get("id")),
        ("mode", "dry-run" if run.get("dry_run") else "live"),
        ("coverage", "passive-only" if run.get("passive_only") else "passive+active"),
        ("status", run.get("status")),
        ("duration", f"{stats.get('duration_seconds', 0)}s"),
        ("generated", data["generated_at"]),
    ):
        add(f"<div>{esc(label)} <b>{esc(str(value))}</b></div>")
    add("</div></header><main>")

    # counts
    add("<div class=counts>")
    add(f"<div class=count><b>{len(data['assets'])}</b><span>assets</span></div>")
    add(f"<div class=count><b>{len(data['new_assets'])}</b><span>new assets</span></div>")
    add(f"<div class=count><b>{len(data['findings'])}</b><span>findings</span></div>")
    add(f"<div class=count><b>{stats.get('skipped_scope', 0)}</b><span>scope drops</span></div>")
    add("</div>")

    missing = [t for t in data["tools"] if t.get("status") == "missing"]
    if missing:
        add("<div class=warn><b>Missing tools - stages skipped.</b><br>")
        for tool in missing:
            add(f"&bull; <code>{esc(tool['tool'])}</code> {esc(tool.get('message') or '')}<br>")
        add("</div>")

    # findings
    add("<h2>Findings</h2>")
    if not data["findings"]:
        add("<p class=meta>No findings recorded.</p>")
    else:
        add("<table><tr><th>Severity</th><th>Finding</th><th>Asset</th>"
            "<th>Confidence</th><th>Verdict</th></tr>")
        for finding in data["findings"]:
            sev = (finding.get("severity") or "unknown").lower()
            color = SEV_COLORS.get(sev, SEV_COLORS["unknown"])
            conf = (
                f"{finding['confidence']}% <span class=meta>({esc(str(finding.get('band')))})</span>"
                if finding.get("confidence") is not None
                else "&mdash;"
            )
            verdict = esc(str(finding.get("verdict"))) if finding.get("verdict") else "&mdash;"
            add("<tr>"
                f"<td><span class=tag style='background:{color}22;color:{color}'>{esc(sev)}</span></td>"
                f"<td>{esc(str(finding.get('title') or ''))}"
                f"{' <span class=new>new</span>' if finding.get('is_new') else ''}</td>"
                f"<td><code>{esc(str(finding.get('asset_value') or ''))}</code></td>"
                f"<td>{conf}</td><td>{verdict}</td></tr>")
        add("</table>")

        for finding in data["findings"]:
            sev = (finding.get("severity") or "unknown").lower()
            color = SEV_COLORS.get(sev, SEV_COLORS["unknown"])
            add("<div class=card>")
            add(f"<h4><span class=tag style='background:{color}22;color:{color}'>{esc(sev)}</span> "
                f"{esc(str(finding.get('title') or finding.get('template_id')))}</h4>")
            add(f"<p class=meta>{esc(str(finding.get('asset_value') or ''))} &middot; "
                f"{esc(str(finding.get('tool')))}/{esc(str(finding.get('template_id')))} &middot; "
                f"fp {esc(str(finding.get('fingerprint')))}</p>")
            if finding.get("confidence") is not None:
                add(f"<p class=meta><b>Model:</b> {esc(str(finding.get('verdict')))} "
                    f"({finding.get('confidence')}%) &mdash; {esc(str(finding.get('reasoning') or ''))}</p>")
                if finding.get("next_step"):
                    add(f"<p class=meta><b>Next:</b> {esc(str(finding.get('next_step')))}</p>")
            if finding.get("evidence_excerpt"):
                add(f"<details><summary>evidence</summary><pre>{esc(finding['evidence_excerpt'])}</pre></details>")
            add("</div>")

    # assets
    add("<h2>Assets</h2>")
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for asset in data["assets"]:
        by_kind.setdefault(asset["kind"], []).append(asset)
    if not by_kind:
        add("<p class=meta>No assets collected.</p>")
    for kind, items in sorted(by_kind.items()):
        add(f"<h3>{esc(kind)} &middot; {len(items)}</h3><div class=card><table>")
        for asset in items:
            add(f"<tr><td><code>{esc(str(asset['value']))}</code>"
                f"{' <span class=new>new</span>' if asset.get('is_new') else ''}</td></tr>")
        add("</table></div>")

    # tools
    add("<h2>Tool execution</h2><table><tr><th>Tool</th><th>Status</th><th>Duration</th>"
        "<th>Assets</th><th>Findings</th><th>Scope drops</th></tr>")
    for tool in data["tools"]:
        add(f"<tr><td>{esc(str(tool.get('tool')))}</td><td>{esc(str(tool.get('status')))}</td>"
            f"<td>{tool.get('duration', 0)}s</td><td>{tool.get('assets_found', 0)}</td>"
            f"<td>{tool.get('findings_found', 0)}</td><td>{tool.get('skipped_scope', 0)}</td></tr>")
    add("</table>")

    # llm
    llm = stats.get("llm") or {}
    add("<h2>Model usage</h2><table>")
    add(f"<tr><th>Provider</th><td>{esc(str(llm.get('provider')))}</td></tr>")
    add(f"<tr><th>Model</th><td>{esc(str(llm.get('model')))}</td></tr>")
    add(f"<tr><th>Mode</th><td>{esc(str(llm.get('usage')))}</td></tr>")
    add(f"<tr><th>Calls</th><td>{llm.get('calls', 0)}</td></tr>")
    add(f"<tr><th>Tokens</th><td>{llm.get('tokens_in', 0)} in / {llm.get('tokens_out', 0)} out</td></tr>")
    add(f"<tr><th>Est. cost</th><td>${float(llm.get('cost_usd', 0) or 0):.4f}</td></tr>")
    add("</table>")

    if data.get("calibration"):
        add("<h2>Confidence calibration</h2><table>"
            "<tr><th>Band</th><th>Assessed</th><th>Confirmed</th><th>False positives</th></tr>")
        for row in data["calibration"]:
            add(f"<tr><td>{esc(str(row.get('band')))}</td><td>{row.get('total')}</td>"
                f"<td>{row.get('confirmed') or 0}</td><td>{row.get('rejected') or 0}</td></tr>")
        add("</table>")

    # scope
    add("<h2>Scope applied</h2><div class=card>")
    for rule in data["scope"].get("in_scope", []):
        add(f"<div><span class=tag style='background:#5ec7a522;color:#5ec7a5'>in</span> "
            f"<code>{esc(str(rule))}</code></div>")
    for rule in data["scope"].get("out_of_scope", []):
        add(f"<div><span class=tag style='background:#ff4d6d22;color:#ff4d6d'>out</span> "
            f"<code>{esc(str(rule))}</code></div>")
    add("</div>")

    add("</main><footer>Generated by DragonEye. Verify every finding manually "
        "before submitting. Only test assets you are authorised to test.</footer>")
    add("</body></html>")
    return "\n".join(parts)
