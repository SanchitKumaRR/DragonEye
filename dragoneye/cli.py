"""DragonEye CLI."""

from __future__ import annotations

import json
import sys
import webbrowser
from pathlib import Path

import typer
from rich.panel import Panel
from rich.table import Table

from . import __version__, db
from .config import (
    USAGE_LEVELS,
    config_path,
    data_dir,
    db_path,
    ensure_dirs,
    load_config,
    masked_keys,
    runs_dir,
    save_config,
    set_api_key,
)
from .doctor import overall as doctor_overall
from .doctor import run_checks
from .doctor import summary as doctor_summary
from .llm.providers import all_models, get_provider
from .pipeline import pipeline_summary, start_run
from .quick import program_name_for, quick_run
from .scope import Scope, ScopeError
from .tools import status as tool_status
from .ui import banner as _banner
from .ui import console, severity_counts, severity_markup

app = typer.Typer(
    add_completion=True,
    no_args_is_help=True,
    help="Scope-aware recon framework for bug bounty hunters.",
)
program_app = typer.Typer(no_args_is_help=True, help="Manage programs (scope + policy).")
config_app = typer.Typer(no_args_is_help=True, help="Settings and API keys.")
app.add_typer(program_app, name="program")
app.add_typer(config_app, name="config")


def _con():
    return db.connect()


def _read_scope(file_value: str | None, text_value: str | None) -> list[str]:
    lines: list[str] = []
    if file_value:
        if file_value == "-":
            lines.extend(sys.stdin.read().splitlines())
        else:
            try:
                lines.extend(Path(file_value).expanduser().read_text().splitlines())
            except OSError as exc:
                raise typer.BadParameter(f"cannot read {file_value}: {exc}") from exc
    if text_value:
        lines.extend(text_value.splitlines())
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def _program_or_exit(ref: str) -> dict:
    con = _con()
    program = db.get_program(con, ref)
    con.close()
    if not program:
        console.print(f"[red]program {ref!r} not found[/red] (try: dragoneye program list)")
        raise typer.Exit(2)
    return program


def _run_or_exit(ref: str) -> dict:
    con = _con()
    run = db.resolve_run(con, ref)
    con.close()
    if not run:
        console.print(f"[red]run {ref!r} not found[/red] (try: dragoneye runs)")
        raise typer.Exit(2)
    return run


def _print_result(result: dict, *, limit: int = 15) -> None:
    """Shared end-of-run summary for `run`, `resume` and `quick`."""
    report = result.get("report") or {}
    stats = result.get("stats") or {}
    data = result.get("summary") or {}
    findings = data.get("findings") or []
    status = result.get("status", "?")
    status_style = "green" if status == "done" else "red"

    console.print()
    console.print(Panel.fit(
        f"run      : [bold]{result.get('id')}[/bold]  [{status_style}]{status}[/{status_style}]\n"
        f"assets   : {stats.get('assets_total', 0)}\n"
        f"findings : {stats.get('findings_total', 0)}"
        + (f"  ({severity_counts(findings)})" if findings else "") + "\n"
        f"scope    : {stats.get('skipped_scope', 0)} target(s) rejected\n"
        f"report   : {report.get('html', '-')}\n"
        f"markdown : {report.get('md', '-')}",
        title="done",
    ))
    if findings:
        table = Table(box=None, pad_edge=False)
        for column in ("id", "severity", "title", "asset", "conf", "verdict"):
            table.add_column(column, no_wrap=(column not in ("title", "asset")))
        for finding in findings[:limit]:
            table.add_row(
                str(finding.get("id")),
                severity_markup(finding.get("severity")),
                (finding.get("title") or "")[:52],
                (finding.get("asset_value") or "")[:36],
                f"{finding['confidence']}%" if finding.get("confidence") is not None else "-",
                finding.get("verdict") or "-",
            )
        console.print(table)
        if len(findings) > limit:
            console.print(f"[dim]... {len(findings) - limit} more - dragoneye show last[/dim]")
    for tool in data.get("tools") or []:
        if tool.get("status") == "missing":
            console.print(f"[yellow]! {tool['tool']} missing[/yellow] - {tool.get('message')}")
    console.print(
        "\n[dim]next:[/dim] [bold]dragoneye show last[/bold] · "
        "[bold]dragoneye diff " + str(stats.get("program", "")) + "[/bold] · "
        "[bold]dragoneye report last --open[/bold]"
    )


# --- top level ------------------------------------------------------------


@app.command()
def init() -> None:
    """Create config/data directories and a default config."""
    _banner()
    ensure_dirs()
    cfg = load_config()
    save_config(cfg)
    console.print(Panel.fit(
        f"[bold green]DragonEye {__version__} initialised[/bold red]\n\n"
        f"config : {config_path()}\n"
        f"data   : {data_dir()}\n"
        f"db     : {db_path()}\n\n"
        "Next:\n"
        "  1. dragoneye doctor                 # what works on this machine\n"
        "  2. dragoneye quick example.com      # one-shot recon\n"
        "  3. dragoneye                        # interactive console\n"
        "  4. dragoneye --help                 # every command",
        title="init",
    ))


@app.command()
def shell() -> None:
    """Open the interactive console (the recommended way to use DragonEye)."""
    _banner()
    from .console import run_console

    run_console()


@app.command()
def quick(
    target: str = typer.Argument(..., help="Domain, URL, IP or host to recon."),
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Print commands, send no traffic."),
    passive: bool = typer.Option(False, "--passive", help="Passive tools only."),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip model triage."),
    usage: str | None = typer.Option(None, "--usage", help="off|low|balanced|high"),
    provider: str | None = typer.Option(None, "--provider"),
    model: str | None = typer.Option(None, "--model"),
    allow_private: bool = typer.Option(False, "--allow-private", help="Permit private/loopback targets."),
    open_report: bool = typer.Option(False, "--open", help="Open the HTML report when done."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the live-scan confirmation."),
) -> None:
    """One-shot recon: derive a program from a target, run, report.

    The fast path. `dragoneye quick example.com` creates (or extends) a program
    named after the target and runs the full pipeline.

    \b
    dragoneye quick example.com              full run, confirm once
    dragoneye quick example.com --dry-run    print the exact commands
    dragoneye quick app.example.com --passive  passive only
    """
    if usage and usage not in USAGE_LEVELS:
        raise typer.BadParameter(f"usage must be one of {', '.join(USAGE_LEVELS)}")

    cfg = load_config()
    if allow_private:
        cfg.allow_private = True
    if no_llm:
        usage = "off"

    try:
        from .quick import derive_host

        host = derive_host(target)
    except ScopeError as exc:
        console.print(f"[red]invalid target: {exc}[/red]")
        raise typer.Exit(2) from exc

    name = program_name_for(host)
    _banner()
    console.print(Panel.fit(
        f"target   : [bold]{host}[/bold]\n"
        f"program  : {name}\n"
        f"mode     : {'DRY RUN' if dry_run else ('passive-only' if passive else 'passive + active')}\n"
        f"model    : {usage or cfg.llm.usage}",
        title="quick",
    ))
    if not dry_run and not yes:
        if not sys.stdin.isatty():
            console.print(
                "[red]refusing a live scan without a terminal[/red] - "
                "pass [bold]--yes[/bold] or [bold]--dry-run[/bold]."
            )
            raise typer.Exit(2)
        if not typer.confirm(f"Run live recon against {host}?", default=True):
            console.print("[yellow]cancelled[/yellow]")
            raise typer.Exit(0)

    con = _con()
    try:
        result = quick_run(
            con,
            target,
            cfg,
            dry_run=dry_run,
            passive=passive,
            usage=usage,
            provider=provider,
            model=model,
            echo=lambda message: console.print(message, highlight=False),
        )
        result["summary"] = pipeline_summary(con, result["id"])
    except ScopeError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    finally:
        con.close()

    _print_result(result)
    if open_report and (result.get("report") or {}).get("html"):
        webbrowser.open(Path(result["report"]["html"]).as_uri())


@app.command()
def doctor(
    json_out: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Diagnose the environment and tell you exactly what to fix."""
    checks = run_checks()
    if json_out:
        console.print_json(json.dumps(
            [check.__dict__ for check in checks],
            indent=2,
        ))
        raise typer.Exit(0 if doctor_overall(checks) != "fail" else 1)

    table = Table(box=None, pad_edge=False)
    table.add_column("check", style="bold")
    table.add_column("status")
    table.add_column("detail", overflow="fold")
    table.add_column("hint", overflow="fold", style="dim")
    styles = {"ok": "[green]ok[/green]", "warn": "[yellow]warn[/yellow]", "fail": "[red]fail[/red]"}
    for check in checks:
        table.add_row(check.name, styles.get(check.status, check.status), check.detail, check.hint)
    console.print(table)
    line = doctor_summary(checks)
    state = doctor_overall(checks)
    if state == "fail":
        console.print(f"\n[red]{line}[/red]")
        raise typer.Exit(1)
    console.print(f"\n[{'yellow' if state == 'warn' else 'green'}]{line}[/]")


@app.command()
def tools(versions: bool = typer.Option(False, "--versions", help="Show detected versions.")) -> None:
    """Show which external tools are installed (and how to get the rest)."""
    rows = tool_status(with_version=versions)
    table = Table(box=None, pad_edge=False)
    table.add_column("tool", style="bold")
    table.add_column("kind")
    table.add_column("status")
    table.add_column("notes", overflow="fold")
    for row in rows:
        installed = "[green]installed[/green]" if row["installed"] else "[red]missing[/red]"
        kind = "passive" if row["passive"] else "active"
        note = row["version"] if (versions and row["version"]) else row["description"]
        if not row["installed"]:
            note = row["install_hint"]
        table.add_row(row["name"], kind, installed, note)
    console.print(table)
    missing = [r for r in rows if not r["installed"]]
    if missing:
        console.print(
            f"\n[yellow]{len(missing)} tool(s) missing.[/yellow] "
            "Stages that need them are skipped, everything else still runs."
        )


@app.command("models")
def models_cmd(
    provider: str | None = typer.Option(None, "--provider", "-p"),
    search: str | None = typer.Option(None, "--search", "-s", help="Filter by substring."),
) -> None:
    """List providers and models (50+ across 16 providers)."""
    entries = all_models()
    if provider:
        entries = [e for e in entries if e["provider"] == provider.lower()]
    if search:
        needle = search.lower()
        entries = [e for e in entries if needle in e["model"].lower() or needle in e["provider"]]
    table = Table(box=None, pad_edge=False)
    table.add_column("provider")
    table.add_column("model", style="bold")
    for entry in entries:
        table.add_row(entry["provider"], entry["model"])
    console.print(table)
    console.print(f"\n[dim]{len(entries)} model(s). Any model id your provider accepts also works.[/dim]")


@app.command()
def run(
    program: str = typer.Argument(..., help="Program name."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, send no traffic."),
    passive: bool = typer.Option(False, "--passive", help="Passive tools only."),
    active: bool = typer.Option(False, "--active", help="Force active tools even if config is passive-only."),
    usage: str | None = typer.Option(None, "--usage", help="off|low|balanced|high"),
    provider: str | None = typer.Option(None, "--provider"),
    model: str | None = typer.Option(None, "--model"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Force LLM off for this run."),
    allow_private: bool = typer.Option(False, "--allow-private", help="Permit private/loopback targets."),
) -> None:
    """Run recon against a saved program."""
    if usage and usage not in USAGE_LEVELS:
        raise typer.BadParameter(f"usage must be one of {', '.join(USAGE_LEVELS)}")
    program_row = _program_or_exit(program)
    cfg = load_config()
    if allow_private:
        cfg.allow_private = True
    if no_llm:
        usage = "off"
    if passive and active:
        raise typer.BadParameter("--passive and --active are mutually exclusive")
    passive_flag = True if passive else (False if active else None)

    try:
        Scope(program_row["in_scope"], program_row["out_of_scope"], allow_private=cfg.allow_private)
    except ScopeError as exc:
        console.print(f"[red]invalid scope for {program}: {exc}[/red]")
        raise typer.Exit(2) from exc

    con = _con()
    try:
        result = start_run(
            con,
            program_row,
            cfg,
            dry_run=dry_run,
            passive_only=passive_flag,
            llm_usage=usage,
            provider=provider,
            model=model,
            echo=lambda message: console.print(message, highlight=False),
        )
        result["summary"] = pipeline_summary(con, result["id"])
    finally:
        con.close()

    _print_result(result)


@app.command()
def resume(run_id: str = typer.Argument(...)) -> None:
    """Resume an interrupted run (completed stages are skipped)."""
    existing = _run_or_exit(run_id)
    con = _con()
    program = db.get_program(con, int(existing["program_id"]))
    cfg = load_config()
    try:
        result = start_run(
            con,
            program,
            cfg,
            resume_run_id=existing["id"],
            echo=lambda message: console.print(message, highlight=False),
        )
        result["summary"] = pipeline_summary(con, result["id"])
    finally:
        con.close()
    _print_result(result)


@app.command("runs")
def runs_cmd(
    program: str | None = typer.Option(None, "--program", "-p"),
    limit: int = typer.Option(20, "--limit"),
) -> None:
    """List recent runs."""
    con = _con()
    program_id = None
    if program:
        row = db.get_program(con, program)
        if not row:
            con.close()
            console.print(f"[red]unknown program {program!r}[/red]")
            raise typer.Exit(2)
        program_id = int(row["id"])
    rows = db.list_runs(con, program_id, limit)
    con.close()

    table = Table(box=None, pad_edge=False)
    for column in ("run", "program", "status", "mode", "started", "assets", "findings"):
        table.add_column(column)
    for row in rows:
        stats = row.get("stats") or {}
        table.add_row(
            row["id"],
            row.get("program_name", "?"),
            row["status"],
            "dry" if row["dry_run"] else ("passive" if row["passive_only"] else "live"),
            row["started_at"],
            str(stats.get("assets_total", "-")),
            str(stats.get("findings_total", "-")),
        )
    console.print(table)


@app.command()
def show(run_id: str = typer.Argument("last")) -> None:
    """Show a run: stats, findings and model verdicts."""
    row = _run_or_exit(run_id)
    con = _con()
    data = pipeline_summary(con, row["id"])
    con.close()
    stats = row.get("stats") or {}
    console.print(Panel.fit(
        f"run      : [bold]{row['id']}[/bold]\n"
        f"program  : {row.get('program_name')}\n"
        f"status   : {row['status']}\n"
        f"duration : {stats.get('duration_seconds', 0)}s\n"
        f"assets   : {len(data['assets'])} ({len(data['new_assets'])} new)\n"
        f"findings : {len(data['findings'])} ({len(data['new_findings'])} new)\n"
        f"scope    : {stats.get('skipped_scope', 0)} target(s) rejected",
        title="run",
    ))

    if data["findings"]:
        console.print(f"\n{severity_counts(data['findings'])}\n")
        table = Table(box=None, pad_edge=False)
        for column in ("id", "severity", "title", "asset", "conf", "verdict"):
            table.add_column(column, no_wrap=(column not in ("title", "asset")))
        for finding in data["findings"]:
            table.add_row(
                str(finding["id"]),
                severity_markup(finding.get("severity")),
                (finding.get("title") or "")[:48],
                (finding.get("asset_value") or "")[:36],
                f"{finding['confidence']}%" if finding.get("confidence") is not None else "-",
                finding.get("verdict") or "-",
            )
        console.print(table)
    else:
        console.print("[dim]no findings[/dim]")

    for tool in data["tools"]:
        if tool["status"] == "missing":
            console.print(f"[yellow]! {tool['tool']} missing[/yellow] - {tool.get('message')}")
    console.print(
        f"\n[dim]next:[/dim] [bold]dragoneye diff {row.get('program_name')}[/bold] · "
        "[bold]dragoneye report last --open[/bold] · "
        "[bold]dragoneye audit --run last[/bold]"
    )


@app.command()
def assets(
    program: str | None = typer.Argument(None, help="Limit to one program."),
    kind: str | None = typer.Option(None, "--kind", "-k", help="domain|url|ip"),
    search: str | None = typer.Option(None, "--search", "-s", help="Substring filter."),
    limit: int = typer.Option(500, "--limit"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List the cumulative asset inventory across all runs."""
    con = _con()
    program_id = None
    if program:
        row = db.get_program(con, program)
        if not row:
            con.close()
            console.print(f"[red]unknown program {program!r}[/red]")
            raise typer.Exit(2)
        program_id = int(row["id"])
    rows = db.list_assets(con, program_id, kind=kind, search=search, limit=limit)
    con.close()
    if as_json:
        console.print_json(json.dumps(rows, indent=2))
        return
    table = Table(box=None, pad_edge=False)
    for column in ("program", "kind", "asset", "source", "last seen"):
        table.add_column(column, no_wrap=(column != "asset"))
    for row in rows:
        table.add_row(
            row.get("program_name", "?"),
            row["kind"],
            row["value"],
            row.get("source_tool") or "-",
            (row.get("last_seen_run") or "-")[:12],
        )
    console.print(table)
    console.print(f"\n[dim]{len(rows)} asset(s) shown[/dim]")


@app.command()
def findings(
    program: str | None = typer.Argument(None, help="Limit to one program."),
    severity: str | None = typer.Option(None, "--severity", "-s"),
    search: str | None = typer.Option(None, "--search", help="Title/asset/template substring."),
    limit: int = typer.Option(500, "--limit"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List every known finding across all runs."""
    con = _con()
    program_id = None
    if program:
        row = db.get_program(con, program)
        if not row:
            con.close()
            console.print(f"[red]unknown program {program!r}[/red]")
            raise typer.Exit(2)
        program_id = int(row["id"])
    rows = db.list_findings(con, program_id, severity=severity, search=search, limit=limit)
    con.close()
    if as_json:
        console.print_json(json.dumps(rows, indent=2))
        return
    if not rows:
        console.print("[dim]no findings recorded[/dim]")
        return
    table = Table(box=None, pad_edge=False)
    for column in ("id", "program", "severity", "title", "asset", "conf", "verdict"):
        table.add_column(column, no_wrap=(column not in ("title", "asset")))
    for row in rows:
        table.add_row(
            str(row["id"]),
            row.get("program_name", "?"),
            severity_markup(row.get("severity")),
            (row.get("title") or "")[:48],
            (row.get("asset_value") or "")[:36],
            f"{row['confidence']}%" if row.get("confidence") is not None else "-",
            row.get("verdict") or "-",
        )
    console.print(table)
    console.print(f"\n[dim]{len(rows)} finding(s) shown[/dim]")


@app.command()
def report(
    run_id: str = typer.Argument("last"),
    open_browser: bool = typer.Option(False, "--open", help="Open the HTML report."),
    as_json: bool = typer.Option(False, "--json", help="Print the JSON report."),
) -> None:
    """Print or open a run's report."""
    row = _run_or_exit(run_id)
    outdir = Path(row["outdir"])
    if as_json:
        path = outdir / "report.json"
        if not path.exists():
            console.print("[red]no report.json yet[/red]")
            raise typer.Exit(1)
        console.print_json(path.read_text())
        return
    html_path = outdir / "report.html"
    if not html_path.exists():
        console.print("[red]no report yet[/red]")
        raise typer.Exit(1)
    console.print(f"html: {html_path}\nmd  : {outdir / 'report.md'}\njson: {outdir / 'report.json'}")
    if open_browser:
        webbrowser.open(html_path.as_uri())


@app.command()
def diff(
    program: str = typer.Argument(...),
    run_id: str | None = typer.Option(None, "--run", help="Compare a specific run (default: last)."),
) -> None:
    """What is new for a program compared to all previous runs."""
    program_row = _program_or_exit(program)
    con = _con()
    if run_id:
        row = db.resolve_run(con, run_id)
    else:
        rows = db.list_runs(con, int(program_row["id"]), 1)
        row = rows[0] if rows else None
    if not row:
        con.close()
        console.print("[yellow]no runs yet[/yellow]")
        raise typer.Exit(1)
    assets = db.diff_assets(con, int(program_row["id"]), row["id"])
    findings = [f for f in db.run_findings(con, row["id"]) if f.get("is_new")]
    con.close()

    console.print(Panel.fit(
        f"run {row['id']} vs history\n"
        f"[green]{len(assets)}[/green] new asset(s), "
        f"[yellow]{len(findings)}[/yellow] new finding(s)",
        title=f"diff {program}",
    ))
    for asset in assets:
        console.print(f"  + {asset['kind']:<8} {asset['value']}")
    for finding in findings:
        console.print(
            f"  * [{(finding.get('severity') or 'info')}] {finding.get('title')} "
            f"@ {finding.get('asset_value')}"
        )


@app.command()
def verdict(
    finding_id: int = typer.Argument(...),
    validated: str = typer.Option(..., "--validated", help="confirmed|false-positive|clear"),
) -> None:
    """Record whether a model verdict was actually correct (calibration data)."""
    value = None if validated == "clear" else validated
    if value not in (None, "confirmed", "false-positive"):
        raise typer.BadParameter("validated must be confirmed, false-positive or clear")
    con = _con()
    finding = db.get_finding(con, finding_id)
    if not finding:
        con.close()
        console.print(f"[red]finding {finding_id} not found[/red]")
        raise typer.Exit(2)
    updated = db.set_verdict_validation(con, finding_id, value)
    con.close()
    console.print(f"[green]finding {finding_id}: validated={value} ({updated} verdict row(s))[/green]")


@app.command()
def audit(
    limit: int = typer.Option(50, "--limit"),
    run_id: str | None = typer.Option(None, "--run", "-r", help="Only this run."),
    action: str | None = typer.Option(None, "--action", "-a", help="e.g. scope_reject"),
) -> None:
    """Show the execution audit log."""
    con = _con()
    if run_id:
        row = db.resolve_run(con, run_id)
        rows = db.run_audit(con, row["id"], action, limit) if row else []
    else:
        rows = db.audit_log(con, limit * 4 if action else limit)
        if action:
            rows = [row for row in rows if row["action"] == action][:limit]
    con.close()
    table = Table(box=None, pad_edge=False)
    table.add_column("timestamp")
    table.add_column("run")
    table.add_column("action")
    table.add_column("detail", overflow="fold")
    for row in rows:
        table.add_row(row["ts"], row["run_id"] or "-", row["action"], (row["detail"] or "")[:120])
    console.print(table)


@app.command()
def awaken() -> None:
    """Wake the dragon: red theme plus the interactive console."""
    cfg = load_config()
    if cfg.theme != "awakened":
        cfg.theme = "awakened"
        save_config(cfg)
    _banner("bold red")
    console.print(
        Panel.fit(
            "[bold red]DragonEye awakened.[/bold red]\n\n"
            "Type [bold]help[/bold] for commands, [bold]exit[/bold] to leave.",
            title="awakened",
        )
    )
    from .console import run_console

    run_console(theme="awakened")


@app.command()
def slumber() -> None:
    """Return to the normal theme."""
    cfg = load_config()
    if cfg.theme == "normal":
        console.print("[yellow]DragonEye is already in the normal state.[/yellow]")
        return
    cfg.theme = "normal"
    save_config(cfg)
    _banner()
    console.print("[bold green]DragonEye returned to normal.[/bold green]")


@app.command()
def serve(
    host: str | None = typer.Option(None, "--host"),
    port: int | None = typer.Option(None, "--port"),
    open_browser: bool = typer.Option(False, "--open", help="Open the UI in a browser."),
    insecure_bind: bool = typer.Option(
        False, "--insecure-bind", help="Allow binding beyond loopback (not recommended)."
    ),
) -> None:
    """Start the local web GUI (binds 127.0.0.1)."""
    import uvicorn

    _banner()
    cfg = load_config()
    host = host or cfg.web_host
    port = port or cfg.web_port
    if host not in ("127.0.0.1", "localhost", "::1"):
        if not insecure_bind:
            console.print(
                "[red]refusing to bind beyond loopback.[/red] This UI can start recon runs "
                "and write config.\nUse [bold]--insecure-bind[/bold] only on a trusted network."
            )
            raise typer.Exit(2)
        console.print(
            "[yellow]warning: binding beyond loopback. Anyone who can reach this port "
            "can start scans and change config.[/yellow]"
        )
    url = f"http://{host}:{port}"
    console.print(Panel.fit(
        f"[bold green]DragonEye GUI[/bold red]\n{url}\n\n"
        "ctrl-c to stop",
        title="serve",
    ))
    if open_browser:
        webbrowser.open(url)
    uvicorn.run("dragoneye.web.app:app", host=host, port=port, log_level="warning")


# --- program subcommands --------------------------------------------------


@program_app.command("add")
def program_add(
    name: str = typer.Argument(..., help="Short program name, e.g. 'acme'."),
    in_file: str | None = typer.Option(None, "--in-file", help="File with in-scope rules ('-' = stdin)."),
    in_text: str | None = typer.Option(None, "--in-text", help="In-scope rules, newline separated."),
    out_file: str | None = typer.Option(None, "--out-file", help="File with out-of-scope rules."),
    out_text: str | None = typer.Option(None, "--out-text", help="Out-of-scope rules, newline separated."),
    platform: str | None = typer.Option(None, "--platform", help="hackerone|bugcrowd|intigriti|other"),
    note: str | None = typer.Option(None, "--note", help="Policy snapshot / URL."),
) -> None:
    """Create or update a program's scope."""
    name = name.strip()
    if not name:
        console.print("[red]program name cannot be empty[/red]")
        raise typer.Exit(2)
    in_scope = _read_scope(in_file, in_text)
    out_scope = _read_scope(out_file, out_text)
    if not in_scope:
        console.print("[red]no in-scope rules given[/red] (--in-file or --in-text)")
        raise typer.Exit(2)
    try:
        scope = Scope(in_scope, out_scope)
    except ScopeError as exc:
        console.print(f"[red]invalid scope: {exc}[/red]")
        raise typer.Exit(2) from exc

    con = _con()
    program_id = db.add_program(con, name, in_scope, out_scope, platform, note)
    con.close()
    console.print(f"[green]program {name!r} saved (id {program_id})[/green]")
    console.print(f"  in-scope rules  : {len(scope.allow)}")
    console.print(f"  out-of-scope    : {len(scope.deny)}")
    console.print(f"  seeds           : {', '.join(scope.roots()) or '(none - CIDR/regex only)'}")


@program_app.command("list")
def program_list() -> None:
    """List saved programs."""
    con = _con()
    rows = db.list_programs(con)
    counts = {row["id"]: db.count_assets(con, int(row["id"])) for row in rows}
    con.close()
    table = Table(box=None, pad_edge=False)
    for column in ("id", "name", "platform", "in-scope", "out-of-scope", "assets", "updated"):
        table.add_column(column)
    for row in rows:
        table.add_row(
            str(row["id"]),
            f"[bold]{row['name']}[/bold]",
            row.get("platform") or "-",
            str(len(row.get("in_scope") or [])),
            str(len(row.get("out_of_scope") or [])),
            str(counts.get(row["id"], 0)),
            row["updated_at"],
        )
    console.print(table)


@program_app.command("show")
def program_show(name: str = typer.Argument(...)) -> None:
    """Show one program's scope rules."""
    row = _program_or_exit(name)
    console.print(f"[bold]{row['name']}[/bold] (id {row['id']}, {row.get('platform') or 'no platform'})")
    if row.get("policy_note"):
        console.print(f"[dim]note: {row['policy_note']}[/dim]")
    console.print("\n[green]in scope[/green]")
    for rule in row.get("in_scope") or []:
        console.print(f"  {rule}")
    console.print("\n[red]out of scope[/red]")
    for rule in row.get("out_of_scope") or []:
        console.print(f"  {rule}")
    console.print()


@program_app.command("rm")
def program_rm(name: str = typer.Argument(...), yes: bool = typer.Option(False, "--yes")) -> None:
    """Delete a program and all of its runs/assets."""
    row = _program_or_exit(name)
    if not yes:
        typer.confirm(f"delete {row['name']} and all its data?", abort=True)
    con = _con()
    db.delete_program(con, int(row["id"]))
    con.close()
    console.print(f"[green]deleted {row['name']}[/green]")


@app.command("scope")
def scope_check(
    program: str = typer.Argument(...),
    targets: list[str] = typer.Argument(..., help="Hosts, URLs, IPs or CIDR members."),
) -> None:
    """Dry-check targets against a program's scope rules (no traffic)."""
    row = _program_or_exit(program)
    try:
        scope = Scope(row["in_scope"], row["out_of_scope"], allow_private=load_config().allow_private)
    except ScopeError as exc:
        console.print(f"[red]invalid scope: {exc}[/red]")
        raise typer.Exit(2) from exc

    table = Table(box=None, pad_edge=False)
    table.add_column("target")
    table.add_column("decision")
    table.add_column("reason", overflow="fold")
    rejected = 0
    for target in targets:
        try:
            decision = scope.check(target)
        except ScopeError as exc:
            decision = None
            rejected += 1
            table.add_row(target, "[red]DENY[/red]", f"invalid target: {exc}")
            continue
        if not decision.allowed:
            rejected += 1
        style = "green" if decision.allowed else "red"
        table.add_row(target, f"[{style}]{'ALLOW' if decision.allowed else 'DENY'}[/{style}]", decision.reason)
    console.print(table)
    if rejected:
        raise typer.Exit(3)


# --- config subcommands ---------------------------------------------------


@config_app.command("show")
def config_show() -> None:
    """Show current settings (keys are masked)."""
    cfg = load_config()
    console.print_json(json.dumps({
        "config_file": str(config_path()),
        "db": str(db_path()),
        "runs": str(runs_dir()),
        "settings": cfg.to_dict(),
        "api_keys": masked_keys(),
    }, indent=2))


@config_app.command("set")
def config_set(
    key: str = typer.Argument(..., help="e.g. llm.provider, llm.model, llm.usage, concurrency"),
    value: str = typer.Argument(...),
) -> None:
    """Change a setting."""
    cfg = load_config()
    if key == "llm.usage" and value not in USAGE_LEVELS:
        raise typer.BadParameter(f"usage must be one of {', '.join(USAGE_LEVELS)}")
    if key == "llm.provider" and not get_provider(value):
        raise typer.BadParameter(f"unknown provider {value!r}; try: dragoneye models")
    if "." in key:
        section, field = key.split(".", 1)
        target = getattr(cfg, section, None)
        if target is None or not hasattr(target, field):
            raise typer.BadParameter(f"unknown setting {key!r}")
        current = getattr(target, field)
        setattr(target, field, _coerce(value, current))
    else:
        if not hasattr(cfg, key):
            raise typer.BadParameter(f"unknown setting {key!r}")
        setattr(cfg, key, _coerce(value, getattr(cfg, key)))
    save_config(cfg)
    console.print(f"[green]{key} = {value}[/green]")


@config_app.command("key")
def config_key(
    provider: str = typer.Argument(..., help="Provider id, e.g. openai, openrouter, ollama"),
    value: str | None = typer.Option(None, "--value", help="Pass inline (avoid; use prompt)."),
    delete: bool = typer.Option(False, "--delete"),
) -> None:
    """Store an API key in ~/.config/dragoneye/keys.json (chmod 600)."""
    if not get_provider(provider):
        console.print(f"[red]unknown provider {provider!r}[/red]")
        raise typer.Exit(2)
    if delete:
        set_api_key(provider, "")
        console.print(f"[yellow]removed key for {provider}[/yellow]")
        return
    key = value or typer.prompt(f"{provider} API key", hide_input=True)
    path = set_api_key(provider, key)
    console.print(f"[green]stored {provider} key in {path} (mode 600)[/green]")


def _coerce(value: str, current: object) -> object:
    if isinstance(current, bool):
        return value.lower() in ("1", "true", "yes", "on")
    if isinstance(current, int):
        try:
            return int(value)
        except ValueError as exc:
            raise typer.BadParameter(f"expected an integer, got {value!r}") from exc
    if isinstance(current, float):
        try:
            return float(value)
        except ValueError as exc:
            raise typer.BadParameter(f"expected a number, got {value!r}") from exc
    if current is None:
        # Infer from the literal so optional numeric/boolean settings stay typed.
        lowered = value.strip().lower()
        if lowered in ("true", "false"):
            return lowered == "true"
        if lowered in ("none", "null", ""):
            return None
        try:
            return int(value)
        except ValueError:
            pass
        try:
            return float(value)
        except ValueError:
            pass
    return value


def _quick_help() -> None:
    """Landing page for a bare, non-interactive `dragoneye` invocation."""
    table = Table(box=None, show_header=False, padding=(0, 2), pad_edge=False)
    table.add_column(style="bold red", no_wrap=True)
    table.add_column(style="dim", no_wrap=True)
    for cmd, desc in (
        ("dragoneye quick example.com", "one-shot: scope + scan + report"),
        ("dragoneye", "interactive console (recommended)"),
        ("dragoneye doctor", "check what works on this machine"),
        ("dragoneye program add NAME --in-text 'example.com'", "define a managed scope"),
        ("dragoneye run NAME --active", "scan a saved program"),
        ("dragoneye show last", "latest results"),
        ("dragoneye serve --open", "local web GUI on 127.0.0.1"),
        ("dragoneye --help", "all commands and options"),
    ):
        table.add_row(cmd, desc)
    console.print(table)


def main() -> None:
    argv = sys.argv[1:]
    if not argv:
        if sys.stdin.isatty():
            from .console import run_console

            run_console()
            raise SystemExit(0)
        _banner()
        _quick_help()
        raise SystemExit(0)
    if argv[0] in ("-h", "--help"):
        _banner()
    elif argv[0] in ("-V", "--version"):
        console.print(f"DragonEye {__version__}")
        raise SystemExit(0)
    app()


if __name__ == "__main__":
    main()
