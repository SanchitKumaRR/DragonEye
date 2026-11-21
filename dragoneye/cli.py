"""DragonEye CLI."""

from __future__ import annotations

import json
import sys
import webbrowser
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
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
from .llm.providers import PROVIDERS, all_models, get_provider
from .pipeline import load_context, pipeline_summary, start_run
from .scope import Scope, ScopeError
from .tools import status as tool_status

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Scope-aware recon framework for bug bounty hunters.",
)
program_app = typer.Typer(no_args_is_help=True, help="Manage programs (scope + policy).")
config_app = typer.Typer(no_args_is_help=True, help="Settings and API keys.")
app.add_typer(program_app, name="program")
app.add_typer(config_app, name="config")

console = Console()
SEV_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "info": "cyan",
}


def _con():
    return db.connect()


def _read_scope(file_value: Optional[str], text_value: Optional[str]) -> list[str]:
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


# --- top level ------------------------------------------------------------


@app.command()
def init() -> None:
    """Create config/data directories and a default config."""
    ensure_dirs()
    cfg = load_config()
    save_config(cfg)
    console.print(Panel.fit(
        f"[bold green]DragonEye {__version__} initialised[/bold green]\n\n"
        f"config : {config_path()}\n"
        f"data   : {data_dir()}\n"
        f"db     : {db_path()}\n\n"
        "Next:\n"
        "  1. dragoneye program add acme --in-text 'acme.com'\n"
        "  2. dragoneye tools\n"
        "  3. dragoneye run acme --passive",
        title="init",
    ))


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
    provider: Optional[str] = typer.Option(None, "--provider", "-p"),
    search: Optional[str] = typer.Option(None, "--search", "-s", help="Filter by substring."),
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
    usage: Optional[str] = typer.Option(None, "--usage", help="off|low|balanced|high"),
    provider: Optional[str] = typer.Option(None, "--provider"),
    model: Optional[str] = typer.Option(None, "--model"),
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
            passive_only=passive or None,
            llm_usage=usage,
            provider=provider,
            model=model,
            echo=lambda message: console.print(message, highlight=False),
        )
    finally:
        con.close()

    report = result.get("report") or {}
    stats = result.get("stats") or {}
    console.print()
    console.print(Panel.fit(
        f"run      : [bold]{result.get('id')}[/bold]\n"
        f"status   : {result.get('status')}\n"
        f"assets   : {stats.get('assets_total', 0)}\n"
        f"findings : {stats.get('findings_total', 0)}\n"
        f"scope    : {stats.get('skipped_scope', 0)} target(s) rejected\n"
        f"report   : {report.get('html', '-')}\n"
        f"markdown : {report.get('md', '-')}",
        title="done",
    ))
    if report.get("html"):
        console.print(f"[dim]open with: xdg-open {report['html']}[/dim]")


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
    finally:
        con.close()
    console.print(f"[green]run {result.get('id')} {result.get('status')}[/green]")


@app.command("runs")
def runs_cmd(
    program: Optional[str] = typer.Option(None, "--program", "-p"),
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
        f"findings : {len(data['findings'])} ({len(data['new_findings']) if 'new_findings' in data else '-'} new)\n"
        f"scope    : {stats.get('skipped_scope', 0)} target(s) rejected",
        title="run",
    ))

    if data["findings"]:
        table = Table(box=None, pad_edge=False)
        for column in ("id", "severity", "title", "asset", "conf", "verdict"):
            table.add_column(column)
        for finding in data["findings"]:
            severity = (finding.get("severity") or "info").lower()
            table.add_row(
                str(finding["id"]),
                f"[{SEV_STYLE.get(severity, 'white')}]{severity}[/]",
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
            console.print(f"[yellow]! {tool['tool']} missing - {tool.get('message')}[/yellow]")


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
    run_id: Optional[str] = typer.Option(None, "--run", help="Compare a specific run (default: last)."),
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
def audit(limit: int = typer.Option(50, "--limit")) -> None:
    """Show the execution audit log."""
    con = _con()
    rows = db.audit_log(con, limit)
    con.close()
    table = Table(box=None, pad_edge=False)
    table.add_column("timestamp")
    table.add_column("run")
    table.add_column("action")
    table.add_column("detail", overflow="fold")
    for row in rows:
        table.add_row(row["ts"], row["run_id"] or "-", row["action"], (row["detail"] or "")[:80])
    console.print(table)


@app.command()
def serve(
    host: Optional[str] = typer.Option(None, "--host"),
    port: Optional[int] = typer.Option(None, "--port"),
    open_browser: bool = typer.Option(False, "--open", help="Open the UI in a browser."),
) -> None:
    """Start the local web GUI (binds 127.0.0.1)."""
    import uvicorn

    cfg = load_config()
    host = host or cfg.web_host
    port = port or cfg.web_port
    if host not in ("127.0.0.1", "localhost", "::1"):
        console.print(
            "[yellow]warning: binding beyond loopback. This UI can start recon runs "
            "and write config - keep it local.[/yellow]"
        )
    url = f"http://{host}:{port}"
    console.print(Panel.fit(
        f"[bold green]DragonEye GUI[/bold green]\n{url}\n\n"
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
    in_file: Optional[str] = typer.Option(None, "--in-file", help="File with in-scope rules ('-' = stdin)."),
    in_text: Optional[str] = typer.Option(None, "--in-text", help="In-scope rules, newline separated."),
    out_file: Optional[str] = typer.Option(None, "--out-file", help="File with out-of-scope rules."),
    out_text: Optional[str] = typer.Option(None, "--out-text", help="Out-of-scope rules, newline separated."),
    platform: Optional[str] = typer.Option(None, "--platform", help="hackerone|bugcrowd|intigriti|other"),
    note: Optional[str] = typer.Option(None, "--note", help="Policy snapshot / URL."),
) -> None:
    """Create or update a program's scope."""
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
        decision = scope.check(target)
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
    value: Optional[str] = typer.Option(None, "--value", help="Pass inline (avoid; use prompt)."),
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
    return value


def main() -> None:
    app()


if __name__ == "__main__":
    main()
