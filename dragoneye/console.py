"""Interactive console - the recommended way to drive DragonEye.

A small, dependency-free REPL with readline history and tab completion. It is
deliberately not an AI shell: every action maps to a known DragonEye operation,
so nothing can be executed just because a language model suggested it.
"""

from __future__ import annotations

import difflib
import getpass
import json
import re
import shlex
import sys
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from . import __version__, db
from .config import (
    USAGE_LEVELS,
    data_dir,
    load_config,
    masked_keys,
    save_config,
    set_api_key,
)
from .doctor import overall as doctor_overall
from .doctor import run_checks
from .doctor import summary as doctor_summary
from .llm.providers import get_provider
from .pipeline import pipeline_summary, start_run
from .quick import quick_run
from .scope import Scope, ScopeError
from .tools import status as tool_status
from .ui import banner, console, severity_counts, severity_markup

COMMANDS: dict[str, str] = {
    "quick <target>": "one-shot recon: auto-program, run, report",
    "programs": "list programs (alias: ls)",
    "use <program>": "select the active program",
    "new [name] [rules...]": "create a program interactively",
    "scope <target...>": "dry-check targets against the active program",
    "run [flags]": "recon the active program (--dry, --passive, --no-llm)",
    "show [run]": "summarise a run and its findings",
    "assets [program]": "cumulative asset inventory",
    "findings [program]": "every known finding across runs",
    "runs": "list recent runs",
    "diff [run]": "what is new since previous runs",
    "report [run]": "show report paths (append --open to launch)",
    "tools": "installed vs missing recon binaries",
    "doctor": "diagnose the environment",
    "config": "show settings; 'config set k v' / 'config key provider'",
    "theme": "toggle normal / awakened (red) theme",
    "slumber": "return to the normal theme",
    "history": "show recent console history",
    "clear": "clear the screen",
    "help": "this list",
    "exit": "leave the console (alias: quit)",
}

ALIASES = {
    "ls": "programs",
    "p": "programs",
    "?": "help",
    "h": "help",
    "quit": "exit",
    "q": "exit",
    "scan": "run",
}

CONFIG_KEYS = (
    "llm.provider",
    "llm.model",
    "llm.usage",
    "llm.base_url",
    "concurrency",
    "request_rate",
    "probe_ports",
    "passive_only",
    "allow_private",
    "nuclei_severities",
    "theme",
)

HISTORY_LIMIT = 1000


@dataclass
class Session:
    con: Any
    cfg: Any
    program: dict[str, Any] | None = None
    last_run_id: str | None = None

    # -- helpers -----------------------------------------------------------

    def out(self, message: str = "", **kwargs: Any) -> None:
        self._console.print(message, **kwargs)

    @property
    def _console(self):
        return console

    def require_program(self) -> dict[str, Any] | None:
        if self.program:
            return self.program
        self.out("[yellow]no program selected[/yellow] - try [bold]use <name>[/bold] or [bold]quick <target>[/bold]")
        return None

    def refresh_program(self) -> None:
        if self.program:
            self.program = db.get_program(self.con, int(self.program["id"]))

    def _run_ref(self, argv: list[str]) -> str:
        return argv[0] if argv and not argv[0].startswith("-") else (self.last_run_id or "last")

    def _resolve_run(self, ref: str) -> dict[str, Any] | None:
        run = db.resolve_run(self.con, ref)
        if run:
            self.last_run_id = run["id"]
        return run

    # -- commands ----------------------------------------------------------

    def do_help(self, argv: list[str]) -> bool:
        table = Table(box=None, pad_edge=False, show_header=True)
        table.add_column("command", style="bold red", no_wrap=True)
        table.add_column("what it does", style="dim")
        for command, description in COMMANDS.items():
            table.add_row(command, description)
        self.out(table)
        self.out(
            "\n[dim]tab completes commands, program names and run ids · "
            "bare `dragoneye` opens this console[/dim]"
        )
        return True

    def do_programs(self, argv: list[str]) -> bool:
        rows = db.list_programs(self.con)
        if not rows:
            self.out("[dim]no programs yet - try[/dim] [bold]quick example.com[/bold]")
            return True
        table = Table(box=None, pad_edge=False)
        for column in ("id", "name", "platform", "in", "out", "assets", "runs", "updated"):
            table.add_column(column, no_wrap=(column != "updated"))
        for row in rows:
            marker = "*" if self.program and row["id"] == self.program["id"] else " "
            table.add_row(
                f"{marker} {row['id']}",
                f"[bold]{row['name']}[/bold]",
                row.get("platform") or "-",
                str(len(row.get("in_scope") or [])),
                str(len(row.get("out_of_scope") or [])),
                str(db.count_assets(self.con, int(row["id"]))),
                str(db.count_runs(self.con, int(row["id"]))),
                (row.get("updated_at") or "")[:19].replace("T", " "),
            )
        self.out(table)
        return True

    def do_use(self, argv: list[str]) -> bool:
        if not argv:
            return self.do_programs(argv)
        row = db.get_program(self.con, argv[0])
        if not row:
            self.out(f"[red]program {argv[0]!r} not found[/red]")
            return True
        self.program = row
        runs = db.list_runs(self.con, int(row["id"]), 1)
        self.last_run_id = runs[0]["id"] if runs else None
        self.out(
            Panel.fit(
                f"[bold]{row['name']}[/bold] ({row.get('platform') or 'no platform'})\n"
                f"in-scope   : {len(row.get('in_scope') or [])} rule(s)\n"
                f"out-scope  : {len(row.get('out_of_scope') or [])} rule(s)\n"
                f"assets     : {db.count_assets(self.con, int(row['id']))}\n"
                f"last run   : {self.last_run_id or '-'}",
                title="active program",
            )
        )
        return True

    def do_new(self, argv: list[str]) -> bool:
        name = argv[0] if argv else Prompt.ask("program name")
        rules = argv[1:]
        if not rules:
            prompt = "in-scope rules (space or comma separated, e.g. acme.com *.acme.com)"
            rules = _split_rules(Prompt.ask(prompt))
        if not rules:
            self.out("[red]at least one in-scope rule is required[/red]")
            return True
        out_raw = Prompt.ask("out-of-scope rules (optional, blank to skip)", default="")
        out_rules = _split_rules(out_raw)
        platform = Prompt.ask("platform (hackerone/bugcrowd/other, blank to skip)", default="") or None
        try:
            Scope(rules, out_rules, allow_private=self.cfg.allow_private)
        except ScopeError as exc:
            self.out(f"[red]invalid scope: {exc}[/red]")
            return True
        program_id = db.add_program(self.con, name.strip(), rules, out_rules, platform, None)
        self.program = db.get_program(self.con, program_id)
        self.last_run_id = None
        self.out(f"[green]saved program {name!r}[/green] - run [bold]run --dry[/bold] to preview commands")
        return True

    def do_scope(self, argv: list[str]) -> bool:
        program = self.require_program()
        if not program:
            return True
        targets = list(argv) or _split_rules(Prompt.ask("targets to check"))
        if not targets:
            return True
        try:
            scope = Scope(
                program.get("in_scope") or [],
                program.get("out_of_scope") or [],
                allow_private=self.cfg.allow_private,
            )
        except ScopeError as exc:
            self.out(f"[red]invalid scope: {exc}[/red]")
            return True
        table = Table(box=None, pad_edge=False)
        table.add_column("target")
        table.add_column("decision")
        table.add_column("reason", overflow="fold")
        for target in targets:
            try:
                decision = scope.check(target)
            except ScopeError as exc:
                table.add_row(target, "[red]DENY[/red]", f"invalid: {exc}")
                continue
            mark = "[green]ALLOW[/green]" if decision.allowed else "[red]DENY[/red]"
            table.add_row(target, mark, decision.reason)
        self.out(table)
        return True

    def do_run(self, argv: list[str]) -> bool:
        program = self.require_program()
        if not program:
            return True
        flags = _run_flags(argv)
        if flags["private"]:
            self.cfg.allow_private = True

        def echo(message: str) -> None:
            console.print(message, highlight=False)

        result = _execute(
            self.con, program, self.cfg,
            dry_run=flags["dry_run"],
            passive_only=flags["passive"] or None,
            usage=flags["usage"],
            echo=echo,
        )
        if result.get("error"):
            self.out(f"[red]run failed: {result['error']}[/red]")
            return True
        self._show_run(result, pipeline_summary(self.con, result["id"]))
        return True

    def do_quick(self, argv: list[str]) -> bool:
        positional = [value for value in argv if not value.startswith("-")]
        if not positional:
            self.out("[red]usage:[/red] quick <target> [--dry] [--passive] [--no-llm]")
            return True
        target = positional[0]
        dry = "--dry" in argv or "--dry-run" in argv
        passive = "--passive" in argv
        usage = "off" if "--no-llm" in argv else None
        if not dry and not Confirm.ask(f"Run live recon against [bold]{target}[/bold]?", default=True):
            self.out("[yellow]cancelled[/yellow]")
            return True

        def echo(message: str) -> None:
            console.print(message, highlight=False)

        try:
            result = quick_run(
                self.con, target, self.cfg,
                dry_run=dry, passive=passive, usage=usage, echo=echo,
            )
        except ScopeError as exc:
            self.out(f"[red]{exc}[/red]")
            return True
        self.program = result.get("program")
        self.last_run_id = result.get("id")
        self.out(
            f"[green]{'created' if result.get('created_program') else 'updated'} program "
            f"{self.program['name']!r}[/green]"
        )
        self._show_run(result, pipeline_summary(self.con, result["id"]))
        return True

    def do_show(self, argv: list[str]) -> bool:
        run = self._resolve_run(self._run_ref(argv))
        if not run:
            self.out("[yellow]no matching run[/yellow]")
            return True
        self._show_run(run, pipeline_summary(self.con, run["id"]))
        return True

    def do_assets(self, argv: list[str]) -> bool:
        program_id = int(self.program["id"]) if self.program else None
        if argv and not argv[0].startswith("-"):
            program = db.get_program(self.con, argv[0])
            if not program:
                self.out(f"[red]program {argv[0]!r} not found[/red]")
                return True
            program_id = int(program["id"])
        rows = db.list_assets(self.con, program_id, limit=500)
        if not rows:
            self.out("[dim]no assets recorded[/dim]")
            return True
        table = Table(box=None, pad_edge=False)
        for column in ("program", "kind", "asset", "source", "last run"):
            table.add_column(column, no_wrap=(column != "asset"))
        for row in rows:
            table.add_row(
                row.get("program_name", "?"),
                row["kind"],
                row["value"],
                row.get("source_tool") or "-",
                (row.get("last_seen_run") or "-")[:12],
            )
        self.out(table)
        self.out(f"[dim]{len(rows)} asset(s)[/dim]")
        return True

    def do_findings(self, argv: list[str]) -> bool:
        program_id = int(self.program["id"]) if self.program else None
        if argv and not argv[0].startswith("-"):
            program = db.get_program(self.con, argv[0])
            if not program:
                self.out(f"[red]program {argv[0]!r} not found[/red]")
                return True
            program_id = int(program["id"])
        rows = db.list_findings(self.con, program_id, limit=500)
        if not rows:
            self.out("[dim]no findings recorded[/dim]")
            return True
        table = Table(box=None, pad_edge=False)
        for column in ("id", "program", "severity", "title", "asset", "conf", "verdict"):
            table.add_column(column, no_wrap=(column not in ("title", "asset")))
        for row in rows:
            table.add_row(
                str(row["id"]),
                row.get("program_name", "?"),
                severity_markup(row.get("severity")),
                (row.get("title") or "")[:44],
                (row.get("asset_value") or "")[:32],
                f"{row['confidence']}%" if row.get("confidence") is not None else "-",
                row.get("verdict") or "-",
            )
        self.out(table)
        self.out(f"[dim]{len(rows)} finding(s)[/dim]")
        return True

    def do_runs(self, argv: list[str]) -> bool:
        program_id = int(self.program["id"]) if self.program else None
        rows = db.list_runs(self.con, program_id, 20)
        if not rows:
            self.out("[dim]no runs yet[/dim]")
            return True
        table = Table(box=None, pad_edge=False)
        for column in ("run", "program", "status", "mode", "started", "assets", "findings"):
            table.add_column(column, no_wrap=True)
        for row in rows:
            stats = row.get("stats") or {}
            mode = "dry" if row["dry_run"] else ("passive" if row["passive_only"] else "live")
            table.add_row(
                row["id"],
                row.get("program_name", "?"),
                row["status"],
                mode,
                (row.get("started_at") or "")[:19].replace("T", " "),
                str(stats.get("assets_total", "-")),
                str(stats.get("findings_total", "-")),
            )
        self.out(table)
        return True

    def do_diff(self, argv: list[str]) -> bool:
        program = self.require_program()
        if not program:
            return True
        run = self._resolve_run(self._run_ref(argv))
        if not run:
            self.out("[dim]no runs yet[/dim]")
            return True
        assets = db.diff_assets(self.con, int(program["id"]), run["id"])
        findings = [f for f in db.run_findings(self.con, run["id"]) if f.get("is_new")]
        self.out(
            Panel.fit(
                f"run [bold]{run['id']}[/bold] vs program history\n"
                f"[green]{len(assets)}[/green] new asset(s) · "
                f"[yellow]{len(findings)}[/yellow] new finding(s)",
                title=f"diff {program['name']}",
            )
        )
        for asset in assets[:40]:
            self.out(f"  [green]+[/green] {asset['kind']:<8} {asset['value']}")
        if len(assets) > 40:
            self.out(f"  [dim]... {len(assets) - 40} more[/dim]")
        for finding in findings:
            self.out(
                f"  {severity_markup(finding.get('severity'))} {finding.get('title')} "
                f"[dim]@ {finding.get('asset_value')}[/dim]"
            )
        return True

    def do_report(self, argv: list[str]) -> bool:
        run = self._resolve_run(self._run_ref(argv))
        if not run:
            self.out("[yellow]no matching run[/yellow]")
            return True
        outdir = Path(run["outdir"])
        paths = {
            "html": outdir / "report.html",
            "md": outdir / "report.md",
            "json": outdir / "report.json",
        }
        existing = {name: path for name, path in paths.items() if path.exists()}
        if not existing:
            self.out("[yellow]report not generated yet[/yellow]")
            return True
        for name, path in existing.items():
            self.out(f"  {name:<4} {path}")
        if "--open" in argv or "open" in argv:
            webbrowser.open(existing["html"].as_uri() if "html" in existing else next(iter(existing.values())).as_uri())
        return True

    def do_tools(self, argv: list[str]) -> bool:
        rows = tool_status(with_version="--versions" in argv)
        table = Table(box=None, pad_edge=False)
        table.add_column("tool", style="bold")
        table.add_column("kind")
        table.add_column("status")
        table.add_column("notes", overflow="fold")
        missing = 0
        for row in rows:
            installed = "[green]installed[/green]" if row["installed"] else "[red]missing[/red]"
            missing += 0 if row["installed"] else 1
            note = row["install_hint"] if not row["installed"] else (row.get("version") or row["description"])
            table.add_row(row["name"], "passive" if row["passive"] else "active", installed, note)
        self.out(table)
        if missing:
            self.out(
                f"\n[yellow]{missing} missing[/yellow] - those stages are skipped, "
                "everything else still runs."
            )
        return True

    def do_doctor(self, argv: list[str]) -> bool:
        checks = run_checks(self.cfg)
        table = Table(box=None, pad_edge=False)
        table.add_column("check", style="bold")
        table.add_column("status")
        table.add_column("detail", overflow="fold")
        table.add_column("hint", overflow="fold", style="dim")
        styles = {"ok": "[green]ok[/green]", "warn": "[yellow]warn[/yellow]", "fail": "[red]fail[/red]"}
        for check in checks:
            table.add_row(check.name, styles.get(check.status, check.status), check.detail, check.hint)
        self.out(table)
        state = doctor_overall(checks)
        line = doctor_summary(checks)
        if state == "fail":
            self.out(f"\n[red]{line}[/red]")
        elif state == "warn":
            self.out(f"\n[yellow]{line}[/yellow]")
        else:
            self.out(f"\n[green]{line}[/green]")
        return True

    def do_config(self, argv: list[str]) -> bool:
        if not argv:
            self.out_json(
                {
                    "config": self.cfg.to_dict(),
                    "api_keys": masked_keys(),
                    "usage_levels": list(USAGE_LEVELS),
                }
            )
            return True
        sub = argv[0].lower()
        if sub == "set" and len(argv) >= 3:
            key, value = argv[1], " ".join(argv[2:])
            try:
                self._config_set(key, value)
            except (ValueError, KeyError) as exc:
                self.out(f"[red]{exc}[/red]")
            return True
        if sub == "key" and len(argv) >= 2:
            provider = argv[1].lower()
            if not get_provider(provider):
                self.out(f"[red]unknown provider {provider!r}[/red]")
                return True
            value = argv[2] if len(argv) >= 3 else getpass.getpass(f"{provider} API key: ")
            if not value:
                self.out("[yellow]empty key - nothing changed[/yellow]")
                return True
            path = set_api_key(provider, value)
            self.out(f"[green]stored {provider} key in {path} (mode 600)[/green]")
            return True
        self.out("usage: config | config set <key> <value> | config key <provider>")
        return True

    def do_theme(self, argv: list[str]) -> bool:
        self.cfg.theme = "normal" if self.cfg.theme == "awakened" else "awakened"
        save_config(self.cfg)
        self.out(f"theme: [bold]{self.cfg.theme}[/bold]")
        return True

    def do_slumber(self, argv: list[str]) -> bool:
        if self.cfg.theme == "normal":
            self.out("[dim]already using the normal theme[/dim]")
            return True
        self.cfg.theme = "normal"
        save_config(self.cfg)
        self.out("[green]theme: normal[/green]")
        return True

    def do_history(self, argv: list[str]) -> bool:
        path = data_dir() / "history"
        if not path.exists():
            self.out("[dim]no history yet[/dim]")
            return True
        lines = path.read_text(errors="replace").splitlines()[-20:]
        for line in lines:
            self.out(f"  [dim]{line}[/dim]")
        return True

    def do_clear(self, argv: list[str]) -> bool:
        console.clear()
        return True

    def do_exit(self, argv: list[str]) -> bool:
        self.out("[dim]bye[/dim]")
        return False

    # -- internal ----------------------------------------------------------

    def _config_set(self, key: str, value: str) -> None:
        if key == "llm.usage" and value not in USAGE_LEVELS:
            raise ValueError(f"usage must be one of {', '.join(USAGE_LEVELS)}")
        if key == "llm.provider" and not get_provider(value):
            raise ValueError(f"unknown provider {value!r}; try: dragoneye models")
        if "." in key:
            section, field = key.split(".", 1)
            target = getattr(self.cfg, section, None)
            if target is None or not hasattr(target, field):
                raise KeyError(f"unknown setting {key!r}")
            current = getattr(target, field)
            setattr(target, field, _coerce(value, current))
        else:
            if not hasattr(self.cfg, key):
                raise KeyError(f"unknown setting {key!r}")
            setattr(self.cfg, key, _coerce(value, getattr(self.cfg, key)))
        save_config(self.cfg)
        self.out(f"[green]{key} = {value}[/green]")

    def out_json(self, data: dict[str, Any]) -> None:
        console.print_json(json.dumps(data, indent=2, default=str))

    def _show_run(self, run: dict[str, Any], data: dict[str, Any], limit: int = 15) -> None:
        stats = run.get("stats") or {}
        status = run.get("status") or "?"
        status_style = "green" if status == "done" else "red"
        report_path = str(Path(run.get("outdir") or "") / "report.html")
        mode = "dry run" if run.get("dry_run") else ("passive" if run.get("passive_only") else "live")
        self.out(
            Panel.fit(
                f"run      : [bold]{run['id']}[/bold]  [{status_style}]{status}[/{status_style}]\n"
                f"program  : {run.get('program_name', '?')}\n"
                f"mode     : {mode}\n"
                f"duration : {stats.get('duration_seconds', 0)}s\n"
                f"assets   : {len(data.get('assets') or [])} "
                f"([green]{len(data.get('new_assets') or [])}[/green] new)\n"
                f"findings : {len(data.get('findings') or [])} "
                f"([yellow]{len(data.get('new_findings') or [])}[/yellow] new)\n"
                f"scope    : {stats.get('skipped_scope', 0)} target(s) rejected\n"
                f"report   : {report_path}",
                title="run complete",
            )
        )
        findings = data.get("findings") or []
        if findings:
            self.out(f"\n{severity_counts(findings)}\n")
            table = Table(box=None, pad_edge=False)
            for column in ("id", "severity", "title", "asset", "conf", "verdict"):
                table.add_column(column, no_wrap=(column != "title" and column != "asset"))
            for finding in findings[:limit]:
                table.add_row(
                    str(finding.get("id")),
                    severity_markup(finding.get("severity")),
                    (finding.get("title") or "")[:52],
                    (finding.get("asset_value") or "")[:36],
                    f"{finding['confidence']}%" if finding.get("confidence") is not None else "-",
                    finding.get("verdict") or "-",
                )
            self.out(table)
            if len(findings) > limit:
                self.out(f"[dim]... {len(findings) - limit} more - dragoneye show {run['id']}[/dim]")
        else:
            self.out("[dim]no findings recorded[/dim]")

        for tool in data.get("tools") or []:
            if tool.get("status") == "missing":
                self.out(f"[yellow]! {tool['tool']} missing[/yellow] - {tool.get('message')}")

        self.out(
            "\n[dim]next:[/dim] [bold]show[/bold] · [bold]diff[/bold] · "
            "[bold]report --open[/bold]"
        )


# --- REPL -----------------------------------------------------------------


_READLINE_SESSION: Session | None = None


def run_console(theme: str | None = None) -> None:
    """Start the interactive console. Requires a TTY."""
    if not sys.stdin.isatty():
        console.print("[yellow]the console needs an interactive terminal[/yellow]")
        console.print("use [bold]dragoneye --help[/bold] or the one-shot commands instead")
        return

    cfg = load_config()
    if theme:
        cfg.theme = theme
    con = db.connect()
    session = Session(con=con, cfg=cfg)
    _install_readline(session)
    banner("bold red")
    console.print(
        Panel(
            f"[bold]DragonEye {__version__}[/bold]\n\n"
            "Type [bold]quick example.com[/bold] to go from zero to a report, or "
            "[bold]help[/bold] for every command.\n"
            "[dim]tab completes · ↑ history · exit to leave[/dim]",
            title="console",
            border_style="red",
        )
    )
    try:
        while True:
            prompt = _prompt_for(session.program)
            try:
                line = input(prompt).strip()
            except EOFError:
                console.print()
                break
            except KeyboardInterrupt:
                console.print("[dim]^C (exit to leave)[/dim]")
                continue
            if not line:
                continue
            try:
                if not dispatch(session, line):
                    break
            except Exception as exc:  # noqa: BLE001 - a bad command must not kill the console
                console.print(f"[red]error: {exc}[/red]")
    finally:
        _save_history()
        con.close()


def dispatch(session: Session, line: str) -> bool:
    """Execute one console line. Returns False when the session should end."""
    try:
        argv = shlex.split(line)
    except ValueError as exc:
        console.print(f"[red]parse error: {exc}[/red]")
        return True
    if not argv:
        return True
    command = ALIASES.get(argv[0].lower(), argv[0].lower())
    handler = getattr(session, f"do_{command}", None)
    if handler is None:
        suggestion = difflib.get_close_matches(command, _command_names(), n=1)
        hint = f" - did you mean [bold]{suggestion[0]}[/bold]?" if suggestion else ""
        console.print(f"[red]unknown command {command!r}[/red]{hint}  try [bold]help[/bold]")
        return True
    return bool(handler(argv[1:]))


def _command_names() -> list[str]:
    return [command.split()[0] for command in COMMANDS] + list(ALIASES)


def _execute(
    con: Any,
    program: dict[str, Any],
    cfg: Any,
    *,
    dry_run: bool,
    passive_only: bool | None,
    usage: str | None,
    echo: Any,
) -> dict[str, Any]:
    try:
        return start_run(
            con,
            program,
            cfg,
            dry_run=dry_run,
            passive_only=passive_only,
            llm_usage=usage,
            echo=echo,
        )
    except Exception as exc:  # noqa: BLE001 - report, never crash the console
        return {"error": str(exc)}


def _run_flags(argv: list[str]) -> dict[str, Any]:
    flags: dict[str, Any] = {
        "dry_run": False,
        "passive": False,
        "private": False,
        "usage": None,
    }
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg in ("--dry", "--dry-run", "-n"):
            flags["dry_run"] = True
        elif arg in ("--passive", "-p"):
            flags["passive"] = True
        elif arg in ("--private", "--allow-private"):
            flags["private"] = True
        elif arg in ("--no-llm", "--off"):
            flags["usage"] = "off"
        elif arg.startswith("--usage="):
            flags["usage"] = arg.split("=", 1)[1]
        elif arg == "--usage" and index + 1 < len(argv):
            index += 1
            flags["usage"] = argv[index]
        index += 1
    if flags["usage"] and flags["usage"] not in USAGE_LEVELS:
        flags["usage"] = None
    return flags


def _split_rules(text: str) -> list[str]:
    rules: list[str] = []
    for line in (text or "").splitlines():
        for chunk in re.split(r"[,\s]+", line):
            chunk = chunk.strip()
            if chunk and not chunk.startswith("#"):
                rules.append(chunk)
    return rules


def _coerce(value: str, current: Any) -> Any:
    if isinstance(current, bool):
        return value.lower() in ("1", "true", "yes", "on")
    if isinstance(current, int):
        return int(value)
    if isinstance(current, float):
        return float(value)
    if isinstance(current, list):
        return _split_rules(value)
    if current is None:
        lowered = value.strip().lower()
        if lowered in ("true", "false"):
            return lowered == "true"
        if lowered in ("none", "null", ""):
            return None
    return value


# --- readline -------------------------------------------------------------


def _prompt_for(program: dict[str, Any] | None) -> str:
    red = "\001\033[1;31m\002"
    dim = "\001\033[2m\002"
    cyan = "\001\033[36m\002"
    reset = "\001\033[0m\002"
    if program:
        return f"{red}dragoneye{reset}[{cyan}{program['name']}{reset}]{dim}>{reset} "
    return f"{red}dragoneye{reset}{dim}>{reset} "


def _install_readline(session: Session) -> None:
    global _READLINE_SESSION
    _READLINE_SESSION = session
    try:
        import readline
    except ImportError:  # pragma: no cover - Windows without pyreadline
        return
    history = data_dir() / "history"
    try:
        readline.set_history_length(HISTORY_LIMIT)
        if history.exists():
            readline.read_history_file(str(history))
        readline.parse_and_bind("tab: complete")
        readline.set_completer_delims(" \t\n")
        readline.set_completer(_completer)
    except OSError:
        return


def _save_history() -> None:
    try:
        import readline
    except ImportError:  # pragma: no cover
        return
    history = data_dir() / "history"
    try:
        readline.write_history_file(str(history))
    except OSError:
        pass


def _completer(text: str, state: int) -> str | None:
    session = _READLINE_SESSION
    if session is None:
        return None
    try:
        import readline

        before = readline.get_line_buffer()[: readline.get_begidx()]
    except Exception:  # noqa: BLE001
        before = ""
    words = before.split()
    try:
        if not words:
            candidates = _command_names()
        elif words[0] in ("use",):
            candidates = [row["name"] for row in db.list_programs(session.con)]
        elif words[0] in ("show", "diff", "report", "resume"):
            candidates = ["last"] + [row["id"] for row in db.list_runs(session.con, limit=15)]
        elif words[0] in ("assets", "findings"):
            candidates = [row["name"] for row in db.list_programs(session.con)]
        elif words[0] in ("run", "quick"):
            candidates = ["--dry", "--passive", "--private", "--no-llm", "--usage"]
        elif words[0] == "config":
            candidates = ["set", "key"] + list(CONFIG_KEYS) + ["off", "low", "balanced", "high"]
        else:
            candidates = _command_names()
    except Exception:  # noqa: BLE001 - completion must never break the prompt
        candidates = _command_names()
    matches = sorted({candidate for candidate in candidates if candidate.startswith(text)})
    return matches[state] if state < len(matches) else None


__all__ = ["Session", "dispatch", "run_console"]
