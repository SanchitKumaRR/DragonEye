"""Environment health checks.

`dragoneye doctor` should tell a new user exactly what works, what is missing
and what to do next - before a live scan fails halfway through.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from dataclasses import dataclass

from . import __version__, db
from .config import Config, config_dir, data_dir, db_path, load_config
from .llm.client import LLMClient
from .llm.providers import get_provider
from .scope import Scope, ScopeError
from .tools import status as tool_status

OK = "ok"
WARN = "warn"
FAIL = "fail"


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str
    hint: str = ""


def run_checks(cfg: Config | None = None) -> list[Check]:
    cfg = cfg or load_config()
    checks: list[Check] = []

    # Python
    version = sys.version_info
    if version >= (3, 11):
        checks.append(Check("python", OK, f"{version.major}.{version.minor}.{version.micro}"))
    else:
        checks.append(
            Check("python", FAIL, f"{version.major}.{version.minor} - need 3.11+", "use a newer Python")
        )

    # Required Python packages
    missing = [
        name
        for name in ("typer", "rich", "httpx", "fastapi", "uvicorn")
        if importlib.util.find_spec(name) is None
    ]
    if missing:
        checks.append(Check("python deps", FAIL, ", ".join(missing), "pip install -r requirements.txt"))
    else:
        checks.append(Check("python deps", OK, "typer, rich, httpx, fastapi, uvicorn"))

    # Directories
    for label, path in (("config dir", config_dir()), ("data dir", data_dir())):
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".write-probe"
            probe.write_text("ok")
            probe.unlink(missing_ok=True)
            checks.append(Check(label, OK, str(path)))
        except OSError as exc:
            checks.append(Check(label, FAIL, f"{path}: {exc}", "check permissions / XDG env vars"))

    # Database
    try:
        con = db.connect()
        try:
            programs = db.list_programs(con)
            runs = db.list_runs(con, limit=1)
        finally:
            con.close()
        checks.append(
            Check("database", OK, f"{db_path()} · {len(programs)} program(s), {len(runs)} recent run(s)")
        )
    except Exception as exc:  # noqa: BLE001 - doctor must never crash
        checks.append(Check("database", FAIL, str(exc), "remove or move the database if it is corrupt"))

    # External tools
    rows = tool_status()
    installed = [row["name"] for row in rows if row["installed"]]
    missing_tools = [row for row in rows if not row["installed"]]
    if not missing_tools:
        checks.append(Check("recon tools", OK, ", ".join(installed)))
    elif not installed:
        checks.append(
            Check(
                "recon tools",
                WARN,
                "none installed - dry runs work, live recon is limited to seeds",
                "see: dragoneye tools",
            )
        )
    else:
        checks.append(
            Check(
                "recon tools",
                WARN,
                f"{len(installed)}/{len(rows)} installed: " + ", ".join(installed),
                "missing: " + ", ".join(row["name"] for row in missing_tools),
            )
        )

    # Programs / scope validity
    try:
        con = db.connect()
        try:
            programs = db.list_programs(con)
        finally:
            con.close()
        bad: list[str] = []
        for program in programs:
            try:
                Scope(
                    program.get("in_scope") or [],
                    program.get("out_of_scope") or [],
                    allow_private=cfg.allow_private,
                )
            except ScopeError as exc:
                bad.append(f"{program['name']}: {exc}")
        if bad:
            checks.append(Check("scope", FAIL, "; ".join(bad), "fix with: dragoneye program add"))
        elif programs:
            checks.append(Check("scope", OK, f"{len(programs)} program(s) parse cleanly"))
        else:
            checks.append(
                Check("scope", WARN, "no programs yet", "add one: dragoneye quick example.com")
            )
    except Exception as exc:  # noqa: BLE001
        checks.append(Check("scope", FAIL, str(exc)))

    # Model configuration
    provider = get_provider(cfg.llm.provider)
    if provider is None:
        checks.append(
            Check("model", FAIL, f"unknown provider {cfg.llm.provider!r}", "dragoneye models")
        )
    else:
        try:
            client = LLMClient(
                provider.id,
                cfg.llm.model,
                base_url=cfg.llm.base_url,
                timeout=cfg.llm.timeout,
            )
            available, reason = client.available()
        except Exception as exc:  # noqa: BLE001
            available, reason = False, str(exc)
        if cfg.llm.usage == "off":
            checks.append(Check("model", OK, "disabled (llm.usage=off)"))
        elif available:
            checks.append(Check("model", OK, f"{provider.id} / {cfg.llm.model} ({cfg.llm.usage})"))
        else:
            checks.append(
                Check("model", WARN, reason, f"dragoneye config key {provider.id}  (or set llm.usage=off)")
            )

    # Runtime knobs that commonly cause surprises
    if cfg.allow_private:
        checks.append(
            Check("safety", WARN, "allow_private is enabled", "only use on targets you own")
        )
    elif os.environ.get("DRAGONEYE_INSECURE"):
        checks.append(Check("safety", WARN, "DRAGONEYE_INSECURE is set"))
    else:
        checks.append(Check("safety", OK, "private/loopback/metadata targets blocked"))

    checks.append(Check("version", OK, __version__))
    return checks


def overall(checks: list[Check]) -> str:
    statuses = {check.status for check in checks}
    if FAIL in statuses:
        return FAIL
    if WARN in statuses:
        return WARN
    return OK


def summary(checks: list[Check]) -> str:
    return (
        f"{sum(1 for c in checks if c.status == OK)} ok · "
        f"{sum(1 for c in checks if c.status == WARN)} warn · "
        f"{sum(1 for c in checks if c.status == FAIL)} fail"
    )
