"""Zero-friction one-shot recon.

`dragoneye quick example.com` derives a program name from the target, creates
(or extends) the program's scope, runs the pipeline and hands back the run.
No `program add` ceremony, no remembering rule syntax for the common case.
"""

from __future__ import annotations

import ipaddress
import re
import sqlite3
from collections.abc import Callable
from typing import Any

from . import db
from .config import Config
from .pipeline import start_run
from .scope import Scope, ScopeError, normalize_host

# Second-level labels that appear before a country TLD (example.co.uk).
SECOND_LEVEL = {
    "co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go",
    "gob", "mil", "nom", "web", "art", "info", "biz",
}


def derive_host(target: str) -> str:
    """Normalise a URL, host, IP or CIDR member into a bare hostname/IP."""
    host = normalize_host(target)
    if not host:
        raise ScopeError(f"cannot derive a host from {target!r}")
    return host


def program_name_for(host: str) -> str:
    """A stable, human-readable program name derived from a target.

    `api.example.com` and `www.example.com` both map to `example.com`, so a
    second quick run extends the same program instead of creating near-dupes.
    """
    value = (host or "").strip().lower().strip(".")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    if value.startswith("www."):
        value = value[4:]

    parts = value.split(".")
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL and len(parts[-1]) == 2:
        base = ".".join(parts[-3:])
    elif len(parts) >= 2:
        base = ".".join(parts[-2:])
    else:
        base = value

    name = re.sub(r"[^a-z0-9.-]+", "-", base).strip("-.")
    return name[:80] or "target"


def quick_run(
    con: sqlite3.Connection,
    target: str,
    cfg: Config,
    *,
    dry_run: bool = False,
    passive: bool = False,
    usage: str | None = None,
    provider: str | None = None,
    model: str | None = None,
    echo: Callable[[str], None] = print,
) -> dict[str, Any]:
    """Create/extend a program for `target`, run recon, and return the run."""
    host = derive_host(target)
    name = program_name_for(host)

    existing = db.get_program(con, name) or {}
    in_scope = list(existing.get("in_scope") or [])
    out_scope = list(existing.get("out_of_scope") or [])
    if host not in in_scope:
        in_scope.insert(0, host)

    scope = Scope(in_scope, out_scope, allow_private=cfg.allow_private)
    decision = scope.check(host)
    if not decision.allowed:
        raise ScopeError(f"{host} is not runnable: {decision.reason}")

    program_id = db.add_program(
        con,
        name,
        in_scope,
        out_scope,
        existing.get("platform"),
        existing.get("policy_note"),
    )
    program = db.get_program(con, program_id)
    if not program:
        raise ScopeError(f"could not create program {name!r}")

    result = start_run(
        con,
        program,
        cfg,
        dry_run=dry_run,
        passive_only=True if passive else None,
        llm_usage=usage,
        provider=provider,
        model=model,
        echo=echo,
    )
    result["program"] = program
    result["target"] = host
    result["created_program"] = not bool(existing)
    return result
