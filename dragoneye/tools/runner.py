"""Runs one adapter safely.

Responsibilities kept in one place on purpose:
  * scope filtering (a tool never receives an out-of-scope target)
  * argv-only execution (no shell, no injection)
  * process-group kill on timeout (no orphaned scans)
  * stdout/stderr capture to disk for evidence
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Sequence

from ..scope import Scope
from .base import ToolAdapter, ToolResult

Log = Callable[[str], None]


def execute(
    adapter: ToolAdapter,
    targets: Sequence[str],
    *,
    workdir: Path,
    scope: Scope,
    log: Log,
    dry_run: bool = False,
    passive_only: bool = False,
    request_rate: int = 25,
    user_agent: str | None = None,
    extra_args: Sequence[str] = (),
) -> ToolResult:
    result = ToolResult(tool=adapter.spec.name)
    workdir.mkdir(parents=True, exist_ok=True)

    if passive_only and not adapter.spec.passive:
        result.status = "skipped"
        result.message = "active tool skipped (passive-only mode)"
        log(f"  ! {adapter.spec.name}: {result.message}")
        return result

    allowed, rejected = scope.filter(targets)
    result.skipped_out_of_scope = len(rejected)
    if result.skipped_out_of_scope:
        log(f"  ! {adapter.spec.name}: dropped {result.skipped_out_of_scope} out-of-scope target(s)")

    if not allowed:
        result.status = "skipped"
        result.message = "no in-scope targets"
        log(f"  - {adapter.spec.name}: nothing to do")
        return result

    cmd = adapter.build(list(allowed), workdir)
    cmd = _apply_limits(cmd, adapter, request_rate, user_agent)
    if extra_args:
        cmd = [*cmd, *[str(arg) for arg in extra_args]]
    result.command = cmd

    inputs = workdir / "inputs.txt"
    inputs.write_text("\n".join(allowed) + "\n")

    if dry_run:
        missing = "" if adapter.available() else "  [binary not installed]"
        result.status = "dry-run"
        result.message = f"would run: {' '.join(cmd)}{missing}"
        log(f"  > {adapter.spec.name} (dry-run): {' '.join(cmd)}{missing}")
        return result

    if not adapter.available():
        result.status = "missing"
        result.message = adapter.spec.install_hint
        log(f"  ! {adapter.spec.name}: not installed -> {adapter.spec.install_hint}")
        return result

    out_path = workdir / "out.txt"
    if out_path.exists():
        out_path.unlink()

    log_path = workdir / "console.log"
    started = time.time()
    result.output_path = str(out_path)

    env = dict(os.environ)
    env.setdefault("NO_COLOR", "1")
    env["DRAGONEYE"] = "1"

    try:
        with open(log_path, "wb") as logf:
            proc = subprocess.Popen(
                cmd,
                stdout=logf,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                env=env,
                start_new_session=True,
            )
            try:
                result.exit_code = proc.wait(timeout=adapter.spec.timeout)
            except subprocess.TimeoutExpired:
                _kill_group(proc)
                result.status = "timeout"
                result.message = f"killed after {adapter.spec.timeout}s"
                log(f"  ! {adapter.spec.name}: {result.message}")
                result.duration = round(time.time() - started, 2)
                return result
    except OSError as exc:
        result.status = "failed"
        result.message = str(exc)
        result.duration = round(time.time() - started, 2)
        log(f"  ! {adapter.spec.name}: {exc}")
        return result

    result.duration = round(time.time() - started, 2)

    if result.exit_code not in (0, None):
        result.message = f"exit code {result.exit_code}"
        if not out_path.exists() or out_path.stat().st_size == 0:
            result.status = "failed"
            log(f"  ! {adapter.spec.name}: failed ({result.message})")
            return result

    try:
        assets, findings = adapter.parse(workdir)
    except Exception as exc:  # parser bugs must not kill a run
        assets, findings = [], []
        result.message = f"parse error: {exc}"
        log(f"  ! {adapter.spec.name}: parser error: {exc}")

    result.assets = assets
    result.findings = findings
    result.status = "ok"
    log(
        f"  + {adapter.spec.name}: {len(assets)} asset(s), "
        f"{len(findings)} finding(s) in {result.duration}s"
    )
    return result


def _apply_limits(
    cmd: list[str], adapter: ToolAdapter, request_rate: int, user_agent: str | None
) -> list[str]:
    """Add rate/UA flags only for tools that understand them."""
    args = list(cmd)
    rate_flags = {
        "nuclei": "-rl",
        "katana": "-rl",
        "httpx": "-rl",
    }
    flag = rate_flags.get(adapter.spec.name)
    if flag and request_rate > 0 and flag not in args:
        args.extend([flag, str(request_rate)])
    if user_agent:
        ua_flag = {"nuclei": "-H", "httpx": "-H", "katana": "-H"}.get(adapter.spec.name)
        if ua_flag and ua_flag not in args:
            args.extend([ua_flag, f"User-Agent: {user_agent}"])
    return args


def _kill_group(proc: subprocess.Popen[Any]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=10)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
