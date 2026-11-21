"""Tool adapter contract.

Adding a tool = subclass `ToolAdapter`, fill in `spec`, `build()` and `parse()`,
then append an instance to `dragoneye.tools.ADAPTERS`. Nothing else changes:
scope filtering, timeouts, audit logging, output capture and reporting are
handled by the runner.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ToolSpec:
    name: str
    binary: str
    passive: bool
    install_hint: str
    homepage: str = ""
    timeout: int = 1800
    description: str = ""


@dataclass
class ToolResult:
    tool: str
    status: str = "ok"  # ok | missing | skipped | failed | timeout | dry-run
    command: list[str] = field(default_factory=list)
    exit_code: int | None = None
    duration: float = 0.0
    assets: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    skipped_out_of_scope: int = 0
    message: str = ""
    output_path: str | None = None

    @property
    def ok(self) -> bool:
        return self.status in ("ok", "dry-run")


class ToolAdapter:
    spec: ToolSpec

    # -- availability ------------------------------------------------------

    def available(self) -> bool:
        return shutil.which(self.spec.binary) is not None

    def version(self) -> str:
        if not self.available():
            return "not installed"
        import subprocess

        for flag in ("-version", "--version", "-v"):
            try:
                proc = subprocess.run(
                    [self.spec.binary, flag],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
            except (OSError, subprocess.SubprocessError):
                continue
            text = (proc.stdout or proc.stderr or "").strip()
            if text:
                return text.splitlines()[0][:120]
        return "unknown"

    # -- contract ----------------------------------------------------------

    def build(self, targets: list[str], workdir: Path) -> list[str]:
        """Return argv (never a shell string). Write output to workdir/out.txt."""
        raise NotImplementedError

    def parse(self, workdir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Return (assets, findings) parsed from workdir/out.txt."""
        return [], []

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def write_list(path: Path, values: list[str]) -> Path:
        path.write_text("\n".join(values) + "\n")
        return path

    @staticmethod
    def read_lines(path: Path) -> list[str]:
        if not path.exists():
            return []
        try:
            return [line.strip() for line in path.read_text(errors="replace").splitlines() if line.strip()]
        except OSError:
            return []

    @staticmethod
    def read_jsonl(path: Path) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for line in ToolAdapter.read_lines(path):
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                out.append(parsed)
        return out
