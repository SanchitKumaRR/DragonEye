"""Tool registry."""

from __future__ import annotations

from typing import Any

from .adapters import ADAPTERS
from .base import ToolAdapter, ToolResult, ToolSpec
from .runner import execute

__all__ = [
    "ADAPTERS",
    "ToolAdapter",
    "ToolResult",
    "ToolSpec",
    "execute",
    "all_adapters",
    "get_adapter",
    "status",
]


def all_adapters() -> list[ToolAdapter]:
    return list(ADAPTERS)


def get_adapter(name: str) -> ToolAdapter | None:
    for adapter in ADAPTERS:
        if adapter.spec.name == name:
            return adapter
    return None


def status(with_version: bool = False) -> list[dict[str, Any]]:
    out = []
    for adapter in ADAPTERS:
        spec = adapter.spec
        out.append(
            {
                "name": spec.name,
                "binary": spec.binary,
                "installed": adapter.available(),
                "version": adapter.version() if with_version and adapter.available() else None,
                "passive": spec.passive,
                "description": spec.description,
                "install_hint": spec.install_hint,
                "homepage": spec.homepage,
            }
        )
    return out
