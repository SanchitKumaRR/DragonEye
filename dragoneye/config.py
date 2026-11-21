"""Paths, configuration and local secret storage.

Everything DragonEye writes lives under XDG dirs:

    ~/.config/dragoneye/config.json   settings (safe to read/share)
    ~/.config/dragoneye/keys.json     API keys (chmod 600, never logged)
    ~/.local/share/dragoneye/dragoneye.db
    ~/.local/share/dragoneye/runs/<run_id>/
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

APP_NAME = "dragoneye"
DEFAULT_MODEL = "gpt-4o-mini"
USAGE_LEVELS = ("off", "low", "balanced", "high")


def _xdg(env_var: str, fallback: str) -> Path:
    root = os.environ.get(env_var)
    return Path(root) if root else Path.home() / fallback


def config_dir() -> Path:
    return _xdg("XDG_CONFIG_HOME", ".config") / APP_NAME


def data_dir() -> Path:
    return _xdg("XDG_DATA_HOME", ".local/share") / APP_NAME


def config_path() -> Path:
    return config_dir() / "config.json"


def keys_path() -> Path:
    return config_dir() / "keys.json"


def db_path() -> Path:
    return data_dir() / "dragoneye.db"


def runs_dir() -> Path:
    return data_dir() / "runs"


def ensure_dirs() -> None:
    for path in (config_dir(), data_dir(), runs_dir()):
        path.mkdir(parents=True, exist_ok=True)


@dataclass
class LLMConfig:
    provider: str = "openai"
    model: str = DEFAULT_MODEL
    usage: str = "balanced"  # off | low | balanced | high
    base_url: str | None = None  # overrides the provider default
    max_cost_usd: float | None = None  # hard stop for a single run
    timeout: int = 120


@dataclass
class Config:
    llm: LLMConfig = field(default_factory=LLMConfig)
    # Hard cap on any single recon stage; keeps a 3GB box alive.
    concurrency: int = 4
    # Per-tool request rate limit passed to tools that support it.
    request_rate: int = 25
    allow_private: bool = False
    passive_only: bool = False
    nuclei_severities: list[str] = field(
        default_factory=lambda: ["low", "medium", "high", "critical"]
    )
    user_agent: str = "DragonEye/0.1 (scope-aware recon)"
    web_host: str = "127.0.0.1"
    web_port: int = 8765

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _merge(dataclass_type: Any, raw: dict[str, Any]) -> Any:
    """Build a dataclass from a dict, ignoring unknown keys."""
    known = {f.name for f in dataclass_type.__dataclass_fields__.values()}
    return dataclass_type(**{k: v for k, v in raw.items() if k in known})


def load_config() -> Config:
    ensure_dirs()
    path = config_path()
    if not path.exists():
        cfg = Config()
        save_config(cfg)
        return cfg
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return Config()
    cfg = _merge(Config, raw)
    if isinstance(raw.get("llm"), dict):
        cfg.llm = _merge(LLMConfig, raw["llm"])
    if cfg.llm.usage not in USAGE_LEVELS:
        cfg.llm.usage = "balanced"
    return cfg


def save_config(cfg: Config) -> Path:
    ensure_dirs()
    path = config_path()
    path.write_text(json.dumps(cfg.to_dict(), indent=2) + "\n")
    return path


# --- API keys -------------------------------------------------------------


def _read_keys() -> dict[str, str]:
    path = keys_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
        return {str(k): str(v) for k, v in data.items() if v}
    except (OSError, json.JSONDecodeError):
        return {}


def get_api_key(provider: str, env_var: str | None = None) -> str | None:
    """Env var wins over the local keys file, so nothing must be persisted."""
    if env_var:
        value = os.environ.get(env_var)
        if value:
            return value.strip()
    return _read_keys().get(provider) or None


def set_api_key(provider: str, key: str) -> Path:
    ensure_dirs()
    keys = _read_keys()
    if key:
        keys[provider] = key.strip()
    else:
        keys.pop(provider, None)
    path = keys_path()
    path.write_text(json.dumps(keys, indent=2) + "\n")
    path.chmod(0o600)
    return path


def masked_keys() -> dict[str, str]:
    """Never hand raw keys to the GUI - only a masked preview."""
    out: dict[str, str] = {}
    for provider, key in _read_keys().items():
        out[provider] = f"{key[:4]}...{key[-4:]}" if len(key) > 8 else "set"
    return out
