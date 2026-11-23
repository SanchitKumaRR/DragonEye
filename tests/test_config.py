"""Configuration, secret storage and version metadata."""

from __future__ import annotations

import json
import os
import stat

from dragoneye import __version__
from dragoneye.config import (
    Config,
    config_dir,
    load_config,
    masked_keys,
    save_config,
    set_api_key,
)


def test_version_is_current():
    # Keep this in sync with dragoneye/__init__.py and pyproject.toml.
    assert __version__ == "1.6.0"


def test_api_key_file_is_0600_and_dir_0700(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))

    path = set_api_key("openai", "sk-test-1234567890")

    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(config_dir().stat().st_mode) == 0o700
    assert json.loads(path.read_text())["openai"] == "sk-test-1234567890"
    assert masked_keys()["openai"] == "sk-t...7890"


def test_api_key_delete(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    set_api_key("groq", "gsk-secret-value")
    path = set_api_key("groq", "")
    assert "groq" not in json.loads(path.read_text())


def test_load_config_clamps_bad_values(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    cfg = Config()
    cfg.concurrency = 0
    cfg.request_rate = -1
    cfg.nuclei_severities = []
    save_config(cfg)

    loaded = load_config()
    assert loaded.concurrency == 4
    assert loaded.request_rate == 25
    assert loaded.nuclei_severities == ["low", "medium", "high", "critical"]


def test_run_dirs_are_private(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    load_config()
    assert stat.S_IMODE((tmp_path / "data" / "dragoneye").stat().st_mode) == 0o700
    assert os.path.isdir(tmp_path / "cfg" / "dragoneye")
