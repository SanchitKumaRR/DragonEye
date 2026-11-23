"""CLI-level smoke tests for the one-shot workflow."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from dragoneye import db
from dragoneye.cli import app

runner = CliRunner()


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    con = db.connect()
    yield con
    con.close()


def test_quick_dry_run_creates_program_and_report(env):
    result = runner.invoke(
        app, ["quick", "acme.example", "--dry-run", "--yes", "--no-llm"]
    )
    assert result.exit_code == 0, result.output
    assert "done" in result.output

    program = db.get_program(env, "acme.example")
    assert program is not None
    assert "acme.example" in (program.get("in_scope") or [])

    runs = db.list_runs(env, int(program["id"]), 1)
    assert runs and runs[0]["status"] == "done"


def test_assets_command_lists_inventory(env):
    runner.invoke(app, ["quick", "acme.example", "--dry-run", "--yes", "--no-llm"])
    result = runner.invoke(app, ["assets", "--json"])
    assert result.exit_code == 0, result.output
    assert "acme.example" in result.output


def test_doctor_json_runs(env):
    result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 0, result.output
    assert '"name": "database"' in result.output
