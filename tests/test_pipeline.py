"""End-to-end pipeline smoke test with no external tools installed.

A run against a dry-run must still produce a valid report and never send
traffic - this is the safety net for a fresh machine.
"""

from __future__ import annotations

import json

import pytest

from dragoneye import db
from dragoneye.config import Config
from dragoneye.pipeline import start_run
from dragoneye.scope import ScopeError
from dragoneye.tools import status as tool_status


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    con = db.connect(tmp_path / "test.db")
    yield con
    con.close()


def test_dry_run_produces_report(env):
    program_id = db.add_program(env, "acme", ["acme.example", "*.acme.example"], ["admin.acme.example"])
    program = db.get_program(env, program_id)
    cfg = Config()
    cfg.llm.usage = "off"

    result = start_run(env, program, cfg, dry_run=True, echo=lambda _m: None)

    assert result["status"] == "done"
    assert result["stats"]["seeds"] == 1
    assets = db.run_assets(env, result["id"])
    assert [a["value"] for a in assets] == ["acme.example"]

    outdir = result["report"]["json"].rsplit("/", 1)[0]
    for name in ("report.json", "report.md", "report.html"):
        with open(f"{outdir}/{name}", encoding="utf-8") as handle:
            content = handle.read()
        assert content

    payload = json.loads(open(result["report"]["json"], encoding="utf-8").read())
    assert payload["program"]["name"] == "acme"
    assert payload["run"]["status"] == "done"


def test_dry_run_never_records_out_of_scope(env):
    program_id = db.add_program(env, "acme", ["acme.example"], ["*.acme.example"])
    program = db.get_program(env, program_id)
    cfg = Config()
    result = start_run(env, program, cfg, dry_run=True, echo=lambda _m: None)
    values = [a["value"] for a in db.run_assets(env, result["id"])]
    assert values == ["acme.example"]


def test_invalid_scope_blocks_run(env):
    program_id = db.add_program(env, "broken", ["re:["])
    program = db.get_program(env, program_id)
    with pytest.raises(ScopeError):
        start_run(env, program, Config(), dry_run=True, echo=lambda _m: None)


def test_resume_skips_completed_stages(env):
    program_id = db.add_program(env, "acme", ["acme.example"])
    program = db.get_program(env, program_id)
    cfg = Config()
    first = start_run(env, program, cfg, dry_run=True, echo=lambda _m: None)
    second = start_run(env, program, cfg, dry_run=True, resume_run_id=first["id"], echo=lambda _m: None)
    assert second["id"] == first["id"]
    assert "seed" in second["state"]["stages"]


def test_tool_status_shape():
    rows = tool_status()
    assert {row["name"] for row in rows} >= {"subfinder", "dnsx", "httpx", "katana", "nuclei"}
    for row in rows:
        assert "install_hint" in row
