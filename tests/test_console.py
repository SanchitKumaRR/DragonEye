"""Interactive console and one-shot quick-run behaviour."""

from __future__ import annotations

from io import StringIO

import pytest
from rich.console import Console

from dragoneye import console as console_module
from dragoneye import db
from dragoneye.config import Config
from dragoneye.doctor import FAIL, OK, WARN, overall, run_checks
from dragoneye.quick import program_name_for


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    con = db.connect(tmp_path / "test.db")
    yield con
    con.close()


@pytest.fixture()
def session(env, monkeypatch):
    out = StringIO()
    monkeypatch.setattr(console_module, "console", Console(file=out, width=200))
    state = console_module.Session(con=env, cfg=Config())
    state.out_buffer = out  # type: ignore[attr-defined]
    return state


def _text(session) -> str:
    return session.out_buffer.getvalue()


def test_program_name_groups_subdomains():
    assert program_name_for("www.example.com") == "example.com"
    assert program_name_for("api.example.com") == "example.com"
    assert program_name_for("api.example.co.uk") == "example.co.uk"
    assert program_name_for("203.0.113.7") == "203.0.113.7"


def test_dispatch_help_and_unknown(session):
    assert console_module.dispatch(session, "help") is True
    assert console_module.dispatch(session, "notacommand") is True
    text = _text(session)
    assert "quick" in text
    assert "unknown command" in text


def test_dispatch_quick_dry_run_creates_program(session):
    assert console_module.dispatch(session, "quick acme.example --dry") is True
    assert session.program is not None
    assert session.program["name"] == "acme.example"
    assert session.last_run_id
    text = _text(session)
    assert "run complete" in text
    assert "dry run" in text


def test_assets_and_findings_commands(session):
    console_module.dispatch(session, "quick acme.example --dry")
    assert console_module.dispatch(session, "assets") is True
    assert "acme.example" in _text(session)
    assert console_module.dispatch(session, "findings") is True
    assert "no findings recorded" in _text(session)


def test_dispatch_use_and_scope(session):
    session.con.execute(
        "INSERT INTO programs (name, in_scope, out_of_scope, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?)",
        ("acme", '["acme.example"]', "[]", db.utcnow(), db.utcnow()),
    )
    session.con.commit()
    assert console_module.dispatch(session, "use acme") is True
    assert session.program["name"] == "acme"
    assert console_module.dispatch(session, "scope acme.example outside.example") is True
    text = _text(session)
    assert "ALLOW" in text
    assert "DENY" in text


def test_console_commands_do_not_exit_on_errors(session):
    assert console_module.dispatch(session, "use does-not-exist") is True
    assert "not found" in _text(session)


def test_doctor_checks_have_statuses(env):
    checks = run_checks(Config())
    assert checks
    assert {check.status for check in checks} <= {OK, WARN, FAIL}
    assert any(check.name == "database" for check in checks)
    assert overall(checks) in {OK, WARN, FAIL}
