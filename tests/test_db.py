"""Schema creation and migration."""

from __future__ import annotations

import pytest

from dragoneye import db


def test_schema_is_created_at_current_version(tmp_path):
    con = db.connect(tmp_path / "new.db")
    try:
        version = con.execute("PRAGMA user_version").fetchone()[0]
        assert version == db.SCHEMA_VERSION
        indexes = {
            row[0]
            for row in con.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()
        }
        assert "idx_audit_run" in indexes
    finally:
        con.close()


def test_v1_database_is_migrated_additively(tmp_path):
    path = tmp_path / "old.db"
    con = db.connect(path)
    con.execute("DROP INDEX idx_audit_run")
    con.execute("PRAGMA user_version = 1")
    con.commit()
    con.close()

    con = db.connect(path)
    try:
        assert con.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
        indexes = {
            row[0]
            for row in con.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()
        }
        assert "idx_audit_run" in indexes
    finally:
        con.close()


def test_newer_database_is_refused(tmp_path):
    path = tmp_path / "future.db"
    con = db.connect(path)
    con.execute("PRAGMA user_version = 9999")
    con.commit()
    con.close()

    with pytest.raises(RuntimeError, match="newer than this DragonEye"):
        db.connect(path)


def test_run_audit_filters(tmp_path):
    con = db.connect(tmp_path / "audit.db")
    try:
        db.audit(con, "scope_reject", "first", "run1")
        db.audit(con, "run_start", "start", "run1")
        db.audit(con, "scope_reject", "second", "run1")
        rows = db.run_audit(con, "run1", "scope_reject")
        assert [row["detail"] for row in rows] == ["first", "second"]
    finally:
        con.close()
