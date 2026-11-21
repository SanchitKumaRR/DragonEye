"""SQLite persistence.

One database for every program: assets and findings are de-duplicated across
runs, while `run_assets` / `finding_runs` keep the per-run history that makes
`dragoneye diff` possible.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from .config import db_path

SCHEMA = """
PRAGMA user_version = 1;

CREATE TABLE IF NOT EXISTS programs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL UNIQUE,
    platform      TEXT,
    policy_note   TEXT,
    in_scope      TEXT NOT NULL,
    out_of_scope  TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id           TEXT PRIMARY KEY,
    program_id   INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    status       TEXT NOT NULL,
    dry_run      INTEGER NOT NULL DEFAULT 0,
    passive_only INTEGER NOT NULL DEFAULT 0,
    llm_usage    TEXT,
    llm_provider TEXT,
    llm_model    TEXT,
    outdir       TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    error        TEXT,
    state        TEXT NOT NULL DEFAULT '{}',
    stats        TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS assets (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id     INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    kind           TEXT NOT NULL,
    value          TEXT NOT NULL,
    source_tool    TEXT,
    in_scope       INTEGER NOT NULL DEFAULT 1,
    first_seen_run TEXT,
    last_seen_run  TEXT,
    meta           TEXT NOT NULL DEFAULT '{}',
    UNIQUE (program_id, kind, value)
);

CREATE TABLE IF NOT EXISTS run_assets (
    run_id   TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    is_new   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id, asset_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id     INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    fingerprint    TEXT NOT NULL,
    tool           TEXT NOT NULL,
    template_id    TEXT,
    title          TEXT,
    severity       TEXT,
    asset_id       INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    first_seen_run TEXT,
    last_seen_run  TEXT,
    evidence_path  TEXT,
    raw            TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL,
    UNIQUE (program_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS finding_runs (
    run_id     TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    is_new     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id, finding_id)
);

CREATE TABLE IF NOT EXISTS llm_verdicts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id       INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    run_id           TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    provider         TEXT,
    model            TEXT,
    verdict          TEXT,
    confidence       INTEGER,
    band             TEXT,
    reasoning        TEXT,
    counter_evidence TEXT,
    next_step        TEXT,
    tokens_in        INTEGER DEFAULT 0,
    tokens_out       INTEGER DEFAULT 0,
    cost_usd         REAL DEFAULT 0,
    validated        TEXT,
    created_at       TEXT,
    UNIQUE (finding_id, run_id)
);

CREATE TABLE IF NOT EXISTS tool_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    tool          TEXT NOT NULL,
    status        TEXT,
    command       TEXT,
    exit_code     INTEGER,
    duration      REAL,
    assets_found  INTEGER DEFAULT 0,
    findings_found INTEGER DEFAULT 0,
    skipped_scope INTEGER DEFAULT 0,
    message       TEXT,
    output_path   TEXT,
    started_at    TEXT,
    finished_at   TEXT
);

CREATE TABLE IF NOT EXISTS audit (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT NOT NULL,
    run_id TEXT,
    action TEXT NOT NULL,
    detail TEXT
);

CREATE INDEX IF NOT EXISTS idx_assets_program   ON assets(program_id);
CREATE INDEX IF NOT EXISTS idx_findings_program ON findings(program_id);
CREATE INDEX IF NOT EXISTS idx_finding_runs_run ON finding_runs(run_id);
CREATE INDEX IF NOT EXISTS idx_tool_runs_run    ON tool_runs(run_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts         ON audit(ts);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    target = Path(path) if path else db_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(target, timeout=30, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript(SCHEMA)
    return con


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    out = dict(row)
    for key in ("in_scope", "out_of_scope", "meta", "raw", "stats", "state"):
        if key in out and isinstance(out[key], str):
            try:
                out[key] = json.loads(out[key])
            except json.JSONDecodeError:
                pass
    return out


def _rows(rows: Iterable[sqlite3.Row]) -> list[dict[str, Any]]:
    return [_row(r) for r in rows]  # type: ignore[misc]


# --- programs -------------------------------------------------------------


def add_program(
    con: sqlite3.Connection,
    name: str,
    in_scope: Sequence[str],
    out_of_scope: Sequence[str] = (),
    platform: str | None = None,
    policy_note: str | None = None,
) -> int:
    now = utcnow()
    cur = con.execute(
        """INSERT INTO programs (name, platform, policy_note, in_scope, out_of_scope,
                                 created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(name) DO UPDATE SET
               platform=excluded.platform,
               policy_note=excluded.policy_note,
               in_scope=excluded.in_scope,
               out_of_scope=excluded.out_of_scope,
               updated_at=excluded.updated_at""",
        (
            name,
            platform,
            policy_note,
            json.dumps(list(in_scope)),
            json.dumps(list(out_of_scope)),
            now,
            now,
        ),
    )
    con.commit()
    if cur.lastrowid:
        return int(cur.lastrowid)
    row = con.execute("SELECT id FROM programs WHERE name = ?", (name,)).fetchone()
    return int(row["id"])


def get_program(con: sqlite3.Connection, ref: str | int) -> dict[str, Any] | None:
    if isinstance(ref, int) or str(ref).isdigit():
        row = con.execute("SELECT * FROM programs WHERE id = ?", (int(ref),)).fetchone()
    else:
        row = con.execute("SELECT * FROM programs WHERE name = ?", (ref,)).fetchone()
    return _row(row)


def list_programs(con: sqlite3.Connection) -> list[dict[str, Any]]:
    return _rows(con.execute("SELECT * FROM programs ORDER BY name").fetchall())


def delete_program(con: sqlite3.Connection, ref: str | int) -> bool:
    program = get_program(con, ref)
    if not program:
        return False
    con.execute("DELETE FROM programs WHERE id = ?", (program["id"],))
    con.commit()
    return True


# --- runs -----------------------------------------------------------------


def add_run(
    con: sqlite3.Connection,
    run_id: str,
    program_id: int,
    outdir: str,
    *,
    dry_run: bool = False,
    passive_only: bool = False,
    llm_usage: str | None = None,
    llm_provider: str | None = None,
    llm_model: str | None = None,
) -> None:
    con.execute(
        """INSERT INTO runs (id, program_id, status, dry_run, passive_only, llm_usage,
                             llm_provider, llm_model, outdir, started_at)
           VALUES (?, ?, 'running', ?, ?, ?, ?, ?, ?, ?)""",
        (
            run_id,
            program_id,
            int(dry_run),
            int(passive_only),
            llm_usage,
            llm_provider,
            llm_model,
            outdir,
            utcnow(),
        ),
    )
    con.commit()


def update_run(con: sqlite3.Connection, run_id: str, **fields: Any) -> None:
    if not fields:
        return
    allowed = {"status", "finished_at", "error", "state", "stats"}
    clean: dict[str, Any] = {}
    for key, value in fields.items():
        if key not in allowed:
            continue
        clean[key] = json.dumps(value) if isinstance(value, (dict, list)) else value
    if not clean:
        return
    assignments = ", ".join(f"{k} = ?" for k in clean)
    con.execute(f"UPDATE runs SET {assignments} WHERE id = ?", (*clean.values(), run_id))
    con.commit()


def get_run(con: sqlite3.Connection, run_id: str) -> dict[str, Any] | None:
    row = con.execute(
        """SELECT r.*, p.name AS program_name
             FROM runs r JOIN programs p ON p.id = r.program_id
            WHERE r.id = ?""",
        (run_id,),
    ).fetchone()
    return _row(row)


def list_runs(con: sqlite3.Connection, program_id: int | None = None, limit: int = 20) -> list[dict[str, Any]]:
    if program_id is None:
        rows = con.execute(
            """SELECT r.*, p.name AS program_name
                 FROM runs r JOIN programs p ON p.id = r.program_id
                ORDER BY r.started_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    else:
        rows = con.execute(
            """SELECT r.*, p.name AS program_name
                 FROM runs r JOIN programs p ON p.id = r.program_id
                WHERE r.program_id = ? ORDER BY r.started_at DESC LIMIT ?""",
            (program_id, limit),
        ).fetchall()
    return _rows(rows)


def resolve_run(con: sqlite3.Connection, ref: str) -> dict[str, Any] | None:
    """Accept a full id, an unambiguous prefix, or 'last'."""
    if ref in ("last", "latest"):
        runs = list_runs(con, limit=1)
        return runs[0] if runs else None
    exact = get_run(con, ref)
    if exact:
        return exact
    rows = con.execute(
        "SELECT id FROM runs WHERE id LIKE ? ORDER BY started_at DESC LIMIT 5", (ref + "%",)
    ).fetchall()
    if len(rows) == 1:
        return get_run(con, rows[0]["id"])
    return None


# --- assets ---------------------------------------------------------------


def upsert_asset(
    con: sqlite3.Connection,
    program_id: int,
    run_id: str,
    kind: str,
    value: str,
    source_tool: str | None = None,
    meta: dict[str, Any] | None = None,
    in_scope: bool = True,
) -> tuple[int, bool]:
    """Returns (asset_id, is_new_for_program)."""
    existing = con.execute(
        "SELECT id FROM assets WHERE program_id = ? AND kind = ? AND value = ?",
        (program_id, kind, value),
    ).fetchone()
    if existing:
        asset_id = int(existing["id"])
        is_new = False
        con.execute(
            "UPDATE assets SET last_seen_run = ?, in_scope = ? WHERE id = ?",
            (run_id, int(in_scope), asset_id),
        )
        if meta:
            con.execute(
                """UPDATE assets SET meta = json_patch(COALESCE(meta,'{}'), ?) WHERE id = ?""",
                (json.dumps(meta), asset_id),
            )
    else:
        cur = con.execute(
            """INSERT INTO assets (program_id, kind, value, source_tool, in_scope,
                                   first_seen_run, last_seen_run, meta)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (program_id, kind, value, source_tool, int(in_scope), run_id, run_id, json.dumps(meta or {})),
        )
        asset_id = int(cur.lastrowid or 0)
        is_new = True
    con.execute(
        """INSERT INTO run_assets (run_id, asset_id, is_new) VALUES (?, ?, ?)
           ON CONFLICT(run_id, asset_id) DO UPDATE SET is_new = MAX(is_new, excluded.is_new)""",
        (run_id, asset_id, int(is_new)),
    )
    return asset_id, is_new


def get_asset(con: sqlite3.Connection, asset_id: int) -> dict[str, Any] | None:
    return _row(con.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone())


def run_assets(con: sqlite3.Connection, run_id: str) -> list[dict[str, Any]]:
    rows = con.execute(
        """SELECT a.*, ra.is_new
             FROM run_assets ra JOIN assets a ON a.id = ra.asset_id
            WHERE ra.run_id = ? ORDER BY a.kind, a.value""",
        (run_id,),
    ).fetchall()
    return _rows(rows)


def count_assets(con: sqlite3.Connection, program_id: int) -> int:
    row = con.execute("SELECT COUNT(*) AS n FROM assets WHERE program_id = ?", (program_id,)).fetchone()
    return int(row["n"]) if row else 0


def diff_assets(con: sqlite3.Connection, program_id: int, run_id: str) -> list[dict[str, Any]]:
    """Assets seen in this run that were never seen in an earlier run."""
    rows = con.execute(
        """SELECT a.*
             FROM run_assets ra JOIN assets a ON a.id = ra.asset_id
            WHERE ra.run_id = ? AND a.program_id = ? AND ra.is_new = 1
            ORDER BY a.kind, a.value""",
        (run_id, program_id),
    ).fetchall()
    return _rows(rows)


# --- findings -------------------------------------------------------------


def upsert_finding(
    con: sqlite3.Connection,
    program_id: int,
    run_id: str,
    fingerprint: str,
    *,
    tool: str,
    template_id: str | None = None,
    title: str | None = None,
    severity: str | None = None,
    asset_id: int | None = None,
    evidence_path: str | None = None,
    raw: dict[str, Any] | None = None,
) -> tuple[int, bool]:
    existing = con.execute(
        "SELECT id FROM findings WHERE program_id = ? AND fingerprint = ?",
        (program_id, fingerprint),
    ).fetchone()
    if existing:
        finding_id = int(existing["id"])
        is_new = False
        con.execute("UPDATE findings SET last_seen_run = ? WHERE id = ?", (run_id, finding_id))
    else:
        cur = con.execute(
            """INSERT INTO findings (program_id, fingerprint, tool, template_id, title, severity,
                                     asset_id, first_seen_run, last_seen_run, evidence_path, raw, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                program_id,
                fingerprint,
                tool,
                template_id,
                title,
                severity,
                asset_id,
                run_id,
                run_id,
                evidence_path,
                json.dumps(raw or {}),
                utcnow(),
            ),
        )
        finding_id = int(cur.lastrowid or 0)
        is_new = True
    con.execute(
        """INSERT INTO finding_runs (run_id, finding_id, is_new) VALUES (?, ?, ?)
           ON CONFLICT(run_id, finding_id) DO UPDATE SET is_new = MAX(is_new, excluded.is_new)""",
        (run_id, finding_id, int(is_new)),
    )
    return finding_id, is_new


def run_findings(con: sqlite3.Connection, run_id: str) -> list[dict[str, Any]]:
    rows = con.execute(
        """SELECT f.*, fr.is_new, a.value AS asset_value, a.kind AS asset_kind,
                  v.verdict, v.confidence, v.band, v.reasoning, v.counter_evidence,
                  v.next_step, v.validated, v.model AS verdict_model
             FROM finding_runs fr
             JOIN findings f ON f.id = fr.finding_id
             LEFT JOIN assets a ON a.id = f.asset_id
             LEFT JOIN llm_verdicts v ON v.finding_id = f.id AND v.run_id = fr.run_id
            WHERE fr.run_id = ?
            ORDER BY CASE lower(COALESCE(f.severity,'info'))
                       WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                       WHEN 'low' THEN 3 ELSE 4 END,
                     f.title""",
        (run_id,),
    ).fetchall()
    return _rows(rows)


def get_finding(con: sqlite3.Connection, finding_id: int) -> dict[str, Any] | None:
    row = con.execute(
        """SELECT f.*, a.value AS asset_value FROM findings f
             LEFT JOIN assets a ON a.id = f.asset_id WHERE f.id = ?""",
        (finding_id,),
    ).fetchone()
    return _row(row)


def add_verdict(
    con: sqlite3.Connection,
    finding_id: int,
    run_id: str,
    *,
    provider: str | None,
    model: str | None,
    verdict: str,
    confidence: int,
    band: str,
    reasoning: str = "",
    counter_evidence: str = "",
    next_step: str = "",
    tokens_in: int = 0,
    tokens_out: int = 0,
    cost_usd: float = 0.0,
) -> None:
    con.execute(
        """INSERT INTO llm_verdicts (finding_id, run_id, provider, model, verdict, confidence,
                                     band, reasoning, counter_evidence, next_step,
                                     tokens_in, tokens_out, cost_usd, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(finding_id, run_id) DO UPDATE SET
               provider=excluded.provider, model=excluded.model, verdict=excluded.verdict,
               confidence=excluded.confidence, band=excluded.band,
               reasoning=excluded.reasoning, counter_evidence=excluded.counter_evidence,
               next_step=excluded.next_step, tokens_in=excluded.tokens_in,
               tokens_out=excluded.tokens_out, cost_usd=excluded.cost_usd""",
        (
            finding_id, run_id, provider, model, verdict, confidence, band,
            reasoning, counter_evidence, next_step, tokens_in, tokens_out, cost_usd, utcnow(),
        ),
    )
    con.commit()


def set_verdict_validation(con: sqlite3.Connection, finding_id: int, validated: str | None) -> int:
    cur = con.execute(
        "UPDATE llm_verdicts SET validated = ? WHERE finding_id = ?",
        (validated, finding_id),
    )
    con.commit()
    return cur.rowcount


def calibration(con: sqlite3.Connection, program_id: int | None = None) -> list[dict[str, Any]]:
    """How often model confidence bands were actually right."""
    where = "" if program_id is None else "WHERE f.program_id = ?"
    params: tuple[Any, ...] = () if program_id is None else (program_id,)
    rows = con.execute(
        f"""SELECT v.band,
                   COUNT(*) AS total,
                   SUM(CASE WHEN v.validated = 'confirmed' THEN 1 ELSE 0 END) AS confirmed,
                   SUM(CASE WHEN v.validated = 'false-positive' THEN 1 ELSE 0 END) AS rejected
              FROM llm_verdicts v JOIN findings f ON f.id = v.finding_id
              {where}
             GROUP BY v.band""",
        params,
    ).fetchall()
    return _rows(rows)


# --- tool runs / audit ----------------------------------------------------


def add_tool_run(con: sqlite3.Connection, run_id: str, **fields: Any) -> None:
    con.execute(
        """INSERT INTO tool_runs (run_id, tool, status, command, exit_code, duration,
                                  assets_found, findings_found, skipped_scope, message,
                                  output_path, started_at, finished_at)
           VALUES (:run_id, :tool, :status, :command, :exit_code, :duration,
                   :assets_found, :findings_found, :skipped_scope, :message,
                   :output_path, :started_at, :finished_at)""",
        {
            "run_id": run_id,
            "tool": fields.get("tool", "?"),
            "status": fields.get("status"),
            "command": json.dumps(fields.get("command") or []),
            "exit_code": fields.get("exit_code"),
            "duration": fields.get("duration"),
            "assets_found": fields.get("assets_found", 0),
            "findings_found": fields.get("findings_found", 0),
            "skipped_scope": fields.get("skipped_scope", 0),
            "message": fields.get("message"),
            "output_path": fields.get("output_path"),
            "started_at": fields.get("started_at"),
            "finished_at": fields.get("finished_at"),
        },
    )
    con.commit()


def tool_runs(con: sqlite3.Connection, run_id: str) -> list[dict[str, Any]]:
    return _rows(con.execute("SELECT * FROM tool_runs WHERE run_id = ? ORDER BY id", (run_id,)).fetchall())


def audit(con: sqlite3.Connection, action: str, detail: str = "", run_id: str | None = None) -> None:
    con.execute(
        "INSERT INTO audit (ts, run_id, action, detail) VALUES (?, ?, ?, ?)",
        (utcnow(), run_id, action, detail),
    )
    con.commit()


def audit_log(con: sqlite3.Connection, limit: int = 100) -> list[dict[str, Any]]:
    return _rows(con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall())
