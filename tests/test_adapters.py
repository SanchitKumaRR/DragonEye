"""Full pipeline test with fake, input-driven tool binaries.

This is the test that actually exercises adapters, parsing, ingestion, finding
fingerprints and report rendering - none of which run on a machine without the
ProjectDiscovery stack installed.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from dragoneye import db
from dragoneye.config import Config
from dragoneye.llm.triage import triage_run
from dragoneye.pipeline import load_context, start_run
from dragoneye.report import build_report

# Every fake honours the real argv shape (-o OUT, and -l/-list/-dL for input),
# so the test exercises the same command lines production uses.
SUBFINDER = """#!/bin/sh
out=""; prev=""
for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
cat > "$out" <<'EOF'
sub.acme.example
outsider.evil.example
private.acme.example
EOF
"""

DNSX = """#!/bin/sh
in=""; out=""; prev=""
for a in "$@"; do
  [ "$prev" = "-l" ] && in="$a"
  [ "$prev" = "-o" ] && out="$a"
  prev="$a"
done
: > "$out"
while read -r host; do
  [ -z "$host" ] && continue
  case "$host" in
    private.acme.example) ip=10.0.0.5 ;;
    *) ip=93.184.216.34 ;;
  esac
  echo "$host [$ip]" >> "$out"
done < "$in"
"""

HTTPX = """#!/bin/sh
in=""; out=""; prev=""
for a in "$@"; do
  [ "$prev" = "-l" ] && in="$a"
  [ "$prev" = "-o" ] && out="$a"
  prev="$a"
done
: > "$out"
while read -r host; do
  [ -z "$host" ] && continue
  printf '{"url":"https://%s","host":"%s","status_code":200,"title":"Acme","tech":["nginx"],"webserver":"nginx"}\\n' "$host" "$host" >> "$out"
done < "$in"
"""

KATANA = """#!/bin/sh
in=""; out=""; prev=""
for a in "$@"; do
  [ "$prev" = "-list" ] && in="$a"
  [ "$prev" = "-o" ] && out="$a"
  prev="$a"
done
: > "$out"
while read -r url; do
  [ -z "$url" ] && continue
  echo "$url/admin" >> "$out"
  echo "$url/admin" >> "$out"
done < "$in"
"""

NUCLEI = """#!/bin/sh
in=""; out=""; prev=""
for a in "$@"; do
  [ "$prev" = "-l" ] && in="$a"
  [ "$prev" = "-o" ] && out="$a"
  prev="$a"
done
: > "$out"
while read -r url; do
  [ -z "$url" ] && continue
  case "$url" in
    */admin)
      printf '{"template-id":"exposed-admin","info":{"name":"Exposed Admin Panel","severity":"high","tags":["panel"]},"host":"%s","matched-at":"%s","matcher-name":"word"}\\n' "$url" "$url" >> "$out" ;;
    *api*)
      : ;;
    *)
      printf '{"template-id":"tech-detect","info":{"name":"Nginx Detect","severity":"info"},"host":"%s","matched-at":"%s","matcher-name":"word"}\\n' "$url" "$url" >> "$out" ;;
  esac
done < "$in"
# A scanner finding on a host the scope engine never approved must be dropped.
printf '{"template-id":"out-of-scope","info":{"name":"Out Of Scope Finding","severity":"critical"},"host":"outsider.evil.example","matched-at":"https://outsider.evil.example/x"}\\n' >> "$out"
"""


@pytest.fixture()
def fake_tools(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (
        ("subfinder", SUBFINDER),
        ("dnsx", DNSX),
        ("httpx", HTTPX),
        ("katana", KATANA),
        ("nuclei", NUCLEI),
    ):
        path = bin_dir / name
        path.write_text(body)
        path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    con = db.connect(tmp_path / "test.db")
    yield con
    con.close()


def _program(con):
    program_id = db.add_program(
        con,
        "acme",
        ["acme.example", "93.184.216.0/24"],
        ["internal.acme.example"],
    )
    return db.get_program(con, program_id)


def test_full_run_with_fake_tools(fake_tools):
    con = fake_tools
    cfg = Config()
    cfg.llm.usage = "off"

    result = start_run(con, _program(con), cfg, echo=lambda _m: None)
    assert result["status"] == "done"

    assets = {a["value"]: a for a in db.run_assets(con, result["id"])}
    assert "acme.example" in assets
    assert "sub.acme.example" in assets
    assert "https://sub.acme.example" in assets
    assert "https://sub.acme.example/admin" in assets
    # scope enforcement: never stored
    assert "outsider.evil.example" not in assets
    # resolved to a private IP -> dropped even though the name is in scope
    assert "private.acme.example" not in assets

    findings = db.run_findings(con, result["id"])
    assert len(findings) == 4
    titles = {f["title"] for f in findings}
    assert "Exposed Admin Panel" in titles
    assert "Out Of Scope Finding" not in titles
    high = [f for f in findings if f["severity"] == "high"]
    assert len(high) == 2
    assert any(f["asset_value"] == "https://sub.acme.example/admin" for f in high)
    assert len(high[0]["fingerprint"]) == 32
    assert all(f["is_new"] == 1 for f in findings)

    stats = result["stats"]
    assert stats["skipped_scope"] >= 2
    assert stats["scope_rejections"] >= 2

    audit_actions = {row["action"] for row in db.run_audit(con, result["id"])}
    assert {"run_start", "scope_loaded", "scope_reject", "run_finish", "scope_summary"} <= audit_actions
    rejected = db.run_audit(con, result["id"], "scope_reject")
    assert any("outsider.evil.example" in (row["detail"] or "") for row in rejected)

    reports = result["report"]
    assert Path(reports["html"]).exists()
    html = Path(reports["html"]).read_text()
    assert "Exposed Admin Panel" in html
    assert "&amp;mdash;" not in html
    assert "Missing tools" not in html  # all five are present
    assert "Scope rejections" in html
    assert "outsider.evil.example" in html

    payload = json.loads(Path(reports["json"]).read_text())
    assert payload["run"]["status"] == "done"
    assert len(payload["findings"]) == 4
    assert payload["counts"]["high"] == 2
    assert any(t["status"] == "ok" for t in payload["tools"])


def test_second_run_dedupes_and_diffs(fake_tools):
    con = fake_tools
    cfg = Config()
    program = _program(con)
    first = start_run(con, program, cfg, echo=lambda _m: None)
    second = start_run(con, program, cfg, echo=lambda _m: None)

    findings = db.run_findings(con, second["id"])
    assert len(findings) == 4
    assert all(f["is_new"] == 0 for f in findings)
    assert db.diff_assets(con, int(program["id"]), second["id"]) == []
    assert first["id"] != second["id"]


def test_out_of_scope_ip_dropped_by_deny_cidr(fake_tools):
    con = fake_tools
    program_id = db.add_program(
        con,
        "cidr",
        ["acme.example", "93.184.216.0/24"],
        ["93.184.216.0/24"],
    )
    program = db.get_program(con, program_id)
    result = start_run(con, program, Config(), echo=lambda _m: None)
    values = {a["value"] for a in db.run_assets(con, result["id"])}
    assert "sub.acme.example" not in values
    assert result["stats"]["skipped_scope"] >= 1


class _MockLLM:
    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.payload = b"{}"

    def _respond(self, content: str) -> None:
        self.payload = json.dumps(
            {
                "choices": [{"message": {"content": content}}],
                "usage": {"prompt_tokens": 120, "completion_tokens": 40},
            }
        ).encode()

    def handler(self):
        outer = self

        from http.server import BaseHTTPRequestHandler

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("content-length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                outer.calls.append(body)
                if len(outer.calls) == 1:
                    outer._respond('{"action":"search","query":"admin"}')
                else:
                    outer._respond(
                        json.dumps(
                            {
                                "verdict": "likely",
                                "confidence": 72,
                                "reasoning": "HTTP 200 with an admin title and a crawlable path.",
                                "counter_evidence": "Could be a decoy page with no auth bypass.",
                                "next_step": "curl the URL and confirm it renders admin content.",
                                "needs_more_data": False,
                            }
                        )
                    )
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(outer.payload)))
                self.end_headers()
                self.wfile.write(outer.payload)

            def log_message(self, *_args):
                return

        return Handler


def test_triage_with_mock_model_and_search_round(fake_tools):
    import threading
    from http.server import ThreadingHTTPServer

    con = fake_tools
    cfg = Config()
    program = _program(con)
    run = start_run(con, program, cfg, echo=lambda _m: None)

    ctx = load_context(con, run["id"], cfg, echo=lambda _m: None)
    ctx.llm_usage = "balanced"

    mock = _MockLLM()
    server = ThreadingHTTPServer(("127.0.0.1", 0), mock.handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        cfg.llm.base_url = f"http://127.0.0.1:{server.server_address[1]}/v1"
        summary = triage_run(ctx, provider="ollama", model="mock-model")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert summary["assessed"] == 4
    assert len(mock.calls) >= 2
    assert mock.calls[0]["model"] == "mock-model"
    # first call must have been about the highest-severity finding, not the first row
    first_user = mock.calls[0]["messages"][1]["content"]
    assert "Exposed Admin Panel" in first_user

    findings = db.run_findings(con, run["id"])
    verdicts = [f for f in findings if f.get("verdict")]
    assert len(verdicts) == 4
    assert all(v["verdict"] == "likely" for v in verdicts)
    assert all(v["confidence"] == 72 and v["band"] == "medium" for v in verdicts)
    assert summary["cost_usd"] == 0.0
    assert summary["tokens_in"] > 0
    # Search and final-answer rounds are both billed and both accounted for.
    assert summary["tokens_in"] == 120 * len(mock.calls)
    assert summary["price_known"] is False

    # re-render so the report includes verdicts added after the run
    build_report(con, run["id"], Path(run["outdir"]))
    report = Path(run["report"]["html"]).read_text()
    assert "likely" in report
    assert "72%" in report


def test_triage_skips_without_key(fake_tools):
    con = fake_tools
    cfg = Config()
    program = _program(con)
    run = start_run(con, program, cfg, echo=lambda _m: None)
    ctx = load_context(con, run["id"], cfg, echo=lambda _m: None)
    ctx.llm_usage = "low"
    cfg.llm.base_url = None
    summary = triage_run(ctx, provider="openai", model="gpt-4o-mini")
    assert summary["reason"].startswith("no API key")
    assert summary["assessed"] == 0
