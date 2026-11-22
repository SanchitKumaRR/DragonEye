"""Staged, resumable recon pipeline.

Stage order (each stage is skippable and cached per run):

    seed -> subdomains -> resolve -> probe -> crawl -> scan -> triage -> report

Invariants:
  * Only in-scope assets are ever stored or fed to a tool.
  * A missing tool is reported, never fatal.
  * A run always produces a report, even if a stage failed.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import sqlite3
import time
import traceback
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import db
from .config import Config, runs_dir
from .scope import Scope, ScopeError, normalize_host
from .tools import get_adapter
from .tools import status as tool_status
from .tools.runner import execute

STAGES = ("seed", "subdomains", "resolve", "probe", "crawl", "scan", "triage")


@dataclass
class RunContext:
    con: sqlite3.Connection
    cfg: Config
    program: dict[str, Any]
    scope: Scope
    run_id: str
    outdir: Path
    dry_run: bool = False
    passive_only: bool = False
    llm_usage: str = "off"
    echo: Callable[[str], None] = print
    assets: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    stages_done: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    log_handle: Any = None

    @property
    def raw_dir(self) -> Path:
        return self.outdir / "raw"

    def log(self, message: str) -> None:
        line = f"[{time.strftime('%H:%M:%S')}] {message}"
        if self.log_handle:
            self.log_handle.write(line + "\n")
            self.log_handle.flush()
        self.echo(line)

    def note(self, key: str, value: Any) -> None:
        self.stats[key] = value


def start_run(
    con: sqlite3.Connection,
    program: dict[str, Any],
    cfg: Config,
    *,
    dry_run: bool = False,
    passive_only: bool | None = None,
    llm_usage: str | None = None,
    provider: str | None = None,
    model: str | None = None,
    resume_run_id: str | None = None,
    run_id: str | None = None,
    echo: Callable[[str], None] = print,
) -> dict[str, Any]:
    """Create (or resume) a run and execute the pipeline synchronously."""
    allow_private = cfg.allow_private
    scope = Scope(
        program.get("in_scope") or [],
        program.get("out_of_scope") or [],
        allow_private=allow_private,
    )

    passive = cfg.passive_only if passive_only is None else passive_only
    usage = (llm_usage or cfg.llm.usage or "off").lower()
    provider = provider or cfg.llm.provider
    model = model or cfg.llm.model

    run_id = resume_run_id or run_id or uuid.uuid4().hex[:12]
    outdir = runs_dir() / run_id
    (outdir / "raw").mkdir(parents=True, exist_ok=True)

    if resume_run_id:
        run = db.get_run(con, run_id)
        if not run:
            raise ValueError(f"run {run_id} not found")
        ctx_usage = run.get("llm_usage") or usage
        ctx = RunContext(
            con=con,
            cfg=cfg,
            program=program,
            scope=scope,
            run_id=run_id,
            outdir=outdir,
            dry_run=bool(run["dry_run"]),
            passive_only=bool(run["passive_only"]),
            llm_usage=ctx_usage,
            echo=echo,
            stages_done=list((run.get("state") or {}).get("stages", [])),
            stats=dict(run.get("stats") or {}),
        )
        _reload_assets(ctx)
        if ctx.echo is print:
            ctx.log(f"resuming run {run_id} (done: {', '.join(ctx.stages_done) or 'none'})")
    else:
        db.add_run(
            con,
            run_id,
            int(program["id"]),
            str(outdir),
            dry_run=dry_run,
            passive_only=passive,
            llm_usage=usage,
            llm_provider=provider,
            llm_model=model,
        )
        ctx = RunContext(
            con=con,
            cfg=cfg,
            program=program,
            scope=scope,
            run_id=run_id,
            outdir=outdir,
            dry_run=dry_run,
            passive_only=passive,
            llm_usage=usage,
            echo=echo,
        )

    ctx.stats.setdefault("program", program["name"])
    ctx.stats.setdefault("started", time.time())
    ctx.stats.setdefault("allow_private", allow_private)
    ctx.stats.setdefault("skipped_scope", 0)
    ctx.stats.setdefault("new_assets", 0)
    ctx.stats.setdefault("new_findings", 0)
    ctx.stats["llm"] = {
        "usage": ctx.llm_usage,
        "provider": provider,
        "model": model,
        "calls": ctx.stats.get("llm", {}).get("calls", 0),
        "tokens_in": ctx.stats.get("llm", {}).get("tokens_in", 0),
        "tokens_out": ctx.stats.get("llm", {}).get("tokens_out", 0),
        "cost_usd": ctx.stats.get("llm", {}).get("cost_usd", 0.0),
    }

    log_path = outdir / "run.log"
    ctx.log_handle = open(log_path, "a", encoding="utf-8")

    db.audit(con, "run_start", f"program={program['name']} dry_run={dry_run}", run_id)
    db.audit(con, "scope_loaded", json.dumps(scope.summary())[:1200], run_id)
    ctx.log(
        f"DragonEye run {run_id} | program={program['name']} | "
        f"{'DRY RUN' if ctx.dry_run else 'live'} | "
        f"{'passive-only' if ctx.passive_only else 'passive+active'} | llm={ctx.llm_usage}"
    )
    try:
        _execute(ctx, provider, model)
        status = "done"
    except Exception as exc:  # noqa: BLE001 - always keep a report
        status = "failed"
        ctx.log(f"!! run failed: {exc}")
        ctx.log(traceback.format_exc(limit=3))
        db.update_run(con, run_id, error=str(exc))
    finally:
        report_paths = _finalise(ctx, status)

    run = db.get_run(con, run_id) or {}
    run["report"] = report_paths
    return run


def _execute(ctx: RunContext, provider: str, model: str) -> None:
    _stage(ctx, "seed", _stage_seed)
    _stage(ctx, "subdomains", lambda c: _stage_subdomains(c), passive=False)
    _stage(ctx, "resolve", _stage_resolve)
    _stage(ctx, "probe", _stage_probe)
    _stage(ctx, "crawl", _stage_crawl)
    _stage(ctx, "scan", _stage_scan)
    if ctx.llm_usage == "off":
        ctx.log("- triage: LLM disabled (usage=off)")
        ctx.note("triage", "disabled")
    else:
        _stage(ctx, "triage", lambda c: _stage_triage(c, provider, model))


def _stage(
    ctx: RunContext,
    name: str,
    fn: Callable[[RunContext], None],
    *,
    passive: bool | None = None,
) -> None:
    if name in ctx.stages_done:
        ctx.log(f"- {name}: already done (resumed)")
        return
    if passive is False and ctx.passive_only:
        ctx.log(f"- {name}: skipped (passive-only)")
        return
    ctx.log(f"> {name}")
    started = time.time()
    fn(ctx)
    ctx.stages_done.append(name)
    ctx.note(f"{name}_seconds", round(time.time() - started, 2))
    db.update_run(
        ctx.con,
        ctx.run_id,
        state={"stages": ctx.stages_done},
        stats=ctx.stats,
    )


# --- stages ---------------------------------------------------------------


def _stage_seed(ctx: RunContext) -> None:
    seeds = ctx.scope.roots()
    if not seeds:
        ctx.log("  ! no seedable domain/IP rules in scope (CIDR/regex only) - nothing to expand")
    assets = []
    for seed in seeds:
        try:
            decision = ctx.scope.check(seed)
        except ScopeError as exc:
            _audit_scope_reject(ctx, seed, f"invalid seed: {exc}", "scope")
            continue
        if not decision.allowed:
            _audit_scope_reject(ctx, seed, decision.reason, "scope", decision.rule)
            continue
        kind = "ip" if _is_ip(seed) else "domain"
        assets.append({"kind": kind, "value": seed, "meta": {"source": "scope", "seed": True}})
    _ingest(ctx, assets, "scope")
    ctx.note("seeds", len(assets))


def _hosts(ctx: RunContext) -> list[str]:
    """Every host-looking asset (domains and bare IPs), in insertion order."""
    return [
        a["value"]
        for a in ctx.assets.values()
        if a["kind"] in ("domain", "ip")
    ]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _resolved_map(ctx: RunContext) -> dict[str, list[str]]:
    """Hostname -> DNS answers, for scope checks that allow CIDR/IP rules."""
    out: dict[str, list[str]] = {}
    for asset in ctx.assets.values():
        if asset.get("kind") != "domain":
            continue
        ips = list((asset.get("meta") or {}).get("ips") or [])
        if not ips:
            continue
        try:
            out[normalize_host(asset["value"])] = ips
        except ScopeError:
            continue
    return out


def _resolved_for_host(ctx: RunContext, value: str) -> list[str]:
    try:
        host = normalize_host(value)
    except ScopeError:
        return []
    for (kind, item), asset in ctx.assets.items():
        if kind != "domain":
            continue
        try:
            if normalize_host(item) != host:
                continue
        except ScopeError:
            continue
        return list((asset.get("meta") or {}).get("ips") or [])
    return []


# Cap the number of individual rejections persisted; the count is always kept.
MAX_AUDIT_REJECTIONS = 200


def _audit_scope_reject(
    ctx: RunContext,
    target: str,
    reason: str,
    source: str,
    rule: str | None = None,
) -> None:
    count = int(ctx.stats.get("scope_rejections", 0)) + 1
    ctx.stats["scope_rejections"] = count
    if count <= MAX_AUDIT_REJECTIONS:
        detail = f"{source}: {target}: {reason}"
        if rule:
            detail += f" (rule {rule!r})"
        db.audit(ctx.con, "scope_reject", detail[:1000], ctx.run_id)


def _stage_subdomains(ctx: RunContext) -> None:
    adapter = get_adapter("subfinder")
    domains = [a["value"] for a in ctx.assets.values() if a["kind"] == "domain"]
    if not adapter or not domains:
        ctx.log("  - subdomains: nothing to enumerate")
        return
    result = execute(
        adapter,
        domains,
        workdir=ctx.raw_dir / "subfinder",
        scope=ctx.scope,
        resolved=_resolved_map(ctx),
        concurrency=ctx.cfg.concurrency,
        log=ctx.log,
        dry_run=ctx.dry_run,
        passive_only=ctx.passive_only,
        request_rate=ctx.cfg.request_rate,
        user_agent=ctx.cfg.user_agent,
    )
    _record_tool(ctx, result)
    _ingest(ctx, result.assets, "subfinder")


def _stage_resolve(ctx: RunContext) -> None:
    adapter = get_adapter("dnsx")
    domains = _hosts(ctx)
    if not adapter or not domains:
        ctx.log("  - resolve: nothing to resolve")
        return
    if ctx.passive_only:
        ctx.log("  - resolve: skipped (passive-only)")
        return
    result = execute(
        adapter,
        domains,
        workdir=ctx.raw_dir / "dnsx",
        scope=ctx.scope,
        resolved=_resolved_map(ctx),
        concurrency=ctx.cfg.concurrency,
        log=ctx.log,
        dry_run=ctx.dry_run,
        passive_only=ctx.passive_only,
        request_rate=ctx.cfg.request_rate,
        user_agent=ctx.cfg.user_agent,
    )
    _record_tool(ctx, result)
    _ingest(ctx, result.assets, "dnsx")


def _stage_probe(ctx: RunContext) -> None:
    adapter = get_adapter("httpx")
    hosts = _hosts(ctx)
    if not adapter or not hosts:
        ctx.log("  - probe: nothing to probe")
        return
    if ctx.passive_only:
        ctx.log("  - probe: skipped (passive-only)")
        return
    extra = ["-ports", ctx.cfg.probe_ports] if ctx.cfg.probe_ports else []
    result = execute(
        adapter,
        hosts,
        workdir=ctx.raw_dir / "httpx",
        scope=ctx.scope,
        resolved=_resolved_map(ctx),
        concurrency=ctx.cfg.concurrency,
        log=ctx.log,
        dry_run=ctx.dry_run,
        passive_only=ctx.passive_only,
        request_rate=ctx.cfg.request_rate,
        user_agent=ctx.cfg.user_agent,
        extra_args=extra,
    )
    _record_tool(ctx, result)
    _ingest(ctx, result.assets, "httpx")


def _stage_crawl(ctx: RunContext) -> None:
    adapter = get_adapter("katana")
    urls = [a["value"] for a in ctx.assets.values() if a["kind"] == "url"]
    if not adapter or not urls:
        ctx.log("  - crawl: no live URLs to crawl")
        return
    if ctx.passive_only:
        ctx.log("  - crawl: skipped (passive-only)")
        return
    result = execute(
        adapter,
        urls,
        workdir=ctx.raw_dir / "katana",
        scope=ctx.scope,
        resolved=_resolved_map(ctx),
        concurrency=ctx.cfg.concurrency,
        log=ctx.log,
        dry_run=ctx.dry_run,
        passive_only=ctx.passive_only,
        request_rate=max(5, ctx.cfg.request_rate // 2),
        user_agent=ctx.cfg.user_agent,
    )
    _record_tool(ctx, result)
    _ingest(ctx, result.assets, "katana")


def _stage_scan(ctx: RunContext) -> None:
    adapter = get_adapter("nuclei")
    urls = [a["value"] for a in ctx.assets.values() if a["kind"] == "url"]
    hosts = _hosts(ctx)
    targets = urls or hosts
    if not adapter or not targets:
        ctx.log("  - scan: nothing to scan")
        return
    if ctx.passive_only:
        ctx.log("  - scan: skipped (passive-only)")
        return
    result = execute(
        adapter,
        targets,
        workdir=ctx.raw_dir / "nuclei",
        scope=ctx.scope,
        resolved=_resolved_map(ctx),
        concurrency=ctx.cfg.concurrency,
        log=ctx.log,
        dry_run=ctx.dry_run,
        passive_only=ctx.passive_only,
        request_rate=ctx.cfg.request_rate,
        user_agent=ctx.cfg.user_agent,
        extra_args=["-severity", ",".join(ctx.cfg.nuclei_severities)],
    )
    _record_tool(ctx, result)
    for item in result.findings:
        _ingest_finding(ctx, item, "nuclei", result.output_path)


def _stage_triage(ctx: RunContext, provider: str, model: str) -> None:
    if not ctx.findings:
        ctx.log("  - triage: no findings to assess")
        ctx.note("triage", "no findings")
        return
    from .llm.triage import triage_run

    summary = triage_run(ctx, provider=provider, model=model)
    ctx.note("triage", summary)
    ctx.log(
        f"  + triage: {summary.get('assessed', 0)} assessed, "
        f"{summary.get('skipped', 0)} skipped, "
        f"{summary.get('cost_usd', 0):.4f} USD"
    )


# --- ingestion ------------------------------------------------------------


def _ingest(
    ctx: RunContext,
    assets: list[dict[str, Any]],
    tool: str,
) -> list[dict[str, Any]]:
    stored: list[dict[str, Any]] = []
    for item in assets:
        kind = item.get("kind") or "domain"
        value = (item.get("value") or "").strip()
        if not value:
            continue

        meta = dict(item.get("meta") or {})
        resolved = [str(ip) for ip in (meta.get("ips") or [])]
        if not resolved:
            resolved = _resolved_for_host(ctx, value)

        try:
            decision = ctx.scope.check(value, resolved)
        except ScopeError as exc:
            ctx.stats["skipped_scope"] = ctx.stats.get("skipped_scope", 0) + 1
            _audit_scope_reject(ctx, value, f"invalid asset: {exc}", tool)
            ctx.log(f"    · dropped invalid asset {value!r}: {exc}")
            _drop_asset(ctx, kind, value)
            continue
        if not decision.allowed:
            ctx.stats["skipped_scope"] = ctx.stats.get("skipped_scope", 0) + 1
            _audit_scope_reject(ctx, value, decision.reason, tool, decision.rule)
            _drop_asset(ctx, kind, value)
            continue

        bad, reason = _screen_resolved_ips(ctx, resolved)
        if bad:
            ctx.stats["skipped_scope"] = ctx.stats.get("skipped_scope", 0) + 1
            _audit_scope_reject(ctx, value, reason, tool)
            ctx.log(f"    · dropped {value}: {reason}")
            _drop_asset(ctx, kind, value)
            continue

        current = ctx.assets.get((kind, value))
        if current:
            current["meta"].update(meta)
            continue

        asset_id, is_new = db.upsert_asset(
            ctx.con,
            int(ctx.program["id"]),
            ctx.run_id,
            kind,
            value,
            source_tool=tool,
            meta=meta,
            in_scope=True,
        )
        record = {
            "id": asset_id,
            "kind": kind,
            "value": value,
            "meta": meta,
            "is_new": is_new,
        }
        ctx.assets[(kind, value)] = record
        stored.append(record)
        if is_new:
            ctx.stats["new_assets"] = ctx.stats.get("new_assets", 0) + 1
            if kind == "domain":
                ctx.log(f"    + new asset {value}")
    return stored


def _ingest_finding(
    ctx: RunContext, item: dict[str, Any], tool: str, evidence_path: str | None
) -> None:
    matched = item.get("matched_at") or item.get("host") or ""
    template_id = item.get("template_id") or "unknown"

    if matched:
        resolved = _resolved_for_host(ctx, matched)
        try:
            decision = ctx.scope.check(matched, resolved)
        except ScopeError as exc:
            ctx.stats["skipped_scope"] = ctx.stats.get("skipped_scope", 0) + 1
            _audit_scope_reject(ctx, matched, f"invalid finding target: {exc}", tool)
            ctx.log(f"    · dropped finding on invalid target {matched!r}: {exc}")
            return
        if not decision.allowed:
            ctx.stats["skipped_scope"] = ctx.stats.get("skipped_scope", 0) + 1
            _audit_scope_reject(ctx, matched, decision.reason, f"{tool} finding", decision.rule)
            ctx.log(f"    · dropped out-of-scope finding @ {matched}")
            return

    try:
        host = normalize_host(matched) if matched else ""
    except ScopeError:
        host = ""
    fingerprint = hashlib.sha256(
        f"{ctx.program['id']}|{tool}|{template_id}|{host}|{matched}".lower().encode()
    ).hexdigest()[:32]

    asset_id = _asset_id_for(ctx, matched, host)
    finding_id, is_new = db.upsert_finding(
        ctx.con,
        int(ctx.program["id"]),
        ctx.run_id,
        fingerprint,
        tool=tool,
        template_id=template_id,
        title=item.get("title"),
        severity=item.get("severity"),
        asset_id=asset_id,
        evidence_path=evidence_path,
        raw=item.get("raw") or item,
    )
    record = {
        "id": finding_id,
        "fingerprint": fingerprint,
        "tool": tool,
        "template_id": template_id,
        "title": item.get("title") or template_id,
        "severity": (item.get("severity") or "info").lower(),
        "asset": matched or host,
        "evidence_path": evidence_path,
        "raw": item.get("raw") or item,
        "is_new": is_new,
    }
    ctx.findings.append(record)
    if is_new:
        ctx.stats["new_findings"] = ctx.stats.get("new_findings", 0) + 1
        ctx.log(f"    * new finding [{record['severity']}] {record['title']} @ {record['asset']}")


def _drop_asset(ctx: RunContext, kind: str, value: str) -> None:
    """Remove a previously-seen asset from this run and mark it out of scope."""
    existing = ctx.assets.pop((kind, value), None)
    if existing:
        db.set_asset_scope(ctx.con, int(existing["id"]), False)


def _screen_resolved_ips(ctx: RunContext, ips: list[str]) -> tuple[bool, str]:
    for raw in ips:
        try:
            decision = ctx.scope.screen_ip(str(raw))
        except ScopeError:
            continue
        if not decision.allowed:
            return True, decision.reason
    return False, ""


def _asset_id_for(ctx: RunContext, matched: str, host: str) -> int | None:
    # Exact match wins, so a finding on /admin is attached to /admin and not to
    # the parent URL that happens to share the same host.
    for (_, value), record in ctx.assets.items():
        if value == matched:
            return record["id"]
    if host:
        for (kind, value), record in ctx.assets.items():
            if kind not in ("url", "domain"):
                continue
            try:
                if normalize_host(value) == host:
                    return record["id"]
            except ScopeError:
                continue
    if not matched:
        return None
    try:
        if not ctx.scope.check(matched).allowed:
            return None
    except ScopeError:
        return None
    asset_id, _ = db.upsert_asset(
        ctx.con, int(ctx.program["id"]), ctx.run_id, "url", matched, source_tool="nuclei"
    )
    ctx.assets[("url", matched)] = {
        "id": asset_id,
        "kind": "url",
        "value": matched,
        "meta": {},
        "is_new": False,
    }
    return asset_id


def _record_tool(ctx: RunContext, result: Any) -> None:
    for decision in getattr(result, "rejected", []) or []:
        _audit_scope_reject(
            ctx,
            getattr(decision, "host", str(decision)),
            getattr(decision, "reason", ""),
            result.tool,
            getattr(decision, "rule", None),
        )
    db.add_tool_run(
        ctx.con,
        ctx.run_id,
        tool=result.tool,
        status=result.status,
        command=result.command,
        exit_code=result.exit_code,
        duration=result.duration,
        assets_found=len(result.assets),
        findings_found=len(result.findings),
        skipped_scope=result.skipped_out_of_scope,
        message=result.message,
        output_path=result.output_path,
        started_at=db.utcnow(),
        finished_at=db.utcnow(),
    )
    if result.status == "missing":
        ctx.stats.setdefault("missing_tools", []).append(result.tool)


def _reload_assets(ctx: RunContext) -> None:
    for row in db.run_assets(ctx.con, ctx.run_id):
        if row["in_scope"]:
            ctx.assets[(row["kind"], row["value"])] = {
                "id": row["id"],
                "kind": row["kind"],
                "value": row["value"],
                "meta": row.get("meta") or {},
                "is_new": bool(row.get("is_new")),
            }
    for finding in db.run_findings(ctx.con, ctx.run_id):
        ctx.findings.append(
            {
                "id": finding["id"],
                "fingerprint": finding["fingerprint"],
                "tool": finding["tool"],
                "template_id": finding.get("template_id"),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "asset": finding.get("asset_value"),
                "evidence_path": finding.get("evidence_path"),
                "raw": finding.get("raw"),
                "is_new": bool(finding.get("is_new")),
            }
        )


# --- finishing ------------------------------------------------------------


def _finalise(ctx: RunContext, status: str) -> dict[str, Any]:
    from .report import build_report

    ctx.stats["duration_seconds"] = round(time.time() - float(ctx.stats.get("started", time.time())), 1)
    ctx.stats["assets_total"] = len(ctx.assets)
    ctx.stats["findings_total"] = len(ctx.findings)
    ctx.stats["tools"] = tool_status()

    # Persist final status + stats before rendering, so the report reflects them.
    db.update_run(
        ctx.con,
        ctx.run_id,
        status=status,
        finished_at=db.utcnow(),
        state={"stages": ctx.stages_done},
        stats=ctx.stats,
    )

    try:
        paths = build_report(ctx.con, ctx.run_id, ctx.outdir)
        ctx.log(f"+ report: {paths['html']}")
    except Exception as exc:  # noqa: BLE001
        paths = {}
        ctx.log(f"! report generation failed: {exc}")

    db.audit(ctx.con, "run_finish", f"status={status}", ctx.run_id)
    db.audit(
        ctx.con,
        "scope_summary",
        f"rejected={ctx.stats.get('scope_rejections', 0)} "
        f"skipped={ctx.stats.get('skipped_scope', 0)} "
        f"assets={ctx.stats.get('assets_total', 0)}",
        ctx.run_id,
    )
    ctx.log(f"= run {ctx.run_id} {status}")

    if ctx.log_handle:
        ctx.log_handle.close()
        ctx.log_handle = None

    return paths


def load_context(con: sqlite3.Connection, run_id: str, cfg: Config, echo=print) -> RunContext:
    """Rebuild a context for a finished/partial run (used by triage/report tools)."""
    run = db.get_run(con, run_id)
    if not run:
        raise ValueError(f"run {run_id} not found")
    program = db.get_program(con, int(run["program_id"]))
    if not program:
        raise ValueError("program vanished")
    ctx = RunContext(
        con=con,
        cfg=cfg,
        program=program,
        scope=Scope(
            program.get("in_scope") or [],
            program.get("out_of_scope") or [],
            allow_private=cfg.allow_private,
        ),
        run_id=run_id,
        outdir=Path(run["outdir"]),
        echo=echo,
        llm_usage=run.get("llm_usage") or "off",
        stages_done=list((run.get("state") or {}).get("stages", [])),
        stats=dict(run.get("stats") or {}),
    )
    _reload_assets(ctx)
    return ctx


def pipeline_summary(con: sqlite3.Connection, run_id: str) -> dict[str, Any]:
    run = db.get_run(con, run_id) or {}
    findings = db.run_findings(con, run_id)
    return {
        "run": run,
        "assets": db.run_assets(con, run_id),
        "findings": findings,
        "new_findings": [f for f in findings if f.get("is_new")],
        "tools": db.tool_runs(con, run_id),
        "new_assets": db.diff_assets(con, int(run["program_id"]), run_id) if run else [],
        "calibration": db.calibration(con, int(run["program_id"])) if run else [],
    }
