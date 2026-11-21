"""LLM-assisted finding triage.

Design constraints that keep this honest:
  * verdicts are evidence-bound; the model never sees the open internet
  * the model may request local greps instead of being handed megabytes
  * every number is stored, including token cost, so calibration is measurable
  * a failure here never breaks a recon run
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .. import db
from .budgets import Budget, get_budget
from .client import LLMClient, LLMError

SYSTEM_PROMPT = """You are a triage assistant inside a bug bounty recon pipeline.

You receive ONE finding produced by an automated scanner, plus (optionally) excerpts from the raw
scan output. Judge how likely it is to be a real, reportable issue.

Hard rules:
- Use only the supplied evidence. Never invent responses, versions, or exploitation results.
- A scanner template firing is NOT proof. Consider false positives, generic/soft-404 matches,
  missing auth context, WAF pages, and whether the matched asset is actually in scope.
- Confidence is your honest certainty GIVEN the evidence, 0-100. Be conservative:
  high confidence requires direct, verifiable evidence in the excerpt.
- If the evidence is insufficient, say so (needs_more_data=true) and, if allowed, request
  exactly one local search over the raw scan output.

Reply with JSON only, no prose and no code fences:
{"verdict": "confirmed|likely|needs-manual-check|false-positive",
 "confidence": 0-100,
 "reasoning": "max 60 words, cite the evidence",
 "counter_evidence": "what would make this wrong (or 'none')",
 "next_step": "the single cheapest manual check a human should run",
 "needs_more_data": true|false}

To search the raw output instead of answering, reply with exactly:
{"action": "search", "query": "regex or literal"}

A confirmation that requires a manual step is "likely" or "needs-manual-check", never "confirmed"."""

SEVERITY_WEIGHT = {"critical": 100, "high": 70, "medium": 45, "low": 25, "info": 5, "unknown": 10}
HOT_KEYWORDS = (
    "rce", "sqli", "sql-injection", "ssrf", "lfi", "rfi", "xxe", "ssti",
    "takeover", "exposure", "disclosure", "default-login", "cve-", "auth-bypass",
    "graphql", "debug", "backup", "git-config", "env", "actuator",
)

VERDICTS = {"confirmed", "likely", "needs-manual-check", "false-positive"}


def triage_run(ctx: Any, *, provider: str, model: str) -> dict[str, Any]:
    budget = get_budget(ctx.llm_usage)
    if budget is None:
        return {"skipped": len(ctx.findings), "reason": "usage=off"}

    client = LLMClient(
        provider,
        model,
        base_url=ctx.cfg.llm.base_url,
        timeout=ctx.cfg.llm.timeout,
    )
    ok, reason = client.available()
    if not ok:
        ctx.log(f"  ! triage skipped: {reason}")
        return {"skipped": len(ctx.findings), "reason": reason, "assessed": 0, "cost_usd": 0.0}

    max_cost = ctx.cfg.llm.max_cost_usd
    index = EvidenceIndex(ctx.raw_dir)
    candidates = _rank(ctx.findings)[: budget.review_limit]
    ctx.log(f"  · triage: {len(candidates)} finding(s) queued ({budget.describe()})")

    assessed = skipped = 0
    tokens_in = tokens_out = 0
    cost = 0.0

    for finding in candidates:
        if max_cost is not None and cost >= max_cost:
            ctx.log(f"  ! triage: cost cap ${max_cost:.2f} reached, stopping")
            break
        try:
            verdict, response = _assess(client, budget, finding, index)
        except (LLMError, ValueError) as exc:
            ctx.log(f"  ! triage: {finding.get('title')!r}: {exc}")
            skipped += 1
            continue

        if response:
            tokens_in += response.tokens_in
            tokens_out += response.tokens_out
            cost += response.cost_usd

        if verdict is None:
            skipped += 1
            continue

        band = _band(int(verdict["confidence"]))
        db.add_verdict(
            ctx.con,
            int(finding["id"]),
            ctx.run_id,
            provider=client.provider.id,
            model=client.model,
            verdict=str(verdict["verdict"]),
            confidence=int(verdict["confidence"]),
            band=band,
            reasoning=str(verdict.get("reasoning") or "")[:2000],
            counter_evidence=str(verdict.get("counter_evidence") or "")[:1000],
            next_step=str(verdict.get("next_step") or "")[:500],
            tokens_in=response.tokens_in if response else 0,
            tokens_out=response.tokens_out if response else 0,
            cost_usd=response.cost_usd if response else 0.0,
        )
        finding["verdict"] = verdict["verdict"]
        finding["confidence"] = verdict["confidence"]
        finding["band"] = band
        finding["reasoning"] = verdict.get("reasoning")
        assessed += 1
        ctx.log(
            f"    ~ [{verdict['verdict']} {verdict['confidence']}%] "
            f"{finding.get('title')}"
        )

    llm_stats = ctx.stats.setdefault("llm", {})
    llm_stats.update(
        {
            "calls": int(llm_stats.get("calls", 0)) + assessed + skipped,
            "tokens_in": int(llm_stats.get("tokens_in", 0)) + tokens_in,
            "tokens_out": int(llm_stats.get("tokens_out", 0)) + tokens_out,
            "cost_usd": round(float(llm_stats.get("cost_usd", 0.0)) + cost, 6),
            "assessed": assessed,
            "budget": budget.name,
        }
    )
    return {
        "assessed": assessed,
        "skipped": skipped,
        "cost_usd": round(cost, 6),
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "budget": budget.name,
    }


def _assess(
    client: LLMClient, budget: Budget, finding: dict[str, Any], index: "EvidenceIndex"
) -> tuple[dict[str, Any] | None, Any]:
    """One finding -> verdict, allowing bounded local searches."""
    excerpt = _finding_evidence(finding, budget.evidence_chars, index)
    user = _prompt_for(finding, excerpt, budget)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]

    last_response = None
    for round_no in range(budget.max_search_rounds + 1):
        response = client.chat(
            messages,
            temperature=budget.temperature,
            max_tokens=budget.max_output_tokens,
            json_mode=True,
        )
        last_response = response

        try:
            data = _extract_json(response.text)
        except ValueError:
            # One repair attempt: ask for JSON only.
            messages.append({"role": "assistant", "content": response.text[:2000]})
            messages.append(
                {"role": "user", "content": "That was not valid JSON. Reply with the JSON object only."}
            )
            response = client.chat(
                messages,
                temperature=0.0,
                max_tokens=budget.max_output_tokens,
                json_mode=True,
            )
            last_response = response
            try:
                data = _extract_json(response.text)
            except ValueError:
                raise

        if data.get("action") == "search":
            if round_no >= budget.max_search_rounds:
                break
            query = str(data.get("query") or "").strip()
            if not query:
                break
            hits = index.search(query, limit=budget.search_results)
            messages.append({"role": "assistant", "content": json.dumps(data)[:500]})
            messages.append(
                {
                    "role": "user",
                    "content": "SEARCH RESULTS for "
                    + query
                    + ":\n"
                    + ("\n".join(hits) if hits else "(no matches)")
                    + "\n\nNow answer with the verdict JSON.",
                }
            )
            continue

        verdict = _normalise(data)
        if verdict is None:
            raise ValueError(f"model returned no usable verdict: {str(data)[:200]}")
        return verdict, last_response

    return None, last_response


def _prompt_for(finding: dict[str, Any], excerpt: str, budget: Budget) -> str:
    scope_note = "Asset already passed the program's scope filter."
    return (
        f"{scope_note}\n\n"
        f"TITLE: {finding.get('title')}\n"
        f"SEVERITY (scanner): {finding.get('severity')}\n"
        f"TOOL: {finding.get('tool')}\n"
        f"TEMPLATE: {finding.get('template_id')}\n"
        f"ASSET: {finding.get('asset')}\n"
        f"RAW MATCH: {json.dumps(finding.get('raw'))[:1200]}\n\n"
        f"RAW OUTPUT EXCERPT (may be partial):\n{excerpt[: budget.evidence_chars]}\n\n"
        "Give your verdict JSON now."
    )


def _finding_evidence(finding: dict[str, Any], limit: int, index: "EvidenceIndex") -> str:
    path = finding.get("evidence_path")
    if not path:
        return ""
    try:
        text = Path(str(path)).read_text(errors="replace")
    except OSError:
        return ""
    template = str(finding.get("template_id") or "")
    asset = str(finding.get("asset") or "")
    lines = [line for line in text.splitlines() if template and template in line]
    if not lines:
        lines = [line for line in text.splitlines() if asset and asset in line]
    if not lines:
        lines = index.search(asset or template, limit=5)
    return "\n".join(lines)[:limit]


def _rank(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def score(finding: dict[str, Any]) -> int:
        severity = (finding.get("severity") or "unknown").lower()
        total = SEVERITY_WEIGHT.get(severity, 10)
        blob = f"{finding.get('template_id')} {finding.get('title')}".lower()
        if any(keyword in blob for keyword in HOT_KEYWORDS):
            total += 30
        return total

    return sorted(findings, key=score, reverse=True)


def _normalise(data: dict[str, Any]) -> dict[str, Any] | None:
    verdict = str(data.get("verdict") or "").strip().lower()
    if verdict not in VERDICTS:
        return None
    try:
        confidence = int(float(data.get("confidence", 0)))
    except (TypeError, ValueError):
        confidence = 0
    confidence = max(0, min(100, confidence))
    return {
        "verdict": verdict,
        "confidence": confidence,
        "reasoning": str(data.get("reasoning") or ""),
        "counter_evidence": str(data.get("counter_evidence") or ""),
        "next_step": str(data.get("next_step") or ""),
        "needs_more_data": bool(data.get("needs_more_data")),
    }


def _band(confidence: int) -> str:
    if confidence >= 80:
        return "high"
    if confidence >= 55:
        return "medium"
    return "low"


def _extract_json(text: str) -> dict[str, Any]:
    """Tolerate code fences and chatty models, fail loudly otherwise."""
    raw = (text or "").strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-zA-Z]*\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end > start:
        try:
            parsed = json.loads(raw[start : end + 1])
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    raise ValueError("no JSON object found in model output")


class EvidenceIndex:
    """Bounded local grep over raw tool output - the model's only 'tool'."""

    MAX_FILE_BYTES = 4_000_000
    TEXT_SUFFIXES = {".txt", ".json", ".jsonl", ".log", ".xml", ".html", ".csv"}

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def search(self, query: str, limit: int = 10) -> list[str]:
        query = (query or "").strip()
        if not query:
            return []
        try:
            pattern = re.compile(query, re.I)
        except re.error:
            pattern = re.compile(re.escape(query), re.I)

        hits: list[str] = []
        if not self.root.exists():
            return hits
        for path in sorted(self.root.rglob("*")):
            if len(hits) >= limit:
                break
            if not path.is_file() or path.suffix.lower() not in self.TEXT_SUFFIXES:
                continue
            try:
                if path.stat().st_size > self.MAX_FILE_BYTES:
                    continue
                text = path.read_text(errors="replace")
            except OSError:
                continue
            for line_no, line in enumerate(text.splitlines(), 1):
                if pattern.search(line):
                    hits.append(f"{path.relative_to(self.root)}:{line_no}: {line[:400]}")
                    if len(hits) >= limit:
                        break
        return hits
