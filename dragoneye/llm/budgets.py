"""Usage tiers -> concrete limits.

"Nudge the model a bit" is not a setting. Each tier is a budget: how many
findings get looked at, how much evidence fits in a prompt, and how many
search rounds the model may spend before it must answer.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Budget:
    name: str
    review_limit: int  # how many findings get a verdict
    batch_size: int  # findings per API call
    evidence_chars: int  # evidence included per finding
    max_search_rounds: int  # local grep rounds before an answer is forced
    search_results: int  # lines returned per search
    temperature: float
    max_output_tokens: int
    max_context_chars: int  # hard cap on a single prompt

    def describe(self) -> str:
        return (
            f"{self.name}: up to {self.review_limit} findings, {self.evidence_chars} "
            f"evidence chars, {self.max_search_rounds} search round(s)"
        )


BUDGETS: dict[str, Budget] = {
    "low": Budget(
        name="low",
        review_limit=10,
        batch_size=1,
        evidence_chars=1200,
        max_search_rounds=0,
        search_results=8,
        temperature=0.0,
        max_output_tokens=350,
        max_context_chars=6000,
    ),
    "balanced": Budget(
        name="balanced",
        review_limit=50,
        batch_size=2,
        evidence_chars=4000,
        max_search_rounds=1,
        search_results=12,
        temperature=0.1,
        max_output_tokens=700,
        max_context_chars=16000,
    ),
    "high": Budget(
        name="high",
        review_limit=500,
        batch_size=4,
        evidence_chars=12000,
        max_search_rounds=3,
        search_results=20,
        temperature=0.2,
        max_output_tokens=1200,
        max_context_chars=48000,
    ),
}

DEFAULT_BUDGET = "balanced"


def get_budget(name: str | None) -> Budget | None:
    if not name or name == "off":
        return None
    return BUDGETS.get(name.lower(), BUDGETS[DEFAULT_BUDGET])
