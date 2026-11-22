"""One OpenAI-compatible client with retries, cost and token accounting."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

from .providers import (
    JSON_MODE_PROVIDERS,
    Provider,
    api_key_for,
    estimate_cost,
    extra_headers,
    get_provider,
    price_known,
)


class LLMError(RuntimeError):
    pass


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    price_known: bool = True
    latency: float = 0.0


class LLMClient:
    def __init__(
        self,
        provider_id: str,
        model: str,
        *,
        base_url: str | None = None,
        timeout: int = 120,
    ) -> None:
        provider = get_provider(provider_id)
        if provider is None:
            raise LLMError(f"unknown provider {provider_id!r}")
        if provider.needs_base_url and not (base_url or provider.base_url):
            raise LLMError(f"provider {provider.id} requires a base_url")
        self.provider: Provider = provider
        self.model = model or (provider.models[0] if provider.models else "custom-model")
        self.base_url = (base_url or provider.base_url).rstrip("/")
        self.timeout = timeout

    # -- availability ------------------------------------------------------

    @property
    def api_key(self) -> str | None:
        return api_key_for(self.provider)

    def available(self) -> tuple[bool, str]:
        if self.provider.auth == "none":
            return True, "local"
        if not self.api_key:
            env = self.provider.env or "an API key"
            return False, f"no API key for {self.provider.id} (set {env} or run: dragoneye config key {self.provider.id})"
        return True, "ok"

    # -- request -----------------------------------------------------------

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.1,
        max_tokens: int = 800,
        json_mode: bool = False,
        retries: int = 3,
    ) -> LLMResponse:
        ok, reason = self.available()
        if not ok:
            raise LLMError(reason)

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode and self.provider.id in JSON_MODE_PROVIDERS:
            payload["response_format"] = {"type": "json_object"}

        headers = extra_headers(self.provider)
        if self.provider.auth == "bearer" and self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        headers.setdefault("User-Agent", "DragonEye/1.0 (+https://github.com/SanchitKumaRR/DragonEye)")

        url = f"{self.base_url}/chat/completions"
        last_error: str = ""
        started = time.time()

        for attempt in range(retries):
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.post(url, json=payload, headers=headers)
            except httpx.HTTPError as exc:
                last_error = f"network error: {exc}"
                _sleep(attempt)
                continue

            if response.status_code in (429, 500, 502, 503, 504):
                last_error = f"HTTP {response.status_code}: {response.text[:200]}"
                _sleep(attempt, response.headers.get("retry-after"))
                continue
            if response.status_code >= 400:
                raise LLMError(f"HTTP {response.status_code}: {response.text[:400]}")

            try:
                body = response.json()
                text = body["choices"][0]["message"].get("content") or ""
            except (KeyError, IndexError, ValueError) as exc:
                raise LLMError(f"unexpected response shape: {exc}: {response.text[:300]}") from exc

            usage = body.get("usage") or {}
            tokens_in = int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0)
            tokens_out = int(usage.get("completion_tokens") or usage.get("output_tokens") or 0)
            return LLMResponse(
                text=text,
                provider=self.provider.id,
                model=self.model,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                cost_usd=estimate_cost(self.model, tokens_in, tokens_out),
                price_known=price_known(self.model),
                latency=round(time.time() - started, 2),
            )

        raise LLMError(last_error or "request failed")


def _sleep(attempt: int, retry_after: str | None = None) -> None:
    delay = min(8.0, 1.5 * (2**attempt))
    if retry_after:
        try:
            delay = min(30.0, max(delay, float(retry_after)))
        except ValueError:
            pass
    time.sleep(delay)
