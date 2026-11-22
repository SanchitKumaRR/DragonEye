"""Provider registry.

Almost every vendor exposes an OpenAI-compatible `/chat/completions` endpoint,
so one client covers them all. The model lists are a convenience starting
point, not a gate: any model id the provider accepts can be typed in.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..config import get_api_key


@dataclass(frozen=True)
class Provider:
    id: str
    label: str
    base_url: str
    auth: str  # bearer | x-api-key | none
    models: tuple[str, ...]
    env: str | None = None
    needs_base_url: bool = False
    local: bool = False
    notes: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)


PROVIDERS: dict[str, Provider] = {
    "openai": Provider(
        "openai", "OpenAI", "https://api.openai.com/v1", "bearer",
        ("gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini", "gpt-4.1-nano",
         "o3", "o4-mini", "o1-mini", "gpt-4-turbo", "openai/gpt-oss-120b"),
        env="OPENAI_API_KEY",
    ),
    "anthropic": Provider(
        "anthropic", "Anthropic", "https://api.anthropic.com/v1", "x-api-key",
        ("claude-sonnet-4-5", "claude-opus-4-1", "claude-3-7-sonnet-latest",
         "claude-3-5-haiku-latest"),
        env="ANTHROPIC_API_KEY",
        extra_headers={"anthropic-version": "2023-06-01"},
    ),
    "google": Provider(
        "google", "Google Gemini", "https://generativelanguage.googleapis.com/v1beta/openai", "bearer",
        ("gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash",
         "gemini-2.0-flash-lite", "gemma-3-27b-it"),
        env="GEMINI_API_KEY",
    ),
    "deepseek": Provider(
        "deepseek", "DeepSeek", "https://api.deepseek.com/v1", "bearer",
        ("deepseek-chat", "deepseek-reasoner"), env="DEEPSEEK_API_KEY",
    ),
    "groq": Provider(
        "groq", "Groq", "https://api.groq.com/openai/v1", "bearer",
        ("llama-3.3-70b-versatile", "llama-3.1-8b-instant", "qwen-2.5-32b",
         "mixtral-8x7b-32768", "gemma2-9b-it", "deepseek-r1-distill-llama-70b", "openai/gpt-oss-120b"),
        env="GROQ_API_KEY",
    ),
    "mistral": Provider(
        "mistral", "Mistral", "https://api.mistral.ai/v1", "bearer",
        ("mistral-large-latest", "mistral-small-latest", "codestral-latest",
         "open-mistral-nemo"), env="MISTRAL_API_KEY",
    ),
    "xai": Provider(
        "xai", "xAI", "https://api.x.ai/v1", "bearer",
        ("grok-4", "grok-3-mini"), env="XAI_API_KEY",
    ),
    "openrouter": Provider(
        "openrouter", "OpenRouter (gateway)", "https://openrouter.ai/api/v1", "bearer",
        ("anthropic/claude-sonnet-4.5", "openai/gpt-4o-mini", "openai/gpt-4.1",
         "google/gemini-2.5-flash", "meta-llama/llama-3.3-70b-instruct",
         "qwen/qwen3-235b-a22b", "deepseek/deepseek-chat",
         "mistralai/mistral-large", "microsoft/phi-4",
         "nvidia/llama-3.1-nemotron-70b-instruct"),
        env="OPENROUTER_API_KEY",
        notes="One key for most hosted models. Best option for breadth.",
    ),
    "together": Provider(
        "together", "Together AI", "https://api.together.xyz/v1", "bearer",
        ("meta-llama/Llama-3.3-70B-Instruct-Turbo", "Qwen/Qwen2.5-72B-Instruct-Turbo",
         "deepseek-ai/DeepSeek-V3"), env="TOGETHER_API_KEY",
    ),
    "fireworks": Provider(
        "fireworks", "Fireworks AI", "https://api.fireworks.ai/inference/v1", "bearer",
        ("accounts/fireworks/models/llama-v3p3-70b-instruct",
         "accounts/fireworks/models/qwen2p5-72b-instruct",
         "accounts/fireworks/models/deepseek-v3"), env="FIREWORKS_API_KEY",
    ),
    "perplexity": Provider(
        "perplexity", "Perplexity", "https://api.perplexity.ai", "bearer",
        ("sonar", "sonar-pro", "sonar-reasoning"), env="PERPLEXITY_API_KEY",
        notes="Search-augmented; good for CVE context, weaker at strict JSON.",
    ),
    "ollama": Provider(
        "ollama", "Ollama (local)", "http://127.0.0.1:11434/v1", "none",
        ("llama3.2", "qwen2.5-coder", "mistral", "deepseek-r1", "phi4"),
        local=True, notes="No key, no data leaves the machine.",
    ),
    "lmstudio": Provider(
        "lmstudio", "LM Studio (local)", "http://127.0.0.1:1234/v1", "none",
        ("local-model",), local=True,
    ),
    "vllm": Provider(
        "vllm", "vLLM (local)", "http://127.0.0.1:8000/v1", "none",
        ("local-model",), env="VLLM_API_KEY", local=True,
    ),
    "azure": Provider(
        "azure", "Azure OpenAI", "", "bearer", ("gpt-4o", "gpt-4o-mini"),
        env="AZURE_OPENAI_API_KEY", needs_base_url=True,
        notes="Set base_url to https://<resource>.openai.azure.com/openai/deployments/<deployment>",
    ),
    "custom": Provider(
        "custom", "Custom (OpenAI-compatible)", "", "bearer", ("custom-model",),
        env="DRAGONEYE_API_KEY", needs_base_url=True,
    ),
}

# JSON-mode support is not universal; be conservative.
JSON_MODE_PROVIDERS = {
    "openai", "deepseek", "groq", "mistral", "xai", "openrouter",
    "together", "fireworks", "google", "ollama", "lmstudio", "vllm", "custom",
}

# USD per 1M tokens, approximate. Unknown models cost 0 (never used for billing).
PRICING: tuple[tuple[str, float, float], ...] = (
    ("gpt-4o-mini", 0.15, 0.60),
    ("gpt-4.1-mini", 0.40, 1.60),
    ("gpt-4.1-nano", 0.10, 0.40),
    ("gpt-4.1", 2.00, 8.00),
    ("gpt-4o", 2.50, 10.00),
    ("gpt-4-turbo", 10.00, 30.00),
    ("o4-mini", 1.10, 4.40),
    ("o3", 2.00, 8.00),
    ("o1-mini", 1.10, 4.40),
    ("claude-3-5-haiku", 0.80, 4.00),
    ("claude-haiku", 0.80, 4.00),
    ("claude-3-7-sonnet", 3.00, 15.00),
    ("claude-sonnet", 3.00, 15.00),
    ("claude-opus", 15.00, 75.00),
    ("gemini-2.5-flash", 0.30, 2.50),
    ("gemini-2.5-pro", 1.25, 10.00),
    ("gemini-2.0-flash", 0.10, 0.40),
    ("deepseek-chat", 0.27, 1.10),
    ("deepseek-reasoner", 0.55, 2.19),
    ("llama-3.3-70b", 0.59, 0.79),
    ("llama-3.1-8b", 0.05, 0.08),
    ("qwen", 0.20, 0.60),
    ("grok-4", 3.00, 15.00),
    ("grok-3-mini", 0.30, 0.50),
    ("mistral-large", 2.00, 6.00),
    ("mistral-small", 0.20, 0.60),
    ("sonar", 1.00, 1.00),
    ("phi-4", 0.13, 0.52),
)


def get_provider(provider_id: str) -> Provider | None:
    return PROVIDERS.get((provider_id or "").lower())


def provider_list() -> list[dict[str, object]]:
    return [
        {
            "id": p.id,
            "label": p.label,
            "models": list(p.models),
            "local": p.local,
            "needs_base_url": p.needs_base_url,
            "env": p.env,
            "notes": p.notes,
        }
        for p in PROVIDERS.values()
    ]


def all_models() -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for provider in PROVIDERS.values():
        for model in provider.models:
            out.append({"provider": provider.id, "model": model})
    return out


def api_key_for(provider: Provider) -> str | None:
    return get_api_key(provider.id, provider.env)


def extra_headers(provider: Provider) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    key = api_key_for(provider)
    if provider.auth == "x-api-key":
        if key:
            headers["x-api-key"] = key
            # Anthropic's OpenAI-compatible layer also accepts bearer auth.
            headers["Authorization"] = f"Bearer {key}"
    elif provider.auth == "none" and key:
        # Local servers that optionally accept a token.
        headers["Authorization"] = f"Bearer {key}"
    headers.update(provider.extra_headers)
    if provider.id == "openrouter":
        headers["HTTP-Referer"] = "https://github.com/SanchitKumaRR/DragonEye"
        headers["X-Title"] = "DragonEye"
    return headers


def price_for(model: str) -> tuple[float, float] | None:
    """USD per 1M tokens as (input, output), or None when unpriced."""
    name = (model or "").lower()
    for needle, price_in, price_out in PRICING:
        if needle in name:
            return price_in, price_out
    return None


def price_known(model: str) -> bool:
    return price_for(model) is not None


def estimate_cost(model: str, tokens_in: int, tokens_out: int) -> float:
    price = price_for(model)
    if price is None:
        return 0.0
    price_in, price_out = price
    return (tokens_in / 1_000_000) * price_in + (tokens_out / 1_000_000) * price_out
