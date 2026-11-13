"""Provider-agnostic chat client with tool calling.

Speaks the OpenAI-compatible chat completions API, which OpenRouter, Ollama and most hosted or
local servers expose, so switching provider is configuration only (base URL, key, model).
Reliability lives here: per-request timeout, retries with backoff on rate limits and server errors
(handled by the SDK), and a fallback model when the primary keeps failing.
"""

import json
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol

import openai

from detectforge.config import Settings


class LLMError(Exception):
    """The model could not be reached or returned something unusable (after retries/fallback)."""


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: str  # raw JSON text from the model; validated by the tool dispatcher


@dataclass
class LLMResponse:
    model: str
    content: str | None
    tool_calls: list[ToolCall]
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0
    used_fallback: bool = False
    finish_reason: str | None = None


@dataclass
class ModelCallRecord:
    model: str
    ok: bool
    latency_ms: float
    prompt_tokens: int = 0
    completion_tokens: int = 0
    used_fallback: bool = False
    error: str | None = None


class ChatClient(Protocol):
    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMResponse: ...


@dataclass
class OpenAICompatibleClient:
    """Calls `model`, then `fallback_model` if the primary fails after the SDK's own retries."""

    base_url: str
    api_key: str
    model: str
    fallback_model: str | None = None
    timeout_s: float = 120.0
    max_retries: int = 3
    max_output_tokens: int = 4096
    _client: Any = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._client = openai.OpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            timeout=self.timeout_s,
            max_retries=self.max_retries,
        )

    @classmethod
    def from_settings(cls, settings: Settings) -> "OpenAICompatibleClient":
        if settings.llm_api_key is None:
            raise LLMError("no LLM API key: set OPENROUTER_API_KEY in .env (any value for a local server)")
        return cls(
            base_url=settings.llm_base_url,
            api_key=settings.llm_api_key.get_secret_value(),
            model=settings.model,
            fallback_model=settings.fallback_model,
            timeout_s=settings.llm_timeout_s,
            max_retries=settings.llm_max_retries,
            max_output_tokens=settings.max_output_tokens,
        )

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMResponse:
        try:
            return self._call(self.model, messages, tools, used_fallback=False)
        except LLMError as primary_error:
            if not self.fallback_model:
                raise
            try:
                return self._call(self.fallback_model, messages, tools, used_fallback=True)
            except LLMError as fallback_error:
                raise LLMError(
                    f"primary failed ({primary_error}); fallback failed ({fallback_error})"
                ) from None

    def _call(
        self, model: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]], used_fallback: bool
    ) -> LLMResponse:
        start = time.perf_counter()
        try:
            completion = self._client.chat.completions.create(
                model=model,
                messages=messages,
                tools=tools,
                tool_choice="auto",
                max_tokens=self.max_output_tokens,
            )
        except openai.APIStatusError as e:
            raise LLMError(f"{model}: HTTP {e.status_code}") from None
        except (openai.APIConnectionError, openai.APITimeoutError) as e:
            raise LLMError(f"{model}: {type(e).__name__}") from None
        if not completion.choices:
            raise LLMError(f"{model}: empty response")
        choice = completion.choices[0]
        usage = completion.usage
        return LLMResponse(
            model=completion.model or model,
            content=choice.message.content,
            tool_calls=[
                ToolCall(id=tc.id, name=tc.function.name, arguments=tc.function.arguments or "{}")
                for tc in choice.message.tool_calls or []
                if getattr(tc, "function", None) is not None
            ],
            prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
            latency_ms=round((time.perf_counter() - start) * 1000, 1),
            used_fallback=used_fallback,
            finish_reason=choice.finish_reason,
        )


def list_free_tool_models(base_url: str, timeout_s: float = 30.0) -> list[dict[str, Any]]:
    """Free models that support tool calling, from an OpenRouter-style /models listing (no key needed)."""
    with urllib.request.urlopen(f"{base_url.rstrip('/')}/models", timeout=timeout_s) as response:
        models = json.loads(response.read().decode("utf-8")).get("data", [])
    return [
        {"id": m["id"], "context_length": m.get("context_length")}
        for m in models
        if "tools" in (m.get("supported_parameters") or [])
        and (
            m["id"].endswith(":free")
            or all(m.get("pricing", {}).get(k) == "0" for k in ("prompt", "completion"))
        )
    ]


def openai_tool_definitions(schemas: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Provider-neutral tool schemas → the OpenAI-compatible `tools` format."""
    return [
        {
            "type": "function",
            "function": {"name": s["name"], "description": s["description"], "parameters": s["input_schema"]},
        }
        for s in schemas
    ]
