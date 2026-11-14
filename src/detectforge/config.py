"""Centralized configuration, read from environment variables and an optional .env file."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="DETECTFORGE_", extra="ignore")

    data_dir: Path = Path("data")
    # UI: build the SigmaHQ index on first launch if missing (needed on a fresh cloud deploy).
    ui_auto_fetch_index: bool = True

    # LLM for the agent loop: any OpenAI-compatible endpoint. Default is OpenRouter's free tier;
    # for a local model use llm_base_url=http://localhost:11434/v1 (Ollama) and any non-empty key.
    llm_base_url: str = "https://openrouter.ai/api/v1"
    llm_api_key: SecretStr | None = Field(default=None, validation_alias="OPENROUTER_API_KEY")
    model: str = "nvidia/nemotron-3-ultra-550b-a55b:free"
    fallback_model: str | None = "google/gemma-4-31b-it:free"
    llm_timeout_s: float = Field(default=120.0, gt=0)
    llm_max_retries: int = Field(default=3, ge=0)

    # Per-rule budgets for the agent loop.
    max_iterations: int = Field(default=5, ge=1, description="run_tuning_set calls per rule")
    max_model_calls: int = Field(default=20, ge=1, description="LLM requests per rule")
    max_tokens_per_rule: int = Field(default=400_000, ge=1_000, description="prompt + completion tokens")
    max_output_tokens: int = Field(default=4_096, ge=256, description="per LLM response")

    # Tracing (Langfuse).
    langfuse_host: str | None = None
    langfuse_public_key: SecretStr | None = Field(default=None, validation_alias="LANGFUSE_PUBLIC_KEY")
    langfuse_secret_key: SecretStr | None = Field(default=None, validation_alias="LANGFUSE_SECRET_KEY")


@lru_cache
def get_settings() -> Settings:
    return Settings()
