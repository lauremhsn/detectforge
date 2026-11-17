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
    # UI: allow the "Ask the agent" button. Off by default so a public deployment can't spend the
    # model quota; turn it on locally with DETECTFORGE_UI_ALLOW_AGENT_RUNS=true in .env.
    ui_allow_agent_runs: bool = False

    @property
    def runs_dir(self) -> Path:
        """Where agent runs, review decisions and approved rules are saved."""
        return self.data_dir / "runs"

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
    # Reasoning models spend hidden "thinking" tokens from this same allowance; at 4096 a dev run
    # was cut off mid-thought three times and returned empty answers.
    max_output_tokens: int = Field(default=16_384, ge=256, description="per LLM response")

    # Tracing (Langfuse): enabled when both keys are set. Cloud (free tier) or self-hosted URL.
    langfuse_host: str = Field(default="https://cloud.langfuse.com", validation_alias="LANGFUSE_HOST")
    langfuse_public_key: SecretStr | None = Field(default=None, validation_alias="LANGFUSE_PUBLIC_KEY")
    langfuse_secret_key: SecretStr | None = Field(default=None, validation_alias="LANGFUSE_SECRET_KEY")


@lru_cache
def get_settings() -> Settings:
    return Settings()
