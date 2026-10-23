"""Centralized configuration, read from environment variables and an optional .env file."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="DETECTFORGE_", extra="ignore")

    data_dir: Path = Path("data")

    # LLM (agent loop, week 2). The API key uses the provider's standard variable name.
    anthropic_api_key: SecretStr | None = Field(default=None, validation_alias="ANTHROPIC_API_KEY")
    model: str = "claude-sonnet-5-5"
    fallback_model: str = "claude-haiku-5-5"

    # Per-rule budgets (CLAUDE.md section 8).
    max_iterations: int = Field(default=5, ge=1)
    max_cost_usd_per_rule: float = Field(default=1.0, gt=0)
    tool_timeout_s: float = Field(default=30.0, gt=0)

    # Tracing (week 2).
    langfuse_host: str | None = None
    langfuse_public_key: SecretStr | None = Field(default=None, validation_alias="LANGFUSE_PUBLIC_KEY")
    langfuse_secret_key: SecretStr | None = Field(default=None, validation_alias="LANGFUSE_SECRET_KEY")


@lru_cache
def get_settings() -> Settings:
    return Settings()
