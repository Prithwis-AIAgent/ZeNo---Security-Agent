"""
SecureAgent — Centralised settings loaded from .env
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── LLM ───────────────────────────────────────────────────────────
    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    gemini_api_key: str = Field(default="", alias="GEMINI_API_KEY")
    llm_provider: Literal["openai", "gemini"] = Field(
        default="openai", alias="LLM_PROVIDER"
    )
    llm_model: str = Field(default="gpt-4o", alias="LLM_MODEL")

    # ── GitHub ────────────────────────────────────────────────────────
    github_token: str = Field(default="", alias="GITHUB_TOKEN")

    # ── Server ────────────────────────────────────────────────────────
    host: str = Field(default="0.0.0.0", alias="HOST")
    port: int = Field(default=8000, alias="PORT")
    log_level: str = Field(default="info", alias="LOG_LEVEL")

    # ── Agent tunables ────────────────────────────────────────────────
    max_files: int = Field(default=100, alias="MAX_FILES")
    max_file_size_kb: int = Field(default=500, alias="MAX_FILE_SIZE_KB")

    @property
    def github_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers

    @property
    def active_llm_key(self) -> str:
        if self.llm_provider == "gemini":
            return self.gemini_api_key
        return self.openai_api_key

    def validate_llm_config(self) -> None:
        """Raise ValueError if the required LLM key is missing."""
        if not self.active_llm_key:
            provider = self.llm_provider
            env_var = "OPENAI_API_KEY" if provider == "openai" else "GEMINI_API_KEY"
            raise ValueError(
                f"LLM provider is set to '{provider}' but {env_var} is not configured. "
                f"Add it to your .env file."
            )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton Settings instance."""
    return Settings()
