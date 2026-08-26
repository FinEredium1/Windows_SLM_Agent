"""Runtime settings for the one-shot Windows agent."""

from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .errors import ConfigurationError


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Settings(BaseModel):
    """Validated settings shared by the CLI, controller, and model client."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    base_url: str = "http://127.0.0.1:11434/v1"
    model: str = "gemma"
    api_key: str | None = None
    allow_remote_model: bool = False
    timeout_seconds: float = Field(default=120.0, gt=0, le=600)
    max_steps: int = Field(default=12, ge=1, le=30)
    tool_top_k: int = Field(default=3, ge=1, le=8)
    card_top_k: int = Field(default=3, ge=0, le=8)
    max_model_output_tokens: int = Field(default=1200, ge=128, le=4096)
    max_observation_chars: int = Field(default=12_000, ge=1000, le=100_000)
    max_consecutive_errors: int = Field(default=3, ge=1, le=5)
    stream: bool = True
    verbose: bool = False
    debug: bool = False

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("base_url must be an http(s) URL with a hostname")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("base_url cannot contain credentials, query, or fragment")
        return value.rstrip("/")

    @classmethod
    def from_env(cls, **overrides: object) -> "Settings":
        """Build settings from TERMINUS_* variables plus explicit CLI values."""
        values: dict[str, object] = {
            "base_url": os.getenv(
                "TERMINUS_BASE_URL", "http://127.0.0.1:11434/v1"
            ),
            "model": os.getenv("TERMINUS_MODEL", "gemma"),
            "api_key": os.getenv("TERMINUS_API_KEY") or None,
            "allow_remote_model": _env_bool("TERMINUS_ALLOW_REMOTE_MODEL"),
            "timeout_seconds": float(os.getenv("TERMINUS_TIMEOUT", "120")),
            "max_steps": int(os.getenv("TERMINUS_MAX_STEPS", "12")),
            "tool_top_k": int(os.getenv("TERMINUS_TOOL_TOP_K", "3")),
            "card_top_k": int(os.getenv("TERMINUS_CARD_TOP_K", "3")),
            "max_model_output_tokens": int(
                os.getenv("TERMINUS_MAX_OUTPUT_TOKENS", "1200")
            ),
            "max_observation_chars": int(
                os.getenv("TERMINUS_MAX_OBSERVATION_CHARS", "12000")
            ),
            "stream": not _env_bool("TERMINUS_NO_STREAM"),
            "verbose": _env_bool("TERMINUS_VERBOSE"),
            "debug": _env_bool("TERMINUS_DEBUG"),
        }
        values.update({key: value for key, value in overrides.items() if value is not None})
        settings = cls.model_validate(values)
        settings.require_safe_model_endpoint()
        return settings

    def require_safe_model_endpoint(self) -> None:
        """Keep live Windows observations local unless explicitly overridden."""
        host = urlparse(self.base_url).hostname
        if not host:
            raise ConfigurationError("The model endpoint has no hostname.")
        local = host.lower() == "localhost"
        if not local:
            try:
                local = ipaddress.ip_address(host).is_loopback
            except ValueError:
                local = False
        if not local and not self.allow_remote_model:
            raise ConfigurationError(
                "Refusing a non-loopback model endpoint because tool observations "
                "may contain private Windows data. Pass --allow-remote-model or "
                "set TERMINUS_ALLOW_REMOTE_MODEL=1 only if that data may leave "
                "this computer."
            )
