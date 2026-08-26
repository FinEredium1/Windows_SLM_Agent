"""Default read-only tool registry."""

from __future__ import annotations

from .base import (
    DEFAULT_MAX_OBSERVATION_CHARS,
    ObservationError,
    Provenance,
    ToolDefinition,
    ToolInput,
    ToolObservation,
    ToolRegistry,
)
from .filesystem import filesystem_tools
from .network import network_tools
from .system import system_tools
from .windows import windows_tools


def build_default_registry(
    max_observation_chars: int = DEFAULT_MAX_OBSERVATION_CHARS,
) -> ToolRegistry:
    """Build a fresh registry; definitions themselves hold no mutable state."""

    registry = ToolRegistry(max_observation_chars=max_observation_chars)
    # Purpose-built operator workflows are registered first only as a stable
    # tie-breaker. Lexical score, not registration order, drives selection.
    registry.register_many(windows_tools())
    registry.register_many(network_tools())
    registry.register_many(system_tools())
    registry.register_many(filesystem_tools())
    return registry


__all__ = [
    "DEFAULT_MAX_OBSERVATION_CHARS",
    "ObservationError",
    "Provenance",
    "ToolDefinition",
    "ToolInput",
    "ToolObservation",
    "ToolRegistry",
    "build_default_registry",
]
