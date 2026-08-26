"""Shared typed values used by the model client and controller."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    raw_arguments: str = "{}"


class ModelUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ModelResponse(BaseModel):
    content: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    usage: ModelUsage = Field(default_factory=ModelUsage)


class TraceEntry(BaseModel):
    step: int
    tool: str
    arguments: dict[str, Any]
    observation: str
    repeated: bool = False


class AgentResult(BaseModel):
    kind: Literal["answer", "proposal"]
    text: str
    steps: int
    usage: ModelUsage = Field(default_factory=ModelUsage)
    trace: list[TraceEntry] = Field(default_factory=list)
    proposal: dict[str, Any] | None = None

