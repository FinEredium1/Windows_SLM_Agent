"""Typed, bounded contracts for read-only tools.

The controller only needs three operations from :class:`ToolRegistry`:

* ``select(query, limit)`` chooses a small lexical tool set for a one-shot run.
* ``openai_schemas(names)`` exposes strict Pydantic input schemas.
* ``dispatch(name, arguments)`` validates input and always returns an observation.

Tool failures are data, not controller exceptions.  This is important on Windows,
where access to process details, event logs, and registry hives varies by account.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError


DEFAULT_MAX_OBSERVATION_CHARS = 12_000
_MIN_OBSERVATION_CHARS = 512
_TOKEN_RE = re.compile(r"[a-z0-9]+", re.IGNORECASE)
_CANONICAL_TOKENS = {
    "apps": "application",
    "app": "application",
    "applications": "application",
    "software": "application",
    "ports": "port",
    "listeners": "listen",
    "listener": "listen",
    "listening": "listen",
    "processes": "process",
    "services": "service",
    "files": "file",
    "folders": "directory",
    "directories": "directory",
    "blocked": "block",
    "blocking": "block",
    "locked": "lock",
    "locking": "lock",
    "crashed": "crash",
    "crashing": "crash",
    "crashes": "crash",
    "hung": "hang",
    "hanging": "hang",
    "hangs": "hang",
    "policies": "policy",
    "scripts": "script",
    "events": "event",
    "logs": "log",
}


class ToolInput(BaseModel):
    """Base class for all model-supplied tool arguments."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Provenance(BaseModel):
    """Where and how a tool obtained an observation."""

    model_config = ConfigDict(extra="forbid")

    source: str
    method: str
    target: str | None = None
    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class ObservationError(BaseModel):
    """A stable, model-readable failure classification."""

    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    retryable: bool = False


class ToolObservation(BaseModel):
    """A structured tool result suitable for both audit and model context."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    ok: bool
    summary: str
    data: Any = None
    provenance: list[Provenance] = Field(default_factory=list)
    error: ObservationError | None = None
    truncated: bool = False

    @classmethod
    def success(
        cls,
        tool: str,
        summary: str,
        data: Any,
        *,
        provenance: Iterable[Provenance] = (),
    ) -> "ToolObservation":
        return cls(
            tool=tool,
            ok=True,
            summary=summary,
            data=data,
            provenance=list(provenance),
        )

    @classmethod
    def failure(
        cls,
        tool: str,
        code: str,
        message: str,
        *,
        data: Any = None,
        provenance: Iterable[Provenance] = (),
        retryable: bool = False,
    ) -> "ToolObservation":
        return cls(
            tool=tool,
            ok=False,
            summary=message,
            data=data,
            provenance=list(provenance),
            error=ObservationError(
                code=code,
                message=message,
                retryable=retryable,
            ),
        )

    @classmethod
    def unsupported(
        cls,
        tool: str,
        capability: str,
        platform_name: str,
    ) -> "ToolObservation":
        message = (
            f"{capability} is available only on Windows; this host reports "
            f"{platform_name!r}."
        )
        return cls.failure(
            tool,
            "capability_unavailable",
            message,
            data={
                "supported": False,
                "required_platform": "Windows",
                "current_platform": platform_name,
            },
            provenance=[
                Provenance(
                    source="runtime",
                    method="platform capability check",
                    target=platform_name,
                )
            ],
        )

    def bounded(self, max_chars: int) -> "ToolObservation":
        """Return an observation whose compact JSON fits ``max_chars``.

        Complete results should be retained separately by an audit layer if that
        is ever added.  The MVP only passes this bounded value to the model.
        """

        if max_chars < _MIN_OBSERVATION_CHARS:
            raise ValueError(
                f"max_chars must be at least {_MIN_OBSERVATION_CHARS}"
            )
        if len(self.model_dump_json()) <= max_chars:
            return self

        serialized_data = json.dumps(
            self.data,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
        # Reserve room for the observation envelope and an explicit warning.
        preview_chars = max(64, max_chars - 900)
        preview = serialized_data[:preview_chars]
        candidate = self.model_copy(
            update={
                "data": {
                    "incomplete_preview": preview,
                    "notice": (
                        "Result exceeded the observation limit. This preview is "
                        "incomplete and must not be treated as a complete inventory."
                    ),
                    "original_characters": len(serialized_data),
                },
                "truncated": True,
            },
            deep=True,
        )
        while len(candidate.model_dump_json()) > max_chars and len(preview) > 32:
            overflow = len(candidate.model_dump_json()) - max_chars
            preview = preview[: max(32, len(preview) - overflow - 16)]
            candidate.data["incomplete_preview"] = preview
        if len(candidate.model_dump_json()) > max_chars:
            candidate = ToolObservation(
                tool=self.tool[:80],
                ok=self.ok,
                summary=self.summary[:160],
                data={
                    "notice": "Result omitted because it exceeded the observation limit."
                },
                provenance=self.provenance[:1],
                error=(
                    self.error.model_copy(
                        update={"message": self.error.message[:120]}
                    )
                    if self.error
                    else None
                ),
                truncated=True,
            )
        return candidate

    def to_model_text(self, max_chars: int | None = None) -> str:
        value = self.bounded(max_chars) if max_chars is not None else self
        return value.model_dump_json()

    @property
    def content(self) -> str:
        """Compatibility convenience for controllers that expect text results."""

        return self.to_model_text()


ToolHandler = Callable[[ToolInput], ToolObservation | Any]


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """A single strict tool contract."""

    name: str
    description: str
    input_model: type[ToolInput]
    handler: ToolHandler
    keywords: tuple[str, ...] = field(default_factory=tuple)

    def openai_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.input_model.model_json_schema(),
            },
        }


def _tokens(text: str) -> list[str]:
    result: list[str] = []
    for raw in _TOKEN_RE.findall(text.casefold()):
        result.append(_CANONICAL_TOKENS.get(raw, raw))
    return result


class ToolRegistry:
    """Ordered registry with validation, lexical selection, and failure isolation."""

    def __init__(self, *, max_observation_chars: int = DEFAULT_MAX_OBSERVATION_CHARS):
        if max_observation_chars < _MIN_OBSERVATION_CHARS:
            raise ValueError(
                f"max_observation_chars must be at least {_MIN_OBSERVATION_CHARS}"
            )
        self.max_observation_chars = max_observation_chars
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, definition: ToolDefinition) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", definition.name):
            raise ValueError(f"Invalid tool name: {definition.name!r}")
        if definition.name in self._tools:
            raise ValueError(f"Duplicate tool name: {definition.name}")
        self._tools[definition.name] = definition

    def register_many(self, definitions: Iterable[ToolDefinition]) -> None:
        for definition in definitions:
            self.register(definition)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(self._tools)

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: object) -> bool:
        return name in self._tools

    def get(self, name: str) -> ToolDefinition:
        return self._tools[name]

    def select(self, query: str, limit: int = 3) -> list[str]:
        """Return the most lexically relevant tool names.

        Rich descriptions and keywords deliberately carry common operator
        language, keeping this selector deterministic and easy to test.
        """

        if limit < 1:
            return []
        query_tokens = _tokens(query)
        query_counts = Counter(query_tokens)
        query_phrase = " ".join(query_tokens)
        scored: list[tuple[int, int, str]] = []
        for order, definition in enumerate(self._tools.values()):
            name_tokens = _tokens(definition.name.replace("_", " "))
            keyword_tokens = _tokens(" ".join(definition.keywords))
            description_tokens = _tokens(definition.description)
            score = 0
            for token, count in query_counts.items():
                score += min(count, name_tokens.count(token)) * 7
                score += min(count, keyword_tokens.count(token)) * 5
                score += min(count, description_tokens.count(token)) * 2
            for keyword in definition.keywords:
                canonical_keyword = " ".join(_tokens(keyword))
                if canonical_keyword and canonical_keyword in query_phrase:
                    score += 8 + len(canonical_keyword.split())
            scored.append((score, -order, definition.name))
        scored.sort(reverse=True)
        return [name for _, _, name in scored[: min(limit, len(scored))]]

    def openai_schemas(
        self,
        names: Sequence[str] | None = None,
    ) -> list[dict[str, Any]]:
        selected = self.names if names is None else tuple(names)
        return [self._tools[name].openai_schema() for name in selected]

    def dispatch(
        self,
        name: str,
        arguments: Mapping[str, Any] | str | None = None,
    ) -> ToolObservation:
        definition = self._tools.get(name)
        if definition is None:
            return ToolObservation.failure(
                name,
                "unknown_tool",
                f"Unknown tool {name!r}.",
                data={"available_tools": list(self.names)},
            ).bounded(self.max_observation_chars)

        try:
            raw_arguments: Any = {} if arguments is None else arguments
            if isinstance(raw_arguments, str):
                raw_arguments = json.loads(raw_arguments)
            if not isinstance(raw_arguments, Mapping):
                raise ValueError("tool arguments must be a JSON object")
            validated = definition.input_model.model_validate(raw_arguments)
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            return ToolObservation.failure(
                name,
                "invalid_arguments",
                f"Invalid arguments for {name}: {exc}",
            ).bounded(self.max_observation_chars)

        try:
            result = definition.handler(validated)
            if not isinstance(result, ToolObservation):
                result = ToolObservation.success(
                    name,
                    "Tool completed.",
                    result,
                    provenance=[
                        Provenance(source=name, method="registered handler")
                    ],
                )
            elif result.tool != name:
                result = result.model_copy(update={"tool": name})
        except (KeyboardInterrupt, SystemExit):
            raise
        except PermissionError as exc:
            result = ToolObservation.failure(
                name,
                "permission_denied",
                f"Access was denied: {exc}",
            )
        except TimeoutError as exc:
            result = ToolObservation.failure(
                name,
                "timeout",
                f"The read timed out: {exc}",
                retryable=True,
            )
        except Exception as exc:  # tool boundaries must not crash the controller
            result = ToolObservation.failure(
                name,
                "tool_failed",
                f"{type(exc).__name__}: {exc}",
            )
        return result.bounded(self.max_observation_chars)
