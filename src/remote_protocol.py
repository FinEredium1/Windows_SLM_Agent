"""Strict JSON-lines protocol shared by the remote host and executor."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any, BinaryIO, Literal, NoReturn, TextIO

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .tools.base import ToolRegistry


PROTOCOL_VERSION = 1
MAX_JSON_LINE_BYTES = 2 * 1024 * 1024
_TOOL_NAME_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"
_CALL_ID_PATTERN = r"^[A-Za-z0-9_.:-]{1,128}$"
_ERROR_CODE_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"


class RemoteProtocolError(ValueError):
    """A peer sent or requested an invalid protocol message."""


class _WireMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _single_line(value: str) -> str:
    if not value.strip():
        raise ValueError("value cannot be empty")
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise ValueError("value must be a single line without NUL")
    return value


class StartMessage(_WireMessage):
    type: Literal["start"] = "start"
    protocol: Literal[1] = PROTOCOL_VERSION
    task: str = Field(min_length=1, max_length=20_000)
    catalog_sha256: str = Field(pattern=_SHA256_PATTERN)
    executor_name: str = Field(min_length=1, max_length=256)
    executor_platform: str = Field(min_length=1, max_length=256)

    @field_validator("task")
    @classmethod
    def _task_is_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("task cannot be blank")
        return value

    @field_validator("executor_name", "executor_platform")
    @classmethod
    def _executor_metadata_is_single_line(cls, value: str) -> str:
        return _single_line(value)


class ReadyMessage(_WireMessage):
    type: Literal["ready"] = "ready"
    protocol: Literal[1] = PROTOCOL_VERSION
    allowed_tools: list[str] = Field(max_length=64)

    @field_validator("allowed_tools")
    @classmethod
    def _allowed_tools_are_valid(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("allowed_tools cannot contain duplicates")
        for value in values:
            if not re.fullmatch(_TOOL_NAME_PATTERN, value):
                raise ValueError(f"invalid tool name: {value!r}")
        return values


class ToolCallMessage(_WireMessage):
    type: Literal["tool_call"] = "tool_call"
    id: str = Field(pattern=_CALL_ID_PATTERN)
    name: str = Field(pattern=_TOOL_NAME_PATTERN)
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolResultMessage(_WireMessage):
    type: Literal["tool_result"] = "tool_result"
    id: str = Field(pattern=_CALL_ID_PATTERN)
    observation: dict[str, Any]


class FinalMessage(_WireMessage):
    type: Literal["final"] = "final"
    result: dict[str, Any]


class ErrorMessage(_WireMessage):
    type: Literal["error"] = "error"
    code: str = Field(pattern=_ERROR_CODE_PATTERN)
    message: str = Field(min_length=1, max_length=20_000)

    @field_validator("message")
    @classmethod
    def _message_has_no_nul(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("message cannot contain NUL")
        return value


WireMessage = (
    StartMessage
    | ReadyMessage
    | ToolCallMessage
    | ToolResultMessage
    | FinalMessage
    | ErrorMessage
)


class JsonLineChannel:
    """Send and receive one bounded UTF-8 JSON object per line."""

    def __init__(
        self,
        reader: BinaryIO | TextIO,
        writer: BinaryIO | TextIO,
        *,
        max_line_bytes: int = MAX_JSON_LINE_BYTES,
    ) -> None:
        if max_line_bytes < 1024:
            raise ValueError("max_line_bytes must be at least 1024")
        self.reader = reader
        self.writer = writer
        self.max_line_bytes = max_line_bytes

    def send(self, message: BaseModel | Mapping[str, Any]) -> None:
        if isinstance(message, BaseModel):
            payload: Any = message.model_dump(mode="json")
        elif isinstance(message, Mapping):
            payload = dict(message)
        else:
            raise TypeError("message must be a Pydantic model or mapping")
        if not isinstance(payload, dict):
            raise TypeError("protocol messages must serialize as JSON objects")
        try:
            encoded = json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise RemoteProtocolError(
                f"message is not JSON serializable: {exc}"
            ) from exc
        if len(encoded) > self.max_line_bytes:
            raise RemoteProtocolError(
                f"message exceeds {self.max_line_bytes} UTF-8 bytes"
            )
        wire = encoded + b"\n"
        try:
            self.writer.write(wire)  # type: ignore[arg-type]
        except TypeError:
            self.writer.write(wire.decode("utf-8"))  # type: ignore[arg-type]
        self.writer.flush()

    def receive(self) -> dict[str, Any]:
        raw = self.reader.readline(self.max_line_bytes + 2)
        if raw in {b"", ""}:
            raise EOFError("remote protocol channel closed")
        if isinstance(raw, str):
            try:
                encoded = raw.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise RemoteProtocolError(
                    f"message is not valid UTF-8: {exc}"
                ) from exc
        else:
            encoded = bytes(raw)
        if not encoded.endswith(b"\n"):
            if len(encoded) > self.max_line_bytes:
                raise RemoteProtocolError(
                    f"message exceeds {self.max_line_bytes} UTF-8 bytes"
                )
            raise RemoteProtocolError("protocol message is not newline terminated")
        encoded = encoded[:-1]
        if encoded.endswith(b"\r"):
            encoded = encoded[:-1]
        if len(encoded) > self.max_line_bytes:
            raise RemoteProtocolError(
                f"message exceeds {self.max_line_bytes} UTF-8 bytes"
            )
        try:
            decoded = encoded.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RemoteProtocolError(
                f"message is not valid UTF-8: {exc}"
            ) from exc
        try:
            payload = json.loads(
                decoded,
                parse_constant=_reject_nonfinite_json,
            )
        except (json.JSONDecodeError, ValueError) as exc:
            raise RemoteProtocolError(
                f"message is not valid JSON: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise RemoteProtocolError("protocol message must be a JSON object")
        return payload


def _reject_nonfinite_json(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON number {value!r} is not allowed")


def catalog_fingerprint(registry: ToolRegistry) -> str:
    """Hash only deterministic tool metadata, never executable handlers."""

    entries: list[dict[str, Any]] = []
    for name in sorted(registry.names):
        definition = registry.get(name)
        entries.append(
            {
                "name": definition.name,
                "description": definition.description,
                "keywords": sorted(definition.keywords),
                "schema": definition.input_model.model_json_schema(),
            }
        )
    canonical = json.dumps(
        entries,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


__all__ = [
    "PROTOCOL_VERSION",
    "MAX_JSON_LINE_BYTES",
    "RemoteProtocolError",
    "StartMessage",
    "ReadyMessage",
    "ToolCallMessage",
    "ToolResultMessage",
    "FinalMessage",
    "ErrorMessage",
    "WireMessage",
    "JsonLineChannel",
    "catalog_fingerprint",
]
