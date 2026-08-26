"""Device-1 model host for the serial SSH reverse tool channel."""

from __future__ import annotations

import hmac
import json
import sys
from collections.abc import Mapping, Sequence
from typing import Any, NoReturn

from pydantic import ValidationError

from .agent import ReactAgent
from .config import Settings
from .errors import ConfigurationError, ModelError, TerminusError
from .llm import LocalModelClient
from .remote_protocol import (
    ErrorMessage,
    FinalMessage,
    JsonLineChannel,
    ReadyMessage,
    RemoteProtocolError,
    StartMessage,
    ToolCallMessage,
    ToolResultMessage,
    catalog_fingerprint,
)
from .tools import ToolObservation, ToolRegistry, build_default_registry


class CatalogMismatchError(RemoteProtocolError):
    """Device 1 and Device 2 do not expose identical tool contracts."""


class RemoteToolRegistry:
    """Use local tool metadata while forwarding every allowed read to Device 2."""

    def __init__(
        self,
        local_registry: ToolRegistry,
        channel: JsonLineChannel,
        allowed_tools: Sequence[str],
    ) -> None:
        allowed = tuple(allowed_tools)
        if len(allowed) != len(set(allowed)):
            raise ValueError("allowed_tools cannot contain duplicates")
        missing = [name for name in allowed if name not in local_registry]
        if missing:
            raise ValueError(
                "allowed_tools are absent from the local catalog: "
                + ", ".join(missing)
            )
        self.local_registry = local_registry
        self.channel = channel
        self.allowed_tools = allowed
        self._allowed_set = frozenset(allowed)
        self._next_call_number = 1
        self._in_flight = False
        self._fatal_error: RemoteProtocolError | None = None

    def select(self, _query: str, _limit: int = 3) -> list[str]:
        """Return the Device-1 selection fixed during the handshake."""

        return list(self.allowed_tools)

    def openai_schemas(
        self,
        names: Sequence[str] | None = None,
    ) -> list[dict[str, Any]]:
        selected = self.allowed_tools if names is None else tuple(names)
        outside = [name for name in selected if name not in self._allowed_set]
        if outside:
            raise RemoteProtocolError(
                "schema requested outside the session allowlist: "
                + ", ".join(outside)
            )
        return self.local_registry.openai_schemas(selected)

    def dispatch(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> ToolObservation:
        """Validate locally, then perform exactly one remote request/response."""

        if self._fatal_error is not None:
            raise self._fatal_error
        if name not in self._allowed_set:
            return ToolObservation.failure(
                name,
                "tool_not_allowed",
                f"Tool {name!r} is not allowed in this remote session.",
                data={"allowed_tools": list(self.allowed_tools)},
            ).bounded(self.local_registry.max_observation_chars)
        if self._in_flight:
            self._fail("serial_violation", "a tool request is already in flight")

        definition = self.local_registry.get(name)
        try:
            validated = definition.input_model.model_validate(arguments or {})
        except ValidationError as exc:
            return ToolObservation.failure(
                name,
                "invalid_arguments",
                f"Invalid arguments for {name}: {exc}",
            ).bounded(self.local_registry.max_observation_chars)

        call_id = f"remote_{self._next_call_number}"
        self._next_call_number += 1
        self._in_flight = True
        try:
            self.channel.send(
                ToolCallMessage(
                    id=call_id,
                    name=name,
                    arguments=validated.model_dump(mode="json"),
                )
            )
            raw_response = self.channel.receive()
            if raw_response.get("type") == "error":
                try:
                    remote_error = ErrorMessage.model_validate(raw_response)
                except ValidationError as exc:
                    self._fail(
                        "invalid_error",
                        f"Device 2 sent an invalid error message: {exc}",
                    )
                self._fail(remote_error.code, remote_error.message)
            try:
                response = ToolResultMessage.model_validate(raw_response)
            except ValidationError as exc:
                self._fail(
                    "invalid_tool_result",
                    f"Device 2 sent an invalid tool result: {exc}",
                )
            if response.id != call_id:
                self._fail(
                    "mismatched_tool_result",
                    f"expected result {call_id!r}, received {response.id!r}",
                )
            try:
                observation = ToolObservation.model_validate(
                    response.observation
                )
            except ValidationError as exc:
                self._fail(
                    "invalid_observation",
                    f"Device 2 sent an invalid ToolObservation: {exc}",
                )
            if observation.tool != name:
                self._fail(
                    "mismatched_observation",
                    f"expected observation for {name!r}, "
                    f"received {observation.tool!r}",
                )
            return observation.bounded(
                self.local_registry.max_observation_chars
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            if self._fatal_error is None:
                self._fatal_error = (
                    exc
                    if isinstance(exc, RemoteProtocolError)
                    else RemoteProtocolError(str(exc))
                )
            raise self._fatal_error
        finally:
            self._in_flight = False

    def raise_if_failed(self) -> None:
        if self._fatal_error is not None:
            raise self._fatal_error

    def _fail(self, code: str, message: str) -> NoReturn:
        error = RemoteProtocolError(f"{code}: {message}")
        self._fatal_error = error
        raise error


def serve_once(channel: JsonLineChannel) -> None:
    """Serve exactly one start/tool*/final exchange."""

    raw_start = channel.receive()
    try:
        start = StartMessage.model_validate(raw_start)
    except ValidationError as exc:
        raise RemoteProtocolError(f"invalid start message: {exc}") from exc

    settings = Settings.from_env()
    local_registry = build_default_registry(
        settings.max_observation_chars
    )
    local_fingerprint = catalog_fingerprint(local_registry)
    if not hmac.compare_digest(
        start.catalog_sha256,
        local_fingerprint,
    ):
        raise CatalogMismatchError(
            "tool catalog mismatch: "
            f"Device 1 has {local_fingerprint}, "
            f"Device 2 reported {start.catalog_sha256}"
        )

    allowed_tools = local_registry.select(
        start.task,
        settings.tool_top_k,
    )
    remote_registry = RemoteToolRegistry(
        local_registry,
        channel,
        allowed_tools,
    )
    runtime_context = _runtime_context(start)

    with LocalModelClient(settings) as model:
        channel.send(
            ReadyMessage(
                allowed_tools=allowed_tools,
            )
        )
        agent = ReactAgent(
            settings=settings,
            model=model,
            tools=remote_registry,
        )
        try:
            result = agent.run(
                start.task,
                runtime_context=runtime_context,
            )
        except Exception:
            remote_registry.raise_if_failed()
            raise
        remote_registry.raise_if_failed()
        channel.send(
            FinalMessage(result=result.model_dump(mode="json"))
        )


def _runtime_context(start: StartMessage) -> str:
    executor_name = json.dumps(start.executor_name, ensure_ascii=False)
    executor_platform = json.dumps(
        start.executor_platform,
        ensure_ascii=False,
    )
    return (
        "All typed read-only tools execute on Device 2, not Device 1, "
        "through the serial SSH tool channel. "
        f"Device 2 executor name: {executor_name}. "
        f"Device 2 platform: {executor_platform}. "
        "Attribute live observations to Device 2. Any PowerShell command "
        "proposal targets Device 2 and remains unexecuted."
    )


def _error_code(exc: BaseException) -> str:
    if isinstance(exc, CatalogMismatchError):
        return "catalog_mismatch"
    if isinstance(exc, ConfigurationError):
        return "configuration_error"
    if isinstance(exc, ModelError):
        return "model_error"
    if isinstance(exc, RemoteProtocolError):
        return "protocol_error"
    if isinstance(exc, TerminusError):
        return "terminus_error"
    if isinstance(exc, EOFError):
        return "unexpected_eof"
    return "host_error"


def main() -> int:
    """Run one protocol session, keeping stdout machine-only."""

    channel = JsonLineChannel(sys.stdin.buffer, sys.stdout.buffer)
    try:
        serve_once(channel)
        return 0
    except Exception as exc:
        code = _error_code(exc)
        print(
            f"Terminus remote host failed [{code}]: {exc}",
            file=sys.stderr,
        )
        try:
            channel.send(
                ErrorMessage(
                    code=code,
                    message=str(exc)[:20_000] or type(exc).__name__,
                )
            )
        except Exception as send_exc:
            print(
                f"Could not send protocol error: {send_exc}",
                file=sys.stderr,
            )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CatalogMismatchError",
    "RemoteToolRegistry",
    "serve_once",
    "main",
]
