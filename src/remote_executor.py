"""Device-2 SSH executor for local Windows reads.

The remote host owns the model/controller.  This process owns the Windows tool
registry and executes only the read tools selected by the remote host.  Natural
language and observations travel exclusively over the bounded JSON-lines
channel; neither is ever interpolated into an SSH or remote-shell command.
"""

from __future__ import annotations

from collections.abc import Callable
import json
import platform
import re
import socket
import subprocess
from typing import Annotated, Any, Protocol

from pydantic import ValidationError
import typer

from .errors import TerminusError
from .models import AgentResult
from .remote_protocol import (
    PROTOCOL_VERSION,
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
from .tools import ToolObservation, build_default_registry


DEFAULT_REMOTE_COMMAND = "terminus-agent-host"
DEFAULT_MAX_REMOTE_TOOL_CALLS = 32
_TARGET_PATTERN = re.compile(
    r"^(?:[A-Za-z0-9_.+-]+@)?(?:[A-Za-z0-9_.:-]+|\[[0-9A-Fa-f:.]+\])$"
)
_REMOTE_COMMAND_PATTERN = re.compile(
    r"^(?:[A-Za-z0-9][A-Za-z0-9._+-]*|"
    r"/(?:[A-Za-z0-9._+-]+/)*[A-Za-z0-9._+-]+|"
    r"[A-Za-z]:/(?:[A-Za-z0-9._+-]+/)*[A-Za-z0-9._+-]+)$"
)
_TARGET_METACHARACTERS = frozenset(";&|$`\"'\\<>(){}*!?%")


class RemoteExecutionError(TerminusError):
    """The SSH transport or remote protocol failed safely."""


class RegistryLike(Protocol):
    @property
    def names(self) -> tuple[str, ...]: ...

    def dispatch(self, name: str, arguments: dict[str, Any]) -> Any: ...


class ChannelLike(Protocol):
    def send(self, message: Any) -> None: ...

    def receive(self) -> dict[str, Any]: ...


def validate_ssh_target(target: str) -> str:
    """Accept one inert OpenSSH destination, never an option or shell fragment."""

    if not target or target != target.strip():
        raise ValueError("SSH target cannot be empty or surrounded by whitespace")
    if target.startswith("-"):
        raise ValueError("SSH target cannot be an option")
    if any(ord(character) < 32 or ord(character) == 127 for character in target):
        raise ValueError("SSH target cannot contain control characters")
    if any(character.isspace() for character in target):
        raise ValueError("SSH target cannot contain whitespace")
    if any(character in _TARGET_METACHARACTERS for character in target):
        raise ValueError("SSH target cannot contain shell metacharacters")
    if not _TARGET_PATTERN.fullmatch(target):
        raise ValueError(
            "SSH target must be a hostname, IP address, or user@hostname"
        )
    destination = target.rsplit("@", 1)[-1]
    if destination.startswith("-") or destination in {"", ".", ".."}:
        raise ValueError("SSH destination is invalid")
    return target


def validate_remote_command(command: str) -> str:
    """Allow one conservative command name or absolute POSIX/Windows path."""

    if not command or command != command.strip():
        raise ValueError("remote command cannot be empty or contain whitespace")
    if any(ord(character) < 32 or ord(character) == 127 for character in command):
        raise ValueError("remote command cannot contain control characters")
    if not _REMOTE_COMMAND_PATTERN.fullmatch(command):
        raise ValueError(
            "remote command must be one safe command token or absolute path"
        )
    return command


def _validate_local_path_argument(value: str, label: str) -> str:
    if not value or "\x00" in value:
        raise ValueError(f"{label} cannot be empty or contain NUL")
    if any(character in value for character in ("\r", "\n")):
        raise ValueError(f"{label} cannot contain line breaks")
    return value


def build_ssh_argv(
    target: str,
    *,
    port: int = 22,
    identity: str | None = None,
    ssh_executable: str = "ssh",
    remote_command: str = DEFAULT_REMOTE_COMMAND,
    connect_timeout: int = 10,
) -> list[str]:
    """Build an SSH argv with no task or model-controlled command fragments."""

    target = validate_ssh_target(target)
    remote_command = validate_remote_command(remote_command)
    ssh_executable = _validate_local_path_argument(
        ssh_executable,
        "SSH executable",
    )
    if not 1 <= port <= 65_535:
        raise ValueError("SSH port must be between 1 and 65535")
    if not 1 <= connect_timeout <= 600:
        raise ValueError("connect timeout must be between 1 and 600 seconds")
    argv = [
        ssh_executable,
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={connect_timeout}",
        "-p",
        str(port),
    ]
    if identity is not None:
        argv.extend(
            [
                "-i",
                _validate_local_path_argument(identity, "identity path"),
            ]
        )
    argv.extend([target, remote_command])
    return argv


def terminal_safe_text(text: str) -> str:
    """Strip terminal controls while preserving ordinary text, LF, and TAB."""

    return "".join(
        character
        for character in text
        if character in {"\n", "\t"}
        or (
            ord(character) >= 32
            and not 127 <= ord(character) <= 159
        )
    )


def _protocol_failure(message: str, exc: Exception | None = None) -> RemoteExecutionError:
    error = RemoteExecutionError(message)
    if exc is not None:
        error.__cause__ = exc
    return error


def _receive_ready(channel: ChannelLike) -> ReadyMessage:
    try:
        payload = channel.receive()
    except (EOFError, RemoteProtocolError, OSError) as exc:
        raise _protocol_failure(
            f"Remote host closed before becoming ready: {exc}",
            exc,
        )
    if payload.get("type") == "error":
        try:
            remote_error = ErrorMessage.model_validate(payload)
        except ValidationError as exc:
            raise _protocol_failure(
                f"Remote host sent an invalid error message: {exc}",
                exc,
            )
        raise RemoteExecutionError(
            f"Remote host error {remote_error.code}: {remote_error.message}"
        )
    try:
        return ReadyMessage.model_validate(payload)
    except ValidationError as exc:
        raise _protocol_failure(
            f"Expected a ready message from the remote host: {exc}",
            exc,
        )


def _safe_local_dispatch(
    registry: RegistryLike,
    call: ToolCallMessage,
) -> ToolObservation:
    try:
        observation = registry.dispatch(call.name, call.arguments)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        return ToolObservation.failure(
            call.name,
            "remote_dispatch_failed",
            f"Local read handler failed safely: {type(exc).__name__}: {exc}",
        )
    if isinstance(observation, ToolObservation):
        return observation
    try:
        return ToolObservation.model_validate(observation)
    except (ValidationError, TypeError, ValueError):
        return ToolObservation.failure(
            call.name,
            "invalid_local_observation",
            "The local registry returned an invalid observation object.",
        )


def run_protocol_session(
    channel: ChannelLike,
    *,
    task: str,
    registry: RegistryLike,
    catalog_sha256: str,
    executor_name: str | None = None,
    executor_platform: str | None = None,
    max_tool_calls: int = DEFAULT_MAX_REMOTE_TOOL_CALLS,
    on_status: Callable[[str], None] | None = None,
) -> AgentResult:
    """Run one strict start/ready/tool/final exchange."""

    if max_tool_calls < 1:
        raise ValueError("max_tool_calls must be positive")
    start = StartMessage(
        protocol=PROTOCOL_VERSION,
        task=task,
        catalog_sha256=catalog_sha256,
        executor_name=executor_name or socket.gethostname() or "unknown-host",
        executor_platform=executor_platform or platform.platform(),
    )
    channel.send(start)
    ready = _receive_ready(channel)
    allowed_tools = frozenset(ready.allowed_tools)
    if on_status:
        on_status(
            f"Remote host ready; {len(allowed_tools)} local read tool(s) allowed."
        )

    tool_call_count = 0
    seen_call_ids: set[str] = set()
    while True:
        try:
            payload = channel.receive()
        except (EOFError, RemoteProtocolError, OSError) as exc:
            raise _protocol_failure(
                f"Remote protocol ended before a final result: {exc}",
                exc,
            )
        message_type = payload.get("type")
        if message_type == "error":
            try:
                remote_error = ErrorMessage.model_validate(payload)
            except ValidationError as exc:
                raise _protocol_failure(
                    f"Remote host sent an invalid error message: {exc}",
                    exc,
                )
            raise RemoteExecutionError(
                f"Remote host error {remote_error.code}: {remote_error.message}"
            )
        if message_type == "final":
            try:
                final = FinalMessage.model_validate(payload)
                return AgentResult.model_validate(final.result)
            except ValidationError as exc:
                raise _protocol_failure(
                    f"Remote host sent an invalid final result: {exc}",
                    exc,
                )
        if message_type != "tool_call":
            raise RemoteExecutionError(
                f"Unexpected remote protocol message type: {message_type!r}"
            )
        try:
            call = ToolCallMessage.model_validate(payload)
        except ValidationError as exc:
            raise _protocol_failure(
                f"Remote host sent an invalid tool call: {exc}",
                exc,
            )
        if tool_call_count >= max_tool_calls:
            message = (
                f"Remote host exceeded the {max_tool_calls}-call local read limit."
            )
            channel.send(
                ErrorMessage(
                    code="tool_call_limit",
                    message=message,
                )
            )
            raise RemoteExecutionError(message)
        tool_call_count += 1

        if call.id in seen_call_ids:
            observation = ToolObservation.failure(
                call.name,
                "remote_duplicate_call_id",
                (
                    f"Remote host replayed tool-call ID {call.id!r}; the local "
                    "handler was not run again."
                ),
            )
        elif call.name not in allowed_tools:
            seen_call_ids.add(call.id)
            observation = ToolObservation.failure(
                call.name,
                "remote_tool_not_allowed",
                (
                    f"Remote host requested {call.name!r}, but it was not in the "
                    "ready message's allowed tool set."
                ),
                data={"allowed_tools": sorted(allowed_tools)},
            )
        else:
            seen_call_ids.add(call.id)
            observation = _safe_local_dispatch(registry, call)
        channel.send(
            ToolResultMessage(
                id=call.id,
                observation=observation.model_dump(mode="json"),
            )
        )
        if on_status:
            on_status(
                f"Local read {tool_call_count}/{max_tool_calls}: {call.name}"
            )


def _finish_child(process: Any, *, timeout_seconds: float = 5.0) -> int | None:
    """Close protocol pipes and reap, terminate, or kill the SSH child."""

    stdin = getattr(process, "stdin", None)
    if stdin is not None:
        try:
            stdin.close()
        except OSError:
            pass
    try:
        return process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        try:
            process.terminate()
        except OSError:
            pass
        try:
            return process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except OSError:
                pass
            try:
                return process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                return None
    finally:
        stdout = getattr(process, "stdout", None)
        if stdout is not None:
            try:
                stdout.close()
            except OSError:
                pass


def execute_remote(
    target: str,
    task: str,
    *,
    port: int = 22,
    identity: str | None = None,
    ssh_executable: str = "ssh",
    remote_command: str = DEFAULT_REMOTE_COMMAND,
    connect_timeout: int = 10,
    max_tool_calls: int = DEFAULT_MAX_REMOTE_TOOL_CALLS,
    registry: RegistryLike | None = None,
    popen_factory: Callable[..., Any] = subprocess.Popen,
    on_status: Callable[[str], None] | None = None,
) -> AgentResult:
    """Open SSH, run one protocol session, and always reap the child."""

    if not task or not task.strip():
        raise ValueError("task cannot be empty")
    argv = build_ssh_argv(
        target,
        port=port,
        identity=identity,
        ssh_executable=ssh_executable,
        remote_command=remote_command,
        connect_timeout=connect_timeout,
    )
    local_registry = registry or build_default_registry()
    fingerprint = catalog_fingerprint(local_registry)  # type: ignore[arg-type]
    try:
        process = popen_factory(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            shell=False,
            bufsize=0,
        )
    except OSError as exc:
        raise RemoteExecutionError(f"Could not start SSH: {exc}") from exc
    if process.stdin is None or process.stdout is None:
        _finish_child(process)
        raise RemoteExecutionError("SSH process did not expose protocol pipes")

    channel = JsonLineChannel(process.stdout, process.stdin)
    try:
        result = run_protocol_session(
            channel,
            task=task,
            registry=local_registry,
            catalog_sha256=fingerprint,
            max_tool_calls=max_tool_calls,
            on_status=on_status,
        )
    except BaseException:
        _finish_child(process)
        raise
    return_code = _finish_child(process)
    if return_code is None:
        raise RemoteExecutionError("SSH child did not terminate after the final result")
    if return_code != 0:
        raise RemoteExecutionError(
            f"SSH child exited with status {return_code} after the protocol session"
        )
    return result


app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    help=(
        "Run the model/controller over SSH while executing selected read-only "
        "tools on this Windows device."
    ),
)


@app.command()
def run(
    target: Annotated[
        str,
        typer.Argument(help="OpenSSH destination, such as user@device1."),
    ],
    task: Annotated[
        list[str],
        typer.Argument(help="Natural-language request sent only over JSON stdin."),
    ],
    port: Annotated[
        int,
        typer.Option("--port", min=1, max=65_535),
    ] = 22,
    identity: Annotated[
        str | None,
        typer.Option("--identity", "-i", help="SSH private-key path."),
    ] = None,
    ssh_executable: Annotated[
        str,
        typer.Option("--ssh-executable", help="Local OpenSSH executable."),
    ] = "ssh",
    remote_command: Annotated[
        str,
        typer.Option(
            "--remote-command",
            help="Safe remote host command token or absolute path.",
        ),
    ] = DEFAULT_REMOTE_COMMAND,
    connect_timeout: Annotated[
        int,
        typer.Option("--connect-timeout", min=1, max=600),
    ] = 10,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the complete AgentResult as JSON."),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show protocol status on stderr."),
    ] = False,
) -> None:
    request = " ".join(task).strip()

    def status(message: str) -> None:
        typer.echo(terminal_safe_text(message), err=True)

    try:
        result = execute_remote(
            target,
            request,
            port=port,
            identity=identity,
            ssh_executable=ssh_executable,
            remote_command=remote_command,
            connect_timeout=connect_timeout,
            on_status=status if verbose else None,
        )
    except (RemoteExecutionError, ValueError, OSError) as exc:
        typer.echo(
            "Terminus SSH stopped: " + terminal_safe_text(str(exc)),
            err=True,
        )
        raise typer.Exit(code=1) from exc

    if json_output:
        typer.echo(
            json.dumps(
                result.model_dump(mode="json"),
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
    else:
        typer.echo(terminal_safe_text(result.text))
    if verbose:
        status(
            f"Remote result received: {result.steps} model step(s), "
            f"{len(result.trace)} traced local read(s)."
        )


def main() -> None:
    app()


if __name__ == "__main__":
    main()


__all__ = [
    "DEFAULT_MAX_REMOTE_TOOL_CALLS",
    "DEFAULT_REMOTE_COMMAND",
    "RemoteExecutionError",
    "app",
    "build_ssh_argv",
    "execute_remote",
    "main",
    "run_protocol_session",
    "terminal_safe_text",
    "validate_remote_command",
    "validate_ssh_target",
]
