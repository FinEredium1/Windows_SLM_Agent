"""Minimal one-shot ReAct controller."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any, Protocol

from pydantic import ValidationError

from .cards import CommandCard, CommandCardCatalog, get_default_catalog
from .config import Settings
from .errors import AgentExhaustedError, ModelError, is_retryable_model_error
from .models import AgentResult, ModelResponse, ModelUsage, TraceEntry, ToolCall
from .prompts import SYSTEM_PROMPT, build_user_message, observation_message, ASSISTANT_PROMPT
from .proposals import (
    FinishArguments,
    ProposeCommandArguments,
    classify_proposal,
    finish_schema,
    format_proposal,
    proposal_schema,
)


class ModelClient(Protocol):
    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        stream: bool | None = None,
        on_token: Callable[[str], None] | None = None,
    ) -> ModelResponse: ...


class ToolRegistry(Protocol):
    def select(self, query: str, limit: int) -> list[Any]: ...

    def openai_schemas(self, names: list[str]) -> list[dict[str, Any]]: ...

    def dispatch(self, name: str, arguments: dict[str, Any]) -> Any: ...


class ReactAgent:
    """One task, one in-memory transcript, one hard step bound."""

    def __init__(
        self,
        *,
        settings: Settings,
        model: ModelClient,
        tools: ToolRegistry,
        cards: CommandCardCatalog | None = None,
    ) -> None:
        self.settings = settings
        self.model = model
        self.tools = tools
        self.cards = cards or get_default_catalog()

    def run(
        self,
        task: str,
        *,
        assistant_mode: bool = False,
        on_token: Callable[[str], None] | None = None,
        runtime_context: str | None = None,
    ) -> AgentResult:
        task = task.strip()
        if not task:
            raise ValueError("The operator request cannot be empty.")
        if assistant_mode:
            return self._run_assistant(task, on_token=on_token)

        card_hits = self.cards.search(
            task,
            limit=max(1, self.settings.card_top_k)
            if self.settings.card_top_k
            else 1,
            include_write=True,
        ) if self.settings.card_top_k else []
        chosen_tools = self.tools.select(task, self.settings.tool_top_k)
        chosen_names = [_tool_name(tool) for tool in chosen_tools]
        schemas = self.tools.openai_schemas(chosen_names)
        schemas.extend([proposal_schema(), finish_schema()])
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": build_user_message(
                    task,
                    self.cards.format_for_prompt(card_hits),
                    runtime_context=runtime_context or "",
                ),
            },
        ]
        trace: list[TraceEntry] = []
        usage = ModelUsage()
        consecutive_errors = 0

        for step in range(1, self.settings.max_steps + 1):
            try:
                response = self.model.complete(
                    messages,
                    schemas,
                    stream=self.settings.stream,
                    on_token=on_token,
                )
                usage = _add_usage(usage, response.usage)
                consecutive_errors = 0
            except Exception as exc:
                if (
                    not is_retryable_model_error(exc)
                    or consecutive_errors + 1 >= self.settings.max_consecutive_errors
                    or step >= self.settings.max_steps
                ):
                    if isinstance(exc, ModelError):
                        raise
                    raise ModelError(str(exc)) from exc
                consecutive_errors += 1
                time.sleep(min(0.25 * (2 ** (consecutive_errors - 1)), 1.0))
                continue

            if not response.tool_calls:
                answer = response.content.strip()
                if answer:
                    return AgentResult(
                        kind="answer",
                        text=answer,
                        steps=step,
                        usage=usage,
                        trace=trace,
                    )
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Your response was empty. Use one available tool, "
                            "call finish, or answer directly."
                        ),
                    }
                )
                continue

            # Keep the loop serial and simple. llama.cpp is also asked for
            # parallel_tool_calls=false, but this normalizes a backend that
            # ignores that flag.
            call = response.tool_calls[0]
            messages.append(_assistant_tool_message(call, response.content))

            if call.name == "finish":
                terminal = _parse_finish(call)
                if isinstance(terminal, str):
                    messages.append(_tool_message(call, terminal))
                    continue
                return AgentResult(
                    kind="answer",
                    text=terminal.result,
                    steps=step,
                    usage=usage,
                    trace=trace,
                )

            if call.name == "propose_command":
                proposal_or_error = self._compile_proposal(call)
                if isinstance(proposal_or_error, str):
                    messages.append(_tool_message(call, proposal_or_error))
                    continue
                text = format_proposal(proposal_or_error)
                return AgentResult(
                    kind="proposal",
                    text=text,
                    steps=step,
                    usage=usage,
                    trace=trace,
                    proposal=proposal_or_error.model_dump(mode="json"),
                )

            observation = self._dispatch_read(call)
            raise_if_failed = getattr(self.tools, "raise_if_failed", None)
            if callable(raise_if_failed):
                raise_if_failed()
            if len(response.tool_calls) > 1:
                observation += (
                    "\n\nThe model requested multiple calls. Only the first "
                    "read was performed; choose the next read after considering "
                    "this observation."
                )
            observation = _bound_text(
                observation,
                self.settings.max_observation_chars,
            )
            trace.append(
                TraceEntry(
                    step=step,
                    tool=call.name,
                    arguments=call.arguments,
                    observation=observation,
                )
            )
            messages.append(
                _tool_message(
                    call,
                    observation_message(call.name, observation),
                )
            )

        raise AgentExhaustedError(
            f"Terminus reached the {self.settings.max_steps}-step limit "
            "without a final answer."
        )

    def _run_assistant(
        self,
        task: str,
        *,
        on_token: Callable[[str], None] | None = None,
    ) -> AgentResult:
        messages: list[dict[str, Any]] = [
            {
                "role": "system",
                "content": ASSISTANT_PROMPT,
            },
            {
                "role": "user",
                "content": task,
            },
        ]

        response = self.model.complete(
            messages,
            [],
            stream=self.settings.stream,
            on_token=on_token,
        )

        if response.tool_calls:
            raise ModelError(
                "The model returned a tool call while running in assistant mode."
            )

        answer = response.content.strip()
        if not answer:
            raise ModelError(
                "The model returned an empty response in assistant mode."
            )

        return AgentResult(
            kind="answer",
            text=answer,
            steps=1,
            usage=response.usage,
            trace=[],
        )
        
    def _dispatch_read(self, call: ToolCall) -> str:
        try:
            result = self.tools.dispatch(call.name, call.arguments)
        except Exception as exc:
            return f"Tool {call.name!r} failed safely: {exc}"
        if hasattr(result, "model_dump"):
            payload = result.model_dump(mode="json")
            return json.dumps(payload, indent=2, ensure_ascii=False)
        if isinstance(result, str):
            return result
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)

    def _compile_proposal(self, call: ToolCall) -> Any | str:
        try:
            request = ProposeCommandArguments.model_validate(call.arguments)
        except ValidationError as exc:
            return f"Invalid propose_command arguments: {exc}"
        card = self.cards.get(request.card_id)
        if card is None:
            return (
                f"Unknown command-card ID {request.card_id!r}. Use one of the "
                "trusted IDs shown in CONTROLLER COMMAND CARDS."
            )
        if card.read_only:
            return (
                f"Card {card.id!r} is read-only and is not a write-command "
                "proposal. Answer from its syntax or use a write card."
            )
        try:
            command = card.render(request.arguments)
            rollback = _render_rollback(card, request.arguments)
            return classify_proposal(
                card_id=card.id,
                command=command,
                summary=card.summary,
                rollback=rollback,
                requires_admin=card.requires_admin,
                warnings=list(card.gotchas),
                supports_whatif=bool(getattr(card, "supports_whatif", False)),
                declared_risk=getattr(card, "risk", None),
            )
        except (ValueError, TypeError) as exc:
            return f"Could not render trusted card {card.id!r}: {exc}"


def _parse_finish(call: ToolCall) -> FinishArguments | str:
    try:
        return FinishArguments.model_validate(call.arguments)
    except ValidationError as exc:
        return f"Invalid finish arguments: {exc}"


def _tool_name(tool: Any) -> str:
    name = getattr(tool, "name", None)
    if isinstance(name, str):
        return name
    if isinstance(tool, str):
        return tool
    raise TypeError(f"Selected tool has no name: {tool!r}")


def _assistant_tool_message(call: ToolCall, content: str) -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": content or "",
        "tool_calls": [
            {
                "id": call.id,
                "type": "function",
                "function": {
                    "name": call.name,
                    "arguments": call.raw_arguments
                    if call.raw_arguments.strip()
                    else json.dumps(call.arguments),
                },
            }
        ],
    }


def _tool_message(call: ToolCall, content: str) -> dict[str, Any]:
    return {
        "role": "tool",
        "tool_call_id": call.id,
        "name": call.name,
        "content": content,
    }


def _render_rollback(
    card: CommandCard,
    arguments: dict[str, Any],
) -> str | None:
    render = getattr(card, "render_rollback", None)
    if callable(render):
        return render(arguments)
    rollback = getattr(card, "rollback", None)
    return str(rollback) if rollback else None


def _bound_text(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    marker = "\n...[observation truncated by controller]...\n"
    remaining = max_chars - len(marker)
    if remaining <= 0:
        return text[:max_chars]
    head = remaining // 2
    tail = remaining - head
    return text[:head] + marker + text[-tail:]


def _add_usage(left: ModelUsage, right: ModelUsage) -> ModelUsage:
    return ModelUsage(
        prompt_tokens=left.prompt_tokens + right.prompt_tokens,
        completion_tokens=left.completion_tokens + right.completion_tokens,
        total_tokens=left.total_tokens + right.total_tokens,
    )
