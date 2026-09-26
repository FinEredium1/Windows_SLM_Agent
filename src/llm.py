"""OpenAI-compatible llama.cpp client with streamed tool-call reconstruction."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import Any

import httpx

from .config import Settings
from .errors import ModelError
from .models import ModelResponse, ModelUsage, ToolCall
TokenCallback = Callable[[str], None]


class LocalModelClient:
    """Small synchronous client for the local Gemma llama-server."""

    def __init__(
        self,
        settings: Settings,
        *,
        http_client: httpx.Client | None = None,
    ) -> None:
        settings.require_safe_model_endpoint()
        self.settings = settings
        headers = {"Content-Type": "application/json"}
        if settings.api_key:
            headers["Authorization"] = f"Bearer {settings.api_key}"
        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(
            timeout=httpx.Timeout(settings.timeout_seconds),
            headers=headers,
            trust_env=False,
        )

    @property
    def endpoint(self) -> str:
        return f"{self.settings.base_url}/chat/completions"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "LocalModelClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def complete(
        self,
        messages: list[dict[str, Any]],
        temp: float, 
        tools: list[dict[str, Any]],
        *,
        stream: bool | None = None,
        on_token: TokenCallback | None = None,
    ) -> ModelResponse:
        should_stream = self.settings.stream if stream is None else stream
        payload: dict[str, Any] = {
            "model": self.settings.model,
            "messages": messages,
            "temperature": temp,
            "stream": should_stream,
            "max_tokens": self.settings.max_model_output_tokens,
            "chat_template_kwargs": {"enable_thinking": False},
        }

        if tools:
            payload.update(
                {
                    "tools": tools,
                    "tool_choice": "auto",
                    "parallel_tool_calls": False,
                }
            )
        if should_stream:
            payload["stream_options"] = {"include_usage": True}
        if self.settings.debug:
            safe_payload = dict(payload)
            if self.settings.api_key:
                safe_payload["api_key"] = "(redacted)"
            print(
                json.dumps(safe_payload, indent=2, ensure_ascii=False),
                file=sys.stderr,
            )
        try:
            if should_stream:
                return self._complete_stream(payload, on_token)
            response = self._client.post(self.endpoint, json=payload)
            response.raise_for_status()
            return self._parse_complete(response.json())
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text[:1000]
            status_code = exc.response.status_code
            raise ModelError(
                f"Model endpoint returned HTTP {status_code}: {detail}",
                retryable=(
                    status_code in {408, 409, 425, 429}
                    or status_code >= 500
                ),
            ) from exc
        except httpx.RequestError as exc:
            raise ModelError(
                f"Could not reach the local model endpoint: {exc}",
                retryable=True,
            ) from exc
        except (
            AttributeError,
            OverflowError,
            ValueError,
            KeyError,
            TypeError,
        ) as exc:
            raise ModelError(f"Could not read the local model response: {exc}") from exc

    def _complete_stream(
        self,
        payload: dict[str, Any],
        on_token: TokenCallback | None,
    ) -> ModelResponse:
        content: list[str] = []
        calls: dict[int, dict[str, str]] = {}
        usage = ModelUsage()
        with self._client.stream("POST", self.endpoint, json=payload) as response:
            if response.is_error:
                response.read()
            response.raise_for_status()
            for line in response.iter_lines():
                if not line or not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                chunk = json.loads(data)
                if chunk.get("usage"):
                    usage = _parse_usage(chunk["usage"])
                choices = chunk.get("choices") or []
                if not choices:
                    continue
                delta = choices[0].get("delta") or {}
                token = delta.get("content") or ""
                if token:
                    content.append(token)
                    if on_token is not None:
                        on_token(token)
                for call_delta in delta.get("tool_calls") or []:
                    index = int(call_delta.get("index", 0))
                    slot = calls.setdefault(
                        index, {"id": "", "name": "", "arguments": ""}
                    )
                    if call_delta.get("id"):
                        slot["id"] = str(call_delta["id"])
                    function = call_delta.get("function") or {}
                    if function.get("name"):
                        slot["name"] += str(function["name"])
                    if function.get("arguments"):
                        slot["arguments"] += str(function["arguments"])
        return ModelResponse(
            content="".join(content),
            tool_calls=[
                _tool_call_from_parts(index, parts)
                for index, parts in sorted(calls.items())
                if parts["name"]
            ],
            usage=usage,
        )

    @staticmethod
    def _parse_complete(payload: dict[str, Any]) -> ModelResponse:
        choices = payload.get("choices") or []
        if not choices:
            raise ModelError("Model response did not contain a choice.")
        message = choices[0].get("message") or {}
        calls: list[ToolCall] = []
        for index, raw_call in enumerate(message.get("tool_calls") or []):
            function = raw_call.get("function") or {}
            calls.append(
                _tool_call_from_parts(
                    index,
                    {
                        "id": str(raw_call.get("id") or ""),
                        "name": str(function.get("name") or ""),
                        "arguments": str(function.get("arguments") or "{}"),
                    },
                )
            )
        legacy = message.get("function_call")
        if legacy and not calls:
            calls.append(
                _tool_call_from_parts(
                    0,
                    {
                        "id": "legacy_call_0",
                        "name": str(legacy.get("name") or ""),
                        "arguments": str(legacy.get("arguments") or "{}"),
                    },
                )
            )
        return ModelResponse(
            content=str(message.get("content") or ""),
            tool_calls=calls,
            usage=_parse_usage(payload.get("usage") or {}),
        )


def _parse_usage(raw: dict[str, Any]) -> ModelUsage:
    prompt = int(raw.get("prompt_tokens") or 0)
    completion = int(raw.get("completion_tokens") or 0)
    return ModelUsage(
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=int(raw.get("total_tokens") or prompt + completion),
    )


def _tool_call_from_parts(index: int, parts: dict[str, str]) -> ToolCall:
    raw_arguments = parts.get("arguments") or "{}"
    try:
        arguments = json.loads(raw_arguments)
    except json.JSONDecodeError:
        arguments = {}
    if not isinstance(arguments, dict):
        arguments = {}
    return ToolCall(
        id=parts.get("id") or f"call_{index}",
        name=parts.get("name") or "",
        arguments=arguments,
        raw_arguments=raw_arguments,
    )
