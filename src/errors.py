"""Product-level exceptions and model retry classification."""

from __future__ import annotations


class TerminusError(RuntimeError):
    """Base error shown to the operator without a Python traceback."""


class ConfigurationError(TerminusError):
    """The local runtime configuration is invalid or unsafe."""


class ModelError(TerminusError):
    """The local model endpoint failed or returned an invalid response."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


class AgentExhaustedError(TerminusError):
    """The bounded controller stopped before receiving a valid terminal action."""


class ToolError(TerminusError):
    """A controller-owned tool could not satisfy its contract."""


def is_retryable_model_error(exc: BaseException) -> bool:
    """Return whether a model call is safe to retry in the same invocation."""
    if isinstance(exc, ModelError):
        return exc.retryable
    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        status = getattr(getattr(current, "response", None), "status_code", None)
        if status is not None:
            try:
                status_code = int(status)
            except (TypeError, ValueError):
                break
            if 400 <= status_code < 500 and status_code not in {
                408,
                409,
                425,
                429,
            }:
                return False
            return True
        current = current.__cause__ or current.__context__
    return not isinstance(exc, (ConfigurationError, KeyboardInterrupt))
