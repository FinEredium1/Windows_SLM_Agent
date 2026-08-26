"""Validated Windows command cards and compact BM25 retrieval.

Command cards are trusted, packaged templates.  A model may select a card ID
and provide arguments, but it never supplies an executable command string.
``CommandCard.render`` validates every argument and performs PowerShell-safe
quoting before returning a proposal for the user to review.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
import json
import math
from pathlib import Path
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


_CARD_ID_PATTERN = r"^[a-z0-9]+(?:_[a-z0-9]+)*$"
_PARAMETER_NAME_PATTERN = r"^[a-z][a-z0-9_]*$"
_PLACEHOLDER_RE = re.compile(r"\{([a-z][a-z0-9_]*)\}")
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_SAFE_BARE_RE = re.compile(r"^[A-Za-z0-9_.:/+-]+$")
_RESOURCE_PACKAGE = "terminus_agent.data"
_RESOURCE_NAME = "windows_command_cards.jsonl"

CardCategory = Literal[
    "files",
    "processes",
    "services",
    "registry",
    "event_logs",
    "networking",
    "installed_apps",
    "scheduled_tasks",
    "firewall",
    "users_groups",
    "environment",
    "powershell",
]
QuoteMode = Literal["single", "bare"]
ValueKind = Literal["string", "integer"]
RiskLevel = Literal["low", "medium", "high", "critical"]


class CardCatalogError(ValueError):
    """The packaged command-card catalog is missing or invalid."""


class CommandRenderError(ValueError):
    """A card could not be rendered from the supplied arguments."""


class CommandParameter(BaseModel):
    """One validated placeholder in a command template.

    ``single`` is the default quote mode and emits a PowerShell single-quoted
    literal with embedded apostrophes doubled. ``bare`` is reserved for integer
    values or tightly constrained choices/regular expressions.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    name: str = Field(pattern=_PARAMETER_NAME_PATTERN)
    description: str = Field(min_length=3)
    required: bool = True
    default: str | int | None = None
    choices: tuple[str, ...] = ()
    pattern: str | None = None
    quote: QuoteMode = "single"
    value_kind: ValueKind = "string"
    minimum: int | None = None
    maximum: int | None = None
    example: str | int | None = None

    @field_validator("choices")
    @classmethod
    def _validate_choices(cls, choices: tuple[str, ...]) -> tuple[str, ...]:
        cleaned = tuple(choice.strip() for choice in choices)
        if any(not choice for choice in cleaned):
            raise ValueError("choices cannot contain an empty value")
        if len({choice.casefold() for choice in cleaned}) != len(cleaned):
            raise ValueError("choices must be unique (case-insensitive)")
        return cleaned

    @field_validator("pattern")
    @classmethod
    def _validate_pattern(cls, pattern: str | None) -> str | None:
        if pattern is None:
            return None
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"invalid parameter regex: {exc}") from exc
        return pattern

    @model_validator(mode="after")
    def _validate_constraints(self) -> "CommandParameter":
        if self.minimum is not None or self.maximum is not None:
            if self.value_kind != "integer":
                raise ValueError("minimum/maximum require value_kind='integer'")
            if (
                self.minimum is not None
                and self.maximum is not None
                and self.minimum > self.maximum
            ):
                raise ValueError("minimum cannot exceed maximum")
        if self.quote == "bare" and (
            self.value_kind != "integer" and not self.choices
        ):
            raise ValueError(
                "bare string parameters require strict choices"
            )
        if self.required is False and self.default is None:
            # An omitted optional value intentionally removes its placeholder.
            return self
        if self.default is not None:
            self._validated_text(self.default)
        if self.example is not None:
            self._validated_text(self.example)
        return self

    @staticmethod
    def _reject_controls(text: str) -> None:
        if "\x00" in text or "\r" in text or "\n" in text:
            raise CommandRenderError(
                "command arguments cannot contain NUL or newline characters"
            )

    def _validated_text(self, value: object) -> str:
        if isinstance(value, bool):
            raise CommandRenderError(
                f"parameter {self.name!r} does not accept a boolean"
            )

        if self.value_kind == "integer":
            text = str(value).strip()
            if re.fullmatch(r"[+-]?\d+", text) is None:
                raise CommandRenderError(
                    f"parameter {self.name!r} must be an integer"
                )
            number = int(text)
            if self.minimum is not None and number < self.minimum:
                raise CommandRenderError(
                    f"parameter {self.name!r} must be at least {self.minimum}"
                )
            if self.maximum is not None and number > self.maximum:
                raise CommandRenderError(
                    f"parameter {self.name!r} must be at most {self.maximum}"
                )
            return str(number)

        text = str(value)
        self._reject_controls(text)
        if self.choices:
            canonical = next(
                (
                    choice
                    for choice in self.choices
                    if choice.casefold() == text.casefold()
                ),
                None,
            )
            if canonical is None:
                raise CommandRenderError(
                    f"parameter {self.name!r} must be one of "
                    + ", ".join(repr(choice) for choice in self.choices)
                )
            text = canonical
        if self.pattern is not None and re.fullmatch(self.pattern, text) is None:
            raise CommandRenderError(
                f"parameter {self.name!r} does not match {self.pattern!r}"
            )
        return text

    def render(self, value: object) -> str:
        """Validate and quote one argument for insertion into PowerShell."""
        text = self._validated_text(value)
        if self.quote == "single":
            return "'" + text.replace("'", "''") + "'"
        if _SAFE_BARE_RE.fullmatch(text) is None:
            raise CommandRenderError(
                f"parameter {self.name!r} is not a safe bare PowerShell token"
            )
        return text


class CommandCard(BaseModel):
    """A validated, human-reviewable PowerShell command template."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    id: str = Field(pattern=_CARD_ID_PATTERN)
    category: CardCategory
    shell: Literal["powershell"] = "powershell"
    command: str = Field(min_length=3)
    read_only: bool
    requires_admin: bool
    summary: str = Field(min_length=8)
    triggers: tuple[str, ...] = Field(min_length=2)
    parameters: tuple[CommandParameter, ...]
    gotchas: tuple[str, ...] = Field(min_length=1)
    rollback: str | None = None
    supports_whatif: bool = False
    risk: RiskLevel | None = None

    @field_validator("command", "rollback")
    @classmethod
    def _single_line_command(cls, command: str | None) -> str | None:
        if command is None:
            return None
        if "\x00" in command or "\r" in command or "\n" in command:
            raise ValueError("command templates must be a single line")
        return command

    @field_validator("triggers", "gotchas")
    @classmethod
    def _nonempty_unique_text(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not value.strip() for value in values):
            raise ValueError("list entries cannot be empty")
        if len({value.casefold() for value in values}) != len(values):
            raise ValueError("list entries must be unique (case-insensitive)")
        return values

    @model_validator(mode="after")
    def _parameters_match_placeholders(self) -> "CommandCard":
        names = [parameter.name for parameter in self.parameters]
        if len(set(names)) != len(names):
            raise ValueError("parameter names must be unique")
        placeholders = set(_PLACEHOLDER_RE.findall(self.command))
        declared = set(names)
        unknown = placeholders - declared
        unused = declared - placeholders
        if unknown:
            raise ValueError(
                "undeclared command placeholder(s): " + ", ".join(sorted(unknown))
            )
        if unused:
            raise ValueError(
                "parameter(s) absent from command template: "
                + ", ".join(sorted(unused))
            )
        rollback_placeholders = set(
            _PLACEHOLDER_RE.findall(self.rollback or "")
        )
        rollback_unknown = rollback_placeholders - declared
        if rollback_unknown:
            raise ValueError(
                "undeclared rollback placeholder(s): "
                + ", ".join(sorted(rollback_unknown))
            )
        return self

    def _render_template(
        self,
        template: str,
        arguments: Mapping[str, object] | None,
    ) -> str:
        supplied = dict(arguments or {})
        parameters = {parameter.name: parameter for parameter in self.parameters}
        placeholder_names = set(_PLACEHOLDER_RE.findall(template))
        unknown = set(supplied) - set(parameters)
        if unknown:
            raise CommandRenderError(
                f"unknown argument(s) for {self.id}: "
                + ", ".join(sorted(str(name) for name in unknown))
            )

        rendered: dict[str, str] = {}
        for name in placeholder_names:
            parameter = parameters[name]
            if name in supplied:
                value = supplied[name]
            elif parameter.default is not None:
                value = parameter.default
            elif parameter.required:
                raise CommandRenderError(
                    f"missing required argument {name!r} for {self.id}"
                )
            else:
                rendered[name] = ""
                continue
            rendered[name] = parameter.render(value)

        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            try:
                return rendered[name]
            except KeyError as exc:  # guarded by schema validation
                raise CommandRenderError(
                    f"template placeholder {name!r} has no rendered value"
                ) from exc

        # Do not normalize whitespace after substitution: spaces inside a
        # safely quoted path or value are meaningful PowerShell data.
        return _PLACEHOLDER_RE.sub(replace, template).strip()

    def render(self, arguments: Mapping[str, object] | None = None) -> str:
        """Render this trusted template from validated, safely quoted arguments.

        Missing required values, unknown keys, invalid choices/ranges, and
        unsafe bare values fail closed with :class:`CommandRenderError`.
        """
        return self._render_template(self.command, arguments)

    def render_rollback(
        self,
        arguments: Mapping[str, object] | None = None,
    ) -> str | None:
        """Safely render this card's rollback template, when one is provided."""
        if self.rollback is None:
            return None
        return self._render_template(self.rollback, arguments)

    @property
    def retrieval_text(self) -> str:
        """Text indexed by BM25; warnings are omitted to avoid ranking noise."""
        parameter_text = " ".join(
            f"{parameter.name} {parameter.description}"
            for parameter in self.parameters
        )
        return " ".join(
            (
                self.id.replace("_", " "),
                self.category.replace("_", " "),
                self.summary,
                " ".join(self.triggers),
                self.command,
                parameter_text,
            )
        )


@dataclass(frozen=True, slots=True)
class CardHit:
    """One ranked command-card result."""

    card: CommandCard
    score: float


def _tokens(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.casefold())


class CommandCardCatalog:
    """In-memory command-card catalog with a compact Okapi BM25 index."""

    def __init__(
        self,
        cards: Sequence[CommandCard],
        *,
        k1: float = 1.5,
        b: float = 0.75,
    ) -> None:
        if not cards:
            raise CardCatalogError("command-card catalog cannot be empty")
        if k1 <= 0:
            raise ValueError("k1 must be positive")
        if not 0 <= b <= 1:
            raise ValueError("b must be between 0 and 1")

        ids = [card.id for card in cards]
        duplicates = sorted(
            card_id for card_id, count in Counter(ids).items() if count > 1
        )
        if duplicates:
            raise CardCatalogError(
                "duplicate command-card id(s): " + ", ".join(duplicates)
            )

        self._cards = tuple(cards)
        self._by_id = {card.id: card for card in cards}
        self._k1 = float(k1)
        self._b = float(b)
        self._term_counts = tuple(
            Counter(_tokens(card.retrieval_text)) for card in cards
        )
        self._lengths = tuple(sum(counts.values()) for counts in self._term_counts)
        self._average_length = sum(self._lengths) / len(self._lengths)
        document_frequency: Counter[str] = Counter()
        for counts in self._term_counts:
            document_frequency.update(counts.keys())
        size = len(self._cards)
        self._idf = {
            term: math.log(
                1.0 + (size - frequency + 0.5) / (frequency + 0.5)
            )
            for term, frequency in document_frequency.items()
        }

    def __len__(self) -> int:
        return len(self._cards)

    def __iter__(self) -> Iterable[CommandCard]:
        return iter(self._cards)

    def get(self, card_id: str) -> CommandCard | None:
        return self._by_id.get(card_id)

    def require(self, card_id: str) -> CommandCard:
        try:
            return self._by_id[card_id]
        except KeyError as exc:
            raise KeyError(f"unknown command-card id: {card_id}") from exc

    def search(
        self,
        query: str,
        limit: int = 5,
        include_write: bool = True,
    ) -> list[CardHit]:
        """Return the highest-scoring cards for a natural-language query."""
        if limit < 1:
            raise ValueError("limit must be at least 1")
        query_terms = _tokens(query)
        if not query_terms:
            return []

        query_counts = Counter(query_terms)
        normalized_query = " ".join(query_terms)
        hits: list[CardHit] = []
        for card, counts, length in zip(
            self._cards,
            self._term_counts,
            self._lengths,
            strict=True,
        ):
            if not include_write and not card.read_only:
                continue
            score = 0.0
            norm = self._k1 * (
                1.0
                - self._b
                + self._b * length / max(self._average_length, 1.0)
            )
            for term, query_weight in query_counts.items():
                frequency = counts.get(term, 0)
                if not frequency:
                    continue
                score += (
                    self._idf.get(term, 0.0)
                    * (frequency * (self._k1 + 1.0))
                    / (frequency + norm)
                    * min(query_weight, 2)
                )

            # BM25 remains the ranker; these small corpus-derived bonuses make
            # literal card IDs and full trigger phrases deterministic tie-breaks.
            if normalized_query == " ".join(_tokens(card.id)):
                score += 8.0
            if any(
                " ".join(_tokens(trigger)) in normalized_query
                for trigger in card.triggers
                if len(_tokens(trigger)) >= 2
            ):
                score += 1.0
            if score > 0:
                hits.append(CardHit(card=card, score=score))

        hits.sort(key=lambda hit: (-hit.score, hit.card.id))
        return hits[:limit]

    @staticmethod
    def format_for_prompt(hits: Sequence[CardHit]) -> str:
        """Render ranked cards as compact, trusted model-selection context.

        The block deliberately exposes templates, never rendered commands.  A
        controller should accept only ``card_id`` plus an ``arguments`` object
        and call :meth:`CommandCard.render` itself.
        """
        if not hits:
            return (
                "WINDOWS COMMAND CARDS\n"
                "(no matching cards; do not invent PowerShell)"
            )
        lines = [
            "WINDOWS COMMAND CARDS",
            "Select one card_id and provide only its arguments object. "
            "Never author raw PowerShell. Write cards are suggestion-only and "
            "must never be executed by the agent.",
        ]
        for rank, hit in enumerate(hits, 1):
            card = hit.card
            mode = "read-only" if card.read_only else "WRITE: suggestion-only"
            metadata = [
                mode,
                f"admin={'yes' if card.requires_admin else 'no'}",
            ]
            if card.risk is not None:
                metadata.append(f"risk={card.risk}")
            lines.append(
                f"{rank}. card_id={card.id} [{'; '.join(metadata)}]"
            )
            lines.append(f"   purpose: {card.summary}")
            lines.append(f"   template: {card.command}")
            if card.parameters:
                for parameter in card.parameters:
                    constraints: list[str] = [
                        "required" if parameter.required else "optional"
                    ]
                    if parameter.default is not None:
                        constraints.append(f"default={parameter.default!r}")
                    if parameter.choices:
                        constraints.append(
                            "choices=" + "|".join(parameter.choices)
                        )
                    if parameter.value_kind == "integer":
                        bounds = (
                            f"{parameter.minimum if parameter.minimum is not None else ''}"
                            ".."
                            f"{parameter.maximum if parameter.maximum is not None else ''}"
                        )
                        constraints.append(f"integer={bounds}")
                    elif parameter.pattern:
                        constraints.append(f"regex={parameter.pattern}")
                    lines.append(
                        f"   arg {parameter.name} ({'; '.join(constraints)}): "
                        f"{parameter.description}"
                    )
            else:
                lines.append("   args: {}")
            if card.supports_whatif:
                lines.append("   preview: supports -WhatIf")
            if card.rollback is not None:
                lines.append(f"   rollback template: {card.rollback}")
            for gotcha in card.gotchas:
                lines.append(f"   warning: {gotcha}")
        return "\n".join(lines)


def _iter_jsonl(
    lines: Iterable[str],
    *,
    source: str,
) -> list[CommandCard]:
    cards: list[CommandCard] = []
    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CardCatalogError(
                f"{source}:{line_number}: invalid JSON: {exc.msg}"
            ) from exc
        try:
            cards.append(CommandCard.model_validate(payload))
        except ValidationError as exc:
            raise CardCatalogError(
                f"{source}:{line_number}: invalid command card: {exc}"
            ) from exc
    return cards


def load_command_cards(path: str | Path | None = None) -> list[CommandCard]:
    """Load and validate cards from *path* or the packaged Windows catalog."""
    if path is not None:
        card_path = Path(path)
        try:
            text = card_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise CardCatalogError(
                f"could not read command-card catalog {card_path}: {exc}"
            ) from exc
        cards = _iter_jsonl(text.splitlines(), source=str(card_path))
    else:
        try:
            resource = resources.files(_RESOURCE_PACKAGE).joinpath(_RESOURCE_NAME)
            text = resource.read_text(encoding="utf-8")
        except (FileNotFoundError, ModuleNotFoundError, OSError) as exc:
            raise CardCatalogError(
                f"could not read packaged command-card catalog "
                f"{_RESOURCE_PACKAGE}/{_RESOURCE_NAME}: {exc}"
            ) from exc
        cards = _iter_jsonl(
            text.splitlines(),
            source=f"{_RESOURCE_PACKAGE}/{_RESOURCE_NAME}",
        )

    # Construction performs the cross-record duplicate-ID check.
    CommandCardCatalog(cards)
    return cards


@lru_cache(maxsize=1)
def get_default_catalog() -> CommandCardCatalog:
    """Return the process-wide validated packaged catalog."""
    return CommandCardCatalog(load_command_cards())


def search_command_cards(
    query: str,
    *,
    limit: int = 5,
    include_write: bool = True,
) -> list[CardHit]:
    """Search the packaged catalog without constructing an index per request."""
    return get_default_catalog().search(
        query,
        limit=limit,
        include_write=include_write,
    )
