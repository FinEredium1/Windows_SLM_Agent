"""Bounded, read-only filesystem tools."""

from __future__ import annotations

from datetime import datetime, timezone
import fnmatch
from pathlib import Path
from typing import Literal

from pydantic import Field

from ..security import looks_binary, resolve_read_path
from .base import Provenance, ToolDefinition, ToolInput, ToolObservation


_MAX_SCAN_ENTRIES = 10_000
_MAX_SEARCH_FILE_BYTES = 2 * 1024 * 1024


class ListFilesInput(ToolInput):
    path: str = Field(default=".", description="Directory to inspect.")
    pattern: str = Field(
        default="*",
        min_length=1,
        max_length=256,
        description="Filename glob such as *.log. It does not change the root path.",
    )
    recursive: bool = Field(
        default=False,
        description="Whether to descend into child directories.",
    )
    limit: int = Field(default=200, ge=1, le=1000)


class ReadFileInput(ToolInput):
    path: str = Field(description="Path to a regular text file.")
    offset_bytes: int = Field(default=0, ge=0)
    max_bytes: int = Field(default=65_536, ge=1, le=262_144)
    encoding: Literal["utf-8", "utf-16", "utf-16-le", "utf-16-be", "latin-1"] = (
        "utf-8"
    )


class SearchFilesInput(ToolInput):
    path: str = Field(default=".", description="Directory tree to search.")
    query: str = Field(min_length=1, max_length=500)
    pattern: str = Field(
        default="*",
        min_length=1,
        max_length=256,
        description="Filename glob, for example *.txt or *.log.",
    )
    recursive: bool = True
    case_sensitive: bool = False
    max_results: int = Field(default=100, ge=1, le=500)
    max_file_bytes: int = Field(
        default=_MAX_SEARCH_FILE_BYTES,
        ge=1,
        le=10 * 1024 * 1024,
    )


def _timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def _entry(root: Path, path: Path) -> dict[str, object]:
    info = path.stat()
    try:
        relative = str(path.relative_to(root))
    except ValueError:
        relative = path.name
    return {
        "name": path.name,
        "relative_path": relative,
        "path": str(path),
        "type": "directory" if path.is_dir() else "file",
        "size_bytes": info.st_size if path.is_file() else None,
        "modified_at": _timestamp(info.st_mtime),
    }


def list_files(arguments: ToolInput) -> ToolObservation:
    values = ListFilesInput.model_validate(arguments)
    root = resolve_read_path(values.path, require_directory=True)
    iterator = root.rglob("*") if values.recursive else root.iterdir()
    entries: list[dict[str, object]] = []
    scanned = 0
    inaccessible = 0
    for path in iterator:
        scanned += 1
        if scanned > _MAX_SCAN_ENTRIES:
            break
        relative = str(path.relative_to(root))
        if not (
            fnmatch.fnmatch(path.name, values.pattern)
            or fnmatch.fnmatch(relative, values.pattern)
        ):
            continue
        try:
            entries.append(_entry(root, path))
        except (OSError, PermissionError):
            inaccessible += 1
            continue
        if len(entries) >= values.limit:
            break
    entries.sort(key=lambda item: (str(item["type"]), str(item["relative_path"]).casefold()))
    limited = (
        len(entries) >= values.limit
        or scanned > _MAX_SCAN_ENTRIES
    )
    return ToolObservation.success(
        "list_files",
        f"Found {len(entries)} matching entries under {root}.",
        {
            "root": str(root),
            "pattern": values.pattern,
            "recursive": values.recursive,
            "entries": entries,
            "scanned_entries": min(scanned, _MAX_SCAN_ENTRIES),
            "inaccessible_entries": inaccessible,
            "limit_reached": limited,
        },
        provenance=[
            Provenance(
                source="filesystem",
                method="directory enumeration",
                target=str(root),
            )
        ],
    )


def read_file(arguments: ToolInput) -> ToolObservation:
    values = ReadFileInput.model_validate(arguments)
    path = resolve_read_path(values.path, require_file=True)
    size = path.stat().st_size
    with path.open("rb") as handle:
        handle.seek(values.offset_bytes)
        payload = handle.read(values.max_bytes + 1)
    has_more = len(payload) > values.max_bytes
    payload = payload[: values.max_bytes]
    if looks_binary(payload[:8192]):
        return ToolObservation.failure(
            "read_file",
            "binary_file",
            "The target appears to be binary; this text-only tool did not expose it.",
            data={"path": str(path), "size_bytes": size},
            provenance=[
                Provenance(
                    source="filesystem",
                    method="bounded binary check",
                    target=str(path),
                )
            ],
        )
    try:
        content = payload.decode(values.encoding)
        replacement_characters = 0
    except UnicodeDecodeError:
        content = payload.decode(values.encoding, errors="replace")
        replacement_characters = content.count("\ufffd")
    return ToolObservation.success(
        "read_file",
        f"Read {len(payload)} bytes from {path}.",
        {
            "path": str(path),
            "content": content,
            "encoding": values.encoding,
            "offset_bytes": values.offset_bytes,
            "bytes_read": len(payload),
            "size_bytes": size,
            "has_more": has_more or values.offset_bytes + len(payload) < size,
            "next_offset_bytes": values.offset_bytes + len(payload),
            "replacement_characters": replacement_characters,
        },
        provenance=[
            Provenance(
                source="filesystem",
                method="bounded text read",
                target=str(path),
            )
        ],
    )


def search_files(arguments: ToolInput) -> ToolObservation:
    values = SearchFilesInput.model_validate(arguments)
    root = resolve_read_path(values.path, require_directory=True)
    iterator = root.rglob("*") if values.recursive else root.iterdir()
    needle = values.query if values.case_sensitive else values.query.casefold()
    matches: list[dict[str, object]] = []
    scanned_entries = 0
    searched_files = 0
    skipped_files = 0
    for path in iterator:
        scanned_entries += 1
        if scanned_entries > _MAX_SCAN_ENTRIES:
            break
        if not path.is_file() or not fnmatch.fnmatch(path.name, values.pattern):
            continue
        try:
            size = path.stat().st_size
            if size > values.max_file_bytes:
                skipped_files += 1
                continue
            payload = path.read_bytes()
        except (OSError, PermissionError):
            skipped_files += 1
            continue
        if looks_binary(payload[:8192]):
            skipped_files += 1
            continue
        text = payload.decode("utf-8", errors="replace")
        searched_files += 1
        for line_number, line in enumerate(text.splitlines(), start=1):
            haystack = line if values.case_sensitive else line.casefold()
            if needle not in haystack:
                continue
            matches.append(
                {
                    "path": str(path),
                    "line_number": line_number,
                    "line": line[:500],
                    "line_truncated": len(line) > 500,
                }
            )
            if len(matches) >= values.max_results:
                break
        if len(matches) >= values.max_results:
            break
    return ToolObservation.success(
        "search_files",
        f"Found {len(matches)} text matches under {root}.",
        {
            "root": str(root),
            "query": values.query,
            "pattern": values.pattern,
            "matches": matches,
            "searched_files": searched_files,
            "skipped_files": skipped_files,
            "scanned_entries": min(scanned_entries, _MAX_SCAN_ENTRIES),
            "limit_reached": (
                len(matches) >= values.max_results
                or scanned_entries > _MAX_SCAN_ENTRIES
            ),
        },
        provenance=[
            Provenance(
                source="filesystem",
                method="bounded literal text search",
                target=str(root),
            )
        ],
    )


def filesystem_tools() -> tuple[ToolDefinition, ...]:
    return (
        ToolDefinition(
            name="list_files",
            description=(
                "List files and directories, with metadata, under a local path. "
                "Read-only and bounded."
            ),
            input_model=ListFilesInput,
            handler=list_files,
            keywords=(
                "show files",
                "list directory",
                "folder contents",
                "find filename",
            ),
        ),
        ToolDefinition(
            name="read_file",
            description=(
                "Read a bounded chunk from a local text file without changing it."
            ),
            input_model=ReadFileInput,
            handler=read_file,
            keywords=("open file", "read log", "view text", "file contents"),
        ),
        ToolDefinition(
            name="search_files",
            description=(
                "Search text files for a literal phrase and return matching lines."
            ),
            input_model=SearchFilesInput,
            handler=search_files,
            keywords=("search files", "find text", "grep", "look in logs"),
        ),
    )


__all__ = [
    "ListFilesInput",
    "ReadFileInput",
    "SearchFilesInput",
    "filesystem_tools",
    "list_files",
    "read_file",
    "search_files",
]
