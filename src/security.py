"""Security primitives shared by filesystem, HTTP, and Windows tools."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import socket
import stat
from typing import Callable
from urllib.parse import SplitResult, urlsplit, urlunsplit


class SecurityViolation(ValueError):
    """A read request violates a hard local security boundary."""


def resolve_read_path(
    raw_path: str,
    *,
    must_exist: bool = True,
    require_file: bool = False,
    require_directory: bool = False,
) -> Path:
    """Resolve a normal local path and reject network/device namespaces.

    A model-directed UNC read can silently initiate SMB authentication, and
    Windows ``\\?\\`` / ``\\.\\`` paths can expose device objects.  Reject
    those forms before ``Path`` or the operating system touches the target.
    """

    if not raw_path or not raw_path.strip():
        raise SecurityViolation("path cannot be empty")
    if "\x00" in raw_path:
        raise SecurityViolation("path cannot contain a NUL byte")
    expanded = os.path.expandvars(os.path.expanduser(raw_path.strip()))
    normalized = expanded.replace("/", "\\").casefold()
    if normalized.startswith(("\\\\?\\", "\\\\.\\")):
        raise SecurityViolation(
            "Windows device and extended-length namespaces are not readable tools."
        )
    if normalized.startswith("\\\\"):
        raise SecurityViolation(
            "UNC/network paths are blocked to prevent unintended SMB access "
            "and credential disclosure."
        )
    if normalized.startswith(("\\device\\", "\\??\\")):
        raise SecurityViolation(
            "Windows native device namespaces are not readable tools."
        )
    path = Path(expanded).resolve(strict=must_exist)
    if must_exist:
        mode = path.stat().st_mode
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise SecurityViolation(
                "Only regular files and directories can be inspected."
            )
    if require_file and not path.is_file():
        raise SecurityViolation(f"Not a regular file: {path}")
    if require_directory and not path.is_dir():
        raise SecurityViolation(f"Not a directory: {path}")
    return path


def truncate_utf8(text: str, max_bytes: int) -> tuple[str, bool]:
    """Truncate without splitting a UTF-8 sequence."""

    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text, False
    return encoded[:max_bytes].decode("utf-8", errors="ignore"), True


def looks_binary(sample: bytes) -> bool:
    """Conservative binary detector for model-facing file reads."""

    if not sample:
        return False
    if b"\x00" in sample:
        return True
    control = sum(
        byte < 9 or (13 < byte < 32)
        for byte in sample
    )
    return control / len(sample) > 0.08


@dataclass(frozen=True, slots=True)
class ValidatedURL:
    url: str
    hostname: str
    port: int
    addresses: tuple[str, ...]


AddressResolver = Callable[..., list[tuple]]


def _resolved_addresses(
    host: str,
    port: int,
    resolver: AddressResolver,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    try:
        literal = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        try:
            records = resolver(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise SecurityViolation(f"Could not resolve {host!r}: {exc}") from exc
        values: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for record in records:
            sockaddr = record[4]
            try:
                value = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
            except (ValueError, IndexError):
                continue
            if value not in values:
                values.append(value)
        if not values:
            raise SecurityViolation(f"{host!r} did not resolve to an IP address")
        return tuple(values)
    return (literal,)


def validate_fetch_url(
    raw_url: str,
    *,
    allow_private: bool = False,
    resolver: AddressResolver = socket.getaddrinfo,
) -> ValidatedURL:
    """Validate one GET target, resolving every address before connecting.

    Redirect destinations must be passed through this function independently.
    """

    if not raw_url or len(raw_url) > 4096:
        raise SecurityViolation("URL is empty or too long")
    parsed: SplitResult = urlsplit(raw_url)
    if parsed.scheme.casefold() not in {"http", "https"}:
        raise SecurityViolation("Only http:// and https:// URLs are allowed")
    if not parsed.hostname:
        raise SecurityViolation("URL must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise SecurityViolation("URLs containing credentials are not allowed")
    if parsed.fragment:
        raise SecurityViolation("URL fragments are not allowed")
    host = parsed.hostname.rstrip(".")
    if not host:
        raise SecurityViolation("URL hostname cannot be empty")
    if "%" in host:
        raise SecurityViolation("Scoped IPv6 addresses are not allowed")
    try:
        port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
    except ValueError as exc:
        raise SecurityViolation(f"Invalid URL port: {exc}") from exc
    addresses = _resolved_addresses(host, port, resolver)
    for address in addresses:
        if allow_private:
            unsafe = (
                address.is_unspecified
                or address.is_multicast
                or address.is_reserved
            )
        else:
            # Be explicit as ipaddress has historically classified some
            # multicast ranges as "global" in the routing-scope sense.
            unsafe = (
                not address.is_global
                or address.is_loopback
                or address.is_link_local
                or address.is_private
                or address.is_reserved
                or address.is_unspecified
                or address.is_multicast
            )
        if unsafe:
            raise SecurityViolation(
                f"Refusing non-public address {address} for host {host!r}"
            )
    normalized = urlunsplit(
        (
            parsed.scheme.casefold(),
            parsed.netloc,
            parsed.path or "/",
            parsed.query,
            "",
        )
    )
    return ValidatedURL(
        url=normalized,
        hostname=host,
        port=port,
        addresses=tuple(str(value) for value in addresses),
    )


_TEXT_MEDIA_TYPES = {
    "application/json",
    "application/ld+json",
    "application/xml",
    "application/xhtml+xml",
    "application/javascript",
    "application/x-yaml",
    "application/yaml",
}


def is_model_safe_content_type(content_type: str | None) -> bool:
    """Allow text and structured text; reject archives, executables, and media."""

    if not content_type:
        return False
    media_type = content_type.split(";", 1)[0].strip().casefold()
    return (
        media_type.startswith("text/")
        or media_type in _TEXT_MEDIA_TYPES
        or media_type.endswith("+json")
        or media_type.endswith("+xml")
    )
