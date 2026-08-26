"""Read-only network inventory and a tightly constrained HTTP GET tool."""

from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timezone
import socket
from urllib.parse import urljoin

import httpx
import psutil
from pydantic import Field

from ..security import (
    SecurityViolation,
    is_model_safe_content_type,
    validate_fetch_url,
)
from .base import Provenance, ToolDefinition, ToolInput, ToolObservation


class ListeningPortsInput(ToolInput):
    protocol: str = Field(
        default="all",
        pattern=r"^(all|tcp|udp)$",
        description="Return TCP listeners, bound UDP endpoints, or both.",
    )
    port: int | None = Field(default=None, ge=1, le=65_535)
    process_name: str | None = Field(default=None, min_length=1, max_length=260)
    limit: int = Field(default=500, ge=1, le=2000)


class NetworkInfoInput(ToolInput):
    include_inactive: bool = False


class FetchUrlInput(ToolInput):
    url: str = Field(
        min_length=8,
        max_length=4096,
        description=(
            "Public http(s) URL. Credentials and private, loopback, link-local, "
            "reserved, and multicast targets are rejected."
        ),
    )
    max_bytes: int = Field(default=262_144, ge=1024, le=1_048_576)
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=30.0)
    max_redirects: int = Field(default=3, ge=0, le=5)


def _address(value: object) -> tuple[str, int] | None:
    if not value:
        return None
    if hasattr(value, "ip") and hasattr(value, "port"):
        return str(value.ip), int(value.port)
    if isinstance(value, tuple) and len(value) >= 2:
        return str(value[0]), int(value[1])
    return None


def list_listening_ports(arguments: ToolInput) -> ToolObservation:
    values = ListeningPortsInput.model_validate(arguments)
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return ToolObservation.failure(
            "list_listening_ports",
            "permission_denied",
            (
                "The operating system denied the socket inventory. Run under an "
                "account allowed to inspect system network connections."
            ),
            provenance=[
                Provenance(
                    source="psutil",
                    method="system socket inventory",
                )
            ],
        )
    process_names: dict[int, str | None] = {}
    records: list[dict[str, object]] = []
    requested_name = values.process_name.casefold() if values.process_name else None
    for connection in connections:
        protocol = (
            "tcp"
            if connection.type == socket.SOCK_STREAM
            else "udp"
            if connection.type == socket.SOCK_DGRAM
            else "other"
        )
        if protocol == "tcp" and connection.status != psutil.CONN_LISTEN:
            continue
        if protocol == "udp" and not connection.laddr:
            continue
        if protocol not in {"tcp", "udp"}:
            continue
        if values.protocol != "all" and protocol != values.protocol:
            continue
        local = _address(connection.laddr)
        if local is None:
            continue
        if values.port is not None and local[1] != values.port:
            continue
        pid = connection.pid
        process_name: str | None = None
        if pid is not None:
            if pid not in process_names:
                try:
                    process_names[pid] = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_names[pid] = None
            process_name = process_names[pid]
        if requested_name and requested_name not in (process_name or "").casefold():
            continue
        remote = _address(connection.raddr)
        records.append(
            {
                "protocol": protocol,
                "local_address": local[0],
                "local_port": local[1],
                "state": (
                    connection.status
                    if protocol == "tcp"
                    else "BOUND"
                ),
                "pid": pid,
                "process_name": process_name,
                "remote_address": remote[0] if remote else None,
                "remote_port": remote[1] if remote else None,
            }
        )
    records.sort(
        key=lambda item: (
            int(item["local_port"]),
            str(item["protocol"]),
            str(item["local_address"]),
            int(item["pid"] or -1),
        )
    )
    limit_reached = len(records) > values.limit
    records = records[: values.limit]
    return ToolObservation.success(
        "list_listening_ports",
        f"Found {len(records)} listening or bound network endpoint(s).",
        {
            "listeners": records,
            "filters": {
                "protocol": values.protocol,
                "port": values.port,
                "process_name": values.process_name,
            },
            "tcp_definition": "LISTEN state",
            "udp_definition": "locally bound endpoint",
            "limit_reached": limit_reached,
        },
        provenance=[
            Provenance(
                source="psutil",
                method="system-wide inet socket inventory",
                target=values.process_name,
            )
        ],
    )


def get_network_info(arguments: ToolInput) -> ToolObservation:
    values = NetworkInfoInput.model_validate(arguments)
    stats = psutil.net_if_stats()
    counters = psutil.net_io_counters(pernic=True)
    interfaces: list[dict[str, object]] = []
    for name, addresses in psutil.net_if_addrs().items():
        interface_stats = stats.get(name)
        if (
            not values.include_inactive
            and interface_stats is not None
            and not interface_stats.isup
        ):
            continue
        formatted_addresses = []
        for address in addresses:
            family = getattr(address.family, "name", str(address.family))
            formatted_addresses.append(
                {
                    "family": family,
                    "address": address.address,
                    "netmask": address.netmask,
                    "broadcast": address.broadcast,
                }
            )
        io = counters.get(name)
        interfaces.append(
            {
                "name": name,
                "is_up": interface_stats.isup if interface_stats else None,
                "speed_mbps": interface_stats.speed if interface_stats else None,
                "mtu": interface_stats.mtu if interface_stats else None,
                "addresses": formatted_addresses,
                "bytes_sent": io.bytes_sent if io else None,
                "bytes_received": io.bytes_recv if io else None,
                "packets_sent": io.packets_sent if io else None,
                "packets_received": io.packets_recv if io else None,
            }
        )
    interfaces.sort(key=lambda item: str(item["name"]).casefold())
    hostname = socket.gethostname()
    try:
        resolved = sorted(
            {
                record[4][0]
                for record in socket.getaddrinfo(hostname, None)
                if record[4]
            }
        )
    except OSError:
        resolved = []
    return ToolObservation.success(
        "get_network_info",
        f"Read {len(interfaces)} network interface(s) for {hostname}.",
        {
            "hostname": hostname,
            "resolved_host_addresses": resolved,
            "interfaces": interfaces,
        },
        provenance=[
            Provenance(
                source="psutil",
                method="network interface inventory and counters",
                target=hostname,
            )
        ],
    )


def _decode_body(body: bytes, content_type: str, encoding: str | None) -> str:
    charset = encoding
    if not charset and "charset=" in content_type.casefold():
        charset = content_type.casefold().split("charset=", 1)[1].split(";", 1)[0].strip()
    try:
        return body.decode(charset or "utf-8", errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def fetch_url(arguments: ToolInput) -> ToolObservation:
    """Perform a public, credential-free GET with manual redirect validation."""

    values = FetchUrlInput.model_validate(arguments)
    current = values.url
    provenance: list[Provenance] = []
    visited: list[str] = []
    timeout = httpx.Timeout(values.timeout_seconds)
    try:
        with ExitStack() as clients:
            for redirect_count in range(values.max_redirects + 1):
                validated = validate_fetch_url(current)
                visited.append(validated.url)
                pinned_address = validated.addresses[0]
                provenance.append(
                    Provenance(
                        source="http",
                        method=(
                            "credential-free GET; DNS addresses validated as "
                            "public and the connection pinned to one result"
                        ),
                        target=(
                            f"{validated.url} -> {pinned_address} "
                            f"(validated: {', '.join(validated.addresses)})"
                        ),
                    )
                )
                # Connect to the validated numeric address so a second DNS
                # lookup inside the HTTP stack cannot rebind the request to a
                # loopback/private target. Preserve the original Host header
                # and TLS SNI/certificate hostname.
                original_url = httpx.URL(validated.url)
                pinned_url = original_url.copy_with(host=pinned_address)
                client = clients.enter_context(
                    httpx.Client(
                        follow_redirects=False,
                        timeout=timeout,
                        trust_env=False,
                        headers={
                            "Accept": (
                                "text/plain, text/html, application/json, "
                                "application/xml;q=0.9"
                            ),
                            "User-Agent": "Terminus-ReadOnly/0.1",
                        },
                    )
                )
                request = client.build_request(
                    "GET",
                    pinned_url,
                    headers={"Host": original_url.netloc.decode("ascii")},
                )
                request.extensions["sni_hostname"] = validated.hostname
                response = client.send(request, stream=True)
                try:
                    if response.status_code in {301, 302, 303, 307, 308}:
                        location = response.headers.get("location")
                        if not location:
                            return ToolObservation.failure(
                                "fetch_url",
                                "invalid_redirect",
                                "Redirect response omitted the Location header.",
                                data={"visited": visited},
                                provenance=provenance,
                            )
                        if redirect_count >= values.max_redirects:
                            return ToolObservation.failure(
                                "fetch_url",
                                "redirect_limit",
                                "The response exceeded the allowed redirect count.",
                                data={"visited": visited},
                                provenance=provenance,
                            )
                        current = urljoin(validated.url, location)
                        # The next loop re-resolves and revalidates the full target.
                        continue

                    content_type = response.headers.get("content-type", "")
                    if not is_model_safe_content_type(content_type):
                        return ToolObservation.failure(
                            "fetch_url",
                            "unsupported_content_type",
                            (
                                "The response is not a model-safe text content type: "
                                f"{content_type or '(missing)'}."
                            ),
                            data={
                                "status_code": response.status_code,
                                "final_url": validated.url,
                                "content_type": content_type or None,
                                "visited": visited,
                            },
                            provenance=provenance,
                        )
                    declared_length = response.headers.get("content-length")
                    if declared_length:
                        try:
                            if int(declared_length) > values.max_bytes:
                                return ToolObservation.failure(
                                    "fetch_url",
                                    "response_too_large",
                                    (
                                        "Content-Length exceeds the configured "
                                        f"{values.max_bytes}-byte cap."
                                    ),
                                    data={
                                        "content_length": int(declared_length),
                                        "max_bytes": values.max_bytes,
                                        "final_url": validated.url,
                                    },
                                    provenance=provenance,
                                )
                        except ValueError:
                            pass
                    body = bytearray()
                    too_large = False
                    for chunk in response.iter_bytes():
                        remaining = values.max_bytes + 1 - len(body)
                        if remaining <= 0:
                            too_large = True
                            break
                        body.extend(chunk[:remaining])
                        if len(body) > values.max_bytes:
                            too_large = True
                            break
                    if too_large:
                        return ToolObservation.failure(
                            "fetch_url",
                            "response_too_large",
                            (
                                "The decoded response body exceeded the configured "
                                f"{values.max_bytes}-byte cap."
                            ),
                            data={
                                "max_bytes": values.max_bytes,
                                "final_url": validated.url,
                                "visited": visited,
                            },
                            provenance=provenance,
                        )
                    text = _decode_body(
                        bytes(body),
                        content_type,
                        response.encoding,
                    )
                    return ToolObservation.success(
                        "fetch_url",
                        (
                            f"Fetched {len(body)} bytes with HTTP "
                            f"{response.status_code}."
                        ),
                        {
                            "status_code": response.status_code,
                            "final_url": validated.url,
                            "content_type": content_type,
                            "body": text,
                            "bytes_read": len(body),
                            "visited": visited,
                            "fetched_at": datetime.now(timezone.utc).isoformat(),
                        },
                        provenance=provenance,
                    )
                finally:
                    response.close()
    except SecurityViolation as exc:
        return ToolObservation.failure(
            "fetch_url",
            "unsafe_url",
            str(exc),
            data={"visited": visited},
            provenance=provenance,
        )
    except httpx.TimeoutException as exc:
        return ToolObservation.failure(
            "fetch_url",
            "timeout",
            f"HTTP GET timed out: {exc}",
            data={"visited": visited},
            provenance=provenance,
            retryable=True,
        )
    except httpx.HTTPError as exc:
        return ToolObservation.failure(
            "fetch_url",
            "http_error",
            f"HTTP GET failed: {exc}",
            data={"visited": visited},
            provenance=provenance,
            retryable=True,
        )
    return ToolObservation.failure(
        "fetch_url",
        "fetch_failed",
        "HTTP GET ended without a response.",
        data={"visited": visited},
        provenance=provenance,
    )


def network_tools() -> tuple[ToolDefinition, ...]:
    return (
        ToolDefinition(
            name="list_listening_ports",
            description=(
                "Show every current TCP listening port and UDP bound port, with "
                "local address, PID, and process name."
            ),
            input_model=ListeningPortsInput,
            handler=list_listening_ports,
            keywords=(
                "show all ports listening right now",
                "open ports",
                "listening sockets",
                "what is using port",
                "network listener pid",
            ),
        ),
        ToolDefinition(
            name="get_network_info",
            description=(
                "Read network interfaces, IP addresses, link state, MTU, speed, "
                "and traffic counters."
            ),
            input_model=NetworkInfoInput,
            handler=get_network_info,
            keywords=("ip configuration", "network adapters", "interfaces", "ipconfig"),
        ),
        ToolDefinition(
            name="fetch_url",
            description=(
                "Fetch bounded textual data from a public HTTP or HTTPS URL with "
                "GET only. Never uploads, sends credentials, or reaches private hosts."
            ),
            input_model=FetchUrlInput,
            handler=fetch_url,
            keywords=("download webpage", "read url", "http get", "fetch web data"),
        ),
    )


__all__ = [
    "FetchUrlInput",
    "ListeningPortsInput",
    "NetworkInfoInput",
    "fetch_url",
    "get_network_info",
    "list_listening_ports",
    "network_tools",
]
