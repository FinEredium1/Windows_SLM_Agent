"""Cross-platform system and process inspection backed by psutil."""

from __future__ import annotations

from datetime import datetime, timezone
import os
import platform
import socket
import time
from typing import Literal

import psutil
from pydantic import Field, model_validator

from .base import Provenance, ToolDefinition, ToolInput, ToolObservation


def _iso_timestamp(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    try:
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


class SystemInfoInput(ToolInput):
    include_disks: bool = True


class ListProcessesInput(ToolInput):
    query: str | None = Field(
        default=None,
        max_length=260,
        description="Optional case-insensitive process name substring.",
    )
    sort_by: Literal["memory", "cpu", "name", "pid"] = "memory"
    sample_seconds: float = Field(default=0.1, ge=0.05, le=2.0)
    limit: int = Field(default=50, ge=1, le=300)


class ProcessInfoInput(ToolInput):
    pid: int | None = Field(default=None, ge=0)
    name: str | None = Field(default=None, min_length=1, max_length=260)
    process: int | str | None = Field(
        default=None,
        description="Convenience alternative containing either a PID or process name.",
    )
    sample_seconds: float = Field(
        default=0.25,
        ge=0.05,
        le=3.0,
        description="Interval used to sample process CPU utilization.",
    )
    max_matches: int = Field(default=20, ge=1, le=100)

    @model_validator(mode="after")
    def resolve_target(self) -> "ProcessInfoInput":
        if self.pid is None and self.name is None and self.process is not None:
            if isinstance(self.process, int):
                self.pid = self.process
            else:
                raw = self.process.strip()
                if raw.isdecimal():
                    self.pid = int(raw)
                elif raw:
                    self.name = raw
        if self.pid is None and not self.name:
            raise ValueError("supply pid, name, or process")
        return self


def get_system_info(arguments: ToolInput) -> ToolObservation:
    values = SystemInfoInput.model_validate(arguments)
    virtual_memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disks: list[dict[str, object]] = []
    if values.include_disks:
        for partition in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(partition.mountpoint)
            except (OSError, PermissionError):
                continue
            disks.append(
                {
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "filesystem": partition.fstype,
                    "total_bytes": usage.total,
                    "used_bytes": usage.used,
                    "free_bytes": usage.free,
                    "percent_used": usage.percent,
                }
            )
    data = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "architecture": platform.machine(),
        "python_process_pid": os.getpid(),
        "boot_time": _iso_timestamp(psutil.boot_time()),
        "uptime_seconds": max(0, time.time() - psutil.boot_time()),
        "cpu": {
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "percent_used": psutil.cpu_percent(interval=0.1),
        },
        "memory": {
            "total_bytes": virtual_memory.total,
            "available_bytes": virtual_memory.available,
            "used_bytes": virtual_memory.used,
            "percent_used": virtual_memory.percent,
        },
        "swap": {
            "total_bytes": swap.total,
            "used_bytes": swap.used,
            "free_bytes": swap.free,
            "percent_used": swap.percent,
        },
        "disks": disks,
    }
    return ToolObservation.success(
        "get_system_info",
        f"Read system resource information for {data['hostname']}.",
        data,
        provenance=[
            Provenance(
                source="psutil",
                method="local operating-system counters",
                target=str(data["hostname"]),
            )
        ],
    )


def _safe_process_value(process: psutil.Process, accessor: str) -> object:
    try:
        value = getattr(process, accessor)()
        if accessor == "create_time":
            return _iso_timestamp(value)
        return value
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
        return None


def _matching_processes(
    *,
    pid: int | None,
    name: str | None,
    limit: int,
) -> list[psutil.Process]:
    if pid is not None:
        try:
            return [psutil.Process(pid)]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []
    needle = (name or "").casefold()
    exact: list[psutil.Process] = []
    partial: list[psutil.Process] = []
    for process in psutil.process_iter(["pid", "name"]):
        try:
            process_name = (process.info.get("name") or "").casefold()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if process_name == needle:
            exact.append(process)
        elif needle in process_name:
            partial.append(process)
        if len(exact) >= limit:
            break
    return (exact + partial)[:limit]


def _sample_processes(
    processes: list[psutil.Process],
    interval: float,
) -> dict[int, float | None]:
    active: list[psutil.Process] = []
    for process in processes:
        try:
            process.cpu_percent(interval=None)
            active.append(process)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    time.sleep(interval)
    samples: dict[int, float | None] = {}
    for process in active:
        try:
            samples[process.pid] = process.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            samples[process.pid] = None
    return samples


def _process_record(
    process: psutil.Process,
    cpu_percent: float | None,
) -> dict[str, object]:
    try:
        memory = process.memory_info()
        memory_info: dict[str, int] | None = {
            "rss_bytes": memory.rss,
            "vms_bytes": memory.vms,
        }
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        memory_info = None
    try:
        parent_pid = process.ppid()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        parent_pid = None
    return {
        "pid": process.pid,
        "name": _safe_process_value(process, "name"),
        "status": _safe_process_value(process, "status"),
        "cpu_percent": cpu_percent,
        "memory": memory_info,
        "thread_count": _safe_process_value(process, "num_threads"),
        "username": _safe_process_value(process, "username"),
        "executable": _safe_process_value(process, "exe"),
        "command_line": _safe_process_value(process, "cmdline"),
        "working_directory": _safe_process_value(process, "cwd"),
        "created_at": _safe_process_value(process, "create_time"),
        "parent_pid": parent_pid,
    }


def get_process_info(arguments: ToolInput) -> ToolObservation:
    values = ProcessInfoInput.model_validate(arguments)
    processes = _matching_processes(
        pid=values.pid,
        name=values.name,
        limit=values.max_matches,
    )
    if not processes:
        target = str(values.pid) if values.pid is not None else values.name
        return ToolObservation.success(
            "get_process_info",
            f"No running process matched {target!r}.",
            {
                "query": {"pid": values.pid, "name": values.name},
                "matches": [],
                "sample_seconds": values.sample_seconds,
            },
            provenance=[
                Provenance(
                    source="psutil",
                    method="process inventory lookup",
                    target=str(target),
                )
            ],
        )
    samples = _sample_processes(processes, values.sample_seconds)
    records = [
        _process_record(process, samples.get(process.pid))
        for process in processes
    ]
    records.sort(key=lambda item: int(item["pid"]))
    return ToolObservation.success(
        "get_process_info",
        f"Sampled CPU and details for {len(records)} matching process(es).",
        {
            "query": {"pid": values.pid, "name": values.name},
            "sample_seconds": values.sample_seconds,
            "matches": records,
        },
        provenance=[
            Provenance(
                source="psutil",
                method="process inventory and sampled CPU counters",
                target=str(values.pid if values.pid is not None else values.name),
            )
        ],
    )


def list_processes(arguments: ToolInput) -> ToolObservation:
    values = ListProcessesInput.model_validate(arguments)
    processes: list[psutil.Process] = []
    needle = values.query.casefold() if values.query else None
    for process in psutil.process_iter(["pid", "name"]):
        try:
            name = process.info.get("name") or ""
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if needle and needle not in name.casefold():
            continue
        processes.append(process)
        if len(processes) >= 1000:
            break
    samples = _sample_processes(processes, values.sample_seconds)
    records = [
        _process_record(process, samples.get(process.pid))
        for process in processes
    ]
    if values.sort_by == "cpu":
        records.sort(
            key=lambda item: float(item["cpu_percent"] or 0),
            reverse=True,
        )
    elif values.sort_by == "memory":
        records.sort(
            key=lambda item: int(
                (item["memory"] or {}).get("rss_bytes", 0)  # type: ignore[union-attr]
            ),
            reverse=True,
        )
    elif values.sort_by == "name":
        records.sort(key=lambda item: str(item["name"] or "").casefold())
    else:
        records.sort(key=lambda item: int(item["pid"]))
    records = records[: values.limit]
    return ToolObservation.success(
        "list_processes",
        f"Listed {len(records)} running process(es).",
        {
            "query": values.query,
            "sort_by": values.sort_by,
            "sample_seconds": values.sample_seconds,
            "processes": records,
            "limit": values.limit,
        },
        provenance=[
            Provenance(
                source="psutil",
                method="process inventory and sampled CPU counters",
                target=values.query,
            )
        ],
    )


def system_tools() -> tuple[ToolDefinition, ...]:
    return (
        ToolDefinition(
            name="get_process_info",
            description=(
                "Find a running process by PID or name and sample its CPU usage, "
                "memory, executable, parent, command line, and status."
            ),
            input_model=ProcessInfoInput,
            handler=get_process_info,
            keywords=(
                "check cpu usage for process",
                "process performance",
                "why process running",
                "pid details",
                "memory usage",
            ),
        ),
        ToolDefinition(
            name="list_processes",
            description=(
                "List running processes, optionally filtered by name and sorted "
                "by sampled CPU or memory."
            ),
            input_model=ListProcessesInput,
            handler=list_processes,
            keywords=("task manager", "running programs", "background process"),
        ),
        ToolDefinition(
            name="get_system_info",
            description=(
                "Read host, Windows version, CPU, memory, uptime, swap, and disk "
                "capacity information."
            ),
            input_model=SystemInfoInput,
            handler=get_system_info,
            keywords=("system information", "computer specs", "cpu memory disk"),
        ),
    )


__all__ = [
    "ListProcessesInput",
    "ProcessInfoInput",
    "SystemInfoInput",
    "get_process_info",
    "get_system_info",
    "list_processes",
    "system_tools",
]
