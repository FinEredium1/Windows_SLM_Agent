"""Purpose-built, read-only Windows inspection tools."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path, PureWindowsPath
import platform
import re
from typing import Any, Literal

import psutil
from pydantic import Field, field_validator, model_validator

from ..powershell import (
    PowerShellReadError,
    PowerShellUnavailable,
    run_fixed_powershell,
)
from ..security import SecurityViolation, resolve_read_path
from .base import Provenance, ToolDefinition, ToolInput, ToolObservation


def _unsupported(tool: str, capability: str) -> ToolObservation:
    return ToolObservation.unsupported(tool, capability, platform.system())


def _normalize_rows(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _powershell_failure(
    tool: str,
    operation: str,
    exc: Exception,
) -> ToolObservation:
    return ToolObservation.failure(
        tool,
        "powershell_read_failed",
        f"{operation} failed: {exc}",
        provenance=[
            Provenance(
                source="PowerShell",
                method="fixed allowlisted read script",
                target=operation,
            )
        ],
    )


class RegistryValuesInput(ToolInput):
    hive: Literal["HKCU", "HKLM", "HKCR", "HKU", "HKCC"] = "HKCU"
    path: str = Field(
        min_length=1,
        max_length=1024,
        description="Registry key path beneath the selected hive.",
    )
    value_name: str | None = Field(
        default=None,
        max_length=260,
        description="Optional exact value name; omit to enumerate values.",
    )
    view: Literal["default", "32", "64"] = "default"
    limit: int = Field(default=200, ge=1, le=1000)

    @field_validator("path")
    @classmethod
    def safe_registry_path(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("registry path cannot contain a NUL byte")
        return value.strip("\\")


class EventLogsInput(ToolInput):
    log_name: str = Field(default="System", min_length=1, max_length=260)
    provider: str | None = Field(default=None, min_length=1, max_length=260)
    event_ids: list[int] = Field(default_factory=list, max_length=64)
    level: Literal[
        "critical",
        "error",
        "warning",
        "information",
        "verbose",
    ] | None = None
    message_query: str | None = Field(default=None, min_length=1, max_length=500)
    since_hours: float = Field(default=24.0, gt=0, le=24 * 365)
    start_time: datetime | None = None
    end_time: datetime | None = None
    limit: int = Field(default=100, ge=1, le=500)

    @field_validator("event_ids")
    @classmethod
    def valid_event_ids(cls, value: list[int]) -> list[int]:
        if any(event_id < 0 or event_id > 65_535 for event_id in value):
            raise ValueError("event IDs must be between 0 and 65535")
        return list(dict.fromkeys(value))

    @model_validator(mode="after")
    def valid_time_window(self) -> "EventLogsInput":
        if self.start_time is not None:
            self.start_time = (
                self.start_time.replace(tzinfo=timezone.utc)
                if self.start_time.tzinfo is None
                else self.start_time.astimezone(timezone.utc)
            )
        if self.end_time is not None:
            self.end_time = (
                self.end_time.replace(tzinfo=timezone.utc)
                if self.end_time.tzinfo is None
                else self.end_time.astimezone(timezone.utc)
            )
        if (
            self.start_time
            and self.end_time
            and self.start_time >= self.end_time
        ):
            raise ValueError("start_time must be earlier than end_time")
        return self


class InstalledAppsInput(ToolInput):
    query: str | None = Field(default=None, min_length=1, max_length=260)
    include_updates: bool = False
    limit: int = Field(default=300, ge=1, le=1000)


class ServicesInput(ToolInput):
    query: str | None = Field(
        default=None,
        min_length=1,
        max_length=260,
        description="Optional name, display-name, user, or binary-path substring.",
    )
    status: Literal[
        "running",
        "stopped",
        "paused",
        "start_pending",
        "stop_pending",
        "continue_pending",
        "pause_pending",
    ] | None = None
    limit: int = Field(default=200, ge=1, le=1000)


class DiagnosePathBlockInput(ToolInput):
    path: str = Field(
        min_length=1,
        max_length=4096,
        description="Existing file or directory that cannot be deleted or changed.",
    )
    max_processes: int = Field(default=100, ge=1, le=500)


class ExplainProcessStartupInput(ToolInput):
    pid: int | None = Field(default=None, ge=0)
    name: str | None = Field(default=None, min_length=1, max_length=260)
    process: int | str | None = Field(
        default=None,
        description="A PID or executable/process name.",
    )
    limit: int = Field(default=100, ge=1, le=300)

    @model_validator(mode="after")
    def resolve_target(self) -> "ExplainProcessStartupInput":
        if self.pid is None and self.name is None and self.process is not None:
            if isinstance(self.process, int):
                self.pid = self.process
            else:
                value = self.process.strip()
                if value.isdecimal():
                    self.pid = int(value)
                elif value:
                    self.name = value
        if self.pid is None and not self.name:
            raise ValueError("supply pid, name, or process")
        return self


class ExecutionPolicyInput(ToolInput):
    pass


class DiagnoseProgramCrashInput(ToolInput):
    process_name: str | None = Field(default=None, min_length=1, max_length=260)
    executable_path: str | None = Field(default=None, min_length=1, max_length=4096)
    since_hours: float = Field(default=24.0, gt=0, le=24 * 30)
    limit: int = Field(default=100, ge=1, le=100)

    @model_validator(mode="after")
    def require_target(self) -> "DiagnoseProgramCrashInput":
        if not self.process_name and not self.executable_path:
            raise ValueError("supply process_name or executable_path")
        return self


def _registry_value(value: Any) -> Any:
    if isinstance(value, bytes):
        preview = value[:4096]
        return {
            "type": "binary",
            "length": len(value),
            "hex_preview": preview.hex(),
            "truncated": len(value) > len(preview),
        }
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value[:1000]]
    return str(value)


def get_registry_values(arguments: ToolInput) -> ToolObservation:
    values = RegistryValuesInput.model_validate(arguments)
    if os.name != "nt":
        return _unsupported("get_registry_values", "Windows Registry inspection")
    import winreg

    hive_map = {
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKU": winreg.HKEY_USERS,
        "HKCC": winreg.HKEY_CURRENT_CONFIG,
    }
    access = winreg.KEY_READ
    if values.view == "32":
        access |= winreg.KEY_WOW64_32KEY
    elif values.view == "64":
        access |= winreg.KEY_WOW64_64KEY
    target = f"{values.hive}\\{values.path}"
    rows: list[dict[str, Any]] = []
    subkeys: list[str] = []
    try:
        with winreg.OpenKey(
            hive_map[values.hive],
            values.path,
            0,
            access,
        ) as key:
            if values.value_name is not None:
                raw, registry_type = winreg.QueryValueEx(key, values.value_name)
                rows.append(
                    {
                        "name": values.value_name,
                        "value": _registry_value(raw),
                        "registry_type": registry_type,
                    }
                )
            else:
                index = 0
                while len(rows) < values.limit:
                    try:
                        name, raw, registry_type = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    rows.append(
                        {
                            "name": name,
                            "value": _registry_value(raw),
                            "registry_type": registry_type,
                        }
                    )
                    index += 1
                index = 0
                while len(subkeys) < values.limit:
                    try:
                        subkeys.append(winreg.EnumKey(key, index))
                    except OSError:
                        break
                    index += 1
    except FileNotFoundError:
        return ToolObservation.failure(
            "get_registry_values",
            "not_found",
            f"Registry key or value was not found: {target}",
            provenance=[
                Provenance(
                    source="Windows Registry",
                    method="winreg read",
                    target=target,
                )
            ],
        )
    except PermissionError as exc:
        return ToolObservation.failure(
            "get_registry_values",
            "permission_denied",
            f"Access denied reading {target}: {exc}",
            provenance=[
                Provenance(
                    source="Windows Registry",
                    method="winreg read",
                    target=target,
                )
            ],
        )
    rows.sort(key=lambda item: str(item["name"]).casefold())
    subkeys.sort(key=str.casefold)
    return ToolObservation.success(
        "get_registry_values",
        f"Read {len(rows)} value(s) and {len(subkeys)} subkey name(s) from {target}.",
        {
            "key": target,
            "view": values.view,
            "values": rows,
            "subkeys": subkeys,
            "limit": values.limit,
        },
        provenance=[
            Provenance(
                source="Windows Registry",
                method="winreg read-only enumeration",
                target=target,
            )
        ],
    )


def _aware_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.astimezone()
    return value.astimezone(timezone.utc).isoformat()


def get_event_logs(arguments: ToolInput) -> ToolObservation:
    values = EventLogsInput.model_validate(arguments)
    if os.name != "nt":
        return _unsupported("get_event_logs", "Windows Event Log inspection")
    now = datetime.now(timezone.utc)
    start = values.start_time or now - timedelta(hours=values.since_hours)
    end = values.end_time or now
    levels = {
        "critical": 1,
        "error": 2,
        "warning": 3,
        "information": 4,
        "verbose": 5,
    }
    payload = {
        "log_name": values.log_name,
        "provider": values.provider or "",
        "event_ids": values.event_ids,
        "level": levels.get(values.level) if values.level else None,
        "message_query": values.message_query or "",
        "start_time": _aware_iso(start),
        "end_time": _aware_iso(end),
        "scan_limit": min(max(values.limit * 5, values.limit), 2000),
        "limit": values.limit,
    }
    try:
        rows = _normalize_rows(run_fixed_powershell("query_event_log", payload))
    except (PowerShellUnavailable, PowerShellReadError, TimeoutError) as exc:
        return _powershell_failure(
            "get_event_logs",
            "Windows Event Log query",
            exc,
        )
    rows.sort(
        key=lambda row: (
            str(row.get("timestamp") or ""),
            int(row.get("record_id") or 0),
        ),
        reverse=True,
    )
    return ToolObservation.success(
        "get_event_logs",
        f"Read {len(rows)} matching event(s) from {values.log_name}.",
        {
            "filters": {
                "log_name": values.log_name,
                "provider": values.provider,
                "event_ids": values.event_ids,
                "level": values.level,
                "message_query": values.message_query,
                "start_time": _aware_iso(start),
                "end_time": _aware_iso(end),
            },
            "events": rows,
        },
        provenance=[
            Provenance(
                source="Windows Event Log",
                method="Get-WinEvent via fixed PowerShell read",
                target=values.log_name,
            )
        ],
    )


def _read_installed_apps(values: InstalledAppsInput) -> list[dict[str, Any]]:
    import winreg

    locations = (
        (
            "HKLM-64",
            winreg.HKEY_LOCAL_MACHINE,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ),
        (
            "HKLM-32",
            winreg.HKEY_LOCAL_MACHINE,
            winreg.KEY_READ | winreg.KEY_WOW64_32KEY,
        ),
        ("HKCU", winreg.HKEY_CURRENT_USER, winreg.KEY_READ),
    )
    uninstall_path = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
    records: list[dict[str, Any]] = []
    needle = values.query.casefold() if values.query else None
    for source, hive, access in locations:
        try:
            root = winreg.OpenKey(hive, uninstall_path, 0, access)
        except (FileNotFoundError, PermissionError, OSError):
            continue
        with root:
            index = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(root, index)
                except OSError:
                    break
                index += 1
                try:
                    subkey = winreg.OpenKey(root, subkey_name, 0, access)
                except (PermissionError, FileNotFoundError, OSError):
                    continue
                with subkey:
                    fields: dict[str, Any] = {}
                    for name in (
                        "DisplayName",
                        "DisplayVersion",
                        "Publisher",
                        "InstallLocation",
                        "InstallDate",
                        "UninstallString",
                        "QuietUninstallString",
                        "DisplayIcon",
                        "SystemComponent",
                        "ReleaseType",
                        "ParentKeyName",
                    ):
                        try:
                            fields[name] = winreg.QueryValueEx(subkey, name)[0]
                        except OSError:
                            fields[name] = None
                display_name = str(fields["DisplayName"] or "").strip()
                if not display_name:
                    continue
                if not values.include_updates and (
                    fields["SystemComponent"] == 1
                    or fields["ParentKeyName"]
                    or str(fields["ReleaseType"] or "").casefold()
                    in {"hotfix", "security update", "update rollup", "update"}
                ):
                    continue
                haystack = " ".join(
                    str(fields.get(field) or "")
                    for field in ("DisplayName", "Publisher", "InstallLocation")
                ).casefold()
                if needle and needle not in haystack:
                    continue
                records.append(
                    {
                        "name": display_name,
                        "version": fields["DisplayVersion"],
                        "publisher": fields["Publisher"],
                        "install_location": fields["InstallLocation"],
                        "install_date": fields["InstallDate"],
                        "uninstall_command": fields["UninstallString"],
                        "quiet_uninstall_command": fields["QuietUninstallString"],
                        "display_icon": fields["DisplayIcon"],
                        "registry_source": source,
                        "registry_subkey": subkey_name,
                    }
                )
    deduplicated: dict[tuple[str, str, str], dict[str, Any]] = {}
    for record in records:
        key = (
            str(record["name"]).casefold(),
            str(record["version"] or "").casefold(),
            str(record["install_location"] or "").casefold(),
        )
        deduplicated.setdefault(key, record)
    result = list(deduplicated.values())
    result.sort(
        key=lambda item: (
            str(item["name"]).casefold(),
            str(item["version"] or "").casefold(),
        )
    )
    return result[: values.limit]


def list_installed_apps(arguments: ToolInput) -> ToolObservation:
    values = InstalledAppsInput.model_validate(arguments)
    if os.name != "nt":
        return _unsupported("list_installed_apps", "installed Windows app inventory")
    rows = _read_installed_apps(values)
    return ToolObservation.success(
        "list_installed_apps",
        f"Found {len(rows)} installed application record(s).",
        {
            "query": values.query,
            "include_updates": values.include_updates,
            "applications": rows,
            "limit": values.limit,
        },
        provenance=[
            Provenance(
                source="Windows Registry",
                method="read-only uninstall-key inventory",
                target="HKLM/HKCU Uninstall",
            )
        ],
    )


def get_services(arguments: ToolInput) -> ToolObservation:
    values = ServicesInput.model_validate(arguments)
    if os.name != "nt":
        return _unsupported("get_services", "Windows service inspection")
    needle = values.query.casefold() if values.query else None
    rows: list[dict[str, Any]] = []
    inaccessible = 0
    try:
        services = psutil.win_service_iter()
    except (AttributeError, OSError) as exc:
        return ToolObservation.failure(
            "get_services",
            "service_inventory_failed",
            f"Windows service inventory failed: {exc}",
        )
    for service in services:
        try:
            data = service.as_dict()
        except (psutil.AccessDenied, OSError):
            inaccessible += 1
            continue
        status = str(data.get("status") or "").casefold()
        if values.status and status != values.status:
            continue
        haystack = " ".join(
            str(data.get(key) or "")
            for key in (
                "name",
                "display_name",
                "username",
                "binpath",
            )
        ).casefold()
        if needle and needle not in haystack:
            continue
        rows.append(
            {
                "name": data.get("name"),
                "display_name": data.get("display_name"),
                "status": data.get("status"),
                "start_type": data.get("start_type"),
                "username": data.get("username"),
                "binary_path": data.get("binpath"),
                "pid": data.get("pid"),
            }
        )
        if len(rows) >= values.limit:
            break
    rows.sort(
        key=lambda item: (
            str(item.get("display_name") or item.get("name") or "").casefold(),
            str(item.get("name") or "").casefold(),
        )
    )
    return ToolObservation.success(
        "get_services",
        f"Found {len(rows)} matching Windows service(s).",
        {
            "query": values.query,
            "status": values.status,
            "services": rows,
            "inaccessible_services": inaccessible,
            "limit": values.limit,
        },
        provenance=[
            Provenance(
                source="Windows Service Control Manager",
                method="psutil read-only service inventory",
                target=values.query,
            )
        ],
    )


def _restart_manager_lockers(path: Path) -> list[dict[str, Any]]:
    """Return processes reported by the Windows Restart Manager API."""

    if os.name != "nt":
        return []
    import ctypes
    from ctypes import wintypes

    class RM_UNIQUE_PROCESS(ctypes.Structure):
        _fields_ = [
            ("dwProcessId", wintypes.DWORD),
            ("ProcessStartTime", wintypes.FILETIME),
        ]

    class RM_PROCESS_INFO(ctypes.Structure):
        _fields_ = [
            ("Process", RM_UNIQUE_PROCESS),
            ("strAppName", wintypes.WCHAR * 256),
            ("strServiceShortName", wintypes.WCHAR * 64),
            ("ApplicationType", wintypes.UINT),
            ("AppStatus", wintypes.ULONG),
            ("TSSessionId", wintypes.DWORD),
            ("bRestartable", wintypes.BOOL),
        ]

    manager = ctypes.WinDLL("rstrtmgr")
    manager.RmStartSession.argtypes = [
        ctypes.POINTER(wintypes.DWORD),
        wintypes.DWORD,
        wintypes.LPWSTR,
    ]
    manager.RmRegisterResources.argtypes = [
        wintypes.DWORD,
        wintypes.UINT,
        ctypes.POINTER(wintypes.LPCWSTR),
        wintypes.UINT,
        ctypes.c_void_p,
        wintypes.UINT,
        ctypes.c_void_p,
    ]
    manager.RmGetList.argtypes = [
        wintypes.DWORD,
        ctypes.POINTER(wintypes.UINT),
        ctypes.POINTER(wintypes.UINT),
        ctypes.POINTER(RM_PROCESS_INFO),
        ctypes.POINTER(wintypes.DWORD),
    ]
    manager.RmEndSession.argtypes = [wintypes.DWORD]

    session = wintypes.DWORD()
    key = ctypes.create_unicode_buffer(33)
    result = manager.RmStartSession(ctypes.byref(session), 0, key)
    if result != 0:
        raise OSError(result, "RmStartSession failed")
    try:
        resources = (wintypes.LPCWSTR * 1)(str(path))
        result = manager.RmRegisterResources(
            session,
            1,
            resources,
            0,
            None,
            0,
            None,
        )
        if result != 0:
            raise OSError(result, "RmRegisterResources failed")
        needed = wintypes.UINT(0)
        count = wintypes.UINT(0)
        reboot_reasons = wintypes.DWORD(0)
        result = manager.RmGetList(
            session,
            ctypes.byref(needed),
            ctypes.byref(count),
            None,
            ctypes.byref(reboot_reasons),
        )
        if result == 0 and needed.value == 0:
            return []
        if result != 234:  # ERROR_MORE_DATA
            raise OSError(result, "RmGetList sizing failed")
        records = (RM_PROCESS_INFO * needed.value)()
        count = wintypes.UINT(needed.value)
        result = manager.RmGetList(
            session,
            ctypes.byref(needed),
            ctypes.byref(count),
            records,
            ctypes.byref(reboot_reasons),
        )
        if result != 0:
            raise OSError(result, "RmGetList failed")
        return [
            {
                "pid": int(records[index].Process.dwProcessId),
                "application_name": records[index].strAppName,
                "service_name": records[index].strServiceShortName or None,
                "application_type": int(records[index].ApplicationType),
                "status": int(records[index].AppStatus),
                "session_id": int(records[index].TSSessionId),
                "restartable": bool(records[index].bRestartable),
                "source": "Windows Restart Manager",
            }
            for index in range(count.value)
        ]
    finally:
        manager.RmEndSession(session)


def _path_contains(root: Path, candidate: str | None) -> bool:
    if not candidate:
        return False
    try:
        candidate_path = Path(candidate).resolve(strict=False)
        if root.is_dir():
            return candidate_path == root or root in candidate_path.parents
        return candidate_path == root
    except (OSError, ValueError):
        return False


def _scan_process_path_users(
    target: Path,
    limit: int,
) -> tuple[list[dict[str, Any]], int]:
    matches: list[dict[str, Any]] = []
    inaccessible = 0
    for process in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        evidence: list[str] = []
        try:
            if _path_contains(target, process.info.get("exe")):
                evidence.append("process executable is the target or inside it")
            try:
                if _path_contains(target, process.cwd()):
                    evidence.append("process working directory is the target or inside it")
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                pass
            try:
                open_files = process.open_files()
                matching_files = [
                    item.path
                    for item in open_files
                    if _path_contains(target, item.path)
                ]
                if matching_files:
                    evidence.append(
                        "open file handles: " + ", ".join(matching_files[:10])
                    )
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                inaccessible += 1
            if evidence:
                matches.append(
                    {
                        "pid": process.pid,
                        "process_name": process.info.get("name"),
                        "executable": process.info.get("exe"),
                        "command_line": process.info.get("cmdline"),
                        "evidence": evidence,
                        "source": "psutil process handle correlation",
                    }
                )
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            inaccessible += 1
        if len(matches) >= limit:
            break
    return matches, inaccessible


def diagnose_path_block(arguments: ToolInput) -> ToolObservation:
    values = DiagnosePathBlockInput.model_validate(arguments)
    if os.name != "nt":
        return _unsupported(
            "diagnose_path_block",
            "Windows file-lock and uninstall-block diagnosis",
        )
    try:
        target = resolve_read_path(values.path, must_exist=True)
    except (SecurityViolation, FileNotFoundError, OSError) as exc:
        return ToolObservation.failure(
            "diagnose_path_block",
            "invalid_path",
            f"Cannot inspect the target path: {exc}",
        )
    restart_manager_error: str | None = None
    restart_rows: list[dict[str, Any]] = []
    if target.is_file():
        try:
            restart_rows = _restart_manager_lockers(target)
        except OSError as exc:
            restart_manager_error = str(exc)
    process_rows, inaccessible = _scan_process_path_users(
        target,
        values.max_processes,
    )
    combined: dict[int, dict[str, Any]] = {}
    for row in restart_rows + process_rows:
        pid = int(row.get("pid") or -1)
        if pid not in combined:
            combined[pid] = dict(row)
            continue
        prior = combined[pid]
        prior_evidence = list(prior.get("evidence") or [])
        prior_evidence.extend(row.get("evidence") or [])
        prior["evidence"] = list(dict.fromkeys(prior_evidence))
        for key, value in row.items():
            if prior.get(key) in (None, "", []):
                prior[key] = value
        prior["source"] = "Windows Restart Manager + psutil correlation"
    blockers = sorted(
        combined.values(),
        key=lambda item: int(item.get("pid") or -1),
    )
    if blockers:
        conclusion = (
            f"{len(blockers)} process(es) have evidence linking them to the "
            "target. Closing the app normally is safer than force termination."
        )
    else:
        conclusion = (
            "No user-mode locking process was visible. The block may be caused "
            "by permissions, an installer service, antivirus, a shell extension, "
            "a driver, or a process the current account cannot inspect."
        )
    return ToolObservation.success(
        "diagnose_path_block",
        f"Inspected lock evidence for {target}; found {len(blockers)} candidate blocker(s).",
        {
            "path": str(target),
            "type": "directory" if target.is_dir() else "file",
            "candidate_blockers": blockers,
            "conclusion": conclusion,
            "restart_manager_error": restart_manager_error,
            "inaccessible_process_reads": inaccessible,
            "visibility_limitations": (
                "Results are limited to handles and process details visible to "
                "the current Windows account. Kernel drivers may not appear."
            ),
        },
        provenance=[
            Provenance(
                source="Windows Restart Manager",
                method="RmRegisterResources/RmGetList read",
                target=str(target),
            ),
            Provenance(
                source="psutil",
                method="executable, working-directory, and open-file correlation",
                target=str(target),
            ),
        ],
    )


def _resolve_process(values: ExplainProcessStartupInput) -> psutil.Process | None:
    if values.pid is not None:
        try:
            return psutil.Process(values.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
    needle = (values.name or "").casefold()
    partial: psutil.Process | None = None
    for process in psutil.process_iter(["name"]):
        try:
            name = (process.info.get("name") or "").casefold()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if name == needle:
            return process
        if partial is None and needle in name:
            partial = process
    return partial


def _read_run_keys(needle: str, limit: int) -> list[dict[str, Any]]:
    import winreg

    rows: list[dict[str, Any]] = []
    paths = (
        ("HKCU", winreg.HKEY_CURRENT_USER, winreg.KEY_READ),
        ("HKLM-64", winreg.HKEY_LOCAL_MACHINE, winreg.KEY_READ | winreg.KEY_WOW64_64KEY),
        ("HKLM-32", winreg.HKEY_LOCAL_MACHINE, winreg.KEY_READ | winreg.KEY_WOW64_32KEY),
    )
    for source, hive, access in paths:
        for suffix in ("Run", "RunOnce"):
            key_path = rf"Software\Microsoft\Windows\CurrentVersion\{suffix}"
            try:
                key = winreg.OpenKey(hive, key_path, 0, access)
            except (FileNotFoundError, PermissionError, OSError):
                continue
            with key:
                index = 0
                while True:
                    try:
                        name, command, _ = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    index += 1
                    haystack = f"{name} {command}".casefold()
                    if needle in haystack:
                        rows.append(
                            {
                                "source": source,
                                "key": key_path,
                                "value_name": name,
                                "command": str(command),
                            }
                        )
                    if len(rows) >= limit:
                        return rows
    return rows


def _startup_folder_matches(needle: str, limit: int) -> list[dict[str, Any]]:
    roots = [
        Path(os.environ.get("APPDATA", ""))
        / "Microsoft/Windows/Start Menu/Programs/Startup",
        Path(os.environ.get("PROGRAMDATA", ""))
        / "Microsoft/Windows/Start Menu/Programs/StartUp",
    ]
    rows: list[dict[str, Any]] = []
    for root in roots:
        if not str(root) or not root.is_dir():
            continue
        try:
            entries = list(root.iterdir())
        except (PermissionError, OSError):
            continue
        for entry in entries:
            if needle in entry.name.casefold():
                rows.append(
                    {
                        "path": str(entry),
                        "name": entry.name,
                        "modified_at": datetime.fromtimestamp(
                            entry.stat().st_mtime,
                            timezone.utc,
                        ).isoformat(),
                    }
                )
            if len(rows) >= limit:
                return rows
    return rows


def _matching_services(
    pid: int,
    needle: str,
    executable: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    executable_folded = (executable or "").casefold()
    try:
        services = psutil.win_service_iter()
    except (AttributeError, OSError):
        return rows
    for service in services:
        try:
            data = service.as_dict()
        except (psutil.AccessDenied, OSError):
            continue
        haystack = " ".join(
            str(data.get(key) or "")
            for key in ("name", "display_name", "binpath")
        ).casefold()
        service_pid = data.get("pid")
        matches = service_pid == pid or needle in haystack
        if executable_folded and executable_folded in haystack:
            matches = True
        if not matches:
            continue
        rows.append(
            {
                "name": data.get("name"),
                "display_name": data.get("display_name"),
                "status": data.get("status"),
                "start_type": data.get("start_type"),
                "username": data.get("username"),
                "binary_path": data.get("binpath"),
                "pid": service_pid,
            }
        )
        if len(rows) >= limit:
            break
    return rows


def explain_process_startup(arguments: ToolInput) -> ToolObservation:
    values = ExplainProcessStartupInput.model_validate(arguments)
    if os.name != "nt":
        return _unsupported(
            "explain_process_startup",
            "Windows process startup-source correlation",
        )
    process = _resolve_process(values)
    if process is None:
        target = values.pid if values.pid is not None else values.name
        return ToolObservation.success(
            "explain_process_startup",
            f"No running process matched {target!r}.",
            {"query": target, "process": None, "startup_sources": {}},
            provenance=[
                Provenance(
                    source="psutil",
                    method="running process lookup",
                    target=str(target),
                )
            ],
        )
    try:
        process_name = process.name()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        process_name = values.name or str(process.pid)
    try:
        executable = process.exe()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        executable = None
    try:
        command_line = process.cmdline()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        command_line = None
    try:
        parent = process.parent()
        parent_record = (
            {
                "pid": parent.pid,
                "name": parent.name(),
                "executable": parent.exe(),
            }
            if parent
            else None
        )
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        parent_record = None
    needle = Path(executable).name.casefold() if executable else process_name.casefold()
    simple_needle = Path(needle).stem
    services = _matching_services(
        process.pid,
        simple_needle,
        executable,
        values.limit,
    )
    run_keys = _read_run_keys(simple_needle, values.limit)
    startup_files = _startup_folder_matches(simple_needle, values.limit)
    try:
        scheduled_tasks = _normalize_rows(
            run_fixed_powershell(
                "query_scheduled_tasks",
                {"needle": simple_needle, "limit": values.limit},
            )
        )
        scheduled_task_error = None
    except (PowerShellUnavailable, PowerShellReadError, TimeoutError) as exc:
        scheduled_tasks = []
        scheduled_task_error = str(exc)
    evidence_types = [
        name
        for name, rows in (
            ("Windows service", services),
            ("scheduled task", scheduled_tasks),
            ("Run/RunOnce registry value", run_keys),
            ("Startup folder entry", startup_files),
        )
        if rows
    ]
    if evidence_types:
        conclusion = (
            "Correlated startup source(s): " + ", ".join(evidence_types) + "."
        )
    elif parent_record:
        conclusion = (
            "No persistent startup entry matched. The current parent process is "
            f"{parent_record.get('name')} (PID {parent_record.get('pid')}), which "
            "may have launched it for this session."
        )
    else:
        conclusion = (
            "No service, task, Run key, or Startup folder entry matched. The app "
            "may be launched on demand, by another app, or through a source not "
            "visible to the current account."
        )
    return ToolObservation.success(
        "explain_process_startup",
        f"Correlated startup evidence for {process_name} (PID {process.pid}).",
        {
            "process": {
                "pid": process.pid,
                "name": process_name,
                "executable": executable,
                "command_line": command_line,
                "parent": parent_record,
            },
            "startup_sources": {
                "services": services,
                "scheduled_tasks": scheduled_tasks,
                "run_keys": run_keys,
                "startup_folder": startup_files,
            },
            "scheduled_task_error": scheduled_task_error,
            "conclusion": conclusion,
            "limitations": (
                "This is correlation, not proof of causation. Shell extensions, "
                "COM activation, drivers, and inaccessible user profiles may not appear."
            ),
        },
        provenance=[
            Provenance(
                source="Windows Service Control Manager",
                method="psutil service inventory correlation",
                target=process_name,
            ),
            Provenance(
                source="Windows Task Scheduler",
                method="Get-ScheduledTask via fixed PowerShell read",
                target=process_name,
            ),
            Provenance(
                source="Windows Registry and Startup folders",
                method="read-only startup entry correlation",
                target=process_name,
            ),
        ],
    )


def get_execution_policy(arguments: ToolInput) -> ToolObservation:
    ExecutionPolicyInput.model_validate(arguments)
    if os.name != "nt":
        return _unsupported(
            "get_execution_policy",
            "PowerShell execution-policy inspection",
        )
    try:
        data = run_fixed_powershell("get_execution_policy", {})
    except (PowerShellUnavailable, PowerShellReadError, TimeoutError) as exc:
        return _powershell_failure(
            "get_execution_policy",
            "PowerShell execution-policy query",
            exc,
        )
    return ToolObservation.success(
        "get_execution_policy",
        f"Effective PowerShell policy is {data.get('effective_policy') if isinstance(data, dict) else 'unknown'}.",
        data,
        provenance=[
            Provenance(
                source="PowerShell",
                method="Get-ExecutionPolicy -List via fixed read script",
                target="all policy scopes",
            )
        ],
    )


_EXCEPTION_CAUSE_HINTS: dict[str, tuple[str, str, str]] = {
    "0xc0000005": (
        "Access violation",
        (
            "Windows reported an invalid memory read, write, or execute access. "
            "Common causes include a bad pointer, use-after-free, incompatible "
            "native module, or memory corruption."
        ),
        (
            "The code identifies the failure class, not which component created "
            "the invalid address; a dump stack is needed for root cause."
        ),
    ),
    "0xc0000374": (
        "Heap corruption",
        (
            "The Windows heap manager detected damaged heap metadata, commonly "
            "after an out-of-bounds write, double free, or use-after-free."
        ),
        (
            "Detection can occur later than the corrupting operation, so the "
            "faulting module at termination may not be the corruptor."
        ),
    ),
    "0xc0000409": (
        "Fail-fast / stack-buffer-overrun status",
        (
            "The process invoked a security fail-fast path. This status is used "
            "for stack-cookie failures and by modern applications for other "
            "fatal invariant violations."
        ),
        (
            "Do not conclude that a literal stack buffer overflow occurred "
            "without the fail-fast subcode or a dump stack."
        ),
    ),
    "0xc00000fd": (
        "Stack overflow",
        (
            "The thread exhausted its stack, often because of unbounded "
            "recursion or unusually large stack allocations."
        ),
        (
            "The event code does not identify the recursive call chain; a dump "
            "or debugger stack is required."
        ),
    ),
    "0xe0434352": (
        ".NET / CLR exception wrapper",
        (
            "The CLR surfaced an unhandled managed exception. Nearby .NET "
            "Runtime event 1026 evidence may contain the managed exception type "
            "and stack."
        ),
        (
            "This wrapper code alone does not identify the managed exception or "
            "the application code that raised it."
        ),
    ),
    "0xc0000135": (
        "Required DLL or runtime not found",
        (
            "Windows could not locate a required DLL or runtime dependency while "
            "starting the process."
        ),
        (
            "The event code does not name the missing dependency; loader tracing "
            "or a process monitor may be needed."
        ),
    ),
    "0xc0000142": (
        "DLL initialization failed",
        (
            "A loaded DLL failed its initialization routine, preventing normal "
            "process startup."
        ),
        (
            "The status does not prove which DLL failed or why; module and loader "
            "evidence is needed."
        ),
    ),
}
_WINDOWS_CRASH_SURFACES = frozenset({"ntdll.dll", "kernelbase.dll"})


def _normalized_exception_code(value: object) -> str | None:
    raw = str(value or "").strip().casefold()
    match = re.fullmatch(r"(?:0x)?([0-9a-f]{8})", raw)
    return f"0x{match.group(1)}" if match else None


def _event_reference(row: dict[str, Any]) -> dict[str, Any]:
    """Return the stable fields that link a hint back to captured evidence."""

    return {
        key: row.get(key)
        for key in (
            "timestamp",
            "provider",
            "event_id",
            "record_id",
            "exception_code",
            "faulting_module",
        )
        if row.get(key) not in (None, "")
    }


def _cause_hints(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    events_by_code: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        code = _normalized_exception_code(event.get("exception_code"))
        if code:
            events_by_code.setdefault(code, []).append(event)
    for code in sorted(events_by_code):
        mapping = _EXCEPTION_CAUSE_HINTS.get(code)
        if mapping is None:
            continue
        matching = sorted(
            events_by_code[code],
            key=lambda row: (
                str(row.get("timestamp") or ""),
                str(row.get("provider") or ""),
                int(row.get("event_id") or 0),
                int(row.get("record_id") or 0),
            ),
            reverse=True,
        )
        label, interpretation, caveat = mapping
        hints.append(
            {
                "kind": "exception_code",
                "label": label,
                "exception_code": code,
                "interpretation": interpretation,
                "confidence": "medium",
                "caveat": caveat,
                "matching_event_count": len(matching),
                "evidence_refs": [
                    _event_reference(row)
                    for row in matching[:5]
                ],
                "additional_matching_events": max(0, len(matching) - 5),
            }
        )

    events_by_surface: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        raw_module = str(event.get("faulting_module") or "").strip()
        if not raw_module:
            continue
        module_name = PureWindowsPath(raw_module).name.casefold()
        if module_name in _WINDOWS_CRASH_SURFACES:
            events_by_surface.setdefault(module_name, []).append(event)
    for module_name in sorted(events_by_surface):
        matching = sorted(
            events_by_surface[module_name],
            key=lambda row: (
                str(row.get("timestamp") or ""),
                str(row.get("provider") or ""),
                int(row.get("event_id") or 0),
                int(row.get("record_id") or 0),
            ),
            reverse=True,
        )
        hints.append(
            {
                "kind": "crash_surface",
                "label": f"{module_name} is a crash surface",
                "faulting_module": module_name,
                "interpretation": (
                    f"The failure surfaced inside {module_name}, a core Windows "
                    "runtime boundary where upstream application or third-party "
                    "module faults are often detected."
                ),
                "confidence": "low",
                "caveat": (
                    f"The module name is not proof that {module_name} caused the "
                    "fault. Use a dump stack and loaded-module versions to locate "
                    "the originating code."
                ),
                "matching_event_count": len(matching),
                "evidence_refs": [
                    _event_reference(row)
                    for row in matching[:5]
                ],
                "additional_matching_events": max(0, len(matching) - 5),
            }
        )
    return hints


def _crash_summary(data: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    events = data["events"]
    reliability = data["reliability_records"]
    reports = data["wer_reports"]
    dumps = data["crash_dumps"]
    all_timestamps = [
        str(row.get("timestamp"))
        for rows in (events, reliability, reports, dumps)
        for row in rows
        if row.get("timestamp")
    ]
    event_counts = Counter(
        (
            str(row.get("provider") or "unknown"),
            int(row.get("event_id") or 0),
        )
        for row in events
    )
    exception_codes = sorted(
        {
            _normalized_exception_code(row["exception_code"])
            or str(row["exception_code"]).casefold()
            for row in events
            if row.get("exception_code")
        },
        key=str.casefold,
    )
    modules = sorted(
        {
            str(row["faulting_module"])
            for row in events
            if row.get("faulting_module")
        },
        key=str.casefold,
    )
    total = len(events) + len(reliability) + len(reports) + len(dumps)
    if events:
        conclusion = (
            f"Found {len(events)} correlated crash, hang, .NET runtime, WER, "
            "or service-termination event(s)."
        )
    elif reports or dumps or reliability:
        conclusion = (
            "No matching primary event remained in the queried logs, but "
            "reliability/WER/dump metadata provides crash evidence."
        )
    else:
        conclusion = (
            "No correlated evidence was found in the selected window. Logs may "
            "have rolled over, reporting may be disabled, or the process name may differ."
        )
    return {
        "total_evidence_items": total,
        "event_count": len(events),
        "reliability_record_count": len(reliability),
        "wer_report_count": len(reports),
        "crash_dump_count": len(dumps),
        "newest_timestamp": max(all_timestamps) if all_timestamps else None,
        "event_signatures": [
            {"provider": provider, "event_id": event_id, "count": count}
            for (provider, event_id), count in sorted(
                event_counts.items(),
                key=lambda item: (item[0][0].casefold(), item[0][1]),
            )
        ],
        "exception_codes": exception_codes,
        "faulting_modules": modules,
        "cause_hints": _cause_hints(events),
        "cause_hint_policy": (
            "Hints classify only exception codes and crash-surface modules "
            "present in the captured event evidence. They are diagnostic leads, "
            "not root-cause findings."
        ),
        "conclusion": conclusion,
    }


def diagnose_program_crash(arguments: ToolInput) -> ToolObservation:
    values = DiagnoseProgramCrashInput.model_validate(arguments)
    if os.name != "nt":
        return _unsupported(
            "diagnose_program_crash",
            "Windows crash-log and WER diagnosis",
        )
    start = datetime.now(timezone.utc) - timedelta(hours=values.since_hours)
    payload = {
        "process_name": values.process_name or "",
        "executable_path": values.executable_path or "",
        "start_time": start.isoformat(),
        "limit": values.limit,
    }
    try:
        raw = run_fixed_powershell(
            "crash_diagnostics",
            payload,
            timeout_seconds=30.0,
        )
    except (PowerShellUnavailable, PowerShellReadError, TimeoutError) as exc:
        return _powershell_failure(
            "diagnose_program_crash",
            "Windows crash evidence query",
            exc,
        )
    raw = raw if isinstance(raw, dict) else {}
    evidence = {
        "events": _normalize_rows(raw.get("events")),
        "reliability_records": _normalize_rows(raw.get("reliability_records")),
        "wer_reports": _normalize_rows(raw.get("wer_reports")),
        "crash_dumps": _normalize_rows(raw.get("crash_dumps")),
    }
    for rows in evidence.values():
        rows.sort(
            key=lambda row: (
                str(row.get("timestamp") or ""),
                str(row.get("provider") or row.get("source") or ""),
                int(row.get("event_id") or row.get("event_identifier") or 0),
            ),
            reverse=True,
        )
    summary = _crash_summary(evidence)
    data = {
        "query": {
            "process_name": values.process_name,
            "executable_path": values.executable_path,
            "start_time": start.isoformat(),
            "since_hours": values.since_hours,
        },
        "evidence_summary": summary,
        **evidence,
        "read_only_guarantee": (
            "This query did not enable, disable, clear, or reconfigure event logs, "
            "Windows Error Reporting, LocalDumps, or dump collection."
        ),
    }
    return ToolObservation.success(
        "diagnose_program_crash",
        summary["conclusion"],
        data,
        provenance=[
            Provenance(
                source="Windows Application and System Event Logs",
                method=(
                    "fixed Get-WinEvent query for 1000, 1001, 1002, 1026, "
                    "7031, and 7034"
                ),
                target=values.process_name or values.executable_path,
            ),
            Provenance(
                source="Win32_ReliabilityRecords",
                method="fixed read-only CIM query",
                target=values.process_name or values.executable_path,
            ),
            Provenance(
                source="Windows Error Reporting and CrashDumps directories",
                method="bounded metadata and Report.wer read",
                target=values.process_name or values.executable_path,
            ),
        ],
    )


def windows_tools() -> tuple[ToolDefinition, ...]:
    return (
        ToolDefinition(
            name="diagnose_path_block",
            description=(
                "Find which Windows process is holding an app file or directory, "
                "or explain why deletion/uninstall may still be blocked."
            ),
            input_model=DiagnosePathBlockInput,
            handler=diagnose_path_block,
            keywords=(
                "cannot delete app because running in background",
                "software will not uninstall",
                "file in use",
                "folder locked",
                "find process blocking path",
            ),
        ),
        ToolDefinition(
            name="explain_process_startup",
            description=(
                "Explain why a Windows process may be running by correlating its "
                "service, scheduled task, Run key, Startup folder, and parent process."
            ),
            input_model=ExplainProcessStartupInput,
            handler=explain_process_startup,
            keywords=(
                "why is process running",
                "background app keeps starting",
                "starts automatically",
                "startup service scheduled task",
                "autostart",
            ),
        ),
        ToolDefinition(
            name="diagnose_program_crash",
            description=(
                "Diagnose why a Windows program crashed or hung using filtered "
                "event logs, reliability records, WER reports, and crash dump metadata."
            ),
            input_model=DiagnoseProgramCrashInput,
            handler=diagnose_program_crash,
            keywords=(
                "app crashed",
                "program keeps crashing",
                "application hang",
                "exception code faulting module",
                "windows error reporting dump",
                "crash",
                "hang",
                "why did program crash",
                "why did application hang",
                "event viewer logs",
                "crash yesterday event logs",
            ),
        ),
        ToolDefinition(
            name="get_execution_policy",
            description=(
                "Read the effective PowerShell execution policy and every policy "
                "scope before suggesting how to run scripts. Makes no changes."
            ),
            input_model=ExecutionPolicyInput,
            handler=get_execution_policy,
            keywords=(
                "how to set execution policy to run scripts",
                "powershell script blocked",
                "get executionpolicy",
                "restricted remotesigned bypass",
            ),
        ),
        ToolDefinition(
            name="get_event_logs",
            description=(
                "Read Windows Event Logs with provider, event ID, severity, text, "
                "start time, end time, and bounded result filters."
            ),
            input_model=EventLogsInput,
            handler=get_event_logs,
            keywords=(
                "windows event viewer",
                "system logs",
                "application error log",
                "event id provider time",
            ),
        ),
        ToolDefinition(
            name="list_installed_apps",
            description=(
                "List installed Windows applications and their uninstall metadata "
                "from current-user and machine registry views."
            ),
            input_model=InstalledAppsInput,
            handler=list_installed_apps,
            keywords=("installed software", "programs and features", "uninstall app"),
        ),
        ToolDefinition(
            name="get_services",
            description=(
                "List or find Windows services with status, startup type, account, "
                "binary path, and PID. Read-only."
            ),
            input_model=ServicesInput,
            handler=get_services,
            keywords=(
                "windows services",
                "service status",
                "background service",
                "automatic service startup",
                "service executable pid",
            ),
        ),
        ToolDefinition(
            name="get_registry_values",
            description=(
                "Read values and child-key names from one Windows Registry key. "
                "Never creates, changes, or deletes registry data."
            ),
            input_model=RegistryValuesInput,
            handler=get_registry_values,
            keywords=("registry key", "regedit", "HKLM", "HKCU", "registry value"),
        ),
    )


__all__ = [
    "DiagnosePathBlockInput",
    "DiagnoseProgramCrashInput",
    "EventLogsInput",
    "ExecutionPolicyInput",
    "ExplainProcessStartupInput",
    "InstalledAppsInput",
    "RegistryValuesInput",
    "ServicesInput",
    "diagnose_path_block",
    "diagnose_program_crash",
    "explain_process_startup",
    "get_event_logs",
    "get_execution_policy",
    "get_registry_values",
    "get_services",
    "list_installed_apps",
    "windows_tools",
]
