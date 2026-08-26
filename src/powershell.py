"""Allowlisted PowerShell reads with JSON stdin and ``shell=False``.

There is intentionally no API that accepts PowerShell source from the model.
Callers select one immutable script ID and pass data through standard input.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
import os
import shutil
import subprocess
from types import MappingProxyType
from typing import Any


class PowerShellUnavailable(RuntimeError):
    """PowerShell-backed Windows reads cannot run on this host."""


class PowerShellReadError(RuntimeError):
    """A fixed PowerShell read failed or returned malformed data."""


_COMMON = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8 = New-Object System.Text.UTF8Encoding($false)
[Console]::InputEncoding = $utf8
[Console]::OutputEncoding = $utf8
$raw = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($raw)) {
    $p = [pscustomobject]@{}
} else {
    $p = $raw | ConvertFrom-Json
}
"""


_GET_EXECUTION_POLICY = _COMMON + r"""
$rows = Get-ExecutionPolicy -List | ForEach-Object {
    [pscustomobject]@{
        scope = [string]$_.Scope
        execution_policy = [string]$_.ExecutionPolicy
    }
}
$effective = [string](Get-ExecutionPolicy)
[pscustomobject]@{
    effective_policy = $effective
    scopes = @($rows)
} | ConvertTo-Json -Depth 5 -Compress
"""


_QUERY_EVENT_LOG = _COMMON + r"""
$filter = @{ LogName = [string]$p.log_name }
if ($null -ne $p.start_time -and -not [string]::IsNullOrWhiteSpace([string]$p.start_time)) {
    $filter.StartTime = [datetime]$p.start_time
}
if ($null -ne $p.end_time -and -not [string]::IsNullOrWhiteSpace([string]$p.end_time)) {
    $filter.EndTime = [datetime]$p.end_time
}
$ids = @($p.event_ids | ForEach-Object { [int]$_ })
if ($ids.Count -gt 0) {
    $filter.Id = $ids
}
if ($null -ne $p.level -and [int]$p.level -gt 0) {
    $filter.Level = [int]$p.level
}
$provider = [string]$p.provider
$messageQuery = [string]$p.message_query
if (-not [string]::IsNullOrWhiteSpace($provider)) {
    $filter.ProviderName = $provider
}
$events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents ([int]$p.scan_limit) -ErrorAction SilentlyContinue)
$rows = @(
    $events |
    Where-Object {
        ([string]::IsNullOrWhiteSpace($provider) -or $_.ProviderName -ieq $provider) -and
        ([string]::IsNullOrWhiteSpace($messageQuery) -or ([string]$_.Message).IndexOf($messageQuery, [StringComparison]::OrdinalIgnoreCase) -ge 0)
    } |
    Select-Object -First ([int]$p.limit) |
    ForEach-Object {
        $message = [string]$_.Message
        if ($message.Length -gt 6000) { $message = $message.Substring(0, 6000) }
        [pscustomobject]@{
            timestamp = if ($null -ne $_.TimeCreated) { $_.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
            provider = [string]$_.ProviderName
            event_id = [int]$_.Id
            level = [string]$_.LevelDisplayName
            log_name = [string]$_.LogName
            record_id = [long]$_.RecordId
            machine_name = [string]$_.MachineName
            message = $message
        }
    }
)
@($rows) | ConvertTo-Json -Depth 5 -Compress
"""


_QUERY_SCHEDULED_TASKS = _COMMON + r"""
$needle = ([string]$p.needle).Trim()
$rows = @()
try {
    $rows = @(
        Get-ScheduledTask -ErrorAction Stop |
        ForEach-Object {
            $task = $_
            foreach ($action in @($task.Actions)) {
                $execute = [string]$action.Execute
                $arguments = [string]$action.Arguments
                $haystack = "$($task.TaskName) $($task.TaskPath) $execute $arguments"
                if ([string]::IsNullOrWhiteSpace($needle) -or $haystack.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    [pscustomobject]@{
                        task_name = [string]$task.TaskName
                        task_path = [string]$task.TaskPath
                        state = [string]$task.State
                        executable = $execute
                        arguments = $arguments
                        enabled = [bool]$task.Settings.Enabled
                    }
                }
            }
        } |
        Select-Object -First ([int]$p.limit)
    )
} catch {
    $rows = @()
}
@($rows) | ConvertTo-Json -Depth 5 -Compress
"""


_CRASH_DIAGNOSTICS = _COMMON + r"""
$start = [datetime]$p.start_time
$limit = [int]$p.limit
$scanLimit = [Math]::Min([Math]::Max($limit * 8, 100), 1000)
$processName = ([string]$p.process_name).Trim()
$executablePath = ([string]$p.executable_path).Trim()
$executableName = if ([string]::IsNullOrWhiteSpace($executablePath)) { '' } else { [IO.Path]::GetFileName($executablePath) }
$needles = @($processName, $executableName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

function Test-Relevant([string]$text) {
    if ($needles.Count -eq 0) { return $true }
    foreach ($needle in $needles) {
        if ($text.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    return $false
}

function First-Match([string]$text, [string]$pattern) {
    $match = [regex]::Match($text, $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [Text.RegularExpressions.RegexOptions]::Multiline)
    if ($match.Success -and $match.Groups.Count -gt 1) { return $match.Groups[1].Value.Trim() }
    return $null
}

$eventRows = @()
$applicationFilter = @{ LogName = 'Application'; StartTime = $start; Id = @(1000, 1001, 1002, 1026) }
$applicationEvents = @(Get-WinEvent -FilterHashtable $applicationFilter -MaxEvents $scanLimit -ErrorAction SilentlyContinue)
$systemFilter = @{ LogName = 'System'; StartTime = $start; Id = @(7031, 7034) }
$systemEvents = @(Get-WinEvent -FilterHashtable $systemFilter -MaxEvents $scanLimit -ErrorAction SilentlyContinue)
foreach ($event in @($applicationEvents + $systemEvents)) {
    $message = [string]$event.Message
    if (-not (Test-Relevant $message)) { continue }
    if ($message.Length -gt 8000) { $message = $message.Substring(0, 8000) }
    $eventRows += [pscustomobject]@{
        timestamp = if ($null -ne $event.TimeCreated) { $event.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
        provider = [string]$event.ProviderName
        event_id = [int]$event.Id
        level = [string]$event.LevelDisplayName
        log_name = [string]$event.LogName
        record_id = [long]$event.RecordId
        faulting_application = First-Match $message 'Faulting application name:\s*([^,\r\n]+)'
        faulting_application_path = First-Match $message 'Faulting application path:\s*([^\r\n]+)'
        faulting_module = First-Match $message 'Faulting module name:\s*([^,\r\n]+)'
        faulting_module_path = First-Match $message 'Faulting module path:\s*([^\r\n]+)'
        exception_code = First-Match $message 'Exception code:\s*([^\s,\r\n]+)'
        fault_offset = First-Match $message 'Fault offset:\s*([^\s,\r\n]+)'
        fault_bucket = First-Match $message 'Fault bucket(?: type \d+)?,\s*(?:type \d+\s*)?([^\r\n]+)'
        report_id = First-Match $message 'Report Id:\s*([^\s,\r\n]+)'
        service_name = First-Match $message 'The (.+?) service terminated unexpectedly'
        message = $message
    }
    if ($eventRows.Count -ge $limit) { break }
}

$reliabilityRows = @()
try {
    $records = @(Get-CimInstance -ClassName Win32_ReliabilityRecords -ErrorAction Stop |
        Where-Object { $null -ne $_.TimeGenerated -and $_.TimeGenerated -ge $start } |
        Sort-Object TimeGenerated -Descending)
    foreach ($record in $records) {
        $text = "$($record.ProductName) $($record.SourceName) $($record.Message)"
        if (-not (Test-Relevant $text)) { continue }
        $message = [string]$record.Message
        if ($message.Length -gt 6000) { $message = $message.Substring(0, 6000) }
        $reliabilityRows += [pscustomobject]@{
            timestamp = $record.TimeGenerated.ToUniversalTime().ToString('o')
            source = [string]$record.SourceName
            product_name = [string]$record.ProductName
            event_identifier = [int]$record.EventIdentifier
            message = $message
        }
        if ($reliabilityRows.Count -ge $limit) { break }
    }
} catch {
    $reliabilityRows = @()
}

$werRows = @()
$werRoots = @(
    (Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportArchive'),
    (Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportQueue'),
    (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER\ReportArchive'),
    (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER\ReportQueue')
) | Select-Object -Unique
$wantedWerFields = @(
    'AppName', 'AppPath', 'ApplicationName', 'ApplicationPath',
    'ModuleName', 'ModulePath', 'ExceptionCode', 'ReportIdentifier',
    'Sig[0].Value', 'Sig[1].Value', 'Sig[2].Value', 'Sig[3].Value',
    'FriendlyEventName', 'EventType'
)
foreach ($root in $werRoots) {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
    $directories = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTimeUtc -ge $start.ToUniversalTime() } |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First $scanLimit)
    foreach ($directory in $directories) {
        $reportFile = Join-Path $directory.FullName 'Report.wer'
        $content = ''
        if (Test-Path -LiteralPath $reportFile -PathType Leaf) {
            $content = [string](Get-Content -LiteralPath $reportFile -Raw -ErrorAction SilentlyContinue)
            if ($content.Length -gt 65536) { $content = $content.Substring(0, 65536) }
        }
        if (-not (Test-Relevant "$($directory.Name) $content")) { continue }
        $fields = [ordered]@{}
        foreach ($line in ($content -split "`r?`n")) {
            $index = $line.IndexOf('=')
            if ($index -le 0) { continue }
            $key = $line.Substring(0, $index).Trim()
            if ($wantedWerFields -notcontains $key) { continue }
            $fields[$key] = $line.Substring($index + 1).Trim()
        }
        $dumps = @(Get-ChildItem -LiteralPath $directory.FullName -Filter '*.dmp' -File -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty FullName)
        $werRows += [pscustomobject]@{
            timestamp = $directory.LastWriteTimeUtc.ToString('o')
            report_path = $directory.FullName
            report_file = if (Test-Path -LiteralPath $reportFile -PathType Leaf) { $reportFile } else { $null }
            fields = [pscustomobject]$fields
            dump_paths = @($dumps)
        }
        if ($werRows.Count -ge $limit) { break }
    }
    if ($werRows.Count -ge $limit) { break }
}

$dumpRows = @()
$dumpRoot = Join-Path $env:LOCALAPPDATA 'CrashDumps'
if (Test-Path -LiteralPath $dumpRoot -PathType Container) {
    $dumps = @(Get-ChildItem -LiteralPath $dumpRoot -Filter '*.dmp' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTimeUtc -ge $start.ToUniversalTime() } |
        Sort-Object LastWriteTimeUtc -Descending)
    foreach ($dump in $dumps) {
        if (-not (Test-Relevant $dump.Name)) { continue }
        $dumpRows += [pscustomobject]@{
            timestamp = $dump.LastWriteTimeUtc.ToString('o')
            path = $dump.FullName
            size_bytes = [long]$dump.Length
        }
        if ($dumpRows.Count -ge $limit) { break }
    }
}

[pscustomobject]@{
    events = @($eventRows)
    reliability_records = @($reliabilityRows)
    wer_reports = @($werRows)
    crash_dumps = @($dumpRows)
} | ConvertTo-Json -Depth 8 -Compress
"""


FIXED_SCRIPTS: Mapping[str, str] = MappingProxyType(
    {
        "get_execution_policy": _GET_EXECUTION_POLICY,
        "query_event_log": _QUERY_EVENT_LOG,
        "query_scheduled_tasks": _QUERY_SCHEDULED_TASKS,
        "crash_diagnostics": _CRASH_DIAGNOSTICS,
    }
)


def find_powershell() -> str | None:
    """Return a Windows PowerShell executable, preferring PowerShell 7."""

    if os.name != "nt":
        return None
    for candidate in ("pwsh.exe", "powershell.exe", "pwsh", "powershell"):
        found = shutil.which(candidate)
        if found:
            return found
    return None


@dataclass(slots=True)
class FixedPowerShellRunner:
    """Runs only entries from :data:`FIXED_SCRIPTS`."""

    executable: str | None = None
    timeout_seconds: float = 20.0
    max_stdout_bytes: int = 4 * 1024 * 1024
    allow_non_windows_for_tests: bool = False

    @property
    def available(self) -> bool:
        if os.name != "nt" and not self.allow_non_windows_for_tests:
            return False
        return bool(self.executable or find_powershell())

    def run(self, script_id: str, payload: Mapping[str, Any] | None = None) -> Any:
        script = FIXED_SCRIPTS.get(script_id)
        if script is None:
            raise ValueError(f"Unknown fixed PowerShell script ID: {script_id!r}")
        if os.name != "nt" and not self.allow_non_windows_for_tests:
            raise PowerShellUnavailable(
                "Fixed PowerShell system reads are available only on Windows."
            )
        executable = self.executable or find_powershell()
        if not executable:
            raise PowerShellUnavailable(
                "Neither pwsh.exe nor powershell.exe was found."
            )
        try:
            encoded_payload = json.dumps(
                dict(payload or {}),
                ensure_ascii=False,
                separators=(",", ":"),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(f"PowerShell payload is not JSON serializable: {exc}") from exc
        if len(encoded_payload.encode("utf-8")) > 256 * 1024:
            raise ValueError("PowerShell JSON input exceeds the 256 KiB limit")
        try:
            completed = subprocess.run(
                [
                    executable,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    script,
                ],
                input=encoded_payload,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                shell=False,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(
                f"Fixed PowerShell read {script_id!r} timed out."
            ) from exc
        stdout = completed.stdout.strip()
        stderr = completed.stderr.strip()
        if len(stdout.encode("utf-8")) > self.max_stdout_bytes:
            raise PowerShellReadError(
                f"Fixed PowerShell read {script_id!r} exceeded its output limit."
            )
        if completed.returncode != 0:
            detail = stderr[-2000:] or stdout[-2000:] or "unknown error"
            raise PowerShellReadError(
                f"Fixed PowerShell read {script_id!r} failed: {detail}"
            )
        if not stdout:
            return None
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise PowerShellReadError(
                f"Fixed PowerShell read {script_id!r} returned invalid JSON."
            ) from exc


def run_fixed_powershell(
    script_id: str,
    payload: Mapping[str, Any] | None = None,
    *,
    timeout_seconds: float = 20.0,
) -> Any:
    return FixedPowerShellRunner(timeout_seconds=timeout_seconds).run(
        script_id,
        payload,
    )


__all__ = [
    "FIXED_SCRIPTS",
    "FixedPowerShellRunner",
    "PowerShellReadError",
    "PowerShellUnavailable",
    "find_powershell",
    "run_fixed_powershell",
]
