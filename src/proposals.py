"""Compile trusted command cards into inert, risk-labelled PowerShell proposals."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class FinishArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result: str = Field(min_length=1, max_length=20_000)


class ProposeCommandArguments(BaseModel):
    """The actor identifies a trusted card; it never supplies raw PowerShell."""

    model_config = ConfigDict(extra="forbid")

    card_id: str = Field(min_length=1, max_length=160)
    arguments: dict[str, Any] = Field(default_factory=dict)


class ProposalAnalysis(BaseModel):
    command: str
    summary: str
    risk: Literal["low", "medium", "high", "critical"]
    requires_admin: bool
    read_only: bool = False
    executed: bool = False
    dry_run: str | None = None
    rollback: str | None = None
    warnings: list[str] = Field(default_factory=list)
    card_id: str


_CRITICAL = re.compile(
    r"(?ix)\b("
    r"clear-disk|format-volume|format\s+[a-z]:|diskpart|"
    r"remove-item\b[^\r\n]*(?:-recurse\b[^\r\n]*)?(?:[\"']?[a-z]:\\[\"']?\s*$)|"
    r"bcdedit|disable-bitlocker|manage-bde\s+-off"
    r")"
)
_HIGH = re.compile(
    r"(?ix)\b("
    r"remove-item|remove-appxpackage|uninstall-package|winget\s+uninstall|"
    r"stop-service|restart-service|set-service|"
    r"new-localuser|remove-localuser|add-localgroupmember|remove-localgroupmember|"
    r"new-netfirewallrule|set-netfirewallprofile|remove-netfirewallrule|"
    r"set-executionpolicy|set-itemproperty|new-itemproperty|remove-itemproperty|"
    r"register-scheduledtask|unregister-scheduledtask|"
    r"enable-windowsoptionalfeature|disable-windowsoptionalfeature"
    r")"
)
_MEDIUM = re.compile(
    r"(?ix)\b("
    r"set-content|add-content|new-item|copy-item|move-item|rename-item|"
    r"set-item|setx(?:\.exe)?|winget\s+install|install-package|"
    r"start-service|set-netipinterface|set-dnsclientserveraddress|unblock-file"
    r")"
)
_ADMIN = re.compile(
    r"(?ix)\b("
    r"-scope\s+localmachine|hklm:|hkey_local_machine|"
    r"(?:start|stop|restart|set)-service|"
    r"netfirewall|localuser|localgroup|scheduledtask|windowsoptionalfeature|"
    r"winget\s+(?:install|uninstall)\b[^\r\n]*(?:--scope\s+machine)"
    r")"
)
_BLOCKED_OBFUSCATION = re.compile(
    r"(?ix)("
    r"-encodedcommand\b|(?:^|[\s;|])(?:iex|invoke-expression)(?:\s|$)|"
    r"frombase64string|downloadstring\s*\(|"
    r"invoke-webrequest[^\r\n|]*\|\s*(?:iex|invoke-expression)|"
    r"invoke-restmethod[^\r\n|]*\|\s*(?:iex|invoke-expression)|"
    r"mimikatz|sekurlsa|comsvcs\.dll.*minidump|"
    r"set-mppreference[^\r\n]*-disablerealtimemonitoring|"
    r"add-mppreference[^\r\n]*-exclusion"
    r")"
)


def classify_proposal(
    *,
    card_id: str,
    command: str,
    summary: str,
    rollback: str | None,
    requires_admin: bool = False,
    warnings: list[str] | None = None,
    supports_whatif: bool = False,
    declared_risk: Literal["low", "medium", "high", "critical"] | None = None,
) -> ProposalAnalysis:
    """Apply controller-owned risk labels to a rendered trusted card."""
    command = command.strip()
    if not command:
        raise ValueError("The command card rendered an empty command.")
    if "\x00" in command or len(command) > 8000:
        raise ValueError("The rendered command is invalid or too large.")
    if _BLOCKED_OBFUSCATION.search(command):
        raise ValueError(
            "The rendered card contains obfuscated, credential-access, "
            "download-to-execution, or security-bypass behavior."
        )
    risk: Literal["low", "medium", "high", "critical"]
    if _CRITICAL.search(command):
        risk = "critical"
    elif _HIGH.search(command):
        risk = "high"
    elif _MEDIUM.search(command):
        risk = "medium"
    else:
        risk = "low"
    risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    if declared_risk and risk_order[declared_risk] > risk_order[risk]:
        risk = declared_risk
    inferred_admin = requires_admin or bool(_ADMIN.search(command))
    output_warnings = list(warnings or [])
    if risk in {"high", "critical"} and not rollback:
        output_warnings.append(
            "No automatic rollback is available; capture the current state first."
        )
    dry_run = None
    if supports_whatif and "-whatif" not in command.lower():
        dry_run = f"{command} -WhatIf"
    return ProposalAnalysis(
        command=command,
        summary=summary.strip(),
        risk=risk,
        requires_admin=inferred_admin,
        dry_run=dry_run,
        rollback=rollback.strip() if rollback else None,
        warnings=output_warnings,
        card_id=card_id,
    )


def format_proposal(proposal: ProposalAnalysis) -> str:
    lines = [
        "Suggested PowerShell command (not executed):",
        "",
        "```powershell",
        proposal.command,
        "```",
        "",
        f"Effect: {proposal.summary}",
        f"Risk: {proposal.risk}",
        f"Administrator required: {'yes' if proposal.requires_admin else 'no'}",
    ]
    if proposal.dry_run:
        lines.extend(
            [
                "",
                "Dry run:",
                "```powershell",
                proposal.dry_run,
                "```",
            ]
        )
    if proposal.rollback:
        lines.extend(["", f"Rollback: {proposal.rollback}"])
    if proposal.warnings:
        lines.extend(["", "Warnings:"])
        lines.extend(f"- {warning}" for warning in proposal.warnings)
    return "\n".join(lines)


def finish_schema() -> dict[str, Any]:
    return _terminal_schema(
        "finish",
        "Return the final concise answer after the request is satisfied.",
        FinishArguments,
    )


def proposal_schema() -> dict[str, Any]:
    return _terminal_schema(
        "propose_command",
        "Render a trusted write-command card as an inert PowerShell suggestion. "
        "This tool never executes commands.",
        ProposeCommandArguments,
    )


def _terminal_schema(
    name: str,
    description: str,
    model: type[BaseModel],
) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": model.model_json_schema(),
        },
    }
