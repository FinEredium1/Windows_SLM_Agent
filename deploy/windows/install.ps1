[CmdletBinding()]
param(
    [string] $PythonCommand = "py",
    [switch] $WithDev
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$venvPath = Join-Path $projectRoot ".venv"
$venvPython = Join-Path $venvPath "Scripts\python.exe"

Push-Location $projectRoot
try {
    if (-not (Test-Path -LiteralPath $venvPython)) {
        if ($PythonCommand -eq "py") {
            & py -3 -m venv $venvPath
        }
        else {
            & $PythonCommand -m venv $venvPath
        }
        if ($LASTEXITCODE -ne 0) {
            throw "Could not create the virtual environment."
        }
    }

    & $venvPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) {
        throw "Could not upgrade pip."
    }

    $installTarget = if ($WithDev) { ".[dev]" } else { "." }
    & $venvPython -m pip install -e $installTarget
    if ($LASTEXITCODE -ne 0) {
        throw "Could not install Terminus."
    }

    Write-Host "Installed Terminus."
    Write-Host "Run: $venvPath\Scripts\terminus.exe `"Show me all listening ports`""
}
finally {
    Pop-Location
}
