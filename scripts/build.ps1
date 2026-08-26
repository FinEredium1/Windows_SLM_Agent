[CmdletBinding()]
param(
    [string] $PythonPath = ".\.venv\Scripts\python.exe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Get-Item -LiteralPath (Join-Path $projectRoot $PythonPath)
$dist = Join-Path $projectRoot "dist"

Push-Location $projectRoot
try {
    & $python.FullName -m pip wheel . --no-deps --wheel-dir $dist
    if ($LASTEXITCODE -ne 0) {
        throw "Wheel build failed with code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}

