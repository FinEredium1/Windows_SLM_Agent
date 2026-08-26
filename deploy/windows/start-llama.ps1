[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ServerPath,

    [Parameter(Mandatory = $true)]
    [string] $ModelPath,

    [ValidateRange(1024, 65535)]
    [int] $Port = 11434,

    [ValidateRange(2048, 131072)]
    [int] $Context = 12288,

    [ValidateRange(1, 256)]
    [int] $Threads = [Environment]::ProcessorCount
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$server = Get-Item -LiteralPath $ServerPath
$model = Get-Item -LiteralPath $ModelPath

if ($server.PSIsContainer -or $server.Extension -ne ".exe") {
    throw "ServerPath must identify llama-server.exe."
}
if ($model.PSIsContainer -or $model.Extension -ne ".gguf") {
    throw "ModelPath must identify a GGUF model file."
}

$listener = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
if ($null -ne $listener) {
    throw "TCP port $Port is already listening. Stop that service or choose another port."
}

$serverArguments = @(
    "-m", $model.FullName,
    "--host", "127.0.0.1",
    "--port", $Port.ToString(),
    "-c", $Context.ToString(),
    "-t", $Threads.ToString(),
    "--temp", "0",
    "--jinja"
)

Write-Host "Starting local Gemma endpoint at http://127.0.0.1:$Port/v1"
Write-Host "Model: $($model.FullName)"
Write-Host "Context: $Context; threads: $Threads; temperature: 0"

& $server.FullName @serverArguments
if ($LASTEXITCODE -ne 0) {
    throw "llama-server exited with code $LASTEXITCODE."
}

