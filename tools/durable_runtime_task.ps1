param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Run')]
    [string]$Action
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$python = Join-Path $root '.venv\Scripts\python.exe'
$launcher = Join-Path $PSScriptRoot 'durable_runtime.py'
$manifestPath = Join-Path $root 'var\durable-runtime\owner-pins.json'
function Get-FileSha256([string]$Path) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $stream = [IO.File]::OpenRead($Path)
        try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
        finally { $stream.Dispose() }
    }
    finally { $sha.Dispose() }
}
if (-not (Test-Path -LiteralPath $python -PathType Leaf) -or
    -not (Test-Path -LiteralPath $launcher -PathType Leaf) -or
    -not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    exit 2
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$owner = "$env:USERDOMAIN\$env:USERNAME"
if ($manifest.schema -ne 'fieldwork.durable-runtime-owner/v1' -or
    $manifest.task_name -ne 'Fieldwork.DurableRuntime.v1' -or
    $manifest.root -ne $root -or $manifest.owner_user -ne $owner -or
    $manifest.registration_pending -or
    [string]::IsNullOrWhiteSpace([string]$manifest.task_xml_enabled_sha256) -or
    [string]::IsNullOrWhiteSpace([string]$manifest.task_xml_disabled_sha256)) {
    exit 2
}
$checks = @{
    python = $python
    launcher = $launcher
    task_wrapper = $PSCommandPath
    api = (Join-Path $root 'fieldwork\api.py')
    logging = (Join-Path $root 'fieldwork\privacy_logging.py')
    migration_017 = (Join-Path $root 'migrations\017_privacy_lifecycle.sql')
}
foreach ($name in $checks.Keys) {
    $expected = [string]$manifest.pins.$name
    if ([string]::IsNullOrWhiteSpace($expected) -or
        -not (Test-Path -LiteralPath $checks[$name] -PathType Leaf) -or
        (Get-FileSha256 ([string]$checks[$name])) -ne $expected) {
        exit 2
    }
}
Set-Location -LiteralPath $root
& $python -B $launcher run
exit $LASTEXITCODE
