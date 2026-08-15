[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$deploymentRoot = Split-Path -Parent $PSCommandPath
$composeFile = Join-Path $deploymentRoot 'compose.yml'
$requiredSecrets = @(
    'postgres_password',
    'audit_hmac_key',
    'audit_anchor_key',
    'mfa_encryption_key',
    'local_kek',
    'metrics_token'
)

foreach ($name in $requiredSecrets) {
    $path = Join-Path (Join-Path $deploymentRoot 'secrets') $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing deployment secret: $name. Run init-secrets.ps1 first."
    }
    if ((Get-Item -LiteralPath $path).Length -eq 0) {
        throw "Deployment secret is empty: $name"
    }
}

docker compose -f $composeFile config --quiet
if ($LASTEXITCODE -ne 0) {
    throw 'Docker Compose configuration validation failed.'
}

Write-Host 'SecureStore self-hosted Compose configuration is valid.'
