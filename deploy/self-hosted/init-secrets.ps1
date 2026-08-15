[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$deploymentRoot = Split-Path -Parent $PSCommandPath
$secretRoot = Join-Path $deploymentRoot 'secrets'

if (-not (Test-Path -LiteralPath $secretRoot)) {
    $null = New-Item -ItemType Directory -Path $secretRoot
}

function Write-SecretIfMissing {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('Base64', 'Hex')]
        [string]$Encoding
    )

    $path = Join-Path $secretRoot $Name
    if (Test-Path -LiteralPath $path) {
        Write-Host "Preserved existing secret: $Name"
        return
    }

    $bytes = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    try {
        $value = if ($Encoding -eq 'Hex') {
            [Convert]::ToHexString($bytes).ToLowerInvariant()
        } else {
            [Convert]::ToBase64String($bytes)
        }
        $utf8WithoutBom = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($path, $value + [Environment]::NewLine, $utf8WithoutBom)
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }

    Write-Host "Created secret: $Name"
}

# Hex avoids URL-encoding ambiguity when the entrypoint constructs the private
# PostgreSQL connection URL. Application cryptographic keys remain base64, as
# required by the existing key loaders.
Write-SecretIfMissing -Name 'postgres_password' -Encoding Hex
Write-SecretIfMissing -Name 'audit_hmac_key' -Encoding Base64
Write-SecretIfMissing -Name 'audit_anchor_key' -Encoding Base64
Write-SecretIfMissing -Name 'mfa_encryption_key' -Encoding Base64
Write-SecretIfMissing -Name 'local_kek' -Encoding Base64
Write-SecretIfMissing -Name 'metrics_token' -Encoding Base64

# Remove inherited ACLs from this deployment-only directory. The interactive
# owner needs access for Docker Desktop bind mounts; Windows SYSTEM retains
# recovery and operating-system access without granting other local users.
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$systemIdentity = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18').Translate(
    [System.Security.Principal.NTAccount]
).Value
$acl = [System.Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
$acl.SetOwner([System.Security.Principal.NTAccount]::new($identity))
foreach ($principal in @($identity, $systemIdentity)) {
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $principal,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $secretRoot -AclObject $acl

Write-Host "SecureStore deployment secrets are ready in $secretRoot"
