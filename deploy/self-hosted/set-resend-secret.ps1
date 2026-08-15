[CmdletBinding()]
param(
    [switch]$Replace
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$deploymentRoot = Split-Path -Parent $PSCommandPath
$secretRoot = Join-Path $deploymentRoot 'secrets'
$secretPath = Join-Path $secretRoot 'resend_api_key'

if (-not (Test-Path -LiteralPath $secretRoot -PathType Container)) {
    throw 'The deployment secret directory does not exist. Run init-secrets.ps1 first.'
}
if ((Test-Path -LiteralPath $secretPath -PathType Leaf) -and -not $Replace) {
    throw 'A Resend API key is already installed. Use -Replace only when intentionally rotating it.'
}

Write-Host 'Paste the Resend key at the masked prompt. It will not appear on screen or in PowerShell history.'
$secureValue = Read-Host 'Resend API key' -AsSecureString
$pointer = [IntPtr]::Zero
$plainValue = $null
try {
    $pointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue)
    $plainValue = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer).Trim()
    if (-not $plainValue.StartsWith('re_') -or $plainValue.Length -lt 8 -or $plainValue -match '\s') {
        throw 'The supplied value is not a valid re_ prefixed Resend API key.'
    }
    $utf8WithoutBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($secretPath, $plainValue + [Environment]::NewLine, $utf8WithoutBom)
} finally {
    $plainValue = $null
    $secureValue.Dispose()
    if ($pointer -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

# The secret file inherits the protected directory ACL established by
# init-secrets.ps1. Reassigning directory ownership here is unnecessary and can
# require privileges that an ordinary Windows account intentionally lacks.
Write-Host 'Resend API key installed without displaying its value.'
