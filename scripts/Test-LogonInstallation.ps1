#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ResultPath)
$ErrorActionPreference = 'Stop'
# Only status flags and counts are exported. Never export account names, SIDs,
# certificates, public-key identifiers, encrypted passwords or exception text.
$result = [ordered]@{ CheckCompleted = $false }
try {
    $provider = '{37167329-B6D8-4379-90A9-0D350F82F31A}'
    $result.ProviderRegistered = Test-Path -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\' + $provider)
    $result.ComRegistered = Test-Path -LiteralPath ('HKLM:\SOFTWARE\Classes\CLSID\' + $provider + '\InprocServer32')
    $marker = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\MynaAuth'
    $recovery = Get-LocalUser -SID $marker.RecoverySid
    $result.RecoveryEnabled = [bool]$recovery.Enabled
    $result.RecoveryIsAdmin = [bool](@(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID.Value -eq $recovery.SID.Value }).Count)
    $keys = @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\MynaAuth\Accounts')
    $result.EnrollmentCount = $keys.Count
    $result.RecoveryNotEnrolled = -not ($keys.PSChildName -contains $marker.RecoverySid)
    $result.EnrollmentsReady = $keys.Count -gt 0
    foreach ($key in $keys) {
        $entry = Get-ItemProperty -LiteralPath $key.PSPath
        $result.EnrollmentsReady = $result.EnrollmentsReady -and ($entry.ProtectedPassword -is [byte[]]) -and ($entry.ProtectedPassword.Length -gt 0) -and (@($entry.CredentialIds).Count -gt 0) -and (-not [string]::IsNullOrEmpty($entry.QualifiedName))
    }
    $result.CheckCompleted = $true
}
catch { $result.FailureCode = $_.Exception.HResult }
$result | ConvertTo-Json | Set-Content -LiteralPath $ResultPath -Encoding UTF8
