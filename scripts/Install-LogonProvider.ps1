#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param([switch]$RecoverySignInConfirmed)
$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit PowerShell.' }
if (-not $RecoverySignInConfirmed) { throw 'First verify a real password sign-in with the recovery account.' }
$marker = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\MynaAuth'
if (-not $marker.RecoverySid -or -not $marker.RecoveryVerifiedUtc) { throw 'Recovery account verification is missing.' }
$recovery = Get-LocalUser -SID $marker.RecoverySid
if (-not $recovery.Enabled) { throw 'Recovery account is disabled.' }
$recoveryAdmin = Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID.Value -eq $recovery.SID.Value }
if (-not $recoveryAdmin) { throw 'Recovery account is not an administrator.' }
$accounts = @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\MynaAuth\Accounts' -ErrorAction SilentlyContinue)
if ($accounts.Count -eq 0) { throw 'Enroll a card and Windows account first.' }
if ($accounts.PSChildName -contains $marker.RecoverySid) { throw 'The recovery account must not be enrolled.' }

$source = [IO.Path]::GetFullPath($PSScriptRoot)
$manifestPath = Join-Path $source 'bundle-manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
foreach ($entry in $manifest) {
    if ($entry.Name -ne [IO.Path]::GetFileName($entry.Name)) { throw 'Invalid bundle path.' }
    $file = Join-Path $source $entry.Name
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $entry.Sha256) { throw 'Bundle integrity check failed.' }
}
$dllName = 'MynaAuthCredentialProvider.dll'
if (-not ($manifest.Name -contains $dllName) -or -not ($manifest.Name -contains 'MynaAuth.LogonHost.exe')) { throw 'Required files are missing.' }
$providerId = '{37167329-B6D8-4379-90A9-0D350F82F31A}'
$target = Join-Path $env:ProgramFiles 'MynaAuthSignIn'
$providerKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\' + $providerId
$comKey = 'HKLM:\SOFTWARE\Classes\CLSID\' + $providerId
if (Test-Path -LiteralPath $providerKey) { throw 'Uninstall the existing MynaAuth provider before updating it.' }
if (-not $PSCmdlet.ShouldProcess($target, 'Install MynaAuth and register its credential provider')) { return }
New-Item -ItemType Directory -Path $target -Force | Out-Null
$item = Get-Item -LiteralPath $target
if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'The installation directory must not be a link.' }
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sidText in @('S-1-5-18','S-1-5-32-544')) {
    $sid = New-Object System.Security.Principal.SecurityIdentifier($sidText)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
}
$usersSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($usersSid,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
Set-Acl -LiteralPath $target -AclObject $acl
try {
    foreach ($entry in $manifest) { Copy-Item -LiteralPath (Join-Path $source $entry.Name) -Destination (Join-Path $target $entry.Name) -Force }
    Copy-Item -LiteralPath $manifestPath -Destination $target -Force
    # Validate copied bytes before publishing any COM/provider registration.
    foreach ($entry in $manifest) {
        if ((Get-FileHash -LiteralPath (Join-Path $target $entry.Name) -Algorithm SHA256).Hash -ne $entry.Sha256) { throw 'Installed file verification failed.' }
    }
    $inproc = New-Item -Path ($comKey + '\InprocServer32') -Force
    $inproc.SetValue('', (Join-Path $target $dllName))
    $inproc.SetValue('ThreadingModel', 'Apartment')
    $inproc.Close()
    $registered = New-Item -Path $providerKey -Force
    $registered.SetValue('', 'マイナンバーカードによるログイン')
    $registered.Close()
    Write-Host 'MynaAuth installed. System credential providers were not changed. No restart or lock was initiated.'
}
catch {
    if (Test-Path -LiteralPath $providerKey) { Remove-Item -LiteralPath $providerKey -Recurse -Force }
    if (Test-Path -LiteralPath $comKey) { Remove-Item -LiteralPath $comKey -Recurse -Force }
    throw
}
